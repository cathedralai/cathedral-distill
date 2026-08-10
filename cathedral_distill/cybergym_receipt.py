"""`cathedral_cybergym_receipt_v1` — the signed, auditable result of scoring one
miner on one sealed CyberGym batch.

The CyberGym kernel (`cybergym.score_batch`) produces a `BatchScore`: a Merkle
`items_root` over the graded tasks and a level-weighted work-unit total. That is
the *measurement*; this receipt is the *statement a validator signs about it*, so
the score can enter the shared SN39 feed and be checked without re-running the
batch. It is a sibling of `cathedral_ml_eval_receipt_v1`, and it carries the same
disciplines: canonical JSON with exact key sets (unknown/missing field is an
error), decimal strings for every scored value (no float can move a weight),
domain-separated `receipt_id`, and an Ed25519 signature over the whole body.

The rewardable quantity is re-derivable from the receipt alone: `earned_units`
must equal `Σ per_level_solved[level] × level_weights[level]` for the pinned
weights, exactly as the SAT lane re-derives units from the CNF and never trusts a
worker-reported number. Re-running the differential crash test to confirm the
solved verdicts is the separate spot-check (it needs the binaries); this receipt
binds *which* batch, *which* miner, *which* epoch, and *what* was claimed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from cathedral_distill.cybergym import DEFAULT_LEVEL_WEIGHTS, Level

RECEIPT_SCHEMA_V1 = "cathedral_cybergym_receipt_v1"
RECEIPT_SCHEMA_V2 = "cathedral_cybergym_receipt_v2"
# v3 pins the canonical benchmark environment (the reproduce timeout + resource
# limits + network policy + verifier image digest) INTO the signed receipt, so a
# peer re-deriving the score can confirm the exact conditions the differential ran
# under — not just trust that some code path used them. A v3 receipt is a v2 receipt
# (it still carries the eligibility snapshot) plus the top-level `env` block.
RECEIPT_SCHEMA_V3 = "cathedral_cybergym_receipt_v3"
# Kept for callers constructing legacy/dev receipts without observed eligibility.
RECEIPT_SCHEMA = RECEIPT_SCHEMA_V1
RECEIPT_ID_DOMAIN = b"cathedral-cybergym-receipt-id-v1\x00"
MAX_RECEIPT_BYTES = 262_144

_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_BATCH_ID_RE = _DIGEST_RE
_DECIMAL_RE = re.compile(r"\A(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,12})?\Z")
_TS_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
_HEX_NONCE_RE = re.compile(r"\A[0-9A-Za-z_.:-]{1,128}\Z")

_RECEIPT_KEYS = frozenset(
    {
        "schema", "network", "netuid", "source_epoch",
        "validator_hotkey", "miner_hotkey", "issued_at",
        "valid_from_block", "valid_until_block",
        "batch", "score", "receipt_id", "signing_key_id", "signature",
    }
)
_RECEIPT_KEYS_V3 = _RECEIPT_KEYS | frozenset({"env"})
_BATCH_KEYS_V1 = frozenset({"batch_id", "nonce", "holdout_digest", "graded_tasks"})
_BATCH_KEYS_V2 = _BATCH_KEYS_V1 | frozenset({"eligibility_snapshot_digest"})
_SCORE_KEYS = frozenset(
    {
        "solved_tasks", "per_level_solved", "level_weights",
        "earned_units", "max_units", "score", "work_units", "items_root",
    }
)
# The canonical-environment block (v3). Every field is a canonical string so no
# float can move it and the whole block is bound by the receipt signature.
_ENV_KEYS = frozenset(
    {"reproduce_timeout_s", "cpu_seconds", "memory_bytes", "network_policy", "verifier_digest"}
)
# The network posture the differential ran under. `none` is the creditable
# attested posture (no egress); `unspecified` is the honest value when a legacy /
# non-attested deployment cannot assert it — never silently claim `none`.
_NETWORK_POLICIES = frozenset({"none", "unspecified"})
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})


class CyberGymReceiptError(ValueError):
    """Raised when a receipt is malformed or fails verification. Fails closed."""


def validate_issued_at(value: object) -> str:
    """Return one real canonical receipt timestamp or raise before it is signed.

    This is intentionally usable by the durable epoch store as well as receipt
    validation.  An invalid timestamp must never become the first-write-wins
    value for an epoch: a receipt could not verify with it, and a correct retry
    would otherwise be blocked by the poisoned durable pin.
    """
    if not isinstance(value, str) or not _TS_RE.match(value):
        raise CyberGymReceiptError("issued_at must be six-fraction-digit UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        raise CyberGymReceiptError("issued_at is not a real UTC timestamp") from None
    return value


# --------------------------------------------------------------------------- #
# Canonical bytes — the shared receipt discipline
# --------------------------------------------------------------------------- #

def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise CyberGymReceiptError("floats are not allowed; use decimal strings")
    if isinstance(value, Mapping):
        for item in value.values():
            _reject_floats(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_floats(item)


def canonical_bytes(body: Mapping[str, Any]) -> bytes:
    _reject_floats(body)
    return json.dumps(
        body, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_receipt_id(body: Mapping[str, Any]) -> str:
    stripped = {k: v for k, v in body.items() if k not in ("receipt_id", "signature")}
    return "receipt-sha256:" + _sha256_hex(RECEIPT_ID_DOMAIN + canonical_bytes(stripped))


def holdout_digest(task_ids: list[str]) -> str:
    """A stable digest over the batch's task-set identity, order-independent."""
    body = json.dumps(sorted(task_ids), separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(b"cathedral-cybergym-holdout-v1\x00" + body).hexdigest()


def _weights_to_dict(weights: Mapping[Level, Decimal]) -> dict[str, str]:
    return {str(int(level)): str(Decimal(weight)) for level, weight in weights.items()}


def _validate_env(env: Any) -> dict[str, str]:
    """Validate the canonical-environment block and return it as canonical strings.

    Fails closed: exact key set, decimal-string timeout/cpu, `memory_bytes` a
    decimal string or the literal `"unlimited"` (the sanitizer-target case where
    RLIMIT_AS is deliberately not capped), `network_policy` from a small allow-list,
    and `verifier_digest` a sha256 digest of the pinned verifier/workload image.
    """
    e = _exact_keys(env, _ENV_KEYS, "env")
    _decimal(e["reproduce_timeout_s"], "env.reproduce_timeout_s")
    _decimal(e["cpu_seconds"], "env.cpu_seconds")
    memory = str(e["memory_bytes"])
    if memory != "unlimited" and not _DECIMAL_RE.match(memory):
        raise CyberGymReceiptError("env.memory_bytes must be a decimal string or 'unlimited'")
    if str(e["network_policy"]) not in _NETWORK_POLICIES:
        raise CyberGymReceiptError(
            "env.network_policy must be one of: " + ", ".join(sorted(_NETWORK_POLICIES))
        )
    if not _DIGEST_RE.match(str(e["verifier_digest"])):
        raise CyberGymReceiptError("env.verifier_digest must be sha256:<64 hex>")
    return {k: str(v) for k, v in e.items()}


# --------------------------------------------------------------------------- #
# Build + sign
# --------------------------------------------------------------------------- #

def build_receipt(
    batch_score,
    *,
    network: str,
    netuid: int,
    source_epoch: int,
    validator_hotkey: str,
    miner_hotkey: str,
    nonce: str,
    holdout_digest_value: str,
    eligibility_snapshot_digest: str | None = None,
    valid_from_block: int,
    valid_until_block: int,
    issued_at: str,
    private_key: Ed25519PrivateKey,
    signing_key_id: str,
    level_weights: Mapping[Level, Decimal] = DEFAULT_LEVEL_WEIGHTS,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Assemble and sign a receipt from a `cybergym.BatchScore` and its context.

    When `env` (the canonical benchmark environment — reproduce timeout, resource
    limits, network policy, verifier image digest) is supplied, a v3 receipt is
    produced: it pins those conditions into the signed body so a peer can confirm
    them, not just re-derive the arithmetic. v3 is a superset of v2 and therefore
    still requires the eligibility snapshot.
    """
    if env is not None and eligibility_snapshot_digest is None:
        raise CyberGymReceiptError(
            "a v3 receipt (pinned env) also requires eligibility_snapshot_digest"
        )
    if env is not None:
        schema = RECEIPT_SCHEMA_V3
    elif eligibility_snapshot_digest is not None:
        schema = RECEIPT_SCHEMA_V2
    else:
        schema = RECEIPT_SCHEMA_V1
    body: dict[str, Any] = {
        "schema": schema,
        "network": network,
        "netuid": netuid,
        "source_epoch": source_epoch,
        "validator_hotkey": validator_hotkey,
        "miner_hotkey": miner_hotkey,
        "issued_at": issued_at,
        "valid_from_block": valid_from_block,
        "valid_until_block": valid_until_block,
        "batch": {
            "batch_id": batch_score.batch_id,
            "nonce": nonce,
            "holdout_digest": holdout_digest_value,
            "graded_tasks": int(batch_score.graded_tasks),
        },
        "score": {
            "solved_tasks": int(batch_score.solved_tasks),
            "per_level_solved": {str(k): int(v) for k, v in batch_score.per_level_solved.items()},
            "level_weights": _weights_to_dict(level_weights),
            "earned_units": str(batch_score.earned_units),
            "max_units": str(batch_score.max_units),
            "score": str(batch_score.score),
            "work_units": str(batch_score.earned_units),
            "items_root": batch_score.items_root,
        },
        "signing_key_id": signing_key_id,
    }
    if eligibility_snapshot_digest is not None:
        body["batch"]["eligibility_snapshot_digest"] = eligibility_snapshot_digest
    if env is not None:
        body["env"] = _validate_env(env)
    body["receipt_id"] = compute_receipt_id(body)
    signature = private_key.sign(canonical_bytes(body))
    body["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return body


# --------------------------------------------------------------------------- #
# Independent verification — before scoring
# --------------------------------------------------------------------------- #

def _exact_keys(value: Any, expected: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CyberGymReceiptError(f"{label} must be an object")
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        raise CyberGymReceiptError(f"{label} missing keys: {', '.join(missing)}")
    if unknown:
        raise CyberGymReceiptError(f"{label} unknown keys: {', '.join(unknown)}")
    return value


def _decimal(value: Any, label: str) -> Decimal:
    text = str(value)
    if not _DECIMAL_RE.match(text):
        raise CyberGymReceiptError(f"{label} must be a canonical decimal string")
    try:
        return Decimal(text)
    except InvalidOperation as exc:  # pragma: no cover - regex guards
        raise CyberGymReceiptError(f"{label} is not a valid decimal") from exc


def _nonneg_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CyberGymReceiptError(f"{label} must be a non-negative integer")
    return value


def validate_structure(receipt: Any) -> Mapping[str, Any]:
    if not isinstance(receipt, Mapping):
        raise CyberGymReceiptError("cybergym receipt must be an object")
    # Peek the schema so the exact-key-set matches the version (v3 adds `env`); an
    # unknown/missing schema still fails through the standard unsupported-schema path.
    receipt_keys = _RECEIPT_KEYS_V3 if receipt.get("schema") == RECEIPT_SCHEMA_V3 else _RECEIPT_KEYS
    doc = _exact_keys(receipt, receipt_keys, "cybergym receipt")
    if doc["schema"] not in (RECEIPT_SCHEMA_V1, RECEIPT_SCHEMA_V2, RECEIPT_SCHEMA_V3):
        raise CyberGymReceiptError("unsupported cybergym receipt schema")
    if len(canonical_bytes({k: v for k, v in doc.items() if k != "signature"})) > MAX_RECEIPT_BYTES:
        raise CyberGymReceiptError("receipt exceeds 256 KiB")
    validate_issued_at(doc["issued_at"])
    _nonneg_int(doc["source_epoch"], "source_epoch")
    first = _nonneg_int(doc["valid_from_block"], "valid_from_block")
    last = _nonneg_int(doc["valid_until_block"], "valid_until_block")
    if last <= first:
        raise CyberGymReceiptError("valid_until_block must exceed valid_from_block")

    _v2_or_v3 = doc["schema"] in (RECEIPT_SCHEMA_V2, RECEIPT_SCHEMA_V3)
    batch = _exact_keys(
        doc["batch"],
        _BATCH_KEYS_V2 if _v2_or_v3 else _BATCH_KEYS_V1,
        "batch",
    )
    if not _BATCH_ID_RE.match(str(batch["batch_id"])):
        raise CyberGymReceiptError("batch_id must be sha256:<64 hex>")
    if not _HEX_NONCE_RE.match(str(batch["nonce"])):
        raise CyberGymReceiptError("nonce is invalid")
    if not _DIGEST_RE.match(str(batch["holdout_digest"])):
        raise CyberGymReceiptError("holdout_digest must be sha256:<64 hex>")
    if _v2_or_v3 and not _DIGEST_RE.match(str(batch["eligibility_snapshot_digest"])):
        raise CyberGymReceiptError("eligibility_snapshot_digest must be sha256:<64 hex>")
    if doc["schema"] == RECEIPT_SCHEMA_V3:
        _validate_env(doc["env"])
    graded = _nonneg_int(batch["graded_tasks"], "graded_tasks")

    score = _exact_keys(doc["score"], _SCORE_KEYS, "score")
    solved = _nonneg_int(score["solved_tasks"], "solved_tasks")
    if solved > graded:
        raise CyberGymReceiptError("solved_tasks exceeds graded_tasks")
    if not _DIGEST_RE.match(str(score["items_root"])):
        raise CyberGymReceiptError("items_root must be sha256:<64 hex>")

    weights = score["level_weights"]
    if not isinstance(weights, Mapping) or not weights:
        raise CyberGymReceiptError("level_weights must be a non-empty object")
    weight_by_level: dict[str, Decimal] = {}
    for key, value in weights.items():
        if not isinstance(key, str) or not key.isdigit():
            raise CyberGymReceiptError("level_weights keys must be integer levels")
        weight_by_level[key] = _decimal(value, f"level_weights[{key}]")

    per_level = score["per_level_solved"]
    if not isinstance(per_level, Mapping):
        raise CyberGymReceiptError("per_level_solved must be an object")
    derived_earned = Decimal(0)
    derived_solved = 0
    for key, value in per_level.items():
        if not isinstance(key, str) or key not in weight_by_level:
            raise CyberGymReceiptError("per_level_solved names an unweighted level")
        count = _nonneg_int(value, f"per_level_solved[{key}]")
        derived_solved += count
        derived_earned += count * weight_by_level[key]

    earned = _decimal(score["earned_units"], "earned_units")
    work_units = _decimal(score["work_units"], "work_units")
    max_units = _decimal(score["max_units"], "max_units")
    reported_score = _decimal(score["score"], "score")

    # The rewardable quantity is re-derived, never trusted.
    if derived_solved != solved:
        raise CyberGymReceiptError("solved_tasks does not match per_level_solved")
    if derived_earned != earned:
        raise CyberGymReceiptError("earned_units does not match per_level_solved × weights")
    if work_units != earned:
        raise CyberGymReceiptError("work_units must equal earned_units")
    if max_units < earned:
        raise CyberGymReceiptError("max_units cannot be below earned_units")
    if reported_score > 1:
        raise CyberGymReceiptError("score must be within 0..1")
    expected_score = (
        (earned / max_units) if max_units > 0 else Decimal(0)
    ).quantize(Decimal("0.000000000001"))
    if reported_score.quantize(Decimal("0.000000000001")) != expected_score:
        raise CyberGymReceiptError("score does not match earned/max")

    _exact_keys(doc["signature"], _SIGNATURE_KEYS, "signature")
    receipt_id = doc["receipt_id"]
    if not isinstance(receipt_id, str) or not receipt_id.startswith("receipt-sha256:"):
        raise CyberGymReceiptError("receipt_id is malformed")
    return doc


def verify_receipt(
    receipt: Mapping[str, Any],
    key_registry: Any,
    *,
    source_epoch: int,
) -> Mapping[str, Any]:
    """Independently verify a receipt before scoring. Fails closed on any check.

    Structure → receipt_id recomputation → key resolution → Ed25519 signature →
    source_epoch replay binding. `key_registry` resolves the receipt's
    `signing_key_id` to the anchored public key
    (`key_registry.resolve(key_id, at=issued_at)`); the verifier never takes a
    caller-supplied key. The differential re-run of solved verdicts is the
    separate spot-check.
    """
    doc = validate_structure(receipt)
    if doc["receipt_id"] != compute_receipt_id(doc):
        raise CyberGymReceiptError("receipt_id does not match the receipt body")
    try:
        issued_at = datetime.strptime(
            str(doc["issued_at"]), "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=timezone.utc)
        public_key = key_registry.resolve(doc["signing_key_id"], at=issued_at)
    except CyberGymReceiptError:
        raise
    except Exception as exc:  # ReceiptKeyError / parse failure -> reject
        raise CyberGymReceiptError(f"signing key could not be resolved: {exc}") from exc
    sig = _exact_keys(doc["signature"], _SIGNATURE_KEYS, "signature")
    if sig["algorithm"] != "ed25519":
        raise CyberGymReceiptError("unsupported signature algorithm")
    signed = {k: v for k, v in doc.items() if k != "signature"}
    try:
        public_key.verify(base64.b64decode(sig["value_base64"]), canonical_bytes(signed))
    except (InvalidSignature, ValueError) as exc:
        raise CyberGymReceiptError("signature does not verify") from exc
    if int(doc["source_epoch"]) != int(source_epoch):
        raise CyberGymReceiptError("receipt source_epoch does not match the authorized epoch")
    return doc


def lane_contribution(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """The per-miner contribution this receipt makes to the signed SN39 feed."""
    return {
        "miner_hotkey": str(receipt["miner_hotkey"]),
        "receipt_id": str(receipt["receipt_id"]),
        "work_units": str(receipt["score"]["work_units"]),
    }
