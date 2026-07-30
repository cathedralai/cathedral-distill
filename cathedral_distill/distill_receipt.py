"""`cathedral_distill_receipt_v1` — the Distill lane's assurance receipt.

This is a **versioned extension of the compute receipt, not a parallel format**.
Every shared field carries the same name and meaning as
`cathedral_assurance_receipt_v2` (see `cathedralconfidential/docs/RECEIPTS.md`), so
the existing SN39 receipt verifier reasons about the shared body unchanged. The
only addition is one `evaluation` block holding the Distill-specific evidence an
independent verifier needs to re-derive the score.

The proof path is identical to compute:

    worker identity → challenge → manifest & result digests → assurance claims →
    policy registry → measurement → TCB → lifecycle → issued_at → receipt_id →
    signature

For a Distill result the "worker" is the evaluator machine, the "challenge" is the
evaluation authorization, the "result" is the score record, and the four assurance
claims (channel/hardware/software/work) mean the same as compute — the `work`
claim asserts the evaluation ran and was verified. The `evaluation` block then
pins *what* was evaluated (model, sealed eval set, evaluator, runtime) and the
score, each by digest, so the number can be checked without trusting the issuer.

Canonical bytes follow the compute rule exactly: JSON with sorted keys, ASCII
escaping, `,`/`:` separators, no insignificant whitespace, decimal strings for any
scored value (so zero has one representation), six-fractional-digit UTC
timestamps, and no floats. `receipt_id` is the SHA-256 of the canonical body
before `receipt_id` and `signature` are added; the Ed25519 signature covers every
field except `signature` itself. Unknown or missing fields fail closed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Mapping

_SCORE_Q = Decimal("0.000000000001")  # 12 dp, the shared score-comparison quantum


def _parse_ts(value: str) -> datetime:
    """Parse a six-fraction-digit UTC receipt timestamp to an aware datetime."""
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise DistillReceiptError("issued_at is not a valid UTC timestamp") from exc

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

RECEIPT_SCHEMA = "cathedral_distill_receipt_v1"
EVALUATION_SCHEMA = "cathedral_distill_evaluation_v1"
ASSURANCE_SCHEMA = "assurance_claims_v1"

MAX_RECEIPT_BYTES = 262_144  # 256 KiB, matching the compute receipt limit

_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_RECEIPT_ID_RE = re.compile(r"\Areceipt-sha256:[0-9a-f]{64}\Z")
_DECIMAL_RE = re.compile(r"\A(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,12})?\Z")
_TS_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
# Strict TDX semantics, mirroring cathedral_assurance_receipt_v2 (#3.4).
_TCB_SVN_RE = re.compile(r"\A[0-9a-f]{32}\Z")
_MEASUREMENT_RE = re.compile(r"\Atdx-measurement-sha256:[0-9a-f]{64}\Z")
MAX_TCB_ADVISORIES = 256
# The vendor TCB status vocabulary from the compute repo (cathedral.common).
TDX_TCB_STATUSES = frozenset(
    {
        "UpToDate", "OutOfDate", "ConfigurationNeeded",
        "OutOfDateConfigurationNeeded", "SWHardeningNeeded",
        "ConfigurationAndSWHardeningNeeded", "Revoked",
    }
)
_TCB_KEYS = frozenset(
    {"status", "version", "svn", "advisory_ids", "debug_enabled", "collateral_current"}
)
_CHANNEL_KEYS = frozenset({"status", "binding_digest"})

# The shared top-level field set, verbatim from cathedral_assurance_receipt_v2,
# plus the single Distill extension `evaluation`. Keeping the set explicit is
# what makes "unknown or missing fields fail closed" real.
_SHARED_KEYS = frozenset(
    {
        "schema", "receipt_id", "signing_key_id", "signature",
        "subject_hotkey", "epoch_id", "source_epoch", "issued_at",
        "platform_pseudonym", "measurement", "tcb",
        "policy_registry_release", "policy_registry_digest", "policy_profile_ids",
        "channel", "work", "assurance", "lifecycle",
    }
)
_RECEIPT_KEYS = _SHARED_KEYS | {"evaluation"}

_WORK_KEYS = frozenset(
    {"challenge_id", "manifest_digest", "result_digest", "status", "work_units"}
)
_EVALUATION_KEYS = frozenset(
    {
        "schema", "model_digest", "tokenizer_digest", "evalset_digest",
        "evaluator_digest", "runtime_digest", "score",
        "graded_items", "passed_items", "evidence_digest",
    }
)
_CLAIM_KEYS = frozenset({"channel", "hardware", "software", "work"})


class DistillReceiptError(ValueError):
    """Raised when a receipt is malformed or fails verification. Fails closed."""


# --------------------------------------------------------------------------- #
# Canonical bytes — the exact rule the compute receipt uses
# --------------------------------------------------------------------------- #

def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise DistillReceiptError(
            "floats are not allowed in a receipt; use decimal strings"
        )
    if isinstance(value, Mapping):
        for v in value.values():
            _reject_floats(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _reject_floats(v)


def canonical_bytes(body: Mapping[str, Any]) -> bytes:
    """Sorted keys, ASCII escaping, `,`/`:` separators, no whitespace, no floats."""
    _reject_floats(body)
    return json.dumps(
        body, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_receipt_id(body: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical body *before* receipt_id and signature are added."""
    stripped = {k: v for k, v in body.items() if k not in ("receipt_id", "signature")}
    return "receipt-sha256:" + _sha256_hex(canonical_bytes(stripped))


# --------------------------------------------------------------------------- #
# Build + sign
# --------------------------------------------------------------------------- #

def build_receipt(
    body: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    signing_key_id: str,
) -> dict[str, Any]:
    """Assemble a signed receipt from a body that omits receipt_id and signature.

    The body must already contain every shared field and the `evaluation` block.
    This adds `signing_key_id`, computes `receipt_id`, then signs everything
    except `signature`.
    """
    doc = {k: v for k, v in body.items() if k not in ("receipt_id", "signature")}
    doc["signing_key_id"] = signing_key_id
    doc["receipt_id"] = compute_receipt_id(doc)
    signature = private_key.sign(canonical_bytes(doc))
    doc["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return doc


# --------------------------------------------------------------------------- #
# Independent verification — everything a validator checks before scoring
# --------------------------------------------------------------------------- #

def _exact_keys(value: Any, expected: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DistillReceiptError(f"{label} must be an object")
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        raise DistillReceiptError(f"{label} missing keys: {', '.join(missing)}")
    if unknown:
        raise DistillReceiptError(f"{label} unknown keys: {', '.join(unknown)}")
    return value


def _digest(value: Any, label: str) -> str:
    text = str(value or "")
    if not _DIGEST_RE.match(text):
        raise DistillReceiptError(f"{label} must be sha256:<64 lowercase hex>")
    return text


def _decimal(value: Any, label: str) -> str:
    text = str(value)
    if not _DECIMAL_RE.match(text):
        raise DistillReceiptError(f"{label} must be a canonical decimal string")
    return text


def _validate_tcb(tcb: Any) -> None:
    """The TDX TCB block, verified with the compute receipt's strict rules: a
    known non-Revoked status, a 32-hex SVN, bounded advisories that must be
    listed when the status is not UpToDate, debug OFF, and current collateral."""
    block = _exact_keys(tcb, _TCB_KEYS, "tcb")
    version = block["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise DistillReceiptError("tcb.version must be a non-negative integer")
    if block["status"] not in TDX_TCB_STATUSES:
        raise DistillReceiptError("tcb.status is not a known TDX status")
    if block["status"] == "Revoked":
        raise DistillReceiptError("tcb.status is Revoked")
    if not isinstance(block["svn"], str) or _TCB_SVN_RE.match(block["svn"]) is None:
        raise DistillReceiptError("tcb.svn must be 32 lowercase hex")
    advisories = block["advisory_ids"]
    if not isinstance(advisories, list) or len(advisories) > MAX_TCB_ADVISORIES:
        raise DistillReceiptError("tcb.advisory_ids must be a bounded list")
    if any(not isinstance(a, str) or not a or len(a) > 128 for a in advisories):
        raise DistillReceiptError("tcb.advisory_ids entries are invalid")
    if block["status"] != "UpToDate" and not advisories:
        raise DistillReceiptError("a non-UpToDate TCB must list its advisories")
    if block["debug_enabled"] is not False:
        raise DistillReceiptError("tcb.debug_enabled must be false")
    if block["collateral_current"] is not True:
        raise DistillReceiptError("tcb.collateral_current must be true")


def validate_structure(receipt: Any) -> Mapping[str, Any]:
    """Structural validation: fail closed on any unknown or missing field."""
    doc = _exact_keys(receipt, _RECEIPT_KEYS, "distill receipt")
    if doc["schema"] != RECEIPT_SCHEMA:
        raise DistillReceiptError("unsupported distill receipt schema")
    if len(canonical_bytes({k: v for k, v in doc.items() if k != "signature"})) > MAX_RECEIPT_BYTES:
        raise DistillReceiptError("receipt exceeds 256 KiB")
    if not _RECEIPT_ID_RE.match(str(doc["receipt_id"])):
        raise DistillReceiptError("receipt_id must be receipt-sha256:<64 hex>")
    if not _TS_RE.match(str(doc["issued_at"])):
        raise DistillReceiptError("issued_at must be six-fraction-digit UTC")

    # Shared attestation fields, verified with Compute's strict semantics (#3.4).
    if not _MEASUREMENT_RE.match(str(doc["measurement"])):
        raise DistillReceiptError("measurement must be tdx-measurement-sha256:<64 hex>")
    _validate_tcb(doc["tcb"])
    channel = _exact_keys(doc["channel"], _CHANNEL_KEYS, "channel")
    _digest(channel["binding_digest"], "channel.binding_digest")
    if str(channel["status"]) not in ("passed", "failed", "unknown"):
        raise DistillReceiptError("channel status is invalid")
    # A confidential channel that did not verify is not a confidential channel. The
    # status was previously only checked against the vocabulary, so a correctly
    # signed receipt with channel.status='failed' still credited a perfect score.
    if str(channel["status"]) != "passed":
        raise DistillReceiptError("channel.status must be 'passed' for a creditable receipt")

    work = _exact_keys(doc["work"], _WORK_KEYS, "work")
    _digest(work["manifest_digest"], "work.manifest_digest")
    _digest(work["result_digest"], "work.result_digest")
    work_units = _decimal(work["work_units"], "work.work_units")
    # The evaluation must have SUCCEEDED. Compute has always required this; the
    # Distill lane did not, despite the docstring claiming parity, so a receipt
    # that recorded a failed or degraded evaluation was credited in full.
    if str(work["status"]) != "passed":
        raise DistillReceiptError("work.status must be 'passed' for a creditable receipt")

    assurance = _exact_keys(doc["assurance"], frozenset({"schema", "claims"}), "assurance")
    if assurance["schema"] != ASSURANCE_SCHEMA:
        raise DistillReceiptError("unsupported assurance schema")
    claims = _exact_keys(assurance["claims"], _CLAIM_KEYS, "assurance.claims")
    for name, claim in claims.items():
        if str(claim.get("status")) not in ("passed", "failed", "unknown"):
            raise DistillReceiptError(f"assurance claim {name} has an invalid status")
    # A creditable receipt asserts the confidential channel, the hardware, the
    # software, AND the work itself actually verified: the exact set
    # `compute_receipt.validate_structure` requires. Gating only hardware and
    # software meant a receipt could carry a FAILED channel or work claim and
    # still be admitted as verified work.
    for required in ("channel", "hardware", "software", "work"):
        if str(claims[required].get("status")) != "passed":
            raise DistillReceiptError(f"assurance {required} claim must be passed")

    ev = _exact_keys(doc["evaluation"], _EVALUATION_KEYS, "evaluation")
    if ev["schema"] != EVALUATION_SCHEMA:
        raise DistillReceiptError("unsupported evaluation schema")
    for field in ("model_digest", "tokenizer_digest", "evalset_digest",
                  "evaluator_digest", "runtime_digest", "evidence_digest"):
        _digest(ev[field], f"evaluation.{field}")
    _decimal(ev["score"], "evaluation.score")
    for field in ("graded_items", "passed_items"):
        if isinstance(ev[field], bool) or not isinstance(ev[field], int) or ev[field] < 0:
            raise DistillReceiptError(f"evaluation.{field} must be a non-negative integer")
    if ev["passed_items"] > ev["graded_items"]:
        raise DistillReceiptError("evaluation.passed_items exceeds graded_items")

    # Rederive the score and the rewardable units from the item counts, so a
    # receipt cannot claim a score its own counts do not support (e.g. score=1.0
    # with passed=0) or an arbitrary work_units (e.g. 999). The distill work-unit
    # rule (distill_work_units_v1) is: work_units == passed_items — the count of
    # verified-correct items is the rewardable quantity, never a signer's number.
    graded = ev["graded_items"]
    passed = ev["passed_items"]
    reported_score = Decimal(str(ev["score"]))
    if reported_score > 1:
        raise DistillReceiptError("evaluation.score must be within 0..1")
    expected_score = (
        Decimal(passed) / Decimal(graded) if graded else Decimal(0)
    ).quantize(_SCORE_Q)
    if reported_score.quantize(_SCORE_Q) != expected_score:
        raise DistillReceiptError("evaluation.score does not match passed_items/graded_items")
    if Decimal(work_units) != Decimal(passed):
        raise DistillReceiptError(
            "work.work_units must equal evaluation.passed_items (distill_work_units_v1)"
        )
    return doc


def verify_receipt(
    receipt: Mapping[str, Any],
    key_registry: Any,
    *,
    now_iso: str,
    source_epoch: int,
    allowed_measurements: frozenset[str] | set[str] | None = None,
    allowed_tcb_statuses: frozenset[str] | set[str] | None = None,
    allowed_advisories: frozenset[str] | set[str] | None = None,
) -> Mapping[str, Any]:
    """Independently verify a receipt before scoring. Fails closed on any check.

    Checks, in order — structure, receipt_id, key resolution, signature,
    replay/epoch binding, lifecycle, and freshness — mirroring the compute
    receipt's verification so a Distill contribution is admitted on exactly the
    same evidence a compute contribution is.

    `key_registry` resolves the receipt's `signing_key_id` to the anchored public
    key (`key_registry.resolve(key_id, at=issued_at)`); the verifier NEVER takes a
    caller-supplied key, so a receipt cannot carry its own verifying key. Use
    `cathedral_distill.receipt_keys.ReceiptKeyRegistry`.
    """
    doc = validate_structure(receipt)

    # 1. receipt_id must recompute from the canonical body.
    if doc["receipt_id"] != compute_receipt_id(doc):
        raise DistillReceiptError("receipt_id does not match the receipt body")

    # 2. Resolve the signing key from the anchored registry, at issue time.
    issued_at_dt = _parse_ts(str(doc["issued_at"]))
    try:
        public_key = key_registry.resolve(doc["signing_key_id"], at=issued_at_dt)
    except Exception as exc:  # ReceiptKeyError (or any resolver failure) -> reject
        raise DistillReceiptError(f"signing key could not be resolved: {exc}") from exc

    # 3. Ed25519 signature over everything except `signature`.
    sig = _exact_keys(doc["signature"], frozenset({"algorithm", "value_base64"}), "signature")
    if sig["algorithm"] != "ed25519":
        raise DistillReceiptError("unsupported signature algorithm")
    signed = {k: v for k, v in doc.items() if k != "signature"}
    try:
        public_key.verify(base64.b64decode(sig["value_base64"]), canonical_bytes(signed))
    except (InvalidSignature, ValueError) as exc:
        raise DistillReceiptError("signature does not verify") from exc

    # 3. Policy gating (when the validator supplies the signed-registry policy):
    # measurement, TCB status, and advisories must be admitted by policy — the
    # same membership checks Compute applies against its policy registry.
    if allowed_measurements is not None and doc["measurement"] not in allowed_measurements:
        raise DistillReceiptError("measurement is not admitted by policy")
    if allowed_tcb_statuses is not None and doc["tcb"]["status"] not in allowed_tcb_statuses:
        raise DistillReceiptError("tcb.status is not admitted by policy")
    if allowed_advisories is not None and not set(doc["tcb"]["advisory_ids"]).issubset(
        allowed_advisories
    ):
        raise DistillReceiptError("tcb advisories are not admitted by policy")

    # 4. Replay protection: the receipt is bound to the authorized source epoch.
    if int(doc["source_epoch"]) != int(source_epoch):
        raise DistillReceiptError("receipt source_epoch does not match the authorized epoch")

    # 4. Lifecycle: v2 admits only an issued receipt with no revocation.
    lifecycle = doc["lifecycle"]
    if str(lifecycle.get("state")) != "issued":
        raise DistillReceiptError("receipt lifecycle state is not 'issued'")
    if lifecycle.get("revocation_reference") is not None:
        raise DistillReceiptError("receipt has a revocation reference")

    # 5. Freshness: the evaluator evidence must not have expired by `now`.
    expires = str(lifecycle.get("worker_evidence_expires_at") or "")
    if not _TS_RE.match(expires):
        raise DistillReceiptError("lifecycle evidence-expiry is not a valid timestamp")
    if now_iso >= expires:
        raise DistillReceiptError("evaluator evidence has expired (stale receipt)")
    if now_iso < str(doc["issued_at"]):
        raise DistillReceiptError("receipt issued in the future")

    return doc


# --------------------------------------------------------------------------- #
# Public aliases for the shared `cathedral_assurance_receipt_v2` body primitives.
# The compute receipt (`compute_receipt.py`) verifies the same shared body, so it
# reuses these already-tested helpers rather than re-implementing the TDX/TCB and
# canonical rules — the shared body is validated by one function in both lanes.
# These are thin re-exports; behaviour is unchanged.
# --------------------------------------------------------------------------- #
validate_tcb = _validate_tcb
exact_keys = _exact_keys
digest_field = _digest
decimal_field = _decimal
parse_ts = _parse_ts
MEASUREMENT_RE = _MEASUREMENT_RE
RECEIPT_ID_RE = _RECEIPT_ID_RE
TS_RE = _TS_RE
DIGEST_RE = _DIGEST_RE
CHANNEL_KEYS = _CHANNEL_KEYS
WORK_KEYS = _WORK_KEYS
CLAIM_KEYS = _CLAIM_KEYS


def lane_contribution(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """The per-miner contribution this receipt makes to the signed SN39 feed.

    A verified receipt yields one contribution: the subject miner and the decimal
    work units the validator derived. The feed composes these across lanes.
    """
    return {
        "miner_hotkey": str(receipt["subject_hotkey"]),
        "receipt_id": str(receipt["receipt_id"]),
        "work_units": str(receipt["work"]["work_units"]),
    }
