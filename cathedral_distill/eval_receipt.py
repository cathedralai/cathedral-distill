"""Sealed-evaluation receipts for the Cathedral distillation track.

`cathedral_ml_eval_receipt_v1` is a sibling of `cathedral_ml_inference_receipt_v1`.
The inference receipt answers "did this exact model and runtime produce this one
output?". The eval receipt answers a different question:

    did this exact checkpoint score X on an evaluation set it was never shown?

That inversion is the whole point. In VerifyML the validator authorizes a known
input and later reveals it to check the commitment. An evaluation cannot work
that way: a miner who can read the eval set trains on it, and the score stops
measuring capability. So the set travels encrypted, the data key is released
only into an attested enclave (see `cathedral.key_release`), and the miner
learns nothing but its own score.

Design rules carried over from the inference receipt, deliberately:

- domain-separated hashing everywhere, so no digest can be replayed in another
  position;
- 64-byte TDX `report_data` split into an identity half and an execution half,
  each independently reconstructible by a verifier;
- canonical JSON with exact key sets, so an unknown or missing field is an
  error rather than a silently ignored difference;
- `Decimal` for every number that reaches scoring, so no float rounding can
  move a weight.

What this receipt proves: the named checkpoint was executed under the named
runtime against the named sealed set, and the grader derived this score. What
it does not prove: that the score is a good measure of anything. That is the
eval set's job, and it is why the set is sealed rather than merely hashed.
"""
from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping

SCHEMA = "cathedral_ml_eval_receipt_v1"
AUTHORIZATION_SCHEMA = "cathedral_ml_eval_authorization_v1"

RECEIPT_DOMAIN = b"cathedral-ml-eval-receipt-v1\x00"
RECEIPT_ID_DOMAIN = b"cathedral-ml-eval-receipt-id-v1\x00"
AUTHORIZATION_DOMAIN = b"cathedral-ml-eval-authorization-v1\x00"
IDENTITY_BINDING_DOMAIN = b"cathedral-ml-eval-identity-binding-v1\x00"
EXECUTION_BINDING_DOMAIN = b"cathedral-ml-eval-execution-binding-v1\x00"
# v2 binds the item's position into the leaf. A v1 leaf committed only
# (item_id, output_commitment, passed), so a valid opening at one position could
# be replayed under a different challenged position (issue #1). The position is
# now part of the commitment, and challenge.verify_proof derives orientation from
# that position rather than trusting a prover-supplied direction flag. The domain
# bump means any stray v1 leaf fails loudly instead of being silently reinterpreted.
ITEM_LEAF_DOMAIN = b"cathedral-ml-eval-item-leaf-v2\x00"
ITEM_NODE_DOMAIN = b"cathedral-ml-eval-item-node-v1\x00"

ATTESTATION_KINDS = frozenset({"none", "tdx", "tdx+nvidia", "polaris_tdx"})

# Kinds whose 64-byte report_data can be rebuilt from the receipt alone. For
# these, structural validation is also a binding check.
#
# `polaris_tdx` is deliberately excluded. Polaris binds
# sha256(image_digest || sha256hex(stdout)), which needs the resolved image
# digest and the run nonce/pubkey — context that does not live in the receipt.
# Those receipts are structurally validated here and bound in
# `cathedral_distill.polaris_attest`, so nobody mistakes "parsed cleanly" for
# "proved anything".
SELF_BINDING_ATTESTATION_KINDS = frozenset({"tdx", "tdx+nvidia"})

MAX_RECEIPT_BYTES = 262_144
MAX_ATTESTATION_BYTES = 1_048_576
MAX_MODEL_ID_BYTES = 256
MAX_ITEMS = 65_536

_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_DECIMAL_RE = re.compile(r"\A(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,12})?\Z")
_REPORT_DATA_RE = re.compile(r"\A[0-9a-f]{128}\Z")

_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "network",
        "netuid",
        "source_epoch",
        "eval_id",
        "validator_hotkey",
        "miner_hotkey",
        "nonce_base64",
        "issued_at",
        "completed_at",
        "valid_from_block",
        "valid_until_block",
        "model",
        "runtime",
        "evalset",
        "grader",
        "score",
        "eval_authorization",
        "attestation",
        "receipt_id",
        "signature",
    }
)

# Mirrors _MODEL_KEYS / _RUNTIME_KEYS in cathedral_thin.ml_receipts so a
# checkpoint identified in an eval receipt is byte-identical to the same
# checkpoint identified in an inference receipt.
_MODEL_KEYS = frozenset({"model_id", "weights_digest", "tokenizer_digest"})
_RUNTIME_KEYS = frozenset({"image_digest", "runner_digest", "decode_digest"})

# `sealed_digest` is the digest of the ciphertext the miner actually holds.
# `plaintext_digest` is the digest of the decrypted set: the validator knows it,
# and publishing it in the receipt reveals nothing, but it is what pins the
# miner to the set the validator meant. `key_grant_id` ties the run to the
# attestation-gated release that handed the enclave its data key.
_EVALSET_KEYS = frozenset(
    {
        "evalset_id",
        "sealed_digest",
        "plaintext_digest",
        "item_count",
        "key_grant_id",
    }
)

# The grader is pinned as tightly as the model. A score is only meaningful
# relative to the exact code that produced it.
_GRADER_KEYS = frozenset({"grader_id", "grader_digest", "harness_digest"})

# `items_root` is a Merkle root over per-item results, so a validator can
# spot-check any single item without the miner shipping every output.
_SCORE_KEYS = frozenset(
    {
        "graded_items",
        "passed_items",
        "score",
        "items_root",
        "input_tokens",
        "output_tokens",
        "latency_p50_ms",
        "latency_p95_ms",
        "work_units",
    }
)

_ATTESTATION_KEYS = frozenset(
    {"kind", "evidence_digest", "evidence_uri", "policy_digest", "report_data_hex"}
)
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})
_AUTHORIZATION_KEYS = frozenset(
    {"schema", "eval_id", "validator_hotkey", "miner_hotkey", "signature"}
)


class EvalReceiptError(ValueError):
    """Raised when a receipt or one of its parts fails validation."""


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Byte-exact JSON. Sorted keys, no whitespace, no non-finite floats."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_bytes(data: bytes) -> str:
    return sha256_digest(data)


def _exact_keys(value: Any, expected: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EvalReceiptError(f"{label} must be an object")
    present = set(value)
    missing = sorted(expected - present)
    unknown = sorted(present - expected)
    if missing:
        raise EvalReceiptError(f"{label} missing keys: {', '.join(missing)}")
    if unknown:
        raise EvalReceiptError(f"{label} unknown keys: {', '.join(unknown)}")
    return value


def _digest(value: Any, label: str) -> str:
    text = str(value or "")
    if not _DIGEST_RE.match(text):
        raise EvalReceiptError(f"{label} must be sha256:<64 lowercase hex>")
    return text


def _decimal(value: Any, label: str) -> Decimal:
    text = str(value)
    if not _DECIMAL_RE.match(text):
        raise EvalReceiptError(f"{label} must be a canonical decimal string")
    try:
        return Decimal(text)
    except InvalidOperation as exc:  # pragma: no cover - regex already guards
        raise EvalReceiptError(f"{label} is not a valid decimal") from exc


def canonical_decimal(value: Decimal | int | str) -> str:
    """Normalise a number to the one string form the receipt will ever carry."""
    parsed = Decimal(str(value))
    if parsed < 0:
        raise EvalReceiptError("decimal values must be non-negative")
    text = format(parsed.normalize(), "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _count(value: Any, label: str, *, maximum: int = MAX_ITEMS) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvalReceiptError(f"{label} must be an integer")
    if value < 0 or value > maximum:
        raise EvalReceiptError(f"{label} out of range")
    return value


def item_leaf(index: int, item_id: str, output_commitment: str, passed: bool) -> bytes:
    """Hash one graded item at its position in the graded sequence.

    `index` is the item's 0-based position and is part of the commitment, so an
    opening proved for one position cannot be relabelled under another. A
    validator that wants to audit one item asks the miner to reveal only that
    item's `output_commitment` (a commitment, not the output) at that index.
    """
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise EvalReceiptError("item index must be a non-negative integer")
    body = canonical_json(
        {
            "index": index,
            "item_id": str(item_id),
            "output_commitment": _digest(output_commitment, "output_commitment"),
            "passed": bool(passed),
        }
    )
    return hashlib.sha256(ITEM_LEAF_DOMAIN + body).digest()


def items_root(leaves: list[bytes]) -> str:
    """Merkle root over graded items.

    An odd node is promoted rather than duplicated, which avoids the
    duplicate-leaf ambiguity that lets two different item lists share a root.
    """
    if not leaves:
        return sha256_digest(ITEM_NODE_DOMAIN)
    if len(leaves) > MAX_ITEMS:
        raise EvalReceiptError("too many graded items")
    level = list(leaves)
    while len(level) > 1:
        nxt: list[bytes] = []
        for index in range(0, len(level) - 1, 2):
            nxt.append(
                hashlib.sha256(
                    ITEM_NODE_DOMAIN + level[index] + level[index + 1]
                ).digest()
            )
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return "sha256:" + level[0].hex()


def validate_model(value: Any) -> Mapping[str, Any]:
    model = _exact_keys(value, _MODEL_KEYS, "model")
    model_id = str(model["model_id"] or "")
    if not model_id or len(model_id.encode("utf-8")) > MAX_MODEL_ID_BYTES:
        raise EvalReceiptError("model_id must be 1..256 bytes")
    _digest(model["weights_digest"], "weights_digest")
    _digest(model["tokenizer_digest"], "tokenizer_digest")
    return model


def validate_runtime(value: Any) -> Mapping[str, Any]:
    runtime = _exact_keys(value, _RUNTIME_KEYS, "runtime")
    _digest(runtime["image_digest"], "image_digest")
    _digest(runtime["runner_digest"], "runner_digest")
    # Sampling parameters are execution identity: the same checkpoint under a
    # different temperature or seed is a different measurement. Pinning their
    # digest here puts them inside the report_data binding automatically.
    _digest(runtime["decode_digest"], "decode_digest")
    return runtime


def validate_evalset(value: Any) -> Mapping[str, Any]:
    evalset = _exact_keys(value, _EVALSET_KEYS, "evalset")
    if not str(evalset["evalset_id"] or ""):
        raise EvalReceiptError("evalset_id must be non-empty")
    _digest(evalset["sealed_digest"], "sealed_digest")
    _digest(evalset["plaintext_digest"], "plaintext_digest")
    if evalset["sealed_digest"] == evalset["plaintext_digest"]:
        raise EvalReceiptError(
            "sealed_digest equals plaintext_digest: the set was not encrypted"
        )
    count = _count(evalset["item_count"], "item_count")
    if count == 0:
        raise EvalReceiptError("item_count must be positive")
    if not str(evalset["key_grant_id"] or ""):
        raise EvalReceiptError("key_grant_id must be non-empty")
    return evalset


def validate_grader(value: Any) -> Mapping[str, Any]:
    grader = _exact_keys(value, _GRADER_KEYS, "grader")
    if not str(grader["grader_id"] or ""):
        raise EvalReceiptError("grader_id must be non-empty")
    _digest(grader["grader_digest"], "grader_digest")
    _digest(grader["harness_digest"], "harness_digest")
    return grader


def validate_score(value: Any, *, item_count: int) -> Mapping[str, Any]:
    score = _exact_keys(value, _SCORE_KEYS, "score")
    graded = _count(score["graded_items"], "graded_items")
    passed = _count(score["passed_items"], "passed_items")
    if passed > graded:
        raise EvalReceiptError("passed_items exceeds graded_items")
    if graded != item_count:
        raise EvalReceiptError(
            "graded_items must equal evalset item_count: a partial run is not a score"
        )
    reported = _decimal(score["score"], "score")
    if reported > 1:
        raise EvalReceiptError("score must be within 0..1")
    # The score is derived, never asserted. A miner cannot report a pass rate
    # that disagrees with its own item counts.
    expected = (
        Decimal(passed) / Decimal(graded) if graded else Decimal(0)
    ).quantize(Decimal("0.000000000001"))
    if reported.quantize(Decimal("0.000000000001")) != expected:
        raise EvalReceiptError("score does not match passed_items / graded_items")
    _digest(score["items_root"], "items_root")
    _count(score["input_tokens"], "input_tokens", maximum=2**53)
    _count(score["output_tokens"], "output_tokens", maximum=2**53)
    p50 = _decimal(score["latency_p50_ms"], "latency_p50_ms")
    p95 = _decimal(score["latency_p95_ms"], "latency_p95_ms")
    if p95 < p50:
        raise EvalReceiptError("latency_p95_ms must be >= latency_p50_ms")
    _decimal(score["work_units"], "work_units")
    return score


def validate_attestation(value: Any) -> Mapping[str, Any]:
    attestation = _exact_keys(value, _ATTESTATION_KEYS, "attestation")
    kind = str(attestation["kind"] or "")
    if kind not in ATTESTATION_KINDS:
        raise EvalReceiptError(
            "attestation kind must be one of: " + ", ".join(sorted(ATTESTATION_KINDS))
        )
    if kind == "none":
        # An unattested receipt is signed provenance and nothing more. It is
        # allowed so the harness can be exercised without a TEE, but it must
        # never reach `verified_work_units`.
        return attestation
    _digest(attestation["evidence_digest"], "evidence_digest")
    _digest(attestation["policy_digest"], "policy_digest")
    report_data = str(attestation["report_data_hex"] or "")
    if not _REPORT_DATA_RE.match(report_data):
        raise EvalReceiptError("report_data_hex must be 128 lowercase hex chars")
    return attestation


def unsigned_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in document.items()
        if key not in {"receipt_id", "signature"}
    }


def receipt_id_for(document: Mapping[str, Any]) -> str:
    return sha256_digest(RECEIPT_ID_DOMAIN + canonical_json(unsigned_receipt(document)))


def expected_report_data(document: Mapping[str, Any]) -> bytes:
    """Rebuild the 64-byte TDX report_data from the receipt alone.

    Two independent halves, matching the inference receipt's construction. A
    verifier recomputes both from fields it can already see, so a quote cannot
    be lifted from one run and pasted onto another.
    """
    identity = {
        key: document[key]
        for key in (
            "network",
            "netuid",
            "source_epoch",
            "eval_id",
            "validator_hotkey",
            "miner_hotkey",
            "nonce_base64",
            "issued_at",
            "completed_at",
            "valid_from_block",
            "valid_until_block",
        )
    }
    execution = {
        key: document[key]
        for key in ("eval_id", "model", "runtime", "evalset", "grader", "score")
    }
    return (
        hashlib.sha256(IDENTITY_BINDING_DOMAIN + canonical_json(identity)).digest()
        + hashlib.sha256(EXECUTION_BINDING_DOMAIN + canonical_json(execution)).digest()
    )


def validate_receipt(document: Any) -> Mapping[str, Any]:
    """Structural validation. Signature and quote checks live in the verifier."""
    receipt = _exact_keys(document, _RECEIPT_KEYS, "eval receipt")
    if receipt["schema"] != SCHEMA:
        raise EvalReceiptError("unsupported eval receipt schema")
    encoded = canonical_json(receipt)
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise EvalReceiptError("eval receipt exceeds maximum size")

    _count(receipt["netuid"], "netuid", maximum=2**16)
    _count(receipt["source_epoch"], "source_epoch", maximum=2**53)
    first = _count(receipt["valid_from_block"], "valid_from_block", maximum=2**53)
    last = _count(receipt["valid_until_block"], "valid_until_block", maximum=2**53)
    if last <= first:
        raise EvalReceiptError("valid_until_block must be greater than valid_from_block")

    validate_model(receipt["model"])
    validate_runtime(receipt["runtime"])
    evalset = validate_evalset(receipt["evalset"])
    validate_grader(receipt["grader"])
    validate_score(receipt["score"], item_count=int(evalset["item_count"]))
    attestation = validate_attestation(receipt["attestation"])

    if attestation["kind"] in SELF_BINDING_ATTESTATION_KINDS:
        expected = expected_report_data(receipt).hex()
        if attestation["report_data_hex"] != expected:
            raise EvalReceiptError(
                "attestation report_data does not bind this receipt"
            )

    _exact_keys(receipt["signature"], _SIGNATURE_KEYS, "signature")
    if receipt["receipt_id"] != receipt_id_for(receipt):
        raise EvalReceiptError("receipt_id does not match receipt contents")
    return receipt


def creditable_as_verified_work(document: Mapping[str, Any]) -> bool:
    """Whether this receipt may contribute verified work units.

    Deliberately conservative and deliberately separate from `validate_receipt`:
    a structurally perfect receipt with no quote is still worth zero. This is
    the same stance VerifyML takes, and it is the line that keeps the trust
    claim honest.
    """
    try:
        receipt = validate_receipt(document)
    except EvalReceiptError:
        return False
    return str(receipt["attestation"]["kind"]) != "none"
