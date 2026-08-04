"""Replayable evidence for creditable Compute SAT receipts.

``cathedral_compute_work_evidence_v1`` is the transport companion to a signed
``cathedral_assurance_receipt_v2``.  The receipt commits to the SHA-256 digests
of a SAT work item and result, but digests alone cannot show that its signed
``work_units`` were derived.  This compact sidecar carries the exact canonical
bytes and binds them to one receipt id.  A consumer must replay it before the
receipt can contribute any weight.

The verifier is intentionally self-contained.  The validator must be able to
run it with the standalone Distill integration package; importing the Compute
runtime at verification time would turn a package installation into an
unreviewed part of the security boundary.  ``SAT_WORK_UNIT_RULE`` is therefore
versioned and mirrors Compute's ``sat_work_units_v1`` contract exactly.  A
rule change requires a new evidence schema rather than reinterpretation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import random
import re
from collections.abc import Mapping
from decimal import Decimal
from typing import Any

WORK_EVIDENCE_SCHEMA = "cathedral_compute_work_evidence_v1"
SAT_WORK_UNIT_RULE = "sat_work_units_v1"
WORK_ITEM_SCHEMA = "cathedral_sat_manifest_v1"

# These bounds are the producer's public SAT contract.  Keeping them here makes
# an oversized artifact fail before JSON parsing or SAT replay can consume
# disproportionate validator resources.
MAX_WORK_ITEM_BYTES = 60 * 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024
MAX_N_VARS = 512
MAX_CLAUSES = 8192
MAX_LITERALS = 65_536
MAX_LITERALS_PER_CLAUSE = 1024
MIN_SEED = -(2**63)
MAX_SEED = 2**63 - 1
CUSTOMER_SAT_WORK_UNITS = Decimal("20")

_RECEIPT_ID_RE = re.compile(r"\Areceipt-sha256:[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_CHALLENGE_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_DECIMAL_RE = re.compile(r"\A(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,12})?\Z")
_EVIDENCE_KEYS = frozenset(
    {"schema", "receipt_id", "work_item_base64", "result_base64"}
)


class ComputeWorkEvidenceError(ValueError):
    """Replayable Compute work evidence is malformed or does not prove units."""


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _strict_canonical_json(data: bytes, label: str, *, maximum: int) -> dict[str, Any]:
    if len(data) > maximum:
        raise ComputeWorkEvidenceError(f"{label} is oversized")

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate {label} JSON key")
            out[key] = value
        return out

    try:
        document = json.loads(
            data.decode("ascii"),
            object_pairs_hook=no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite {label} JSON constant {value}")
            ),
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise ComputeWorkEvidenceError(f"{label} is not strict ASCII JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ComputeWorkEvidenceError(f"{label} is not a JSON object")
    try:
        canonical = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ComputeWorkEvidenceError(f"{label} JSON is not finite") from exc
    if canonical != data:
        raise ComputeWorkEvidenceError(f"{label} bytes are not canonical JSON")
    return document


def _decode_base64(value: object, label: str, *, maximum: int) -> bytes:
    if not isinstance(value, str):
        raise ComputeWorkEvidenceError(f"{label} must be a canonical base64 string")
    # Four base64 characters encode at most three bytes.  Bound the encoded form
    # before allocating the decoded bytes.
    max_encoded = ((maximum + 2) // 3) * 4
    if len(value) > max_encoded:
        raise ComputeWorkEvidenceError(f"{label} is oversized")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ComputeWorkEvidenceError(f"{label} is not canonical base64") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise ComputeWorkEvidenceError(f"{label} is not canonical base64")
    if len(raw) > maximum:
        raise ComputeWorkEvidenceError(f"{label} is oversized")
    return raw


def _exact_mapping(value: object, expected: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ComputeWorkEvidenceError(f"{label} must be an object")
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise ComputeWorkEvidenceError(f"{label} has " + "; ".join(details))
    return value


def build_work_evidence(
    receipt: Mapping[str, Any], work_item_bytes: bytes, result_bytes: bytes
) -> dict[str, str]:
    """Encode immutable artifact bytes for transport beside one receipt.

    This producer helper verifies the receipt's digest commitments before it
    emits a sidecar, preventing an exporter from publishing a plausible-looking
    but mismatched artifact pair.
    """
    if not isinstance(receipt, Mapping):
        raise ComputeWorkEvidenceError("receipt must be an object")
    receipt_id = receipt.get("receipt_id")
    work = receipt.get("work")
    if not isinstance(receipt_id, str) or _RECEIPT_ID_RE.fullmatch(receipt_id) is None:
        raise ComputeWorkEvidenceError("receipt_id is invalid")
    if not isinstance(work, Mapping):
        raise ComputeWorkEvidenceError("receipt work block is invalid")
    if not isinstance(work_item_bytes, bytes) or not isinstance(result_bytes, bytes):
        raise ComputeWorkEvidenceError("work artifacts must be bytes")
    if len(work_item_bytes) > MAX_WORK_ITEM_BYTES or len(result_bytes) > MAX_RESULT_BYTES:
        raise ComputeWorkEvidenceError("work artifact is oversized")
    if work.get("manifest_digest") != _digest(work_item_bytes):
        raise ComputeWorkEvidenceError("work item does not match the receipt manifest digest")
    if work.get("result_digest") != _digest(result_bytes):
        raise ComputeWorkEvidenceError("work result does not match the receipt result digest")
    return {
        "schema": WORK_EVIDENCE_SCHEMA,
        "receipt_id": receipt_id,
        "work_item_base64": base64.b64encode(work_item_bytes).decode("ascii"),
        "result_base64": base64.b64encode(result_bytes).decode("ascii"),
    }


def _validate_instance(instance: object) -> tuple[int, list[list[int]]]:
    block = _exact_mapping(instance, frozenset({"n_vars", "clauses"}), "work item instance")
    n_vars = block["n_vars"]
    clauses = block["clauses"]
    if isinstance(n_vars, bool) or not isinstance(n_vars, int) or not 1 <= n_vars <= MAX_N_VARS:
        raise ComputeWorkEvidenceError("work item n_vars is invalid")
    if not isinstance(clauses, list) or len(clauses) > MAX_CLAUSES:
        raise ComputeWorkEvidenceError("work item clauses are invalid")
    literal_count = 0
    checked: list[list[int]] = []
    for clause in clauses:
        if not isinstance(clause, list) or len(clause) > MAX_LITERALS_PER_CLAUSE:
            raise ComputeWorkEvidenceError("work item clause is invalid")
        literal_count += len(clause)
        if literal_count > MAX_LITERALS:
            raise ComputeWorkEvidenceError("work item exceeds literal limit")
        if any(
            isinstance(literal, bool)
            or not isinstance(literal, int)
            or literal == 0
            or abs(literal) > n_vars
            for literal in clause
        ):
            raise ComputeWorkEvidenceError("work item literal is invalid")
        checked.append(clause)
    return n_vars, checked


def _challenge_id(n_vars: int, clauses: list[list[int]], seed: int) -> str:
    # Compute uses json.dumps() defaults for this identity preimage.  Do not
    # "tidy" the separators here: that would create a divergent challenge id.
    return hashlib.sha256(
        json.dumps({"n_vars": n_vars, "clauses": clauses, "seed": seed}, sort_keys=True).encode()
    ).hexdigest()


def _canonical_instance(seed: int) -> tuple[int, list[list[int]]]:
    """The exact deterministic audit-instance generator for sat_work_units_v1."""
    rng = random.Random(seed)
    n_vars = 8
    planted = {value: rng.choice([True, False]) for value in range(1, n_vars + 1)}
    clauses: list[list[int]] = []
    for _ in range(20):
        variables = rng.sample(range(1, n_vars + 1), 3)
        true_var = rng.choice(variables)
        clause: list[int] = []
        for value in variables:
            if value == true_var:
                literal = value if planted[value] else -value
            else:
                literal = value if rng.choice([True, False]) else -value
            clause.append(literal)
        clauses.append(clause)
    return n_vars, clauses


def _derived_units(n_vars: int, clauses: list[list[int]], seed: int) -> Decimal:
    canonical_n_vars, canonical_clauses = _canonical_instance(seed)
    if n_vars == canonical_n_vars and clauses == canonical_clauses:
        return Decimal(len(clauses))
    return CUSTOMER_SAT_WORK_UNITS


def _decimal(value: object, label: str) -> Decimal:
    if not isinstance(value, str) or _DECIMAL_RE.fullmatch(value) is None:
        raise ComputeWorkEvidenceError(f"{label} must be a canonical decimal")
    return Decimal(value)


def verify_work_evidence(receipt: Mapping[str, Any], evidence: object) -> None:
    """Replay SAT artifacts and prove the receipt's signed work units.

    The receipt signature and all normal TEE/policy checks are intentionally
    performed by ``compute_receipt.verify_receipt`` first.  This function adds
    the missing workload proof and fails closed on absent, substituted, or
    malformed artifacts.
    """
    if not isinstance(receipt, Mapping):
        raise ComputeWorkEvidenceError("receipt must be an object")
    envelope = _exact_mapping(evidence, _EVIDENCE_KEYS, "work evidence")
    if envelope["schema"] != WORK_EVIDENCE_SCHEMA:
        raise ComputeWorkEvidenceError("unsupported work evidence schema")
    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or _RECEIPT_ID_RE.fullmatch(receipt_id) is None:
        raise ComputeWorkEvidenceError("receipt_id is invalid")
    if envelope["receipt_id"] != receipt_id:
        raise ComputeWorkEvidenceError("work evidence is bound to a different receipt")
    item_bytes = _decode_base64(envelope["work_item_base64"], "work item", maximum=MAX_WORK_ITEM_BYTES)
    result_bytes = _decode_base64(envelope["result_base64"], "work result", maximum=MAX_RESULT_BYTES)

    work = _exact_mapping(
        receipt.get("work"),
        frozenset({"status", "challenge_id", "manifest_digest", "result_digest", "work_units"}),
        "receipt work",
    )
    if not isinstance(work["manifest_digest"], str) or _DIGEST_RE.fullmatch(work["manifest_digest"]) is None:
        raise ComputeWorkEvidenceError("receipt manifest digest is invalid")
    if not isinstance(work["result_digest"], str) or _DIGEST_RE.fullmatch(work["result_digest"]) is None:
        raise ComputeWorkEvidenceError("receipt result digest is invalid")
    if _digest(item_bytes) != work["manifest_digest"]:
        raise ComputeWorkEvidenceError("work item does not match the receipt manifest digest")
    if _digest(result_bytes) != work["result_digest"]:
        raise ComputeWorkEvidenceError("work result does not match the receipt result digest")

    item = _strict_canonical_json(item_bytes, "work item", maximum=MAX_WORK_ITEM_BYTES)
    if frozenset(item) != {"schema", "challenge_id", "seed", "instance"}:
        raise ComputeWorkEvidenceError("work item has missing or unknown fields")
    if item["schema"] != WORK_ITEM_SCHEMA:
        raise ComputeWorkEvidenceError("work item schema is unsupported")
    if not isinstance(item["challenge_id"], str) or _CHALLENGE_RE.fullmatch(item["challenge_id"]) is None:
        raise ComputeWorkEvidenceError("work item challenge_id is invalid")
    if item["challenge_id"] != work["challenge_id"]:
        raise ComputeWorkEvidenceError("work item challenge does not match the receipt")
    seed = item["seed"]
    if isinstance(seed, bool) or not isinstance(seed, int) or not MIN_SEED <= seed <= MAX_SEED:
        raise ComputeWorkEvidenceError("work item seed is invalid")
    n_vars, clauses = _validate_instance(item["instance"])
    if _challenge_id(n_vars, clauses, seed) != item["challenge_id"]:
        raise ComputeWorkEvidenceError("work item challenge_id is not derived from its contents")
    # This byte-budget calculation intentionally matches Compute's work-item
    # admission exactly, including the fixed maximum hotkey placeholder.
    if len(
        json.dumps(
            {
                "challenge_id": item["challenge_id"],
                "assigned_hotkey": "x" * 256,
                "seed": seed,
                "instance": {"n_vars": n_vars, "clauses": clauses},
            },
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ) > MAX_WORK_ITEM_BYTES:
        raise ComputeWorkEvidenceError("work item exceeds the producer size limit")

    result = _strict_canonical_json(result_bytes, "work result", maximum=MAX_RESULT_BYTES)
    if frozenset(result) != {
        "assigned_hotkey", "assignment", "challenge_id", "satisfiable", "work_units"
    }:
        raise ComputeWorkEvidenceError("work result has missing or unknown fields")
    if result["challenge_id"] != work["challenge_id"]:
        raise ComputeWorkEvidenceError("work result challenge does not match the receipt")
    if result["assigned_hotkey"] != receipt.get("subject_hotkey"):
        raise ComputeWorkEvidenceError("work result is assigned to a different receipt subject")
    if result["satisfiable"] is not True:
        raise ComputeWorkEvidenceError("only satisfiable SAT certificates can earn")
    assignment = result["assignment"]
    if (
        not isinstance(assignment, list)
        or len(assignment) != n_vars
        or any(isinstance(value, bool) or not isinstance(value, int) for value in assignment)
        or {abs(value) for value in assignment} != set(range(1, n_vars + 1))
    ):
        raise ComputeWorkEvidenceError("work result assignment is malformed")
    true_literals = set(assignment)
    if any(not any(literal in true_literals for literal in clause) for clause in clauses):
        raise ComputeWorkEvidenceError("work result assignment does not satisfy every clause")
    result_units = result["work_units"]
    if (
        isinstance(result_units, bool)
        or not isinstance(result_units, (int, float))
        or not math.isfinite(float(result_units))
    ):
        raise ComputeWorkEvidenceError("work result units are malformed")

    expected_units = _decimal(work["work_units"], "receipt work units")
    derived_units = _derived_units(n_vars, clauses, seed)
    if expected_units != derived_units:
        raise ComputeWorkEvidenceError(
            f"receipt-signed units {expected_units} != independently derived "
            f"{derived_units} under {SAT_WORK_UNIT_RULE}"
        )


__all__ = [
    "ComputeWorkEvidenceError",
    "WORK_EVIDENCE_SCHEMA",
    "SAT_WORK_UNIT_RULE",
    "build_work_evidence",
    "verify_work_evidence",
]
