"""The attested-teacher datapath — proof that the pinned teacher actually ran.

SparkProof's audit finding SEC-5 is the one this module answers: *pinning the
request is not proof of the call.* A miner can name `kimi-k3`, name the decode
params, and hand you a bundle of (prompt, completion, logprobs) — and nothing in
that bundle proves the completions came from the pinned teacher rather than a
cheaper local model, a cache, or thin air. You cannot verify an API-relay teacher
from the miner's body.

The fix is to move the teacher call *inside the attested confidential enclave* (our
G4 SEV-SNP + NVIDIA CC path) and bind its output to the attestation:

  1. The enclave runs a fixed image — its measurement is in the verifier's
     allow-list — whose only job is to call the *one* pinned teacher endpoint with
     the *pinned* decode params and record each generation as a leaf. A miner
     cannot substitute its own completions because the code that writes leaves is
     the measured code, not the miner's.
  2. The enclave Merkle-commits the leaves to a `transcript_root` and requests an
     attestation whose `report_data` is a domain-separated commitment to
     `(transcript_root, teacher_pin, decode_pin)`. `report_data` lives *inside* the
     signed quote, so it cannot be edited after the fact.
  3. A validator CPU-verifies the bundle cheaply and trustlessly:
       * `verify_attestation` checks the quote against trusted roots (SEC-1/2/3),
         the measurement against the allow-list (SEC-TDX-1), and `report_data`
         against the value it recomputes from the bundle — so if the miner alters
         the root the commitment breaks, and if it alters `report_data` the
         signature breaks;
       * the pinned teacher is cross-checked against the licence-pinned
         `TeacherRegistry`;
       * any individual leaf is opened with a Merkle proof — no re-running the
         teacher, the same solve-hard/check-cheap asymmetry `challenge.py` uses.

What a verified leaf then yields is provenance-carrying training data: this exact
(prompt, completion, logprobs) was produced by the pinned teacher inside a genuine,
measurement-pinned enclave. For a validate-by-execution lane (CyberGym), the leaf
also commits an `outcome_digest` — the differential-crash result the enclave
observed — which a validator can re-derive with the cheap differential check.

Hardware-free, like `attestation.py`: the Merkle tree and the report_data
commitment are exact and testable; production swaps the token parser and trusted
roots for real NRAS/DCAP material, the commitment shape is unchanged.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Sequence

from cathedral_distill import attestation as att
from cathedral_distill.challenge import MerkleProof, build_proof, verify_proof
from cathedral_distill.eval_receipt import (
    canonical_json,
    items_root,
    sha256_digest,
)
from cathedral_distill.teacher_registry import PURPOSE_DISTILLATION

SCHEMA = "cathedral_attested_transcript_v1"

# Domain separators — every hash here is prefixed so a digest from one position can
# never be replayed in another (the discipline the eval receipt already follows).
LEAF_DOMAIN = b"cathedral-attested-teacher-leaf-v1\x00"
REPORT_DATA_DOMAIN = b"cathedral-attested-teacher-report-data-v1\x00"
TEACHER_PIN_DOMAIN = b"cathedral-attested-teacher-pin-v1\x00"
DECODE_PIN_DOMAIN = b"cathedral-attested-teacher-decode-v1\x00"
OUTCOME_DOMAIN = b"cathedral-attested-teacher-outcome-v1\x00"

# The "nothing committed here" sentinel for an optional leaf field (e.g. logprobs
# absent, or no execution outcome for a pure-distillation leaf).
ABSENT_DIGEST = "sha256:" + hashlib.sha256(b"cathedral-attested-teacher-absent-v1").hexdigest()

MAX_LEAVES = 1 << 20
_DIGEST_LEN = len("sha256:") + 64


class AttestedTranscriptError(ValueError):
    """The attested-teacher bundle failed verification. Fails closed."""


# --------------------------------------------------------------------------- #
# Digest helpers
# --------------------------------------------------------------------------- #

def _require_digest(value: Any, label: str) -> str:
    text = str(value or "")
    if len(text) != _DIGEST_LEN or not text.startswith("sha256:"):
        raise AttestedTranscriptError(f"{label} must be sha256:<64 hex>")
    try:
        bytes.fromhex(text[len("sha256:"):])
    except ValueError as exc:
        raise AttestedTranscriptError(f"{label} must be sha256:<64 hex>") from exc
    return text


def _root_bytes(root: str) -> bytes:
    return bytes.fromhex(_require_digest(root, "transcript_root")[len("sha256:"):])


def _reject_floats(value: Any, label: str) -> None:
    """Decode params reach a commitment, so a float would make the commit
    non-deterministic across encoders — require decimal strings / ints instead."""
    if isinstance(value, float):
        raise AttestedTranscriptError(f"{label} must not contain floats; use decimal strings")
    if isinstance(value, Mapping):
        for k, v in value.items():
            _reject_floats(v, f"{label}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _reject_floats(v, f"{label}[{i}]")


# --------------------------------------------------------------------------- #
# The commitments that bind the enclave's output to its attestation
# --------------------------------------------------------------------------- #

def teacher_pin_digest(teacher_pin: Mapping[str, str]) -> str:
    """Commit to which teacher was pinned: model id, its licence digest, endpoint."""
    pin = {
        "teacher_id": str(teacher_pin["teacher_id"]),
        "licence_digest": _require_digest(teacher_pin.get("licence_digest"), "teacher_pin.licence_digest"),
        "endpoint_id": str(teacher_pin["endpoint_id"]),
    }
    return "sha256:" + hashlib.sha256(TEACHER_PIN_DOMAIN + canonical_json(pin)).hexdigest()


def decode_pin_digest(decode_pin: Mapping[str, Any]) -> str:
    """Commit to the exact decode params (temperature, top_p, max_tokens, seed).

    From the K2.6 relay finding: nondeterministic decode makes replay impossible, so
    the decode params must be pinned and committed — a validator that later replays
    on controlled hardware knows precisely what to reproduce.
    """
    _reject_floats(decode_pin, "decode_pin")
    return "sha256:" + hashlib.sha256(DECODE_PIN_DOMAIN + canonical_json(dict(decode_pin))).hexdigest()


def outcome_digest(outcome: Mapping[str, Any]) -> str:
    """Commit to an execution outcome (e.g. a differential-crash result) a validator
    can re-derive with the cheap check. `{}` maps to the ABSENT sentinel."""
    if not outcome:
        return ABSENT_DIGEST
    _reject_floats(outcome, "outcome")
    return "sha256:" + hashlib.sha256(OUTCOME_DOMAIN + canonical_json(dict(outcome))).hexdigest()


def commit_report_data(
    transcript_root: str, teacher_pin: Mapping[str, str], decode_pin: Mapping[str, Any]
) -> str:
    """The 32-byte value the enclave must place in the attestation `report_data`.

    Binding all three means the quote vouches for *this* transcript under *this*
    teacher and *these* decode params — the enclave cannot be replayed to vouch for
    a different root, and the bundle cannot present a root the quote did not sign.
    Returned as bare hex (attestation `report_data` is a hex string, not sha256:).
    """
    h = hashlib.sha256(
        REPORT_DATA_DOMAIN
        + _root_bytes(transcript_root)
        + bytes.fromhex(teacher_pin_digest(teacher_pin)[len("sha256:"):])
        + bytes.fromhex(decode_pin_digest(decode_pin)[len("sha256:"):])
    )
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Leaves
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class TranscriptLeaf:
    """One teacher generation, committed by digest at its position in the transcript.

    `prompt_digest` / `completion_digest` are the core provenance; `logprobs_digest`
    carries the trajectory/logits signal used for distillation (ABSENT if none);
    `outcome_digest` carries a validate-by-execution result (ABSENT for pure
    distillation). The index is part of the commitment so a leaf proved for one
    position cannot be relabelled to another.
    """

    index: int
    item_id: str
    prompt_digest: str
    completion_digest: str
    logprobs_digest: str = ABSENT_DIGEST
    outcome_digest: str = ABSENT_DIGEST

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int) or self.index < 0:
            raise AttestedTranscriptError("leaf index must be a non-negative integer")
        for name in ("prompt_digest", "completion_digest", "logprobs_digest", "outcome_digest"):
            _require_digest(getattr(self, name), f"leaf.{name}")

    def to_leaf_bytes(self) -> bytes:
        body = canonical_json(
            {
                "index": self.index,
                "item_id": str(self.item_id),
                "prompt_digest": self.prompt_digest,
                "completion_digest": self.completion_digest,
                "logprobs_digest": self.logprobs_digest,
                "outcome_digest": self.outcome_digest,
            }
        )
        return hashlib.sha256(LEAF_DOMAIN + body).digest()


def _leaf_byte_list(leaves: Sequence[TranscriptLeaf]) -> list[bytes]:
    if not leaves:
        raise AttestedTranscriptError("a transcript needs at least one leaf")
    if len(leaves) > MAX_LEAVES:
        raise AttestedTranscriptError("too many leaves")
    out: list[bytes] = []
    for position, leaf in enumerate(leaves):
        if leaf.index != position:
            raise AttestedTranscriptError(
                f"leaf at position {position} has index {leaf.index}; leaves must be in order"
            )
        out.append(leaf.to_leaf_bytes())
    return out


# --------------------------------------------------------------------------- #
# The bundle a validator verifies
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class AttestedTranscript:
    """The published bundle: the transcript root, the pins, and the attestation the
    root is bound into (referenced by the digest of its token bytes)."""

    transcript_root: str
    leaf_count: int
    teacher_pin: Mapping[str, str]
    decode_pin: Mapping[str, Any]
    attestation_report_digest: str
    schema: str = SCHEMA

    def expected_report_data(self) -> str:
        return commit_report_data(self.transcript_root, self.teacher_pin, self.decode_pin)


@dataclass(frozen=True)
class VerifiedTranscript:
    """The trustworthy facts a verified bundle yields."""

    transcript_root: str
    leaf_count: int
    teacher_id: str
    decode_pin: Mapping[str, Any]
    measurement: str
    gpu_measurement: str | None


def build_attested_transcript(
    leaves: Sequence[TranscriptLeaf],
    *,
    teacher_pin: Mapping[str, str],
    decode_pin: Mapping[str, Any],
    token: bytes,
) -> AttestedTranscript:
    """Assemble a bundle over `leaves` (enclave side, after the token is minted).

    The token must already carry `report_data == commit_report_data(root, ...)`;
    this only records the root, the pins, and the token's digest.
    """
    root = items_root(_leaf_byte_list(leaves))
    return AttestedTranscript(
        transcript_root=root,
        leaf_count=len(leaves),
        teacher_pin=dict(teacher_pin),
        decode_pin=dict(decode_pin),
        attestation_report_digest=sha256_digest(token),
    )


def report_data_for(
    leaves: Sequence[TranscriptLeaf],
    *,
    teacher_pin: Mapping[str, str],
    decode_pin: Mapping[str, Any],
) -> str:
    """The `report_data` the enclave must request when attesting these leaves."""
    return commit_report_data(items_root(_leaf_byte_list(leaves)), teacher_pin, decode_pin)


def open_leaf(
    leaves: Sequence[TranscriptLeaf], index: int
) -> tuple[TranscriptLeaf, MerkleProof]:
    """Open one leaf for a validator: the leaf plus its Merkle inclusion proof."""
    proof = build_proof(_leaf_byte_list(leaves), index)
    return leaves[index], proof


def _validate_bundle(bundle: AttestedTranscript) -> AttestedTranscript:
    if not isinstance(bundle, AttestedTranscript):
        raise AttestedTranscriptError("bundle must be an AttestedTranscript")
    if bundle.schema != SCHEMA:
        raise AttestedTranscriptError("unsupported attested-transcript schema")
    _require_digest(bundle.transcript_root, "transcript_root")
    _require_digest(bundle.attestation_report_digest, "attestation_report_digest")
    if isinstance(bundle.leaf_count, bool) or not isinstance(bundle.leaf_count, int) or bundle.leaf_count <= 0:
        raise AttestedTranscriptError("leaf_count must be a positive integer")
    for req in ("teacher_id", "licence_digest", "endpoint_id"):
        if req not in bundle.teacher_pin:
            raise AttestedTranscriptError(f"teacher_pin missing {req}")
    return bundle


def verify_attested_transcript(
    bundle: AttestedTranscript,
    token: bytes,
    *,
    policy: att.AttestationPolicy,
    teacher_registry: Any,
    now: datetime,
    at: datetime,
    purpose: str = PURPOSE_DISTILLATION,
    require_commercial: bool = True,
    verify_attestation: Callable[..., Mapping[str, Any]] = att.verify_attestation,
) -> VerifiedTranscript:
    """CPU-verify an attested-teacher bundle. Fails closed on any check.

    Order: structure; the token bytes hash to the bundle's committed digest; the
    attestation verifies against trusted roots + measurement allow-list with
    `report_data` equal to the value recomputed from the bundle (so the enclave
    genuinely produced this root under these pins); and the pinned teacher is
    permitted by the licence-pinned registry with its licence digest unchanged.
    """
    b = _validate_bundle(bundle)

    if sha256_digest(token) != b.attestation_report_digest:
        raise AttestedTranscriptError("token bytes do not hash to the committed attestation digest")

    expected = b.expected_report_data()
    try:
        doc = verify_attestation(token, expected_report_data=expected, policy=policy, now=now)
    except att.AttestationError as exc:
        raise AttestedTranscriptError(f"attestation did not verify: {exc}") from exc

    teacher_id = str(b.teacher_pin["teacher_id"])
    record = teacher_registry.get(teacher_id)
    if record is None:
        raise AttestedTranscriptError(f"pinned teacher {teacher_id!r} is not in the registry")
    try:
        teacher_registry.assert_permitted(
            teacher_id, purpose=purpose, at=at, require_commercial=require_commercial
        )
    except Exception as exc:  # TeacherNotPermitted (or any registry rejection)
        raise AttestedTranscriptError(f"pinned teacher is not permitted: {exc}") from exc
    if record.licence_digest != b.teacher_pin["licence_digest"]:
        raise AttestedTranscriptError(
            "pinned teacher licence digest does not match the registry (licence changed)"
        )

    return VerifiedTranscript(
        transcript_root=b.transcript_root,
        leaf_count=b.leaf_count,
        teacher_id=teacher_id,
        decode_pin=dict(b.decode_pin),
        measurement=str(doc["measurement"]),
        gpu_measurement=doc.get("gpu_measurement"),
    )


def verify_leaf(
    verified: VerifiedTranscript, leaf: TranscriptLeaf, proof: MerkleProof
) -> bool:
    """Confirm one opened leaf belongs to the verified transcript.

    The proof's leaf must be exactly this leaf's committed bytes (so a valid proof
    for a different leaf cannot be presented for this one), the indices must agree,
    and the opening must reconstruct the verified root at that position.
    """
    if proof.index != leaf.index:
        return False
    if proof.leaf != leaf.to_leaf_bytes():
        return False
    return verify_proof(proof, verified.transcript_root, leaf_count=verified.leaf_count)


__all__ = [
    "SCHEMA", "ABSENT_DIGEST", "AttestedTranscriptError",
    "TranscriptLeaf", "AttestedTranscript", "VerifiedTranscript",
    "teacher_pin_digest", "decode_pin_digest", "outcome_digest", "commit_report_data",
    "build_attested_transcript", "report_data_for", "open_leaf",
    "verify_attested_transcript", "verify_leaf",
]
