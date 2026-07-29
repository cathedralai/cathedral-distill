"""The Intel-TDX attestation gate for the CyberGym miner track.

A verified PoC proves *a* bug was found; it does not prove *this* miner found it,
in an attested run, rather than outsourcing the analysis or replaying another
miner's work. That is exactly the SparkProof **SEC-5** gap (pinning the request is
not proof of the call). So the CyberGym miner MUST run its bug-finding agent inside
an **Intel TDX CPU enclave** and attach a TDX attestation to every submission; a
solve earns work units ONLY when that attestation verifies and is bound to the
exact submission.

The binding is `report_data`: the attesting enclave commits
`sha256(domain || batch_id || task_id || poc_sha256 || miner_hotkey)` into the TDX
quote's report_data, and the validator re-derives the same value and requires the
match. An attestation therefore cannot be replayed for a different task or PoC, nor
lifted from another miner's enclave.

This reuses `cathedral_distill.attestation.verify_attestation` verbatim (trusted-root
signature, measurement allow-list, report_data nonce binding, freshness — all
fail-closed) and adds the two CyberGym-specific requirements: the TEE must be
`intel_tdx` (an AMD SEV-SNP quote is refused for this track), and report_data must
equal the verifier-derived submission binding.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Mapping

from cathedral_distill.attestation import (
    AttestationError,
    AttestationPolicy,
    verify_attestation,
)

# Domain-separated so this binding can never collide with another report_data use.
CYBERGYM_ATTEST_DOMAIN = b"cathedral-cybergym-attest-v1\x00"
REQUIRED_TEE = "intel_tdx"


class CyberGymAttestError(ValueError):
    """A CyberGym submission's Intel-TDX attestation failed. Fails closed."""


def submission_report_data(
    *, batch_id: str, task_id: str, poc_sha256: str, trace_id: str, miner_hotkey: str
) -> str:
    """The report_data the attesting enclave MUST bind and the validator re-derives.

    Binds the attestation to exactly this submission — this batch, this task, this
    PoC, this *trajectory*, this miner — so a valid attestation cannot be replayed
    for another task/PoC or reused from a different miner's enclave (SEC-5), and the
    enclave must have committed to the exact reasoning trace it emitted (so a
    fabricated, out-of-enclave trajectory cannot be paired with an attested crash
    and poison the corpus). `trace_id` content-addresses the trace's steps, model
    id, seal, and licence. Returned as a 64-char lowercase hex digest, matching the
    attestation report_data grammar.
    """
    for name, value in (("batch_id", batch_id), ("task_id", task_id),
                        ("poc_sha256", poc_sha256), ("trace_id", trace_id),
                        ("miner_hotkey", miner_hotkey)):
        if not isinstance(value, str) or not value:
            raise CyberGymAttestError(f"{name} is required to bind the attestation")
    body = "\x00".join((batch_id, task_id, poc_sha256, trace_id, miner_hotkey)).encode("utf-8")
    return hashlib.sha256(CYBERGYM_ATTEST_DOMAIN + body).hexdigest()


def verify_submission_attestation(
    token: bytes,
    *,
    batch_id: str,
    task_id: str,
    poc_sha256: str,
    trace_id: str,
    miner_hotkey: str,
    policy: AttestationPolicy,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Verify a CyberGym submission's Intel-TDX attestation. Fails closed.

    Runs the full attestation discipline (`verify_attestation`) with the verifier-
    derived report_data binding (which commits the enclave to the PoC AND the
    trajectory), then enforces TEE == intel_tdx. Returns the verified token
    document, or raises `CyberGymAttestError`.
    """
    expected = submission_report_data(
        batch_id=batch_id, task_id=task_id, poc_sha256=poc_sha256,
        trace_id=trace_id, miner_hotkey=miner_hotkey,
    )
    try:
        doc = verify_attestation(token, expected_report_data=expected, policy=policy, now=now)
    except AttestationError as exc:
        raise CyberGymAttestError(f"attestation verification failed: {exc}") from exc
    if doc.get("tee") != REQUIRED_TEE:
        raise CyberGymAttestError(
            f"CyberGym requires an Intel TDX enclave, got tee={doc.get('tee')!r}"
        )
    return doc


__all__ = [
    "CYBERGYM_ATTEST_DOMAIN",
    "REQUIRED_TEE",
    "CyberGymAttestError",
    "submission_report_data",
    "verify_submission_attestation",
]
