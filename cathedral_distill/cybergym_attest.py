"""The Intel-TDX attestation gate for the CyberGym miner track.

A verified PoC proves *a* bug was found; it does not prove *this* miner found it,
in an attested run, rather than outsourcing the analysis or replaying another
miner's work. That is exactly the SparkProof **SEC-5** gap (pinning the request is
not proof of the call). So the CyberGym miner MUST run its bug-finding agent inside
an **Intel TDX CPU enclave** and attach a TDX attestation to every submission; a
solve earns work units ONLY when that attestation verifies and is bound to the
exact submission.

The binding is `report_data`: the attesting enclave commits
`sha256(domain || batch_id || task_id || poc_sha256 || trace_id || miner_hotkey ||
model_commitment)` into the TDX quote's report_data, and the validator re-derives
the same value and requires the match. A private challenge additionally commits
the digest of the exact miner artifact dispatched for its sealed batch. An
attestation therefore cannot be replayed for a different task or PoC, lifted from
another miner's enclave, paired with a different model than the commitment that
selected its batch, or reused after artifact substitution.

This reuses `cathedral_distill.attestation.verify_attestation` verbatim (trusted-root
signature, measurement allow-list, report_data nonce binding, freshness — all
fail-closed) and adds the two CyberGym-specific requirements: the TEE must be
`intel_tdx` (an AMD SEV-SNP quote is refused for this track), and report_data must
equal the verifier-derived submission binding.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from cathedral_distill.attestation import (
    AttestationError,
    AttestationPolicy,
    canonical_bytes,
    verify_attestation,
)
from cathedral_distill.cybergym_cathedral_attest import (
    DEFAULT_MAX_AGE_SECONDS,
    QuoteVerifier,
    ReceiptVerifier,
    verify_cathedral_attestation,
    verify_persistent_enclave_attestation,
)

# Domain-separated so this binding can never collide with another report_data use.
CYBERGYM_ATTEST_DOMAIN = b"cathedral-cybergym-attest-v2\x00"
CYBERGYM_ARTIFACT_ATTEST_DOMAIN = b"cathedral-cybergym-attest-v3\x00"
REQUIRED_TEE = "intel_tdx"

# A submission may carry, instead of the report_data-bound cathedral_cc_attestation_v1
# token, a REAL Cathedral receipt wrapped in this envelope. The two are told apart by
# their top-level `schema`, so the existing token path is untouched.
RECEIPT_ATTESTATION_SCHEMA = "cathedral_cybergym_receipt_attestation_v1"
PROFILE_ATTEST_V1 = "attest.v1"
PROFILE_PERSISTENT_ENCLAVE = "persistent_enclave"

# The canonical form of a CathedralReceiptPolicy's verdict-deciding content, for the
# epoch attestation-posture digest. Mirrors attestation.attestation_policy_manifest:
# a second verdict-deciding policy on the reward path has to be posture-bound too, or
# a resume that swaps `expected_workload_sha256` reopens exactly the bypass that guard
# closed for AttestationPolicy.
RECEIPT_POLICY_SCHEMA = "cathedral_cybergym_receipt_policy_v1"
_RECEIPT_POLICY_FIELDS = frozenset(
    {"quote_verifier", "expected_workload_sha256", "receipt_verifier", "max_age_seconds"}
)


class CyberGymAttestError(ValueError):
    """A CyberGym submission's Intel-TDX attestation failed. Fails closed."""


def submission_report_data(
    *,
    batch_id: str,
    task_id: str,
    poc_sha256: str,
    trace_id: str,
    miner_hotkey: str,
    model_commitment: str,
    artifact_digest: str | None = None,
) -> str:
    """The report_data the attesting enclave MUST bind and the validator re-derives.

    Binds the attestation to exactly this submission — this batch, this task, this
    PoC, this *trajectory*, this miner, and the model commitment that selected the
    batch — so a valid attestation cannot be replayed for another task/PoC, reused
    from a different miner's enclave (SEC-5), or paired with a different committed
    model. The enclave must have committed to the exact reasoning trace it emitted
    (so a fabricated, out-of-enclave trajectory cannot be paired with an attested
    crash and poison the corpus). `trace_id` content-addresses the trace's steps,
    model id, seal, and licence. Returned as a 64-char lowercase hex digest,
    matching the attestation report_data grammar.
    """
    for name, value in (("batch_id", batch_id), ("task_id", task_id),
                        ("poc_sha256", poc_sha256), ("trace_id", trace_id),
                        ("miner_hotkey", miner_hotkey),
                        ("model_commitment", model_commitment)):
        if not isinstance(value, str) or not value:
            raise CyberGymAttestError(f"{name} is required to bind the attestation")
    fields = (batch_id, task_id, poc_sha256, trace_id, miner_hotkey, model_commitment)
    if artifact_digest is None:
        body = "\x00".join(fields).encode("utf-8")
        return hashlib.sha256(CYBERGYM_ATTEST_DOMAIN + body).hexdigest()
    if (
        not isinstance(artifact_digest, str)
        or len(artifact_digest) != 71
        or not artifact_digest.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in artifact_digest[7:])
    ):
        raise CyberGymAttestError("artifact_digest must be sha256:<64 lowercase hex>")
    body = "\x00".join((*fields, artifact_digest)).encode("utf-8")
    return hashlib.sha256(CYBERGYM_ARTIFACT_ATTEST_DOMAIN + body).hexdigest()


def verify_submission_attestation(
    token: bytes,
    *,
    batch_id: str,
    task_id: str,
    poc_sha256: str,
    trace_id: str,
    miner_hotkey: str,
    model_commitment: str,
    artifact_digest: str | None = None,
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
        model_commitment=model_commitment, artifact_digest=artifact_digest,
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


@dataclass(frozen=True)
class CathedralReceiptPolicy:
    """Trust anchors for a submission that attests with a REAL Cathedral receipt
    (`verify_cathedral_attestation` / `verify_persistent_enclave_attestation`)
    rather than the report_data-bound `cathedral_cc_attestation_v1` token.

    This is the path #61 needs: an Intel DCAP root is an ECDSA certificate chain,
    which cannot be a 32-byte Ed25519 key in `AttestationPolicy.trusted_roots`, so a
    genuine attest.v1 receipt has nowhere to verify under that policy. It is a
    *separate* policy so it does not change `AttestationPolicy` (and thus the epoch's
    attestation-posture digest).

    Trusted-issuer by default (Cathedral's signed receipt, verified against Intel's
    chain server-side); a `quote_verifier`/`receipt_verifier` opts into checking the
    raw quote or the full customer-receipt signature independently.
    """

    # attest.v1 result quote: trustless raw-quote check, else trusted-issuer.
    quote_verifier: QuoteVerifier | None = None
    # persistent_enclave: the approved solver workload is REQUIRED for that profile
    # (only the approved solver may earn), plus an optional full-receipt verifier.
    expected_workload_sha256: str | None = None
    receipt_verifier: ReceiptVerifier | None = None
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS


def cathedral_receipt_policy_manifest(policy: CathedralReceiptPolicy) -> dict[str, Any]:
    """The verdict-deciding CONTENT of a receipt policy, in canonical form.

    Same purpose and discipline as `attestation.attestation_policy_manifest`: what a
    resume could swap to admit receipts the opening policy refused has to be bound.
    For this policy that is `expected_workload_sha256` (the approved solver — the
    load-bearing anti-lookup pin) and `max_age_seconds`. The `quote_verifier` and
    `receipt_verifier` seams come from CODE, not resume-swappable configuration, so
    their *identity* is not bindable; their PRESENCE is, because engaging or dropping
    an independent-verify seam flips trusted-issuer to trustless and back, and that
    change should be visible in the digest.

    Fails closed on a field it does not know about (a `dataclasses.fields` check), so
    adding a knob to the policy cannot silently shrink this digest by one.
    """
    if not isinstance(policy, CathedralReceiptPolicy):
        raise AttestationError("receipt policy must be a CathedralReceiptPolicy")
    present = {f.name for f in dataclasses.fields(policy)}
    unhandled = sorted(present - _RECEIPT_POLICY_FIELDS)
    if unhandled:
        raise AttestationError(
            "CathedralReceiptPolicy carries fields this manifest does not bind: "
            f"{', '.join(unhandled)}. Add them to `_RECEIPT_POLICY_FIELDS` and encode "
            "them here — an unbound field is a verdict the epoch's posture cannot see change."
        )
    missing = sorted(_RECEIPT_POLICY_FIELDS - present)
    if missing:
        raise AttestationError(
            f"CathedralReceiptPolicy is missing expected fields: {', '.join(missing)}"
        )
    max_age = policy.max_age_seconds
    if isinstance(max_age, bool) or not isinstance(max_age, int):
        raise AttestationError("receipt policy max_age_seconds must be an int")
    return {
        "schema": RECEIPT_POLICY_SCHEMA,
        "expected_workload_sha256": policy.expected_workload_sha256 or "",
        "max_age_seconds": int(max_age),
        "quote_verifier": policy.quote_verifier is not None,
        "receipt_verifier": policy.receipt_verifier is not None,
    }


def cathedral_receipt_policy_digest(policy: CathedralReceiptPolicy | None) -> str:
    """`sha256:<hex>` over `cathedral_receipt_policy_manifest`, or `""` for no policy."""
    if policy is None:
        return ""
    return "sha256:" + hashlib.sha256(
        canonical_bytes(cathedral_receipt_policy_manifest(policy))
    ).hexdigest()


def verify_submission_receipt(
    payload: Mapping[str, Any],
    *,
    task_id: str,
    poc_sha256: str,
    trace_id: str,
    policy: CathedralReceiptPolicy,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Verify a submission that attests with a real Cathedral receipt. Fails closed.

    The receipt binds the SOLVE — `(task, poc, trace[, verdict])` — inside genuine
    Intel TDX. The submission's `(batch, miner, model_commitment)` binding is NOT in
    the receipt; it is enforced upstream by the authenticated dispatch (a sealed
    batch bound to the caller's hotkey, with its model commitment pinned on first
    dispatch). Attestation proves enclave execution of the solve; the dispatch proves
    who owns it. (The `cathedral_cc_attestation_v1` path additionally binds miner and
    model *into the quote*; it is unchanged and stays available for that stronger
    shape.)

    Returns a small verdict mapping on success, or raises `CyberGymAttestError`.
    """
    profile = str(payload.get("profile", ""))
    receipt = payload.get("receipt")
    if not isinstance(receipt, Mapping):
        raise CyberGymAttestError("submission receipt attestation carries no receipt")

    if profile == PROFILE_ATTEST_V1:
        result = verify_cathedral_attestation(
            receipt, task_id=task_id, poc_sha256=poc_sha256, trace_id=trace_id,
            now=now, max_age_seconds=policy.max_age_seconds,
            quote_verifier=policy.quote_verifier,
        )
    elif profile == PROFILE_PERSISTENT_ENCLAVE:
        if not policy.expected_workload_sha256:
            raise CyberGymAttestError(
                "persistent-enclave attestation requires an approved workload pin "
                "(expected_workload_sha256); without it any workload could self-sign"
            )
        try:
            result_bytes = base64.b64decode(str(payload.get("result_b64", "")), validate=True)
        except (ValueError, TypeError) as exc:
            raise CyberGymAttestError(f"enclave result_b64 is not valid base64: {exc}") from exc
        result = verify_persistent_enclave_attestation(
            receipt, task_id=task_id, poc_sha256=poc_sha256, trace_id=trace_id,
            result_bytes=result_bytes,
            expected_workload_sha256=policy.expected_workload_sha256,
            now=now, max_age_seconds=policy.max_age_seconds,
            receipt_verifier=policy.receipt_verifier,
        )
    else:
        raise CyberGymAttestError(f"unknown submission attestation profile {profile!r}")

    if not result.attested:
        raise CyberGymAttestError(f"{profile} receipt verification failed: {result.reason}")
    return {"profile": profile, "tee": result.tee, "reason": result.reason,
            "verdict": getattr(result, "verdict", None)}


__all__ = [
    "CYBERGYM_ATTEST_DOMAIN",
    "CYBERGYM_ARTIFACT_ATTEST_DOMAIN",
    "REQUIRED_TEE",
    "RECEIPT_ATTESTATION_SCHEMA",
    "PROFILE_ATTEST_V1",
    "PROFILE_PERSISTENT_ENCLAVE",
    "RECEIPT_POLICY_SCHEMA",
    "CyberGymAttestError",
    "CathedralReceiptPolicy",
    "cathedral_receipt_policy_manifest",
    "cathedral_receipt_policy_digest",
    "submission_report_data",
    "verify_submission_attestation",
    "verify_submission_receipt",
]
