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
import hmac
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
# The agent itself runs in the enclave (measured workload = the pinned agent + runtime), reaching ONLY
# the official base-model providers over pinned-CA TLS. Same solve/miner/nonce binding as
# persistent_enclave PLUS a verified restricted-egress policy — the runtime enforcement of the
# provider allowlist that closes the answer-oracle (docs/AGENT_ENCLAVE_EGRESS.md in the backend repo).
PROFILE_AGENT_ENCLAVE = "agent_enclave"

# The canonical form of a CathedralReceiptPolicy's verdict-deciding content, for the
# epoch attestation-posture digest. Mirrors attestation.attestation_policy_manifest:
# a second verdict-deciding policy on the reward path has to be posture-bound too, or
# a resume that swaps `expected_workload_sha256` reopens exactly the bypass that guard
# closed for AttestationPolicy.
RECEIPT_POLICY_SCHEMA = "cathedral_cybergym_receipt_policy_v1"
_RECEIPT_POLICY_FIELDS = frozenset(
    {"quote_verifier", "expected_workload_sha256", "receipt_verifier", "max_age_seconds",
     "expected_egress_allowlist", "require_tls_pinning", "require_report_data_nonce"}
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
    # agent_enclave: the EXACT set of egress hosts the attested enclave may reach (the official
    # base-model providers), and whether the receipt must carry tls_pinning=true. On Cathedral TDX
    # that boolean means guest DNS plus CONNECT only to public IPv4 :443 — not an SPKI/CA pin set.
    # Posture-bound below so a resume cannot widen the allowlist or drop the bit.
    expected_egress_allowlist: frozenset[str] | None = None
    require_tls_pinning: bool = True
    # When set, the receipt must prove its report_data is HARDWARE-bound to the dispatch nonce:
    # `nonce_sha256 == sha256(ascii(nonce))` AND `report_data_match` (Cathedral verified the TDX quote's
    # report_data[0:32] == sha256(ascii(nonce)||ascii(e2e_pubkey_b64))). This moves the nonce binding
    # off the miner-supplied result envelope onto the enclave quote, so a receipt cannot be replayed
    # for another dispatch. Posture-bound: a resume dropping it reopens cross-dispatch replay.
    require_report_data_nonce: bool = False


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
        # the agent_enclave egress firewall is verdict-deciding: a resume that widened the allowlist
        # (or dropped TLS pinning) would reopen the answer-oracle, so both are bound into the digest.
        "expected_egress_allowlist": sorted(str(h).lower() for h in (policy.expected_egress_allowlist or ())),
        "require_tls_pinning": bool(policy.require_tls_pinning),
        # verdict-deciding: dropping it reopens cross-dispatch receipt replay.
        "require_report_data_nonce": bool(policy.require_report_data_nonce),
    }


def cathedral_receipt_policy_digest(policy: CathedralReceiptPolicy | None) -> str:
    """`sha256:<hex>` over `cathedral_receipt_policy_manifest`, or `""` for no policy."""
    if policy is None:
        return ""
    return "sha256:" + hashlib.sha256(
        canonical_bytes(cathedral_receipt_policy_manifest(policy))
    ).hexdigest()


def _verify_agent_egress(task_policy: Mapping[str, Any], *, expected_hosts, require_tls_pinning: bool) -> None:
    """The agent-in-enclave egress firewall, verified from the receipt's task_policy. Fails closed.

    The RUNTIME half of the base-url allowlist: it proves the agent, inside the enclave, could reach
    ONLY the approved model hosts and had no out-of-band channel to a stored answer. Distinct from
    `attest.v1`'s `egress == "none"` (a no-network differential workload) — a reasoning agent MUST
    reach the model, so egress is 'restricted' to EXACTLY the approved hosts. The approved set comes
    from the policy, so distill needs no dependency on the backend's provider table.
    """
    expected = {str(h).lower() for h in (expected_hosts or ())}
    if not expected:
        raise CyberGymAttestError("no approved egress hosts; refusing an unconstrained agent enclave")
    egress = str(task_policy.get("egress", ""))
    allow = task_policy.get("egress_allowlist")
    # PolarIS guest jail uses allow:h1,h2. Cathedral mint maps that to restricted
    # plus egress_allowlist; accept the guest form so a signed PolarIS policy still
    # verifies if the mint copies the enforced string through.
    if egress.lower().startswith("allow:"):
        polaris_hosts = [
            host.strip().lower().rstrip(".")
            for host in egress.split(":", 1)[1].split(",")
            if host.strip()
        ]
        egress = "restricted"
        if isinstance(allow, (list, tuple)):
            listed = {str(h).lower().rstrip(".") for h in allow}
            if listed != set(polaris_hosts):
                raise CyberGymAttestError(
                    "agent-enclave allow: string contradicts egress_allowlist"
                )
        else:
            allow = polaris_hosts
    if egress != "restricted":
        raise CyberGymAttestError(
            f"agent-enclave egress must be 'restricted' to the provider allowlist, got {egress!r}: "
            "'none' cannot serve a reasoning agent and 'any'/absent reopens the self-hosted oracle")
    if not isinstance(allow, (list, tuple)) or {str(h).lower() for h in allow} != expected:
        raise CyberGymAttestError(
            "agent-enclave egress_allowlist is not EXACTLY the approved provider hosts "
            "(a broader allowlist reopens the answer-oracle)")
    if require_tls_pinning and task_policy.get("tls_pinning") is not True:
        raise CyberGymAttestError(
            "agent-enclave tls_pinning=true means Cathedral TDX guest DNS plus CONNECT "
            "only to public IPv4 :443, not an SPKI/CA pin set; PolarIS signs this boolean "
            "for restricted allowlists"
        )


def _verify_report_data_nonce(receipt: Mapping[str, Any], *, nonce: str) -> None:
    """Require the receipt's report_data to be HARDWARE-bound to THIS dispatch nonce. Fails closed.

    Cathedral's `attest.v1` composes `report_data[0:32] = sha256(ascii(nonce_hex) || ascii(
    e2e_pubkey_b64))` from the caller-supplied `nonce`, records `nonce_sha256 = sha256(ascii(nonce))`,
    and sets `report_data_match` once it has verified the TDX quote carries that report_data. So a
    receipt minted for the dispatch nonce proves — in the enclave quote, not the miner-supplied result
    envelope — that it belongs to this dispatch, and cannot be replayed for another one. Both must
    hold: `nonce_sha256 == sha256(ascii(nonce))` (the declared nonce IS this dispatch's) and
    `report_data_match is True` (the quote actually carried it).
    """
    expected = hashlib.sha256(str(nonce).encode("utf-8")).hexdigest()
    got = str(receipt.get("nonce_sha256", "")).lower()
    # Validate the shape BEFORE compare_digest: a non-hex (e.g. non-ASCII) attacker-controlled value
    # makes hmac.compare_digest raise TypeError, which would escape this verifier's raise-CyberGym
    # AttestError contract and crash an intake loop. Reject it cleanly (fails closed) instead.
    if len(got) != 64 or any(c not in "0123456789abcdef" for c in got):
        raise CyberGymAttestError(
            "receipt nonce_sha256 is not a 64-char hex digest — the enclave quote's report_data "
            "carries no valid dispatch-nonce binding")
    if not hmac.compare_digest(got, expected):
        raise CyberGymAttestError(
            "receipt nonce_sha256 is not sha256(ascii(dispatch nonce)) — the enclave quote's "
            f"report_data is not bound to this dispatch ({got[:16]}… != {expected[:16]}…)")
    if receipt.get("report_data_match") is not True:
        raise CyberGymAttestError(
            "receipt report_data_match is not true — Cathedral did not verify the quote's report_data "
            "binds this nonce; send e2e_pubkey_b64 + nonce at attest.v1 mint time")


def verify_submission_receipt(
    payload: Mapping[str, Any],
    *,
    task_id: str,
    poc_sha256: str,
    trace_id: str,
    miner_hotkey: str,
    nonce: str,
    policy: CathedralReceiptPolicy,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Verify a submission that attests with a real Cathedral receipt. Fails closed.

    The `persistent_enclave` profile binds the SOLVE **and** the dispatched
    `miner_hotkey` and batch `nonce` into the enclave-signed commitment, so a receipt
    is valid only for the exact miner and dispatch that produced it — another miner
    dispatched the same task cannot resubmit it.

    The `attest.v1` profile's `result.txt` commitment is `(task, poc, trace)` only and
    cannot grow a miner field without changing the Cathedral-side result format, so it
    does NOT bind the miner here; treat it as dev/synthetic, not a live reward path,
    until its miner binding comes through `report_data`.

    Returns a small verdict mapping on success, or raises `CyberGymAttestError`.
    """
    profile = str(payload.get("profile", ""))
    receipt = payload.get("receipt")
    if not isinstance(receipt, Mapping):
        raise CyberGymAttestError("submission receipt attestation carries no receipt")

    if profile == PROFILE_ATTEST_V1:
        # attest.v1 binds only (task, poc, trace) — no miner, no nonce. Refuse the downgrade when the
        # policy demands the dispatch-nonce hardware binding, or it would be satisfied vacuously and
        # the cross-dispatch replay require_report_data_nonce closes would stay open.
        if policy.require_report_data_nonce:
            raise CyberGymAttestError(
                "attest.v1 carries no dispatch-nonce report_data binding; it is refused when the "
                "policy requires it (require_report_data_nonce) — use persistent_enclave/agent_enclave")
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
        if policy.require_report_data_nonce:
            _verify_report_data_nonce(receipt, nonce=nonce)
        try:
            result_bytes = base64.b64decode(str(payload.get("result_b64", "")), validate=True)
        except (ValueError, TypeError) as exc:
            raise CyberGymAttestError(f"enclave result_b64 is not valid base64: {exc}") from exc
        result = verify_persistent_enclave_attestation(
            receipt, task_id=task_id, poc_sha256=poc_sha256, trace_id=trace_id,
            miner_hotkey=miner_hotkey, nonce=nonce, result_bytes=result_bytes,
            expected_workload_sha256=policy.expected_workload_sha256,
            now=now, max_age_seconds=policy.max_age_seconds,
            receipt_verifier=policy.receipt_verifier,
        )
    elif profile == PROFILE_AGENT_ENCLAVE:
        # The AGENT ran in the enclave: same solve/miner/nonce binding as persistent_enclave, PLUS a
        # verified restricted-egress firewall so the agent could not fetch a looked-up answer.
        if not policy.expected_workload_sha256:
            raise CyberGymAttestError(
                "agent-enclave attestation requires an approved workload pin (expected_workload_sha256)")
        if not policy.expected_egress_allowlist:
            raise CyberGymAttestError(
                "agent-enclave attestation requires an approved egress allowlist "
                "(expected_egress_allowlist); without it the agent could reach a self-hosted "
                "answer-oracle and the profile is no stronger than persistent_enclave")
        if policy.receipt_verifier is None:
            # The egress firewall rides in the receipt's task_policy. That is only trustworthy when
            # Cathedral's signature covers it — a trusted-issuer path (no receipt_verifier) would let a
            # miner run with egress='any' and swap the plaintext task_policy to look 'restricted'.
            raise CyberGymAttestError(
                "agent-enclave requires trustless receipt verification (receipt_verifier): the egress "
                "policy is only trustworthy when Cathedral's signature covers the receipt")
        _verify_agent_egress(receipt.get("task_policy", {}),
                             expected_hosts=policy.expected_egress_allowlist,
                             require_tls_pinning=policy.require_tls_pinning)
        if policy.require_report_data_nonce:
            _verify_report_data_nonce(receipt, nonce=nonce)
        try:
            result_bytes = base64.b64decode(str(payload.get("result_b64", "")), validate=True)
        except (ValueError, TypeError) as exc:
            raise CyberGymAttestError(f"enclave result_b64 is not valid base64: {exc}") from exc
        result = verify_persistent_enclave_attestation(
            receipt, task_id=task_id, poc_sha256=poc_sha256, trace_id=trace_id,
            miner_hotkey=miner_hotkey, nonce=nonce, result_bytes=result_bytes,
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
    "PROFILE_AGENT_ENCLAVE",
    "RECEIPT_POLICY_SCHEMA",
    "CyberGymAttestError",
    "CathedralReceiptPolicy",
    "cathedral_receipt_policy_manifest",
    "cathedral_receipt_policy_digest",
    "submission_report_data",
    "verify_submission_attestation",
    "verify_submission_receipt",
]
