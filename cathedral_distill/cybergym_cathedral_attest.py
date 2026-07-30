"""Bind a real Cathedral `attest.v1` (Intel TDX CPU) worker receipt to a CyberGym
submission — the production adapter a validator uses to credit a solve that ran
inside a genuine Cathedral TDX enclave.

Cathedral binds a workload into the TDX quote's `report_data` (its own
`binding_recipe`, verified server-side and reported as `verification.report_data_match`):

    report_data[0:32]  = sha256(nonce_hex || e2e_pubkey_b64)
    report_data[32:64] = sha256(bound_digest || result_sha256 || egress_log_sha ||
                                files_sha || policy_sha || artifacts_sha)

The miner's solve runs in the enclave and writes ONE artifact — `result.txt` — a
canonical commitment to `(task_id, poc_sha256, trace_id)`; Cathedral digests it into
the artifact list (and thereby into `artifacts_sha` / `report_data[32:64]`). This
adapter verifies the receipt is a genuine Intel-TDX, sealed (`reuse=forbidden`,
`egress=none`) run, then **recomputes that commitment from the submitted
`(task_id, poc, trace)` and matches it to the attested artifact digest** — so an
attestation cannot be replayed for another task, lifted from another miner, or paired
with a trace authored outside the enclave.

Two Cathedral Intel-TDX profiles are covered:
  * `verify_cathedral_attestation` — an `attest.v1` **result** quote (above): bounded,
    one-shot, binds the exact `(task, poc, trace)` via the artifact commitment.
  * `verify_boot_attestation` — a `custom.v1` **boot** quote: a sealed TDX worker that
    keeps the real corpus image running with SSH access after a verified boot, binding
    the machine + the customer SSH key (`workload_result_binding` is false). This is the
    path that runs the genuine multi-GB `n132/arvo` build inside TDX, which the bounded
    `attest.v1` enclave cannot.

Trust posture: by default this trusts Cathedral's own verification flags
(`intel_verified` / `report_data_match` / `binding_verified`) — **trusted-issuer**. Pass
a `quote_verifier` to additionally verify the raw `quote_b64` against Intel DCAP
collateral (**trustless**) — that raw-quote parse is the standing INFRA seam; the
binding logic here is independent of it, and fails closed.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Mapping

COMMITMENT_SCHEMA = "cathedral_cybergym_tdx_commitment_v1"
REQUIRED_TEE = "intel_tdx"
REQUIRED_HARDWARE = "tdx_cpu"
RESULT_ARTIFACT = "result.txt"
DEFAULT_MAX_AGE_SECONDS = 24 * 3600

# quote_verifier(quote_b64: str, expected_report_data_hex: str) -> bool
QuoteVerifier = Callable[[str, str], bool]


def commitment_bytes(*, task_id: str, poc_sha256: str, trace_id: str) -> bytes:
    """The exact `result.txt` the enclave writes — a canonical commitment the
    validator can reproduce byte-for-byte from the submission."""
    body = {"schema": COMMITMENT_SCHEMA, "task_id": task_id,
            "poc_sha256": poc_sha256, "trace_id": trace_id}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def commitment_sha256(*, task_id: str, poc_sha256: str, trace_id: str) -> str:
    return hashlib.sha256(commitment_bytes(
        task_id=task_id, poc_sha256=poc_sha256, trace_id=trace_id)).hexdigest()


def tee_kind(receipt: Mapping[str, Any]) -> str:
    """Map Cathedral's quote `kind` (e.g. 'tdx-1.5', 'sev-snp-...') to our canonical
    tee name. An Intel TDX quote → 'intel_tdx'; anything else is refused. Reads the
    top-level `kind` (custom.v1 boot receipt) or the nested `tee_attestation.kind`
    (attest.v1 result receipt)."""
    kind = str(receipt.get("kind") or receipt.get("tee_attestation", {}).get("kind", "")).lower()
    if kind.startswith("tdx"):
        return REQUIRED_TEE
    if kind.startswith("sev"):
        return "amd_sev_snp"
    return kind or "unknown"


@dataclass(frozen=True)
class CathedralAttestation:
    attested: bool
    tee: str
    reason: str
    receipt_id: str = ""
    artifact_sha256: str = ""
    trustless: bool = False   # True iff the raw quote was independently verified


def _iso(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def verify_cathedral_attestation(
    receipt: Mapping[str, Any], *, task_id: str, poc_sha256: str, trace_id: str,
    now: datetime | None = None, max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    quote_verifier: QuoteVerifier | None = None,
) -> CathedralAttestation:
    """Verify a Cathedral worker receipt attests THIS submission ran in real Intel TDX.

    Fails closed to `attested=False` with a reason (never raises on a malformed
    receipt), so a missing/invalid attestation is a soft non-credit, matching the
    rest of the CyberGym gate.
    """
    rid = str(receipt.get("receipt_id") or receipt.get("worker_id") or "")

    def no(reason: str) -> CathedralAttestation:
        return CathedralAttestation(False, tee_kind(receipt), reason, rid)

    if str(receipt.get("receipt_status") or receipt.get("status")) != "ready":
        return no("receipt not ready")
    if int(receipt.get("exit_code", -1)) != 0:
        return no(f"enclave exit_code={receipt.get('exit_code')}")

    tee = tee_kind(receipt)
    if tee != REQUIRED_TEE:
        return no(f"CyberGym requires an Intel TDX enclave, got tee={tee!r}")

    policy = receipt.get("task_policy", {})
    if str(policy.get("hardware_class")) != REQUIRED_HARDWARE:
        return no(f"hardware_class={policy.get('hardware_class')!r} (need {REQUIRED_HARDWARE})")
    if str(policy.get("reuse")) != "forbidden":
        return no("worker is not single-use (reuse must be forbidden)")
    if str(policy.get("egress")) != "none":
        return no("worker egress is not denied")

    # --- freshness ---
    started = _iso(receipt.get("started_at"))
    ref = now or datetime.now(UTC)
    if started is not None:
        age = (ref - started).total_seconds()
        if age > max_age_seconds:
            return no(f"attestation is stale ({int(age)}s > {max_age_seconds}s)")
        if age < -300:
            return no("attestation is from the future")

    # --- the submission binding: the attested result.txt IS the commitment ---
    expect = commitment_sha256(task_id=task_id, poc_sha256=poc_sha256, trace_id=trace_id)
    artifact = next((a for a in receipt.get("artifacts", [])
                     if str(a.get("path")) == RESULT_ARTIFACT), None)
    if artifact is None:
        return no(f"no {RESULT_ARTIFACT} artifact in the attested output")
    got = str(artifact.get("sha256", ""))
    if got != expect:
        return no("attested commitment does not bind this task/poc/trace "
                  f"(artifact {got[:16]}… != expected {expect[:16]}…)")

    # --- the quote itself: trusted-issuer by default, trustless if a verifier is given ---
    verification = receipt.get("verification", {})
    trustless = False
    if quote_verifier is not None:
        quote_b64 = str(receipt.get("tee_attestation", {}).get("quote_b64", ""))
        expected_rd = _expected_report_data_hex(receipt)
        if not quote_b64 or expected_rd is None or not quote_verifier(quote_b64, expected_rd):
            return no("raw TDX quote failed independent verification")
        trustless = True
    else:
        if verification.get("intel_verified") is not True:
            return no("Cathedral did not report intel_verified")
        if verification.get("report_data_match") is not True:
            return no("Cathedral report_data_match is not true")

    return CathedralAttestation(True, REQUIRED_TEE,
                                "attested_intel_tdx" + ("_trustless" if trustless else ""),
                                rid, got, trustless)


@dataclass(frozen=True)
class BootAttestation:
    attested: bool                 # a genuine Intel-TDX worker booted
    tee: str
    reason: str
    receipt_id: str = ""
    key_bound: bool = False        # the quote binds the *expected* (miner's) SSH key
    result_bound: bool = False     # ALWAYS False: a boot quote never binds the PoC/trace

    @property
    def miner_attested(self) -> bool:
        """A boot quote tied to the expected miner key. Still NOT proof the PoC was
        produced in the enclave — see `verify_boot_attestation` (result_bound is False).
        Use for environment attestation / defense-in-depth, never as the sole credit gate."""
        return self.attested and self.key_bound


def verify_boot_attestation(
    receipt: Mapping[str, Any], *, expected_ssh_pubkey: str | None = None,
    quote_verifier: QuoteVerifier | None = None,
) -> BootAttestation:
    """Verify a Cathedral `custom.v1` **boot** quote — a sealed Intel-TDX worker that
    keeps the real corpus image running with SSH access after a verified boot.

    ⚠️  SAFETY — a boot quote attests the ENVIRONMENT, not the solve:
      * It binds the machine boot + the **customer's SSH key**
        (`report_data[0:32] = sha256(nonce_hex || base64(ssh_pubkey))`).
        `trust.workload_result_binding` is false — the PoC/trace are NOT in the quote,
        so `result_bound` is always False.
      * You MUST pass the miner's REGISTERED key as `expected_ssh_pubkey`. Without it
        (`key_bound=False`) a pass only proves "*some* genuine TDX worker booted", which
        any party with any TDX worker satisfies — it must NEVER credit a miner.
      * Even key-bound this is NOT a sufficient anti-cheat gate: the customer holds the
        SSH private key, so a miner can present a valid key-bound boot quote alongside a
        PoC obtained anywhere (looked up). The quote does not tie the PoC to the enclave.

    Use for environment attestation / defense-in-depth. A *creditable* solve must be
    RESULT-bound — `attest.v1`'s result quote (`verify_cathedral_attestation`), or a
    persistent worker whose ENCLAVE holds the signing key and signs the (task, poc, trace)
    commitment. Trusted-issuer by default; a `quote_verifier` checks the raw quote via
    Intel DCAP. Fails closed.
    """
    rid = str(receipt.get("receipt_id") or receipt.get("worker_id") or "")

    def no(reason: str) -> BootAttestation:
        return BootAttestation(False, tee_kind(receipt), reason, rid)

    if str(receipt.get("receipt_status") or receipt.get("status")) != "ready":
        return no("boot receipt not ready")
    tee = tee_kind(receipt)
    if tee != REQUIRED_TEE:
        return no(f"CyberGym requires an Intel TDX worker, got tee={tee!r}")

    key_bound = False
    if expected_ssh_pubkey is not None:
        pub_b64 = base64.b64encode(expected_ssh_pubkey.strip().encode()).decode()
        nonce = str(receipt.get("nonce", ""))
        rd = str(receipt.get("report_data", ""))
        expect = hashlib.sha256((nonce + pub_b64).encode()).hexdigest()
        if not rd or not rd.startswith(expect):
            return no("boot quote report_data does not bind the expected ssh key")
        if str(receipt.get("pubkey_b64", "")) != pub_b64:
            return no("receipt pubkey_b64 does not match the expected ssh key")
        key_bound = True

    if quote_verifier is not None:
        q = str(receipt.get("quote_b64", ""))
        if not q or not quote_verifier(q, str(receipt.get("report_data", ""))):
            return no("raw boot quote failed independent verification")
    else:
        if receipt.get("intel_verified") is not True and str(receipt.get("intel_status")) != "verified":
            return no("Cathedral did not report intel_verified")
        if receipt.get("binding_verified") is not True:
            return no("customer key binding not verified")
        if receipt.get("verified") is not True:
            return no("boot quote not verified (intel chain and/or binding failed)")

    reason = "attested_intel_tdx_boot_" + ("key_bound" if key_bound else "environment_only")
    return BootAttestation(True, REQUIRED_TEE, reason, rid, key_bound)


def _expected_report_data_hex(receipt: Mapping[str, Any]) -> str | None:
    """Recompute report_data[32:64] from the receipt fields per Cathedral's
    binding_recipe, for a trustless quote check. Returns None if a needed field is
    absent (fail closed)."""
    t = receipt.get("tee_attestation", {})
    bound = t.get("bound_digest")
    result_sha = t.get("result_sha256") or receipt.get("result_sha256")
    files_sha = receipt.get("files_sha256", "")
    policy_sha = receipt.get("policy_sha256", "")
    artifacts_sha = receipt.get("artifacts_sha256", "")
    egress_sha = receipt.get("egress_log_sha256", "")
    if not bound or not result_sha:
        return None
    material = "".join(str(x) for x in (bound, result_sha, egress_sha, files_sha, policy_sha, artifacts_sha))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


__all__ = [
    "COMMITMENT_SCHEMA", "REQUIRED_TEE", "REQUIRED_HARDWARE", "RESULT_ARTIFACT",
    "commitment_bytes", "commitment_sha256", "tee_kind",
    "CathedralAttestation", "verify_cathedral_attestation",
    "BootAttestation", "verify_boot_attestation",
]
