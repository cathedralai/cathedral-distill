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
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

COMMITMENT_SCHEMA = "cathedral_cybergym_tdx_commitment_v1"
# The persistent-enclave path (#94/#95): the enclave GENERATES its own signing
# keypair, the boot quote binds that public key, and the enclave signs this
# commitment over (task, poc, trace[, verdict]). Distinct schema so an `attest.v1`
# result.txt commitment can never be replayed as an enclave-signed one.
ENCLAVE_COMMITMENT_SCHEMA = "cathedral_cybergym_tdx_enclave_commitment_v1"
# The canonical bytes the enclave writes as its *result*. A live Cathedral
# `attest.v1` receipt (schema `cathedral_customer_receipt_v1`) binds the workload
# and its result as `workload_sha256` / `result_sha256` under Cathedral's Ed25519
# signature, verified against Intel's DCAP chain — it does NOT expose a
# `report_data[0:32] = nonce||pubkey` field. So the enclave key rides in the
# result (bound by `result_sha256`), exactly the way `attest.v1` already binds its
# `result.txt` commitment. Confirmed on real hardware 2026-08-05 (workers
# c776ca65 free / 19ed3639 paid: intel_verified + report_data_match, distinct
# workload/result digests per command).
ENCLAVE_RESULT_SCHEMA = "cathedral_cybergym_enclave_result_v1"
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


def enclave_commitment_bytes(
    *, task_id: str, poc_sha256: str, trace_id: str, miner_hotkey: str, nonce: str,
    verdict: str | None = None,
) -> bytes:
    """The canonical bytes the persistent enclave signs with its own key.

    Binds `(task, poc, trace)`, the **miner** it was dispatched to, and the batch
    **nonce** — so a receipt is valid only for the exact miner and dispatch that
    produced it. Without the miner and nonce, a second miner dispatched the same
    task could resubmit another miner's `(poc, trace, receipt)` under its own batch
    and earn the credit (the receipt binds only the solve, not who ran it). When the
    differential runs in-enclave (#95) the signed `verdict` is bound too, so an
    external party confirms PASS/FAIL from the signature alone. `verdict` is omitted
    from the body (not sent as null) when absent, so the boot-only #94 shape and the
    verdict-carrying #95 shape are distinct signed messages.
    """
    body: dict[str, Any] = {"schema": ENCLAVE_COMMITMENT_SCHEMA, "task_id": task_id,
                            "poc_sha256": poc_sha256, "trace_id": trace_id,
                            "miner_hotkey": miner_hotkey, "nonce": nonce}
    if verdict is not None:
        body["verdict"] = verdict
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def enclave_result_bytes(
    *, enclave_pubkey_b64: str, task_id: str, poc_sha256: str, trace_id: str,
    miner_hotkey: str, nonce: str, verdict: str | None, signature_b64: str,
) -> bytes:
    """The exact result an approved enclave workload writes, whose sha256 the
    Cathedral receipt binds as `result_sha256`.

    It carries the enclave-generated public key, the
    `(task, poc, trace, miner, nonce[, verdict])` commitment, and the enclave's
    signature over that commitment. Because the workload that produced it is pinned
    by `workload_sha256` to the approved solver and the result is bound by
    `result_sha256`, this envelope could only have been produced by the genuine
    solver inside the attested enclave — for this miner and this dispatch.
    """
    commitment: dict[str, Any] = {"schema": ENCLAVE_COMMITMENT_SCHEMA, "task_id": task_id,
                                  "poc_sha256": poc_sha256, "trace_id": trace_id,
                                  "miner_hotkey": miner_hotkey, "nonce": nonce}
    if verdict is not None:
        commitment["verdict"] = verdict
    body = {"schema": ENCLAVE_RESULT_SCHEMA, "enclave_pubkey_b64": enclave_pubkey_b64,
            "commitment": commitment, "signature_b64": signature_b64}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


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


def _receipt_tee(receipt: Mapping[str, Any]) -> str:
    """Canonical TEE for a live `cathedral_customer_receipt_v1`, which names it as
    `cpu_tee` (e.g. `intel_tdx`) / `execution_class` (`tdx_cpu`), falling back to the
    quote-shaped `kind` the other verifiers read."""
    cpu = str(receipt.get("cpu_tee") or "").lower()
    if cpu.startswith("intel_tdx") or str(receipt.get("execution_class") or "") == "tdx_cpu":
        return REQUIRED_TEE
    if cpu.startswith("amd_sev"):
        return "amd_sev_snp"
    return tee_kind(receipt)


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
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    # A naive (tz-less) timestamp would raise on subtraction against a tz-aware
    # `now`; treat it as UTC so freshness never crashes the intake loop.
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def verify_cathedral_attestation(
    receipt: Mapping[str, Any], *, task_id: str, poc_sha256: str, trace_id: str,
    now: datetime | None = None, max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    quote_verifier: QuoteVerifier | None = None,
    artifacts_digest_recipe: "Callable[[list], str] | None" = None,
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

    # --- freshness (fail closed: a missing/unparseable timestamp is not creditable,
    #     else an old-but-genuine receipt could be replayed forever by omitting it) ---
    started = _iso(receipt.get("started_at"))
    ref = now or datetime.now(UTC)
    if started is None:
        return no("missing or invalid attestation timestamp")
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
    # SECURITY (trustless seam): report_data[32:64] binds the `artifacts_sha256`
    # SCALAR, while the commitment above is matched against the `artifacts[]` LIST.
    # If nothing ties the scalar to the list, a GENUINE quote (which commits to some
    # real scalar S) can be re-paired with a swapped `artifacts[]` list that contains
    # a different result.txt: the commitment-vs-list check passes on the swapped list,
    # the quote check passes on the claimed scalar S, and the two are never
    # cross-checked. The fix is to recompute the scalar FROM the list with Cathedral's
    # canonical recipe and confirm it equals the claimed field before trusting either.
    #
    # That recipe lives server-side, so it is injected (`artifacts_digest_recipe`)
    # rather than reimplemented-and-guessed here. Until it is supplied, the trustless
    # path FAILS CLOSED: it refuses rather than trust an unverified scalar. Trusted-
    # issuer (default) is unaffected — Cathedral validates the full binding server-side.
    verification = receipt.get("verification", {})
    trustless = False
    if quote_verifier is not None:
        claimed_scalar = str(receipt.get("artifacts_sha256", ""))
        if artifacts_digest_recipe is None:
            return no(
                "trustless attestation requires the artifacts list→scalar binding "
                "recipe (artifacts_digest_recipe=...): report_data binds the "
                "artifacts_sha256 scalar, the commitment binds the artifacts[] list, "
                "and nothing here ties them, so a genuine quote could be re-paired "
                "with a swapped result.txt. Refusing rather than trusting the "
                "claimed scalar."
            )
        try:
            recomputed = str(artifacts_digest_recipe(list(receipt.get("artifacts", []))))
        except Exception as exc:  # a recipe that throws is a refusal, never a pass
            return no(f"artifacts digest recipe failed: {exc}")
        if not claimed_scalar or recomputed != claimed_scalar:
            return no(
                "artifacts_sha256 scalar does not match the artifacts[] list "
                f"(recomputed {recomputed[:16]}… != claimed {claimed_scalar[:16]}…): "
                "a genuine quote may have been re-paired with a swapped result.txt"
            )
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
    receipt: Mapping[str, Any], *, expected_ssh_pubkey: str | None,
    now: datetime | None = None, max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    quote_verifier: QuoteVerifier | None = None,
) -> BootAttestation:
    """Verify a Cathedral `custom.v1` **boot** quote: a sealed Intel-TDX worker that
    keeps the real corpus image running with SSH access after a verified boot.

    SAFETY (a boot quote attests the ENVIRONMENT, not the solve):
      * It binds the machine boot + the **customer's SSH key**
        (`report_data[0:32] = sha256(nonce_hex || base64(ssh_pubkey))`).
        `trust.workload_result_binding` is false: the PoC/trace are NOT in the quote,
        so `result_bound` is always False.
      * `expected_ssh_pubkey` is REQUIRED and must be the miner's REGISTERED key.
        Without one, a pass could only prove "*some* genuine TDX worker booted",
        which any party with any TDX worker satisfies; this used to return
        `attested=True, key_bound=False`, an advisory shape one missed
        `key_bound` check away from crediting anybody, so an absent key now
        refuses outright (`attested=False`).
      * Freshness is bounded exactly as `verify_cathedral_attestation` bounds it:
        a stale or future-dated `started_at` is refused, and a missing one fails
        closed, so one enclave boot cannot keep vouching indefinitely.
      * Even key-bound and fresh this is NOT a sufficient anti-cheat gate: the
        customer holds the SSH private key, so a miner can present a valid
        key-bound boot quote alongside a PoC obtained anywhere (looked up). The
        quote does not tie the PoC to the enclave.

    Use for environment attestation / defense-in-depth. A *creditable* solve must be
    RESULT-bound: `attest.v1`'s result quote (`verify_cathedral_attestation`), or a
    persistent worker whose ENCLAVE holds the signing key and signs the (task, poc,
    trace) commitment. Trusted-issuer by default; a `quote_verifier` checks the raw
    quote via Intel DCAP. Fails closed.
    """
    rid = str(receipt.get("receipt_id") or receipt.get("worker_id") or "")

    def no(reason: str) -> BootAttestation:
        return BootAttestation(False, tee_kind(receipt), reason, rid)

    if str(receipt.get("receipt_status") or receipt.get("status")) != "ready":
        return no("boot receipt not ready")
    tee = tee_kind(receipt)
    if tee != REQUIRED_TEE:
        return no(f"CyberGym requires an Intel TDX worker, got tee={tee!r}")

    # The docstring rule, enforced rather than advised: an unbound boot quote can
    # be produced by anyone with any TDX worker, so an absent key is a refusal,
    # never an attested-but-unbound result a caller could misread as credit.
    if not isinstance(expected_ssh_pubkey, str) or not expected_ssh_pubkey.strip():
        return no("no expected ssh pubkey: an unbound boot quote proves only that "
                  "some TDX worker booted and must never credit a miner")

    # Freshness, the same bounds as `verify_cathedral_attestation` (fail closed: a
    # missing or unparseable timestamp refuses, else an old-but-genuine receipt
    # could be replayed forever by omitting it). Without a bound, one enclave boot
    # vouched for submissions indefinitely.
    started = _iso(receipt.get("started_at"))
    ref = now or datetime.now(UTC)
    if started is None:
        return no("missing or invalid boot attestation timestamp")
    age = (ref - started).total_seconds()
    if age > max_age_seconds:
        return no(f"boot attestation is stale ({int(age)}s > {max_age_seconds}s)")
    if age < -300:
        return no("boot attestation is from the future")

    pub_b64 = base64.b64encode(expected_ssh_pubkey.strip().encode()).decode()
    nonce = str(receipt.get("nonce", ""))
    rd = str(receipt.get("report_data", ""))
    expect = hashlib.sha256((nonce + pub_b64).encode()).hexdigest()
    if not rd or not rd.startswith(expect):
        return no("boot quote report_data does not bind the expected ssh key")
    if str(receipt.get("pubkey_b64", "")) != pub_b64:
        return no("receipt pubkey_b64 does not match the expected ssh key")

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

    return BootAttestation(True, REQUIRED_TEE, "attested_intel_tdx_boot_key_bound",
                           rid, True)


# receipt_verifier(receipt) -> bool. The seam for the full Cathedral customer
# receipt signature verification (cathedral-compute's verify_customer_receipt),
# injected so this module needs no cross-repo import. Omitted -> trusted-issuer.
ReceiptVerifier = Callable[[Mapping[str, Any]], bool]


@dataclass(frozen=True)
class EnclaveAttestation:
    """A persistent-enclave (#94) verdict. Result-bound: the approved solver
    workload ran the solve inside the attested enclave and its `(task, poc,
    trace[, verdict])` commitment is bound by the receipt's `result_sha256`."""
    attested: bool
    tee: str
    reason: str
    receipt_id: str = ""
    result_bound: bool = False     # result_sha256 binds THIS (task, poc, trace)
    workload_bound: bool = False   # workload_sha256 is the approved solver
    signature_bound: bool = False  # the enclave signed the commitment (trustless layer)
    verdict: str | None = None     # #95: the in-enclave PASS/FAIL, inside the result
    enclave_key_b64: str = ""
    trustless: bool = False


def verify_persistent_enclave_attestation(
    receipt: Mapping[str, Any], *, task_id: str, poc_sha256: str, trace_id: str,
    miner_hotkey: str, nonce: str,
    result_bytes: bytes, expected_workload_sha256: str,
    require_verdict: bool = False, now: datetime | None = None,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    receipt_verifier: ReceiptVerifier | None = None,
) -> EnclaveAttestation:
    """Verify a persistent-enclave real-corpus solve (`docs/TDX_ATTESTATION.md`
    §*The production real-corpus path*, #94/#95).

    It combines what the two simpler profiles each have half of: a `custom.v1`
    worker runs the real ~4 GB arvo image, `attest.v1` binds the solve. The approved
    solver **workload** (pinned by ``expected_workload_sha256``) generates a keypair
    inside the enclave, runs the reproduction, and writes an ``enclave_result_bytes``
    envelope — the enclave key, the `(task, poc, trace[, verdict])` commitment, and a
    signature over it — as its **result**. A live Cathedral ``attest.v1`` receipt
    (``cathedral_customer_receipt_v1``) then binds ``workload_sha256`` and
    ``result_sha256`` under Cathedral's signature, verified against Intel's DCAP
    chain.

    Three bindings make a looked-up PoC unusable:
      * ``workload_sha256 == expected_workload_sha256`` — only the approved solver
        ran, so a miner cannot substitute a workload that echoes a looked-up answer;
      * ``sha256(result_bytes) == result_sha256`` — the attested result IS this
        envelope, so its committed `(task, poc, trace, verdict)` cannot be swapped;
      * the enclave signature over the commitment (the trustless-external layer for
        #95: an outside party confirms the verdict from the signature alone).

    Receipt trust is the same seam shape as ``verify_cathedral_attestation``:
    trusted-issuer by default (``intel_verified`` + ``report_data_match`` +
    ``execution_binding_verified``), or independent via ``receipt_verifier``
    (cathedral-compute's ``verify_customer_receipt``). Fails closed to
    ``attested=False``; freshness bounds match the sibling verifiers.
    """
    rid = str(receipt.get("receipt_id") or receipt.get("worker_id") or "")

    def no(reason: str) -> EnclaveAttestation:
        return EnclaveAttestation(False, _receipt_tee(receipt), reason, rid)

    if str(receipt.get("receipt_status") or receipt.get("status")) != "ready":
        return no("enclave receipt not ready")
    tee = _receipt_tee(receipt)
    if tee != REQUIRED_TEE:
        return no(f"CyberGym requires an Intel TDX worker, got tee={tee!r}")

    # Freshness on the receipt's issue time, same bounds as the other verifiers.
    issued = _iso(receipt.get("issued_at") or receipt.get("started_at"))
    ref = now or datetime.now(UTC)
    if issued is None:
        return no("missing or invalid enclave attestation timestamp")
    age = (ref - issued).total_seconds()
    if age > max_age_seconds:
        return no(f"enclave attestation is stale ({int(age)}s > {max_age_seconds}s)")
    if age < -300:
        return no("enclave attestation is from the future")

    # (1) Workload allowlist: only the approved solver may earn. Without this a
    # miner could run a workload that just prints a looked-up answer and self-signs.
    if not expected_workload_sha256:
        return no("no expected_workload_sha256: an unpinned workload could echo a "
                  "looked-up answer and must never credit a miner")
    workload_sha = str(receipt.get("workload_sha256", ""))
    if not workload_sha or not hmac.compare_digest(workload_sha, str(expected_workload_sha256)):
        return no("receipt workload_sha256 is not the approved solver workload")

    # (2) Result binding: the attested result IS this envelope, byte-for-byte.
    result_sha = str(receipt.get("result_sha256", ""))
    got = hashlib.sha256(result_bytes).hexdigest()
    if not result_sha or got != result_sha:
        return no("submitted result_bytes do not match the attested result_sha256 "
                  f"({got[:16]}… != {result_sha[:16]}…)")

    # (3) Receipt trust: trusted-issuer by default, or independently via the seam.
    trustless = False
    if receipt_verifier is not None:
        try:
            ok = bool(receipt_verifier(receipt))
        except Exception as exc:  # a verifier that throws is a refusal, never a pass
            return no(f"receipt verifier failed: {exc}")
        if not ok:
            return no("customer receipt failed independent verification")
        trustless = True
    else:
        if receipt.get("intel_verified") is not True:
            return no("Cathedral did not report intel_verified")
        if receipt.get("report_data_match") is not True:
            return no("Cathedral report_data_match is not true")
        if receipt.get("execution_binding_verified") is not True:
            return no("Cathedral execution_binding_verified is not true")

    # The result envelope: parse, confirm it commits to THIS solve, and check the
    # enclave signature over the commitment.
    try:
        envelope = json.loads(result_bytes)
    except (ValueError, TypeError):
        return no("attested result is not valid JSON")
    if not isinstance(envelope, dict) or envelope.get("schema") != ENCLAVE_RESULT_SCHEMA:
        return no("attested result is not an enclave result envelope")
    commitment = envelope.get("commitment")
    if not isinstance(commitment, dict):
        return no("enclave result carries no commitment")
    verdict = commitment.get("verdict")
    if verdict is not None and not isinstance(verdict, str):
        return no("enclave verdict must be a string")
    if require_verdict and not verdict:
        return no("enclave commitment carries no verdict (require_verdict)")
    if (str(commitment.get("task_id")) != task_id
            or str(commitment.get("poc_sha256")) != poc_sha256
            or str(commitment.get("trace_id")) != trace_id
            or str(commitment.get("miner_hotkey")) != miner_hotkey
            or str(commitment.get("nonce")) != nonce):
        return no("attested result commits to a different task/poc/trace/miner/nonce")

    enclave_key_b64 = str(envelope.get("enclave_pubkey_b64", ""))
    sig_b64 = str(envelope.get("signature_b64", ""))
    if not enclave_key_b64 or not sig_b64:
        return no("enclave result is missing the pubkey or signature")
    try:
        enclave_pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(enclave_key_b64))
        signature = base64.b64decode(sig_b64)
    except Exception:
        return no("enclave pubkey or signature is malformed")
    # Recompute the signed bytes from the EXPECTED (submission-supplied) miner and
    # nonce, not the envelope's — so another miner reusing this result verifies its
    # signature against its own hotkey and fails.
    signed = enclave_commitment_bytes(
        task_id=task_id, poc_sha256=poc_sha256, trace_id=trace_id,
        miner_hotkey=miner_hotkey, nonce=nonce, verdict=verdict)
    try:
        enclave_pub.verify(signature, signed)
    except InvalidSignature:
        return no("enclave signature does not verify over this "
                  "task/poc/trace/miner/nonce/verdict")

    return EnclaveAttestation(
        True, REQUIRED_TEE,
        "attested_intel_tdx_enclave_result_bound" + ("_trustless" if trustless else ""),
        rid, result_bound=True, workload_bound=True, signature_bound=True,
        verdict=verdict, enclave_key_b64=enclave_key_b64, trustless=trustless,
    )


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
    "COMMITMENT_SCHEMA", "ENCLAVE_COMMITMENT_SCHEMA", "ENCLAVE_RESULT_SCHEMA",
    "REQUIRED_TEE", "REQUIRED_HARDWARE", "RESULT_ARTIFACT",
    "commitment_bytes", "commitment_sha256", "enclave_commitment_bytes",
    "enclave_result_bytes", "tee_kind",
    "CathedralAttestation", "verify_cathedral_attestation",
    "BootAttestation", "verify_boot_attestation",
    "EnclaveAttestation", "verify_persistent_enclave_attestation", "ReceiptVerifier",
]
