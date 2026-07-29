"""`cathedral_assurance_receipt_v2` — the Compute lane's assurance receipt.

This is the base receipt the Distill receipt (`distill_receipt.py`) extends: the
shared body — worker identity, challenge, manifest & result digests, assurance
claims, policy registry, measurement, TCB, lifecycle, `issued_at`, `receipt_id`,
signature — is validated by the *same* functions in both lanes, so a Compute
contribution is admitted on exactly the same evidence discipline as Distill.

The `platform` block names the confidential CPU TEE and, optionally, a
confidential GPU riding on top of it:

  * **`cpu_tee`** — the CPU trusted execution environment the measurement and TCB
    describe. Two are supported, verified live on Cathedral:
      - `intel_tdx`   — Intel TDX. `measurement` is `tdx-measurement-sha256:<64 hex>`
        and `tcb` is the Intel TDX TCB (known non-Revoked status, 32-hex SVN,
        advisories listed when not UpToDate, debug OFF, current collateral).
      - `amd_sev_snp` — AMD SEV-SNP (the CPU TEE under Cathedral's confidential-GPU
        G4 profile). `measurement` is `sev-snp-measurement-sha384:<96 hex>` (the
        48-byte launch measurement) and `tcb` is the SEV-SNP TCB (guest-policy DEBUG
        disabled, versioned bootloader/tee/snp/microcode SVNs, current collateral).

  * **`class`** — `confidential_cpu` (the CPU TEE alone is the proof) or
    `confidential_gpu` (a *composite*: a confidential GPU bound to the CPU-TEE
    guest). A confidential-GPU receipt admits only when the GPU evidence is bound
    to *this* receipt's confidential guest — confidential-compute mode on, the GPU
    `bound_measurement` equal to the CPU-TEE `measurement` (the guest binding), and
    an injected GPU attestation verifier confirming the report. Because the receipt
    structurally carries and verifies the full CPU-TEE body and the GPU must bind to
    it, a GPU attestation on its own never admits.

The mapping to Cathedral's live G4 receipt is direct: `gpu_attestation_verified`
is the injected verifier's result, `guest_binding_verified` is the
`bound_measurement == measurement` check, and `cpu_tee` is `amd_sev`. The real
TDX/SEV/GPU quote check is injected (`gpu_attestation_verifier`) — the module is
hardware-free and testable, and production swaps in the real verifier unchanged.

A verified receipt yields the same `{miner_hotkey, receipt_id, work_units}` lane
contribution as Distill and CyberGym, so all three compose through
`lane_feed.compose_vector` unchanged.
"""
from __future__ import annotations

import base64
import re
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature

from cathedral_distill import distill_receipt as dr

# Reuse the shared `cathedral_assurance_receipt_v2` body primitives — one
# implementation of the canonical/receipt_id rules and the Intel-TDX TCB rules,
# verified in both lanes.
canonical_bytes = dr.canonical_bytes
compute_receipt_id = dr.compute_receipt_id

RECEIPT_SCHEMA = "cathedral_assurance_receipt_v2"
ASSURANCE_SCHEMA = dr.ASSURANCE_SCHEMA
MAX_RECEIPT_BYTES = dr.MAX_RECEIPT_BYTES

# platform.class — the CPU TEE alone, or a confidential GPU bound to it.
PLATFORM_CPU = "confidential_cpu"
PLATFORM_GPU = "confidential_gpu"

# platform.cpu_tee — which confidential CPU TEE the measurement + TCB describe.
CPU_TEE_TDX = "intel_tdx"
CPU_TEE_SEV = "amd_sev_snp"
_CPU_TEES = frozenset({CPU_TEE_TDX, CPU_TEE_SEV})

_SEV_MEASUREMENT_RE = re.compile(r"\Asev-snp-measurement-sha384:[0-9a-f]{96}\Z")
_SEV_REPORTED_TCB_RE = re.compile(r"\A[0-9a-f]{16}\Z")  # SEV-SNP reported TCB is 8 bytes
_SEV_SVN_FIELDS = ("boot_loader_svn", "tee_svn", "snp_svn", "microcode_svn")

# The shared body verbatim from the compute receipt, plus the `platform` block
# that names the CPU TEE and (for a composite) the confidential GPU.
_RECEIPT_KEYS = dr._SHARED_KEYS | {"platform"}
_PLATFORM_CPU_KEYS = frozenset({"class", "cpu_tee"})
_PLATFORM_GPU_KEYS = frozenset({"class", "cpu_tee", "gpu"})
_GPU_KEYS = frozenset(
    {"cc_mode", "vbios_measurement", "attestation_report_digest", "bound_measurement"}
)
_SEV_TCB_KEYS = frozenset(
    {"tee_type", "policy_debug_disabled", "boot_loader_svn", "tee_svn",
     "snp_svn", "microcode_svn", "reported_tcb", "collateral_current"}
)


class ComputeReceiptError(ValueError):
    """Raised when a compute receipt is malformed or fails verification. Fails closed."""


# A GPU attestation verifier confirms the GPU report is genuine and in CC mode.
# Injected (hardware-free tests pass a stub); production swaps in the real check.
GpuAttestationVerifier = Callable[[Mapping[str, Any]], bool]

# A CPU-TEE quote verifier independently re-checks the raw Intel TDX / AMD SEV-SNP
# quote against the receipt's measurement + TCB. Injected; optional (see
# verify_receipt): absent falls back to the trusted-issuer model.
CpuQuoteVerifier = Callable[[Mapping[str, Any]], bool]


def _validate_sev_tcb(tcb: Any) -> None:
    """The AMD SEV-SNP TCB block, verified with the same discipline as the Intel
    TDX one: the guest-policy DEBUG bit disabled, non-negative versioned SVNs, an
    8-byte reported TCB, and current collateral."""
    block = dr.exact_keys(tcb, _SEV_TCB_KEYS, "tcb")
    if block["tee_type"] != "sev_snp":
        raise ComputeReceiptError("tcb.tee_type must be sev_snp")
    if block["policy_debug_disabled"] is not True:
        raise ComputeReceiptError("SEV-SNP guest-policy DEBUG must be disabled")
    for svn in _SEV_SVN_FIELDS:
        value = block[svn]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ComputeReceiptError(f"tcb.{svn} must be a non-negative integer")
    if not isinstance(block["reported_tcb"], str) or _SEV_REPORTED_TCB_RE.match(block["reported_tcb"]) is None:
        raise ComputeReceiptError("tcb.reported_tcb must be 16 lowercase hex")
    if block["collateral_current"] is not True:
        raise ComputeReceiptError("tcb.collateral_current must be true")


def _validate_cpu_tee_body(doc: Mapping[str, Any], cpu_tee: str) -> None:
    """Validate the shared `measurement` + `tcb` for the receipt's CPU TEE."""
    measurement = str(doc["measurement"])
    if cpu_tee == CPU_TEE_TDX:
        if dr.MEASUREMENT_RE.match(measurement) is None:
            raise ComputeReceiptError("measurement must be tdx-measurement-sha256:<64 hex>")
        dr.validate_tcb(doc["tcb"])
    elif cpu_tee == CPU_TEE_SEV:
        if _SEV_MEASUREMENT_RE.match(measurement) is None:
            raise ComputeReceiptError("measurement must be sev-snp-measurement-sha384:<96 hex>")
        _validate_sev_tcb(doc["tcb"])
    else:  # unreachable: cpu_tee is validated in _validate_platform first
        raise ComputeReceiptError("unsupported cpu_tee")


def _validate_platform(doc: Mapping[str, Any]) -> str:
    platform = doc["platform"]
    if not isinstance(platform, Mapping):
        raise ComputeReceiptError("platform must be an object")
    platform_class = platform.get("class")
    if platform_class == PLATFORM_CPU:
        dr.exact_keys(platform, _PLATFORM_CPU_KEYS, "platform")
    elif platform_class == PLATFORM_GPU:
        dr.exact_keys(platform, _PLATFORM_GPU_KEYS, "platform")
        gpu = dr.exact_keys(platform["gpu"], _GPU_KEYS, "platform.gpu")
        dr.digest_field(gpu["vbios_measurement"], "platform.gpu.vbios_measurement")
        dr.digest_field(gpu["attestation_report_digest"], "platform.gpu.attestation_report_digest")
        # The GPU binds to the confidential guest by equalling the CPU-TEE
        # measurement (checked in verify_receipt); here it must simply be present.
        if not isinstance(gpu["bound_measurement"], str) or not gpu["bound_measurement"]:
            raise ComputeReceiptError("platform.gpu.bound_measurement must be a non-empty string")
        if gpu["cc_mode"] != "on":
            raise ComputeReceiptError("platform.gpu.cc_mode must be 'on'")
    else:
        raise ComputeReceiptError("platform.class must be confidential_cpu or confidential_gpu")
    if platform.get("cpu_tee") not in _CPU_TEES:
        raise ComputeReceiptError("platform.cpu_tee must be intel_tdx or amd_sev_snp")
    return platform_class


def validate_structure(receipt: Any) -> Mapping[str, Any]:
    """Structural validation of the shared compute body. Fails closed."""
    try:
        doc = dr.exact_keys(receipt, _RECEIPT_KEYS, "compute receipt")
        if doc["schema"] != RECEIPT_SCHEMA:
            raise ComputeReceiptError("unsupported compute receipt schema")
        unsigned = {k: v for k, v in doc.items() if k != "signature"}
        if len(canonical_bytes(unsigned)) > MAX_RECEIPT_BYTES:
            raise ComputeReceiptError("receipt exceeds 256 KiB")
        if not dr.RECEIPT_ID_RE.match(str(doc["receipt_id"])):
            raise ComputeReceiptError("receipt_id must be receipt-sha256:<64 hex>")
        if not dr.TS_RE.match(str(doc["issued_at"])):
            raise ComputeReceiptError("issued_at must be six-fraction-digit UTC")

        # The platform block names the CPU TEE; the measurement + TCB are then
        # verified with that TEE's rules (Intel TDX or AMD SEV-SNP).
        _validate_platform(doc)
        _validate_cpu_tee_body(doc, str(doc["platform"]["cpu_tee"]))
        channel = dr.exact_keys(doc["channel"], dr.CHANNEL_KEYS, "channel")
        dr.digest_field(channel["binding_digest"], "channel.binding_digest")
        if str(channel["status"]) not in ("passed", "failed", "unknown"):
            raise ComputeReceiptError("channel status is invalid")

        work = dr.exact_keys(doc["work"], dr.WORK_KEYS, "work")
        dr.digest_field(work["manifest_digest"], "work.manifest_digest")
        dr.digest_field(work["result_digest"], "work.result_digest")
        dr.decimal_field(work["work_units"], "work.work_units")
        if str(work["status"]) != "passed":
            raise ComputeReceiptError("work.status must be 'passed' for a creditable receipt")

        assurance = dr.exact_keys(
            doc["assurance"], frozenset({"schema", "claims"}), "assurance"
        )
        if assurance["schema"] != ASSURANCE_SCHEMA:
            raise ComputeReceiptError("unsupported assurance schema")
        claims = dr.exact_keys(assurance["claims"], dr.CLAIM_KEYS, "assurance.claims")
        for name, claim in claims.items():
            if str(claim.get("status")) not in ("passed", "failed", "unknown"):
                raise ComputeReceiptError(f"assurance claim {name} has an invalid status")
        # Compute credits require the confidential channel, the hardware, the
        # software, AND the work claim to have verified — the compute ran attested.
        for required in ("channel", "hardware", "software", "work"):
            if str(claims[required].get("status")) != "passed":
                raise ComputeReceiptError(f"assurance {required} claim must be passed")
    except dr.DistillReceiptError as exc:  # shared helpers raise the base error
        raise ComputeReceiptError(str(exc)) from exc
    return doc


def build_receipt(body: Mapping[str, Any], private_key, *, signing_key_id: str) -> dict[str, Any]:
    """Assemble a signed compute receipt (test/operator tooling)."""
    return dr.build_receipt(body, private_key, signing_key_id=signing_key_id)


def verify_receipt(
    receipt: Mapping[str, Any],
    key_registry: Any,
    *,
    now_iso: str,
    source_epoch: int,
    gpu_attestation_verifier: GpuAttestationVerifier | None = None,
    cpu_quote_verifier: CpuQuoteVerifier | None = None,
    allowed_measurements: frozenset[str] | set[str] | None = None,
    allowed_tcb_statuses: frozenset[str] | set[str] | None = None,
    allowed_advisories: frozenset[str] | set[str] | None = None,
) -> Mapping[str, Any]:
    """Independently verify a compute receipt before scoring. Fails closed.

    Order: structure, receipt_id, key resolution (anchored registry, never a
    caller-supplied key), signature, policy gating, replay/epoch binding,
    lifecycle, freshness, the CPU-TEE quote, and — for a GPU receipt — the
    composite GPU attestation (CC mode, binding to this quote, injected verifier).

    `cpu_quote_verifier` is the independent raw TDX/SEV-SNP quote check, mirroring
    `gpu_attestation_verifier`. It is OPTIONAL: absent, the receipt is admitted on
    the anchored signature (the trusted-issuer model — the authorized signer
    attested the CPU TEE before signing); present, the CPU quote is re-verified
    from first principles (the trustless model). The GPU verifier, by contrast, is
    required for a GPU receipt, because a confidential GPU is separate hardware the
    CPU-TEE signature cannot vouch for.
    """
    doc = validate_structure(receipt)
    try:
        # 1. receipt_id must recompute from the canonical body.
        if doc["receipt_id"] != compute_receipt_id(doc):
            raise ComputeReceiptError("receipt_id does not match the receipt body")

        # 2. Resolve the signing key from the anchored registry, at issue time.
        issued_at_dt = dr.parse_ts(str(doc["issued_at"]))
        try:
            public_key = key_registry.resolve(doc["signing_key_id"], at=issued_at_dt)
        except Exception as exc:  # ReceiptKeyError or any resolver failure -> reject
            raise ComputeReceiptError(f"signing key could not be resolved: {exc}") from exc

        # 3. Ed25519 signature over everything except `signature`.
        sig = dr.exact_keys(
            doc["signature"], frozenset({"algorithm", "value_base64"}), "signature"
        )
        if sig["algorithm"] != "ed25519":
            raise ComputeReceiptError("unsupported signature algorithm")
        signed = {k: v for k, v in doc.items() if k != "signature"}
        try:
            public_key.verify(base64.b64decode(sig["value_base64"]), canonical_bytes(signed))
        except (InvalidSignature, ValueError) as exc:
            raise ComputeReceiptError("signature does not verify") from exc

        # 4. Policy gating (when the validator supplies the signed-registry policy).
        if allowed_measurements is not None and doc["measurement"] not in allowed_measurements:
            raise ComputeReceiptError("measurement is not admitted by policy")
        if allowed_tcb_statuses is not None and doc["tcb"]["status"] not in allowed_tcb_statuses:
            raise ComputeReceiptError("tcb.status is not admitted by policy")
        if allowed_advisories is not None and not set(doc["tcb"]["advisory_ids"]).issubset(
            allowed_advisories
        ):
            raise ComputeReceiptError("tcb advisories are not admitted by policy")

        # 5. Replay protection: bound to the authorized source epoch.
        if int(doc["source_epoch"]) != int(source_epoch):
            raise ComputeReceiptError("receipt source_epoch does not match the authorized epoch")

        # 6. Lifecycle: only an issued receipt with no revocation.
        lifecycle = doc["lifecycle"]
        if str(lifecycle.get("state")) != "issued":
            raise ComputeReceiptError("receipt lifecycle state is not 'issued'")
        if lifecycle.get("revocation_reference") is not None:
            raise ComputeReceiptError("receipt has a revocation reference")

        # 7. Freshness.
        expires = str(lifecycle.get("worker_evidence_expires_at") or "")
        if not dr.TS_RE.match(expires):
            raise ComputeReceiptError("lifecycle evidence-expiry is not a valid timestamp")
        if now_iso >= expires:
            raise ComputeReceiptError("worker evidence has expired (stale receipt)")
        if now_iso < str(doc["issued_at"]):
            raise ComputeReceiptError("receipt issued in the future")

        # 8. CPU-TEE raw quote (optional independent check). When a verifier is
        # injected, the raw TDX/SEV-SNP quote is re-checked against the receipt's
        # measurement + TCB; absent, the anchored signature is the proof.
        if cpu_quote_verifier is not None:
            evidence = {
                "cpu_tee": doc["platform"]["cpu_tee"],
                "measurement": doc["measurement"],
                "tcb": doc["tcb"],
                "platform_pseudonym": doc["platform_pseudonym"],
                "policy_registry_digest": doc["policy_registry_digest"],
            }
            try:
                ok = cpu_quote_verifier(evidence)
            except Exception as exc:
                raise ComputeReceiptError(f"CPU quote verifier failed: {exc}") from exc
            if ok is not True:
                raise ComputeReceiptError("CPU-TEE quote did not verify")

        # 9. GPU composite: the GPU evidence must be bound to THIS receipt's
        # confidential guest (its CPU-TEE measurement — the guest binding) and be
        # confirmed by the injected verifier. GPU alone never admits.
        if doc["platform"]["class"] == PLATFORM_GPU:
            gpu = doc["platform"]["gpu"]
            if gpu["bound_measurement"] != doc["measurement"]:
                raise ComputeReceiptError(
                    "GPU attestation is not bound to this receipt's confidential guest "
                    "(bound_measurement != CPU-TEE measurement)"
                )
            if gpu_attestation_verifier is None:
                raise ComputeReceiptError(
                    "a confidential-GPU receipt requires a GPU attestation verifier"
                )
            try:
                ok = gpu_attestation_verifier(gpu)
            except Exception as exc:
                raise ComputeReceiptError(f"GPU attestation verifier failed: {exc}") from exc
            if ok is not True:
                raise ComputeReceiptError("GPU attestation did not verify")
    except dr.DistillReceiptError as exc:
        raise ComputeReceiptError(str(exc)) from exc

    return doc


def lane_contribution(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """The per-miner contribution this compute receipt makes to the signed feed.

    Identical tuple shape to Distill and CyberGym, so all three lanes compose
    through `lane_feed.compose_vector` unchanged.
    """
    return {
        "miner_hotkey": str(receipt["subject_hotkey"]),
        "receipt_id": str(receipt["receipt_id"]),
        "work_units": str(receipt["work"]["work_units"]),
    }


def platform_class(receipt: Mapping[str, Any]) -> str:
    return str(receipt["platform"]["class"])


def cpu_tee(receipt: Mapping[str, Any]) -> str:
    return str(receipt["platform"]["cpu_tee"])


__all__ = [
    "ComputeReceiptError", "RECEIPT_SCHEMA",
    "PLATFORM_CPU", "PLATFORM_GPU", "CPU_TEE_TDX", "CPU_TEE_SEV",
    "validate_structure", "verify_receipt", "build_receipt", "lane_contribution",
    "platform_class", "cpu_tee", "canonical_bytes", "compute_receipt_id",
]
