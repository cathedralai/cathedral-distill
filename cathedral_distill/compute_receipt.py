"""`cathedral_assurance_receipt_v2` — the Compute lane's assurance receipt.

This is the base receipt the Distill receipt (`distill_receipt.py`) extends: the
shared body — worker identity, challenge, manifest & result digests, assurance
claims, policy registry, measurement, TCB, lifecycle, `issued_at`, `receipt_id`,
signature — is validated by the *same* functions in both lanes, so a Compute
contribution is admitted on exactly the same evidence discipline as Distill.

Compute comes in two platform classes:

  * **`intel_tdx_cpu`** — an Intel TDX CPU attestation. The shared TDX body (a
    64-hex measurement and a strict TCB block: known non-Revoked status, 32-hex
    SVN, advisories listed when not UpToDate, debug OFF, current collateral) is
    the whole proof.

  * **`confidential_gpu`** — a *composite* TDX-CPU + confidential-GPU attestation.
    The GPU evidence only counts when it is bound to a valid TDX CPU quote in the
    same receipt: confidential-compute mode must be on, the GPU's `bound_measurement`
    must equal this receipt's TDX `measurement`, and an injected GPU attestation
    verifier must confirm the GPU report. A GPU attestation on its own never
    admits — the receipt structurally carries and verifies the full TDX CPU body,
    so there is no "GPU alone" path to positive weight.

The real TDX/GPU quote check is injected (`gpu_attestation_verifier`), exactly as
the compute repo's verifier and the CyberGym crash backend are — the module is
hardware-free and fully testable, and production swaps in the real attestation
verifier without changing this contract.

A verified receipt yields the same `{miner_hotkey, receipt_id, work_units}` lane
contribution as Distill and CyberGym, so all three compose through
`lane_feed.compose_vector` unchanged.
"""
from __future__ import annotations

import base64
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature

from cathedral_distill import distill_receipt as dr

# Reuse the shared `cathedral_assurance_receipt_v2` body primitives — one
# implementation of the TDX/TCB and canonical rules, verified in both lanes.
canonical_bytes = dr.canonical_bytes
compute_receipt_id = dr.compute_receipt_id

RECEIPT_SCHEMA = "cathedral_assurance_receipt_v2"
ASSURANCE_SCHEMA = dr.ASSURANCE_SCHEMA
MAX_RECEIPT_BYTES = dr.MAX_RECEIPT_BYTES

PLATFORM_CPU = "intel_tdx_cpu"
PLATFORM_GPU = "confidential_gpu"

# The shared body verbatim from the compute receipt, plus the `platform` block
# that discriminates CPU from the composite GPU attestation.
_RECEIPT_KEYS = dr._SHARED_KEYS | {"platform"}
_PLATFORM_CPU_KEYS = frozenset({"class"})
_PLATFORM_GPU_KEYS = frozenset({"class", "gpu"})
_GPU_KEYS = frozenset(
    {"cc_mode", "vbios_measurement", "attestation_report_digest", "bound_measurement"}
)


class ComputeReceiptError(ValueError):
    """Raised when a compute receipt is malformed or fails verification. Fails closed."""


# A GPU attestation verifier confirms the GPU report is genuine and in CC mode.
# Injected (hardware-free tests pass a stub); production swaps in the real check.
GpuAttestationVerifier = Callable[[Mapping[str, Any]], bool]


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
        if dr.MEASUREMENT_RE.match(str(gpu["bound_measurement"])) is None:
            raise ComputeReceiptError(
                "platform.gpu.bound_measurement must be tdx-measurement-sha256:<64 hex>"
            )
        if gpu["cc_mode"] != "on":
            raise ComputeReceiptError("platform.gpu.cc_mode must be 'on'")
    else:
        raise ComputeReceiptError("platform.class must be intel_tdx_cpu or confidential_gpu")
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

        # Shared TDX attestation body — identical rules to the Distill receipt.
        if not dr.MEASUREMENT_RE.match(str(doc["measurement"])):
            raise ComputeReceiptError("measurement must be tdx-measurement-sha256:<64 hex>")
        dr.validate_tcb(doc["tcb"])
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

        _validate_platform(doc)
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
    allowed_measurements: frozenset[str] | set[str] | None = None,
    allowed_tcb_statuses: frozenset[str] | set[str] | None = None,
    allowed_advisories: frozenset[str] | set[str] | None = None,
) -> Mapping[str, Any]:
    """Independently verify a compute receipt before scoring. Fails closed.

    Order: structure, receipt_id, key resolution (anchored registry, never a
    caller-supplied key), signature, policy gating, replay/epoch binding,
    lifecycle, freshness, and — for a GPU receipt — the composite GPU attestation
    (CC mode, binding to this TDX quote, and the injected verifier).
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

        # 8. GPU composite: the GPU evidence must bind to THIS TDX quote and be
        # confirmed by the injected verifier. GPU alone never admits.
        if doc["platform"]["class"] == PLATFORM_GPU:
            gpu = doc["platform"]["gpu"]
            if gpu["bound_measurement"] != doc["measurement"]:
                raise ComputeReceiptError(
                    "GPU attestation is not bound to this receipt's TDX measurement"
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


__all__ = [
    "ComputeReceiptError", "RECEIPT_SCHEMA", "PLATFORM_CPU", "PLATFORM_GPU",
    "validate_structure", "verify_receipt", "build_receipt", "lane_contribution",
    "platform_class", "canonical_bytes", "compute_receipt_id",
]
