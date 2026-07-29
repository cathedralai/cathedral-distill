"""Deterministic, hardware-free builders for the shared integration contract.

These are fixtures, not production code: a single deterministic key anchors every
receipt and config by id, so both this repo's tests and the validator's
integration tests build identical Compute (CPU/GPU), Distill, burn, and allocation
artifacts without duplicating the receipt grammar. Real signatures, real canonical
bytes — only the TDX/GPU quote check is injected.

    from cathedral_distill.testing import IntegrationFixtures
    fx = IntegrationFixtures()
    cpu = fx.cpu_receipt(); gpu = fx.gpu_receipt(); distill = fx.distill_receipt()
    burn = fx.burn_config(); alloc = fx.allocation_config([...])
    fx.registry  # a ReceiptKeyRegistry that resolves every id above
"""
from __future__ import annotations

import hashlib
import json
from decimal import Decimal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill import compute_receipt as _compute
from cathedral_distill import distill_receipt as _distill
from cathedral_distill import signed_config as _config
from cathedral_distill.receipt_keys import ReceiptKeyRegistry

_SCORE_Q = Decimal("0.000000000001")


def digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


class IntegrationFixtures:
    """Builds signed receipts and configs anchored to one deterministic key."""

    def __init__(
        self,
        *,
        seed: bytes = bytes(range(32)),
        network: str = "finney",
        netuid: int = 39,
        source_epoch: int = 11,
        measurement: str | None = None,
        issued_at: str = "2026-07-25T12:00:00.000000Z",
        evidence_expires_at: str = "2026-07-26T12:00:00.000000Z",
        config_generated_at: str = "2026-07-25T12:00:00Z",
        config_valid_from: str = "2026-07-25T00:00:00Z",
        config_valid_until: str = "2026-08-01T00:00:00Z",
    ) -> None:
        self.key = Ed25519PrivateKey.from_private_bytes(seed)
        pub = self.key.public_key().public_bytes_raw()
        self.network = network
        self.netuid = netuid
        self.source_epoch = source_epoch
        # Per-TEE measurements. `measurement` overrides the TDX one for callers
        # that pin it; the SEV measurement is the 48-byte (96-hex) launch digest.
        self.measurement = measurement or ("tdx-measurement-sha256:" + "ab" * 32)
        self.tdx_measurement = self.measurement
        self.sev_measurement = "sev-snp-measurement-sha384:" + "cd" * 48
        self.issued_at = issued_at
        self.evidence_expires_at = evidence_expires_at
        self._cfg_gen = config_generated_at
        self._cfg_from = config_valid_from
        self._cfg_until = config_valid_until
        # one registry resolves every receipt/config signing id to the same key
        self.registry = ReceiptKeyRegistry.from_keys(
            {"compute-1": pub, "distill-1": pub, "config-1": pub}
        )

    # -- Compute (cathedral_assurance_receipt_v2) ---------------------------- #
    def _tcb_for(self, cpu_tee: str) -> dict:
        if cpu_tee == _compute.CPU_TEE_SEV:
            return {"tee_type": "sev_snp", "policy_debug_disabled": True,
                    "boot_loader_svn": 3, "tee_svn": 0, "snp_svn": 8,
                    "microcode_svn": 72, "reported_tcb": "0" * 16, "collateral_current": True}
        return {"status": "UpToDate", "version": 3, "svn": "0" * 32,
                "advisory_ids": [], "debug_enabled": False, "collateral_current": True}

    def measurement_for(self, cpu_tee: str) -> str:
        return self.sev_measurement if cpu_tee == _compute.CPU_TEE_SEV else self.tdx_measurement

    def _compute_body(self, subject: str, work_units: str, platform: dict, cpu_tee: str) -> dict:
        return {
            "schema": _compute.RECEIPT_SCHEMA, "subject_hotkey": subject, "epoch_id": 7,
            "source_epoch": self.source_epoch, "issued_at": self.issued_at,
            "platform_pseudonym": "platform-" + digest(subject),
            "measurement": self.measurement_for(cpu_tee), "policy_registry_release": 1,
            "policy_registry_digest": digest("policy"), "policy_profile_ids": ["compute-v1"],
            "tcb": self._tcb_for(cpu_tee),
            "channel": {"status": "passed", "binding_digest": digest("chan")},
            "work": {"challenge_id": "c-11", "manifest_digest": digest("m"),
                     "result_digest": digest("r"), "status": "passed", "work_units": work_units},
            "assurance": {"schema": _compute.ASSURANCE_SCHEMA, "claims": {
                "channel": {"status": "passed"}, "hardware": {"status": "passed"},
                "software": {"status": "passed"}, "work": {"status": "passed"}}},
            "lifecycle": {"state": "issued", "revocation_reference": None,
                          "worker_evidence_expires_at": self.evidence_expires_at},
            "platform": platform,
        }

    def cpu_receipt(self, subject: str = "5CpuMiner", work_units: str = "30",
                    cpu_tee: str = _compute.CPU_TEE_TDX) -> dict:
        platform = {"class": _compute.PLATFORM_CPU, "cpu_tee": cpu_tee}
        return _compute.build_receipt(
            self._compute_body(subject, work_units, platform, cpu_tee),
            self.key, signing_key_id="compute-1")

    def gpu_receipt(self, subject: str = "5GpuMiner", work_units: str = "20",
                    bound: str | None = None, cc_mode: str = "on",
                    cpu_tee: str = _compute.CPU_TEE_SEV) -> dict:
        # Defaults to the real Cathedral G4 shape: AMD SEV-SNP guest + NVIDIA CC GPU.
        platform = {"class": _compute.PLATFORM_GPU, "cpu_tee": cpu_tee, "gpu": {
            "cc_mode": cc_mode, "vbios_measurement": digest("vbios"),
            "attestation_report_digest": digest("gpu-report"),
            "bound_measurement": bound or self.measurement_for(cpu_tee)}}
        return _compute.build_receipt(
            self._compute_body(subject, work_units, platform, cpu_tee),
            self.key, signing_key_id="compute-1")

    # -- Distill (cathedral_distill_receipt_v1) ------------------------------ #
    def distill_receipt(self, subject: str = "5DistillMiner",
                        passed: int = 28, graded: int = 32) -> dict:
        score = str((Decimal(passed) / Decimal(graded)).quantize(_SCORE_Q))
        body = {
            "schema": _distill.RECEIPT_SCHEMA, "subject_hotkey": subject, "epoch_id": 7,
            "source_epoch": self.source_epoch, "issued_at": self.issued_at,
            "platform_pseudonym": "platform-" + digest("eval"), "measurement": self.measurement,
            "policy_registry_release": 1, "policy_registry_digest": digest("policy"),
            "policy_profile_ids": ["distill-v1"],
            "tcb": {"status": "UpToDate", "version": 3, "svn": "0" * 32,
                    "advisory_ids": [], "debug_enabled": False, "collateral_current": True},
            "channel": {"status": "passed", "binding_digest": digest("chan")},
            "work": {"challenge_id": "d-11", "manifest_digest": digest("m"),
                     "result_digest": digest("r"), "status": "passed", "work_units": str(passed)},
            "assurance": {"schema": _distill.ASSURANCE_SCHEMA, "claims": {
                "channel": {"status": "passed"}, "hardware": {"status": "passed"},
                "software": {"status": "passed"}, "work": {"status": "passed"}}},
            "lifecycle": {"state": "issued", "revocation_reference": None,
                          "worker_evidence_expires_at": self.evidence_expires_at},
            "evaluation": {"schema": _distill.EVALUATION_SCHEMA, "model_digest": digest("model"),
                           "tokenizer_digest": digest("tok"), "evalset_digest": digest("evalset"),
                           "evaluator_digest": digest("evaluator"), "runtime_digest": digest("runtime"),
                           "score": score, "graded_items": graded, "passed_items": passed,
                           "evidence_digest": digest("evidence")},
        }
        return _distill.build_receipt(body, self.key, signing_key_id="distill-1")

    # -- Signed config ------------------------------------------------------- #
    def _config_envelope(self, schema: str, version: int) -> dict:
        return {"schema": schema, "config_version": version, "network": self.network,
                "netuid": self.netuid, "generated_at": self._cfg_gen,
                "valid_from": self._cfg_from, "valid_until": self._cfg_until,
                "signing_key_id": "config-1"}

    def burn_config(self, fraction: str = "0.10", burn_hotkey: str = "5Burn",
                    version: int = 1) -> bytes:
        doc = self._config_envelope(_config.BURN_CONFIG_SCHEMA, version)
        doc["burn"] = {"fraction": fraction, "burn_hotkey": burn_hotkey}
        return json.dumps(_config.sign_config(doc, self.key.private_bytes_raw())).encode()

    def allocation_config(self, allocations: list[dict], version: int = 1) -> bytes:
        doc = self._config_envelope(_config.ALLOCATION_CONFIG_SCHEMA, version)
        doc["allocations"] = allocations
        return json.dumps(_config.sign_config(doc, self.key.private_bytes_raw())).encode()


__all__ = ["IntegrationFixtures", "digest"]
