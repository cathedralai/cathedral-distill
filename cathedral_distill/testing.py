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
from datetime import UTC, datetime
from decimal import Decimal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill import compute_receipt as _compute
from cathedral_distill import compute_work_evidence as _compute_work_evidence
from cathedral_distill import cybergym as _cybergym
from cathedral_distill import cybergym_batch as _cybergym_batch
from cathedral_distill import cybergym_receipt as _cybergym_receipt
from cathedral_distill import cybergym_verifier as _cybergym_verifier
from cathedral_distill import distill_receipt as _distill
from cathedral_distill import signed_config as _config
from cathedral_distill.receipt_keys import ReceiptKeyRegistry

_SCORE_Q = Decimal("0.000000000001")


def digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


class _ComputeReceiptFixture(dict):
    """A normal receipt mapping paired with its explicit test transport sidecar."""

    def __init__(self, receipt: dict, work_evidence: dict[str, str]) -> None:
        super().__init__(receipt)
        self.work_evidence = work_evidence


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
            {
                "compute-1": pub,
                "distill-1": pub,
                "config-1": pub,
                "cybergym-1": pub,
            }
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

    @staticmethod
    def _work_artifacts(subject: str, variation: str) -> tuple[str, bytes, bytes]:
        """Build bounded, canonical customer SAT artifacts worth exactly 20 units.

        ``variation`` makes fixture receipts distinct without teaching tests that
        arbitrary signer-selected unit counts are valid.  The result's raw units
        remain a deliberately absurd miner claim to prove the replayer ignores it.
        """
        seed = int.from_bytes(
            hashlib.sha256(f"{subject}\0{variation}".encode()).digest()[:8], "big"
        ) & ((1 << 63) - 1)
        instance = {"n_vars": 3, "clauses": [[1, 2], [-1, 3], [-2, 3]]}
        challenge_id = hashlib.sha256(
            json.dumps(
                {"n_vars": instance["n_vars"], "clauses": instance["clauses"], "seed": seed},
                sort_keys=True,
            ).encode()
        ).hexdigest()
        work_item = json.dumps(
            {
                "schema": "cathedral_sat_manifest_v1",
                "challenge_id": challenge_id,
                "seed": seed,
                "instance": instance,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        result = json.dumps(
            {
                "assigned_hotkey": subject,
                "assignment": [1, 2, 3],
                "challenge_id": challenge_id,
                "satisfiable": True,
                "work_units": 1e300,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        return challenge_id, work_item, result

    def _compute_receipt_with_evidence(
        self,
        subject: str,
        variation: str,
        platform: dict,
        cpu_tee: str,
        *,
        claimed_work_units: str = "20",
    ) -> _ComputeReceiptFixture:
        challenge_id, work_item, result = self._work_artifacts(subject, variation)
        body = self._compute_body(subject, claimed_work_units, platform, cpu_tee)
        body["work"] = {
            "challenge_id": challenge_id,
            "manifest_digest": "sha256:" + hashlib.sha256(work_item).hexdigest(),
            "result_digest": "sha256:" + hashlib.sha256(result).hexdigest(),
            "status": "passed",
            "work_units": claimed_work_units,
        }
        receipt = _compute.build_receipt(body, self.key, signing_key_id="compute-1")
        return _ComputeReceiptFixture(
            receipt,
            _compute_work_evidence.build_work_evidence(receipt, work_item, result),
        )

    @staticmethod
    def attach_compute_work_evidence(
        receipt: dict, source: _ComputeReceiptFixture
    ) -> _ComputeReceiptFixture:
        """Attach the same digest-bound artifacts to a re-signed fixture receipt.

        Tests that alter non-work claims (for example a TCB advisory) re-sign a
        receipt over the same immutable work.  The evidence remains valid only
        after rebinding its explicit transport receipt id to that new receipt.
        """
        evidence = dict(source.work_evidence)
        evidence["receipt_id"] = receipt["receipt_id"]
        return _ComputeReceiptFixture(receipt, evidence)

    def cpu_receipt(self, subject: str = "5CpuMiner", work_units: str = "30",
                    cpu_tee: str = _compute.CPU_TEE_TDX) -> dict:
        platform = {"class": _compute.PLATFORM_CPU, "cpu_tee": cpu_tee}
        return self._compute_receipt_with_evidence(
            subject, str(work_units), platform, cpu_tee
        )

    def cpu_receipt_with_claimed_work_units(
        self,
        subject: str,
        claimed_work_units: str,
        *,
        cpu_tee: str = _compute.CPU_TEE_TDX,
    ) -> _ComputeReceiptFixture:
        """Build a signed but non-creditable claim for replay-gate tests."""
        platform = {"class": _compute.PLATFORM_CPU, "cpu_tee": cpu_tee}
        return self._compute_receipt_with_evidence(
            subject,
            f"claimed-units:{claimed_work_units}",
            platform,
            cpu_tee,
            claimed_work_units=claimed_work_units,
        )

    def gpu_receipt(self, subject: str = "5GpuMiner", work_units: str = "20",
                    bound: str | None = None, cc_mode: str = "on",
                    cpu_tee: str = _compute.CPU_TEE_SEV) -> dict:
        # Defaults to the real Cathedral G4 shape: AMD SEV-SNP guest + NVIDIA CC GPU.
        platform = {"class": _compute.PLATFORM_GPU, "cpu_tee": cpu_tee, "gpu": {
            "cc_mode": cc_mode, "vbios_measurement": digest("vbios"),
            "attestation_report_digest": digest("gpu-report"),
            "bound_measurement": bound or self.measurement_for(cpu_tee)}}
        return self._compute_receipt_with_evidence(
            subject, str(work_units), platform, cpu_tee
        )

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

    # -- CyberGym (cathedral_cybergym_receipt_v1) -------------------------- #
    def cybergym_receipt(
        self,
        subject: str = "5CyberMiner",
        *,
        source_epoch: int | None = None,
        valid_from_block: int = 100,
        valid_until_block: int = 460,
    ) -> dict:
        """Build a real signed CyberGym contract fixture over deterministic tasks.

        Two of the three tasks reproduce only on the vulnerable side, deriving 12
        work units through the production scorer. This is hardware-free test data,
        not a claim about a real corpus or TDX execution.
        """
        epoch = self.source_epoch if source_epoch is None else int(source_epoch)
        disclosed = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
        cutoff = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
        tasks = [
            _cybergym_batch.PooledTask(
                task_id=f"arvo:{number}",
                level=_cybergym.Level(level),
                binary_digest=digest(f"bin-{number}"),
                disclosed_at=disclosed,
                admitted=True,   # a controlled synthetic fixture: admission is not what these exercise
            )
            for number, level in enumerate((0, 1, 2), start=1)
        ]
        nonce = _cybergym_batch.derive_batch_nonce(
            block=valid_from_block,
            block_hash="0x" + "cd" * 32,
            network=self.network,
            netuid=self.netuid,
            source_epoch=epoch,
            miner_hotkey=subject,
            model_commitment=digest("ckpt"),
        )
        batch = _cybergym_batch.draw_batch(
            _cybergym_batch.TaskPool(tasks),
            size=3,
            nonce=nonce,
            as_of=disclosed,
            cutoff=cutoff,
        )
        submissions = [
            _cybergym.PoCSubmission(
                task_id=task.task_id,
                poc_sha256=_cybergym_receipt.holdout_digest([task.task_id]),
                result=_cybergym_verifier.verify_poc(
                    task,
                    b"poc-" + task.task_id.encode(),
                    lambda task_id, _poc, mode: (
                        1
                        if task_id in {"arvo:1", "arvo:2"} and mode == "vul"
                        else 0
                    ),
                ),
            )
            for task in batch.tasks
        ]
        score = _cybergym.score_batch(
            batch.batch_id, list(batch.tasks), submissions
        )
        return _cybergym_receipt.build_receipt(
            score,
            network=self.network,
            netuid=self.netuid,
            source_epoch=epoch,
            validator_hotkey="5Validator",
            miner_hotkey=subject,
            nonce=nonce,
            holdout_digest_value=_cybergym_receipt.holdout_digest(
                list(batch.task_ids)
            ),
            valid_from_block=valid_from_block,
            valid_until_block=valid_until_block,
            issued_at="2026-07-27T12:00:00.000000Z",
            private_key=self.key,
            signing_key_id="cybergym-1",
        )

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
