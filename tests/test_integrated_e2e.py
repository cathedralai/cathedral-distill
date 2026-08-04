"""Cross-repo end-to-end: Compute CPU + Compute GPU + Distill -> one vector.

Issue cathedral-validator#1, Req 7 ("proof is end to end") and Req 8 ("operators
can audit it"). One CPU compute receipt, one GPU compute receipt, and one Distill
receipt go from submission through independent verification, lane score, a
Cathedral-signed burn + allocation config, safe composition, the signed feed, and
final weight — with an audit trail tying every step. The same run exercises the
PASS / FAIL / NOT_PROVEN matrix for CPU, GPU, Distill, remote burn, and remote
allocation.

Hardware-free: the GPU attestation and (in production) the TDX quote verifier are
injected; every crypto discipline — anchored keys, canonical bytes, receipt_id,
Ed25519, replay/epoch binding, freshness, TCB — is real.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import distill_receipt as dr  # noqa: E402
from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill import signed_config as sc  # noqa: E402
from cathedral_distill.receipt_keys import ReceiptKeyRegistry  # noqa: E402
from cathedral_distill.testing import IntegrationFixtures  # noqa: E402

# One deterministic key anchors receipts and configs by id (hardware-free path).
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUB = KEY.public_key().public_bytes_raw()
KEYREG = ReceiptKeyRegistry.from_keys(
    {"compute-1": PUB, "distill-1": PUB, "config-1": PUB}
)

NOW_ISO = "2026-07-25T12:30:00.000000Z"
NOW_DT = datetime(2026, 7, 25, 12, 30, tzinfo=UTC)
SOURCE_EPOCH = 11
MEASUREMENT = "tdx-measurement-sha256:" + "ab" * 32

LANE_CPU = "cathedral_confidential_tdx"
LANE_GPU = "cathedral_confidential_gpu"
LANE_DISTILL = "cathedral_distill"
FIXTURES = IntegrationFixtures(source_epoch=SOURCE_EPOCH)


def _dg(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Receipt builders (each a real signed receipt)
# --------------------------------------------------------------------------- #

def cpu_receipt(subject="5CpuMiner", work_units="30"):
    return FIXTURES.cpu_receipt(subject=subject, work_units=work_units)


def gpu_receipt(subject="5GpuMiner", work_units="20", bound=MEASUREMENT):
    return FIXTURES.gpu_receipt(
        subject=subject,
        work_units=work_units,
        bound=bound,
        cpu_tee="intel_tdx",
    )


def distill_receipt(subject="5DistillMiner", passed=28, graded=32):
    body = {
        "schema": dr.RECEIPT_SCHEMA, "subject_hotkey": subject, "epoch_id": 7,
        "source_epoch": SOURCE_EPOCH, "issued_at": "2026-07-25T12:00:00.000000Z",
        "platform_pseudonym": "platform-" + _dg("eval"), "measurement": MEASUREMENT,
        "policy_registry_release": 1, "policy_registry_digest": _dg("policy"),
        "policy_profile_ids": ["distill-v1"],
        "tcb": {"status": "UpToDate", "version": 3, "svn": "0" * 32,
                "advisory_ids": [], "debug_enabled": False, "collateral_current": True},
        "channel": {"status": "passed", "binding_digest": _dg("chan")},
        "work": {"challenge_id": "d-11", "manifest_digest": _dg("m"),
                 "result_digest": _dg("r"), "status": "passed", "work_units": str(passed)},
        "assurance": {"schema": dr.ASSURANCE_SCHEMA, "claims": {
            "channel": {"status": "passed"}, "hardware": {"status": "passed"},
            "software": {"status": "passed"}, "work": {"status": "passed"}}},
        "lifecycle": {"state": "issued", "revocation_reference": None,
                      "worker_evidence_expires_at": "2026-07-26T12:00:00.000000Z"},
        "evaluation": {"schema": dr.EVALUATION_SCHEMA, "model_digest": _dg("model"),
                       "tokenizer_digest": _dg("tok"), "evalset_digest": _dg("evalset"),
                       "evaluator_digest": _dg("evaluator"), "runtime_digest": _dg("runtime"),
                       "score": str((Decimal(passed) / Decimal(graded)).quantize(Decimal("0.000000000001"))),
                       "graded_items": graded, "passed_items": passed,
                       "evidence_digest": _dg("evidence")},
    }
    return dr.build_receipt(body, KEY, signing_key_id="distill-1")


# --------------------------------------------------------------------------- #
# Signed config builders
# --------------------------------------------------------------------------- #

def _config_envelope(schema, version):
    return {"schema": schema, "config_version": version, "network": "finney", "netuid": 39,
            "generated_at": "2026-07-25T12:00:00Z", "valid_from": "2026-07-25T00:00:00Z",
            "valid_until": "2026-08-01T00:00:00Z", "signing_key_id": "config-1"}


def burn_config(fraction="0.10", burn_hotkey="5Burn", version=1):
    doc = _config_envelope(sc.BURN_CONFIG_SCHEMA, version)
    doc["burn"] = {"fraction": fraction, "burn_hotkey": burn_hotkey}
    return json.dumps(sc.sign_config(doc, KEY.private_bytes_raw())).encode()


def allocation_config(allocations, version=1):
    doc = _config_envelope(sc.ALLOCATION_CONFIG_SCHEMA, version)
    doc["allocations"] = allocations
    return json.dumps(sc.sign_config(doc, KEY.private_bytes_raw())).encode()


def _resolve(burn_bytes, alloc_bytes):
    burn = sc.verify_burn_config(burn_bytes, KEYREG, network="finney", netuid=39, now=NOW_DT)
    alloc = sc.verify_allocation_config(alloc_bytes, KEYREG, network="finney", netuid=39, now=NOW_DT)
    return sc.resolve_allocation(burn, alloc)


# CPU 0.30 + GPU 0.20 + Distill 0.40 + burn 0.10 == 1.0
_ALLOCATIONS = [
    {"lane": LANE_CPU, "allocation": "0.30", "enabled": True},
    {"lane": LANE_GPU, "allocation": "0.20", "enabled": True},
    {"lane": LANE_DISTILL, "allocation": "0.40", "enabled": True},
]


def _accept_gpu(_gpu):
    return True


def _verify_all(*, gpu_verifier=_accept_gpu, distill=None):
    return [
        itf.verify_lane_receipt(itf.KIND_COMPUTE_CPU, cpu_receipt(), lane=LANE_CPU,
                                key_registry=KEYREG, source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO,
                                consumption_ledger=itf.NO_REPLAY_LEDGER),
        itf.verify_lane_receipt(itf.KIND_COMPUTE_GPU, gpu_receipt(), lane=LANE_GPU,
                                key_registry=KEYREG, source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO,
                                gpu_attestation_verifier=gpu_verifier,
                                consumption_ledger=itf.NO_REPLAY_LEDGER),
        itf.verify_lane_receipt(itf.KIND_DISTILL, distill or distill_receipt(), lane=LANE_DISTILL,
                                key_registry=KEYREG, source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO,
                                consumption_ledger=itf.NO_REPLAY_LEDGER),
    ]


# --------------------------------------------------------------------------- #
# The end-to-end happy path
# --------------------------------------------------------------------------- #

def test_cpu_gpu_distill_compose_into_one_audited_vector():
    resolved = _resolve(burn_config(), allocation_config(_ALLOCATIONS))
    decisions = _verify_all()
    assert [d.verdict for d in decisions] == ["PASS", "PASS", "PASS"]

    out = itf.compose_integrated(resolved, decisions)
    feed, audit = out["feed"], out["audit"]

    # three lanes all contribute; all three miners are in the vector
    assert {w["miner_hotkey"] for w in feed["weights"]} == {"5CpuMiner", "5GpuMiner", "5DistillMiner"}
    assert sum(w["weight"] for w in feed["weights"]) == pytest.approx(1.0, abs=1e-9)
    # every lane contributes -> effective burn is exactly the configured 10%
    assert feed["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(10.0)
    assert audit["burn"]["effective_fraction"] == "0.10"

    # Pre-burn rows normalize to 1.0 among earners, so each miner's pre-burn
    # weight is allocation / Σ(contributing allocations) = allocation / 0.90.
    w = {r["miner_hotkey"]: r["weight"] for r in feed["weights"]}
    assert w["5CpuMiner"] == pytest.approx(0.30 / 0.90, abs=1e-6)
    assert w["5GpuMiner"] == pytest.approx(0.20 / 0.90, abs=1e-6)
    assert w["5DistillMiner"] == pytest.approx(0.40 / 0.90, abs=1e-6)
    # ...and after the 10% burn is applied downstream, each miner's share of the
    # TOTAL emission is exactly its configured allocation.
    post_burn = 1.0 - feed["burn_snapshot"]["forced_burn_percentage"] / 100.0
    assert w["5CpuMiner"] * post_burn == pytest.approx(0.30, abs=1e-6)
    assert w["5GpuMiner"] * post_burn == pytest.approx(0.20, abs=1e-6)
    assert w["5DistillMiner"] * post_burn == pytest.approx(0.40, abs=1e-6)

    # audit chain: receipt -> verdict -> contribution -> allocation -> final weight
    assert audit["schema"] == itf.AUDIT_SCHEMA
    assert audit["config_versions"] == {"burn": 1, "allocation": 1}
    assert audit["verdicts"] == {"pass": 3, "fail": 0, "not_proven": 0}
    by_receipt = {r["kind"]: r for r in audit["receipts"]}
    assert by_receipt["compute_gpu"]["lane_allocation"] == "0.20"
    assert by_receipt["compute_gpu"]["final_weight"] == pytest.approx(0.20 / 0.90, abs=1e-6)
    assert by_receipt["distill"]["verdict"] == "PASS"


# --------------------------------------------------------------------------- #
# Req 6 through the whole pipeline: a NOT_PROVEN / FAIL lane -> burn, not others
# --------------------------------------------------------------------------- #

def test_gpu_not_proven_sends_its_share_to_burn_not_the_other_lanes():
    # No GPU attestation verifier -> the GPU lane is NOT_PROVEN and earns nothing;
    # its 0.20 must go to burn, and CPU/Distill keep exactly their 0.30/0.40.
    resolved = _resolve(burn_config(), allocation_config(_ALLOCATIONS))
    decisions = _verify_all(gpu_verifier=None)
    verdicts = {d.kind: d.verdict for d in decisions}
    assert verdicts["compute_gpu"] == "NOT_PROVEN"

    out = itf.compose_integrated(resolved, decisions)
    feed, audit = out["feed"], out["audit"]
    assert {w["miner_hotkey"] for w in feed["weights"]} == {"5CpuMiner", "5DistillMiner"}
    # burn = base 0.10 + orphaned GPU 0.20 = 0.30
    assert feed["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(30.0)
    assert audit["burn"]["effective_fraction"] == "0.30"
    # CPU and Distill keep their configured shares (0.30 / 0.40 -> normalized 0.4285/0.5714)
    w = {r["miner_hotkey"]: r["weight"] for r in feed["weights"]}
    assert w["5CpuMiner"] == pytest.approx(0.30 / 0.70, abs=1e-6)
    assert w["5DistillMiner"] == pytest.approx(0.40 / 0.70, abs=1e-6)
    gpu_lane = next(ln for ln in audit["lanes"] if ln["lane"] == LANE_GPU)
    assert gpu_lane["contributing"] is False and gpu_lane["burned_allocation"] == "0.20"


def test_tampered_distill_receipt_fails_and_burns_its_lane():
    resolved = _resolve(burn_config(), allocation_config(_ALLOCATIONS))
    tampered = distill_receipt()
    tampered["work"]["work_units"] = "999"  # break the signature/receipt_id
    decisions = _verify_all(distill=tampered)
    verdicts = {d.kind: d.verdict for d in decisions}
    assert verdicts["distill"] == "FAIL"

    out = itf.compose_integrated(resolved, decisions)
    feed = out["feed"]
    assert "5DistillMiner" not in {w["miner_hotkey"] for w in feed["weights"]}
    # Distill's 0.40 -> burn: 0.10 + 0.40 = 0.50
    assert feed["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(50.0)


# --------------------------------------------------------------------------- #
# Remote config PASS/FAIL rows for the matrix
# --------------------------------------------------------------------------- #

def test_remote_burn_config_rollback_is_refused_end_to_end():
    # a validator that has applied version 5 refuses a signed version-3 burn config
    with pytest.raises(sc.SignedConfigError, match="rollback"):
        sc.verify_burn_config(burn_config(version=3), KEYREG, network="finney", netuid=39,
                              now=NOW_DT, min_version=5)


def test_remote_allocation_change_takes_effect_without_redeploy():
    # A new signed allocation (GPU share raised) changes the split with no code change.
    changed = [
        {"lane": LANE_CPU, "allocation": "0.20", "enabled": True},
        {"lane": LANE_GPU, "allocation": "0.40", "enabled": True},
        {"lane": LANE_DISTILL, "allocation": "0.30", "enabled": True},
    ]
    resolved = _resolve(burn_config(fraction="0.10"), allocation_config(changed, version=2))
    out = itf.compose_integrated(resolved, _verify_all())
    feed = out["feed"]
    w = {r["miner_hotkey"]: r["weight"] for r in feed["weights"]}
    post_burn = 1.0 - feed["burn_snapshot"]["forced_burn_percentage"] / 100.0
    # GPU's share of total emission is now 0.40 (was 0.20 before) — no code change.
    assert w["5GpuMiner"] * post_burn == pytest.approx(0.40, abs=1e-6)
    assert out["audit"]["config_versions"]["allocation"] == 2


def test_cpu_quote_verifier_threads_through_the_pipeline():
    # an injected CPU quote verifier that rejects turns the compute-CPU lane to FAIL
    d = itf.verify_lane_receipt(
        itf.KIND_COMPUTE_CPU, cpu_receipt(), lane=LANE_CPU, key_registry=KEYREG,
        source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO, cpu_quote_verifier=lambda _e: False,
        consumption_ledger=itf.NO_REPLAY_LEDGER)
    assert d.verdict == "FAIL" and "CPU-TEE quote" in d.detail
    # and admits when it passes
    d2 = itf.verify_lane_receipt(
        itf.KIND_COMPUTE_CPU, cpu_receipt(), lane=LANE_CPU, key_registry=KEYREG,
        source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO, cpu_quote_verifier=lambda _e: True,
        consumption_ledger=itf.NO_REPLAY_LEDGER)
    assert d2.verdict == "PASS"


def test_decision_for_an_unconfigured_lane_earns_nothing_without_aborting():
    """An unknown lane is refused *for that decision only*.

    It used to raise, which meant one mislabelled decision destroyed the whole
    epoch's vector: every lane, every miner. The unknown lane now simply earns
    nothing (its would-be share stays in burn) and the audit says why, while the
    legitimate contributions in the same composition still compose.
    """
    resolved = _resolve(burn_config(), allocation_config(_ALLOCATIONS))
    good = itf.ReceiptDecision(LANE_DISTILL, itf.KIND_DISTILL,
                               "receipt-sha256:" + "1" * 64, "5Good", itf.PASS, Decimal("4"))
    rogue = itf.ReceiptDecision("cathedral_unknown_lane", itf.KIND_DISTILL,
                                "receipt-sha256:" + "0" * 64, "5X", itf.PASS, Decimal("1"))
    composed = itf.compose_integrated(resolved, [good, rogue])
    by_id = {r["receipt_id"]: r for r in composed["audit"]["receipts"]}
    assert by_id[rogue.receipt_id]["credited"] is False
    assert "not in the allocation config" in by_id[rogue.receipt_id]["drop_reason"]
    assert by_id[rogue.receipt_id]["final_weight"] == 0.0
    assert by_id[good.receipt_id]["credited"] is True
    assert "5X" not in {w["miner_hotkey"] for w in composed["feed"]["weights"]}
    assert "5Good" in {w["miner_hotkey"] for w in composed["feed"]["weights"]}
