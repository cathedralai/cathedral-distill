"""Compute lane receipts — `cathedral_assurance_receipt_v2` CPU + GPU composite.

Proves (issue cathedral-validator#1, Req 1 & 3) that the validator independently
verifies both an Intel TDX CPU receipt and a confidential-GPU composite receipt
through the same evidence discipline as Distill, and that a GPU attestation only
admits when bound to a valid TDX CPU quote (GPU alone never admits).
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import compute_receipt as cr  # noqa: E402
from cathedral_distill.receipt_keys import ReceiptKeyRegistry  # noqa: E402

_SEED = bytes(range(32))
KEY = Ed25519PrivateKey.from_private_bytes(_SEED)
KEYREG = ReceiptKeyRegistry.from_keys({"compute-test-1": KEY.public_key().public_bytes_raw()})
NOW = "2026-07-17T12:30:00.000000Z"
SOURCE_EPOCH = 11
MEASUREMENT = "tdx-measurement-sha256:" + "ab" * 32


def _digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _body(*, subject="5ComputeMiner", work_units="42", platform=None):
    body = {
        "schema": cr.RECEIPT_SCHEMA,
        "subject_hotkey": subject,
        "epoch_id": 7,
        "source_epoch": SOURCE_EPOCH,
        "issued_at": "2026-07-17T12:00:00.000000Z",
        "platform_pseudonym": "platform-" + _digest("cpu-machine"),
        "measurement": MEASUREMENT,
        "policy_registry_release": 1,
        "policy_registry_digest": _digest("policy-registry"),
        "policy_profile_ids": ["cpu-tdx-compute-v1"],
        "tcb": {
            "status": "UpToDate", "version": 3, "svn": "0" * 32,
            "advisory_ids": [], "debug_enabled": False, "collateral_current": True,
        },
        "channel": {"status": "passed", "binding_digest": _digest("channel")},
        "work": {
            "challenge_id": "compute-epoch-11",
            "manifest_digest": _digest("manifest"),
            "result_digest": _digest("result"),
            "status": "passed",
            "work_units": work_units,
        },
        "assurance": {
            "schema": cr.ASSURANCE_SCHEMA,
            "claims": {
                "channel": {"status": "passed"},
                "hardware": {"status": "passed"},
                "software": {"status": "passed"},
                "work": {"status": "passed"},
            },
        },
        "lifecycle": {
            "state": "issued",
            "revocation_reference": None,
            "worker_evidence_expires_at": "2026-07-18T12:00:00.000000Z",
        },
        "platform": platform or {"class": cr.PLATFORM_CPU},
    }
    return body


def _gpu_platform(*, bound=MEASUREMENT, cc_mode="on"):
    return {
        "class": cr.PLATFORM_GPU,
        "gpu": {
            "cc_mode": cc_mode,
            "vbios_measurement": _digest("vbios"),
            "attestation_report_digest": _digest("gpu-report"),
            "bound_measurement": bound,
        },
    }


def _cpu_receipt(**kw):
    return cr.build_receipt(_body(**kw), KEY, signing_key_id="compute-test-1")


def _gpu_receipt(*, bound=MEASUREMENT, cc_mode="on", **kw):
    return cr.build_receipt(_body(platform=_gpu_platform(bound=bound, cc_mode=cc_mode), **kw),
                            KEY, signing_key_id="compute-test-1")


def _accept_gpu(_gpu):  # a stub GPU attestation verifier that admits
    return True


# --------------------------------------------------------------------------- #
# CPU — the shared TDX body
# --------------------------------------------------------------------------- #

def test_cpu_receipt_verifies_and_yields_a_contribution():
    receipt = _cpu_receipt()
    doc = cr.verify_receipt(receipt, KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH)
    assert cr.platform_class(doc) == cr.PLATFORM_CPU
    contribution = cr.lane_contribution(doc)
    assert contribution == {
        "miner_hotkey": "5ComputeMiner",
        "receipt_id": doc["receipt_id"],
        "work_units": "42",
    }


def test_cpu_receipt_shares_the_distill_tcb_rules():
    # debug-enabled / revoked / stale-collateral TCB is rejected identically to Distill
    for mutate, msg in [
        (lambda b: b["tcb"].__setitem__("debug_enabled", True), "debug_enabled must be false"),
        (lambda b: b["tcb"].__setitem__("status", "Revoked"), "Revoked"),
        (lambda b: b["tcb"].__setitem__("collateral_current", False), "collateral_current must be true"),
    ]:
        body = _body()
        mutate(body)
        receipt = cr.build_receipt(body, KEY, signing_key_id="compute-test-1")
        with pytest.raises(cr.ComputeReceiptError, match=msg):
            cr.verify_receipt(receipt, KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH)


# --------------------------------------------------------------------------- #
# GPU — composite TDX + confidential GPU
# --------------------------------------------------------------------------- #

def test_gpu_composite_verifies_with_bound_measurement_and_verifier():
    receipt = _gpu_receipt()
    doc = cr.verify_receipt(receipt, KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH,
                            gpu_attestation_verifier=_accept_gpu)
    assert cr.platform_class(doc) == cr.PLATFORM_GPU
    assert cr.lane_contribution(doc)["miner_hotkey"] == "5ComputeMiner"


def test_gpu_without_a_verifier_is_refused():
    receipt = _gpu_receipt()
    with pytest.raises(cr.ComputeReceiptError, match="requires a GPU attestation verifier"):
        cr.verify_receipt(receipt, KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH)


def test_gpu_verifier_rejection_is_refused():
    receipt = _gpu_receipt()
    with pytest.raises(cr.ComputeReceiptError, match="GPU attestation did not verify"):
        cr.verify_receipt(receipt, KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH,
                          gpu_attestation_verifier=lambda _g: False)


def test_gpu_unbound_from_the_tdx_quote_never_admits():
    # GPU evidence that is not bound to THIS receipt's TDX measurement is refused
    # even with a passing verifier — "GPU alone never admits".
    receipt = _gpu_receipt(bound="tdx-measurement-sha256:" + "cd" * 32)
    with pytest.raises(cr.ComputeReceiptError, match="not bound to this receipt's TDX measurement"):
        cr.verify_receipt(receipt, KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH,
                          gpu_attestation_verifier=_accept_gpu)


def test_gpu_cc_mode_off_is_structurally_rejected():
    receipt = _gpu_receipt(cc_mode="off")
    with pytest.raises(cr.ComputeReceiptError, match="cc_mode must be 'on'"):
        cr.verify_receipt(receipt, KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH,
                          gpu_attestation_verifier=_accept_gpu)


# --------------------------------------------------------------------------- #
# Shared verification gates (replay, freshness, signature, structure)
# --------------------------------------------------------------------------- #

def test_wrong_source_epoch_is_refused():
    with pytest.raises(cr.ComputeReceiptError, match="source_epoch"):
        cr.verify_receipt(_cpu_receipt(), KEYREG, now_iso=NOW, source_epoch=99)


def test_expired_evidence_is_refused():
    late = "2026-07-19T12:00:00.000000Z"  # after worker_evidence_expires_at
    with pytest.raises(cr.ComputeReceiptError, match="expired"):
        cr.verify_receipt(_cpu_receipt(), KEYREG, now_iso=late, source_epoch=SOURCE_EPOCH)


def test_tampered_work_units_breaks_signature():
    receipt = _cpu_receipt()
    receipt["work"]["work_units"] = "999999"  # tamper after signing
    with pytest.raises(cr.ComputeReceiptError, match="receipt_id|signature"):
        cr.verify_receipt(receipt, KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH)


def test_unknown_signing_key_is_refused():
    body = _body()
    receipt = cr.build_receipt(body, KEY, signing_key_id="compute-test-1")
    empty = ReceiptKeyRegistry.from_keys({})
    with pytest.raises(cr.ComputeReceiptError, match="signing key could not be resolved"):
        cr.verify_receipt(receipt, empty, now_iso=NOW, source_epoch=SOURCE_EPOCH)


def test_policy_gating_admits_listed_measurement():
    cr.verify_receipt(_cpu_receipt(), KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH,
                      allowed_measurements={MEASUREMENT}, allowed_tcb_statuses={"UpToDate"},
                      allowed_advisories=set())


def test_policy_gating_refuses_unlisted_measurement():
    with pytest.raises(cr.ComputeReceiptError, match="measurement is not admitted"):
        cr.verify_receipt(_cpu_receipt(), KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH,
                          allowed_measurements={"tdx-measurement-sha256:" + "00" * 32})


def test_unverified_work_claim_is_refused():
    body = _body()
    body["assurance"]["claims"]["work"]["status"] = "unknown"
    receipt = cr.build_receipt(body, KEY, signing_key_id="compute-test-1")
    with pytest.raises(cr.ComputeReceiptError, match="work claim must be passed"):
        cr.verify_receipt(receipt, KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH)
