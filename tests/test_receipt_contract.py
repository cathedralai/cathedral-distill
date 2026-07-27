"""The Distill validation + publishing contract (issue #3).

Proves the four "done when" conditions:
  - a concrete Distill receipt fixture exists (generated here, real signature),
  - its shared fields map to the compute receipt,
  - the shared feed carries one compute and one Distill contribution,
  - a validator independently verifies receipt_id, evidence, freshness, replay,
    and signature before scoring.

Running this regenerates the fixtures under tests/fixtures/, so they can never
drift from the code that produces them.
"""
from __future__ import annotations

import json
import sys
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import distill_receipt as dr  # noqa: E402
from cathedral_distill import lane_feed as lf  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
# Deterministic test signing key, so the fixture is reproducible.
_SEED = bytes(range(32))
KEY = Ed25519PrivateKey.from_private_bytes(_SEED)
PUB = KEY.public_key()

NOW = "2026-07-17T12:30:00.000000Z"
SOURCE_EPOCH = 11


def _digest(seed: str) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _receipt_body(*, subject="5Miner", score="0.875", work_units="28",
                  passed=28, graded=32):
    """A Distill receipt body — shared fields identical to the compute receipt,
    plus the one evaluation extension."""
    return {
        "schema": dr.RECEIPT_SCHEMA,
        "subject_hotkey": subject,
        "epoch_id": 7,
        "source_epoch": SOURCE_EPOCH,
        "issued_at": "2026-07-17T12:00:00.000000Z",
        "platform_pseudonym": "platform-" + _digest("evaluator-machine"),
        "measurement": "tdx-measurement-sha256:distill-evaluator-v1",
        "policy_registry_release": 1,
        "policy_registry_digest": _digest("policy-registry"),
        "policy_profile_ids": ["cpu-tdx-distill-v1"],
        "tcb": {
            "advisory_ids": [], "collateral_current": True, "debug_enabled": False,
            "status": "UpToDate", "svn": "01" * 16, "version": 1,
        },
        "channel": {"binding_digest": _digest("channel-binding"), "status": "passed"},
        "work": {
            "challenge_id": "e" * 64,
            "manifest_digest": _digest("eval-job-manifest"),
            "result_digest": _digest("eval-result-record"),
            "status": "passed",
            "work_units": work_units,
        },
        "assurance": {
            "schema": dr.ASSURANCE_SCHEMA,
            "claims": {
                name: {
                    "evidence_digest": _digest(f"{name}-evidence"),
                    "policy_digest": _digest(f"{name}-policy"),
                    "reason": None, "status": "passed",
                    "verified_at": "2026-07-17T12:00:00.000000Z",
                }
                for name in ("channel", "hardware", "software", "work")
            },
        },
        "lifecycle": {
            "state": "issued", "worker_state": "attested",
            "worker_generation": 1, "worker_revision": 2, "worker_event_id": 2,
            "worker_reason": "attestation_verified",
            "worker_evidence_expires_at": "2026-07-17T13:00:00.000000Z",
            "revocation_reference": None,
        },
        "evaluation": {
            "schema": dr.EVALUATION_SCHEMA,
            "model_digest": _digest("student-checkpoint-weights"),
            "tokenizer_digest": _digest("tokenizer"),
            "evalset_digest": _digest("sealed-eval-set-plaintext"),
            "evaluator_digest": _digest("grader-image-and-code"),
            "runtime_digest": _digest("decode-and-environment"),
            "score": score,
            "graded_items": graded,
            "passed_items": passed,
            "evidence_digest": _digest("full-evaluation-evidence-bundle"),
        },
    }


def _receipt(**kw):
    return dr.build_receipt(_receipt_body(**kw), KEY, signing_key_id="distill-test-1")


# --------------------------------------------------------------------------- #
# Receipt: shared fields, canonical bytes, receipt_id, signature
# --------------------------------------------------------------------------- #

def test_shared_fields_match_the_compute_receipt():
    """Every shared field name in the compute receipt is present in the Distill
    receipt with the same meaning — the mapping is exact, not parallel."""
    compute_shared = {
        "schema", "receipt_id", "signing_key_id", "signature", "subject_hotkey",
        "epoch_id", "source_epoch", "issued_at", "platform_pseudonym",
        "measurement", "tcb", "policy_registry_release", "policy_registry_digest",
        "policy_profile_ids", "channel", "work", "assurance", "lifecycle",
    }
    receipt = _receipt()
    assert compute_shared <= set(receipt)                 # all shared fields present
    assert set(receipt) - compute_shared == {"evaluation"}  # only extension added


def test_receipt_verifies_end_to_end():
    receipt = dr.verify_receipt(_receipt(), PUB, now_iso=NOW, source_epoch=SOURCE_EPOCH)
    assert receipt["work"]["status"] == "passed"


def test_receipt_id_recomputes():
    receipt = _receipt()
    assert receipt["receipt_id"] == dr.compute_receipt_id(receipt)


def test_tampering_breaks_the_receipt_id():
    receipt = _receipt()
    receipt["evaluation"]["score"] = "0.999"       # claim a better score
    with pytest.raises(dr.DistillReceiptError, match="receipt_id"):
        dr.verify_receipt(receipt, PUB, now_iso=NOW, source_epoch=SOURCE_EPOCH)


def test_tampering_after_fixing_id_breaks_the_signature():
    receipt = _receipt()
    receipt["evaluation"]["score"] = "0.999"
    receipt["receipt_id"] = dr.compute_receipt_id(receipt)  # relabel it
    with pytest.raises(dr.DistillReceiptError, match="signature"):
        dr.verify_receipt(receipt, PUB, now_iso=NOW, source_epoch=SOURCE_EPOCH)


def test_wrong_key_fails_signature():
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key()
    with pytest.raises(dr.DistillReceiptError, match="signature"):
        dr.verify_receipt(_receipt(), other, now_iso=NOW, source_epoch=SOURCE_EPOCH)


def test_replay_across_epochs_is_rejected():
    with pytest.raises(dr.DistillReceiptError, match="source_epoch"):
        dr.verify_receipt(_receipt(), PUB, now_iso=NOW, source_epoch=SOURCE_EPOCH + 1)


def test_stale_evidence_is_rejected():
    later = "2026-07-17T13:30:00.000000Z"  # past worker_evidence_expires_at
    with pytest.raises(dr.DistillReceiptError, match="expired"):
        dr.verify_receipt(_receipt(), PUB, now_iso=later, source_epoch=SOURCE_EPOCH)


def test_revoked_receipt_is_rejected():
    body = _receipt_body()
    body["lifecycle"]["revocation_reference"] = "revoked-key"
    receipt = dr.build_receipt(body, KEY, signing_key_id="distill-test-1")
    with pytest.raises(dr.DistillReceiptError, match="revocation"):
        dr.verify_receipt(receipt, PUB, now_iso=NOW, source_epoch=SOURCE_EPOCH)


def test_unknown_field_fails_closed():
    receipt = _receipt()
    receipt["surprise"] = 1
    with pytest.raises(dr.DistillReceiptError, match="unknown keys"):
        dr.verify_receipt(receipt, PUB, now_iso=NOW, source_epoch=SOURCE_EPOCH)


def test_floats_are_rejected_in_canonical_bytes():
    with pytest.raises(dr.DistillReceiptError, match="floats"):
        dr.canonical_bytes({"score": 0.875})


def test_score_and_work_units_are_decimal_strings():
    receipt = _receipt()
    assert isinstance(receipt["evaluation"]["score"], str)
    assert isinstance(receipt["work"]["work_units"], str)


def test_passed_cannot_exceed_graded():
    body = _receipt_body(passed=40, graded=32)
    receipt = dr.build_receipt(body, KEY, signing_key_id="distill-test-1")
    with pytest.raises(dr.DistillReceiptError, match="exceeds graded"):
        dr.verify_receipt(receipt, PUB, now_iso=NOW, source_epoch=SOURCE_EPOCH)


# --------------------------------------------------------------------------- #
# The shared feed: one compute + one distill contribution
# --------------------------------------------------------------------------- #

def _compute_contribution():
    # A compute receipt's contribution (from cathedralconfidential) reduces to the
    # same shape: a subject miner and its verified work units.
    return lf.LaneContribution(
        miner_hotkey="5ComputeMiner",
        receipt_id="receipt-" + _digest("compute-receipt"),
        work_units=Decimal("3.5"))


def _distill_contribution(receipt):
    c = dr.lane_contribution(receipt)
    return lf.LaneContribution(
        miner_hotkey=c["miner_hotkey"], receipt_id=c["receipt_id"],
        work_units=Decimal(c["work_units"]))


def test_both_lanes_produce_contributions_in_one_feed():
    verified = dr.verify_receipt(_receipt(), PUB, now_iso=NOW, source_epoch=SOURCE_EPOCH)
    compute = lf.Lane("cathedral_confidential_tdx", Decimal("0.45"),
                      [_compute_contribution()])
    distill = lf.Lane("cathedral_distill", Decimal("0.45"),
                      [_distill_contribution(verified)])
    feed = lf.compose_vector([compute, distill], burn_hotkey="5Burn")

    lanes = {ln["lane"]: ln for ln in feed["lanes"]}
    assert set(lanes) == {"cathedral_confidential_tdx", "cathedral_distill"}
    assert lanes["cathedral_distill"]["contributions"][0]["miner_hotkey"] == "5Miner"
    # each lane records its audit root back to the receipts
    assert lanes["cathedral_distill"]["audit_root"].startswith("sha256:")
    # both miners appear in the composed weights; burn is the contractual 10%
    miners = {w["miner_hotkey"] for w in feed["weights"]}
    assert miners == {"5ComputeMiner", "5Miner"}
    assert feed["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(10.0)
    assert sum(w["weight"] for w in feed["weights"]) == pytest.approx(0.90, abs=1e-9)


def test_empty_lane_mass_falls_to_burn_not_peers():
    compute = lf.Lane("cathedral_confidential_tdx", Decimal("0.45"),
                      [_compute_contribution()])
    empty_distill = lf.Lane("cathedral_distill", Decimal("0.45"), [])  # no solves
    feed = lf.compose_vector([compute, empty_distill], burn_hotkey="5Burn")
    # distill's 0.45 is unallocated → it burns, it does not inflate compute.
    assert feed["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(55.0)
    assert sum(w["weight"] for w in feed["weights"]) == pytest.approx(0.45, abs=1e-9)


# --------------------------------------------------------------------------- #
# Regenerate the committed fixtures from the code above
# --------------------------------------------------------------------------- #

def test_regenerate_fixtures():
    FIXTURES.mkdir(exist_ok=True)
    receipt = _receipt()
    dr.verify_receipt(receipt, PUB, now_iso=NOW, source_epoch=SOURCE_EPOCH)
    (FIXTURES / "distill-receipt-v1.json").write_text(json.dumps(receipt, indent=2, sort_keys=True))

    verified = dr.verify_receipt(receipt, PUB, now_iso=NOW, source_epoch=SOURCE_EPOCH)
    feed = lf.compose_vector(
        [lf.Lane("cathedral_confidential_tdx", Decimal("0.45"), [_compute_contribution()]),
         lf.Lane("cathedral_distill", Decimal("0.45"), [_distill_contribution(verified)])],
        burn_hotkey="5Burn")
    (FIXTURES / "multi-lane-feed.json").write_text(json.dumps(feed, indent=2, sort_keys=True))
    assert (FIXTURES / "distill-receipt-v1.json").exists()
    assert (FIXTURES / "multi-lane-feed.json").exists()
