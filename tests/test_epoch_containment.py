"""One bad receipt must cost one contribution, never the epoch's vector.

Four ways a single submission used to be able to reach past itself, all exercised
here in ONE composition:

  1. a receipt whose verification raises something the typed verifiers do not
     (a bare `KeyError`): it escaped every caller's `except` and aborted every
     lane and every miner;
  2. one signed receipt tagged into two lanes: it earned twice, and made the
     second lane "contributing" on work it did not do, capturing the share that
     should have gone to burn;
  3. a decision naming a lane the signed allocation config does not know: it
     raised out of `compose_integrated`, taking the whole vector with it;
  4. the burn hotkey as a reward subject: burn is a destination, never an earner.

Plus the replay-decision rule: the batch verifier requires either a real
`ConsumptionLedger` or the typed `NO_REPLAY_LEDGER` opt-out, because the state
this repo shipped in had a ledger with zero production instantiations and
`source_epoch` equality as the only replay defense.
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import compute_receipt as cr  # noqa: E402
from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill import signed_config as sc  # noqa: E402
from cathedral_distill.consumption_ledger import ConsumptionLedger  # noqa: E402
from cathedral_distill.testing import IntegrationFixtures  # noqa: E402

NOW_ISO = "2026-07-25T12:30:00.000000Z"
NOW_DT = datetime(2026, 7, 25, 12, 30, tzinfo=UTC)
SOURCE_EPOCH = 11
BURN_HOTKEY = "5Burn"

LANE_CPU = "cathedral_confidential_tdx"
LANE_DISTILL = "cathedral_distill"

FX = IntegrationFixtures(source_epoch=SOURCE_EPOCH)

# CPU 0.50 + Distill 0.40 + burn 0.10 == 1.0
_ALLOCATIONS = [
    {"lane": LANE_CPU, "allocation": "0.50", "enabled": True},
    {"lane": LANE_DISTILL, "allocation": "0.40", "enabled": True},
]


def _resolved():
    burn = sc.verify_burn_config(
        FX.burn_config(burn_hotkey=BURN_HOTKEY), FX.registry,
        network="finney", netuid=39, now=NOW_DT,
    )
    allocation = sc.verify_allocation_config(
        FX.allocation_config(_ALLOCATIONS), FX.registry,
        network="finney", netuid=39, now=NOW_DT,
    )
    return sc.resolve_allocation(burn, allocation)


def _verify(kind, receipt, lane, ledger=itf.NO_REPLAY_LEDGER):
    return itf.verify_lane_receipt(
        kind, receipt, lane=lane, key_registry=FX.registry,
        source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO, consumption_ledger=ledger,
    )


# --------------------------------------------------------------------------- #
# Containment: an untyped exception fails one receipt, not the epoch
# --------------------------------------------------------------------------- #

def test_an_untyped_verifier_exception_fails_only_that_receipt(monkeypatch):
    real_verify = cr.verify_receipt
    poisoned = FX.cpu_receipt(subject="5Poison", work_units="7")

    def verify(receipt, *args, **kwargs):
        if receipt["subject_hotkey"] == "5Poison":
            raise KeyError("status")  # exactly the shape that aborted the vector
        return real_verify(receipt, *args, **kwargs)

    monkeypatch.setattr(cr, "verify_receipt", verify)

    decision = _verify(itf.KIND_COMPUTE_CPU, poisoned, LANE_CPU)
    assert decision.verdict == itf.FAIL
    assert decision.work_units == Decimal(0)
    assert "KeyError" in decision.detail

    healthy = _verify(itf.KIND_COMPUTE_CPU, FX.cpu_receipt(subject="5Healthy"), LANE_CPU)
    assert healthy.verdict == itf.PASS


def test_batch_contains_an_unknown_kind_instead_of_aborting():
    decisions = itf.verify_lane_receipts(
        [
            itf.LaneSubmission("mystery_kind", FX.cpu_receipt(), LANE_CPU),
            itf.LaneSubmission(itf.KIND_COMPUTE_CPU, FX.cpu_receipt(), LANE_CPU),
        ],
        key_registry=FX.registry, source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO,
        consumption_ledger=itf.NO_REPLAY_LEDGER,
    )
    assert decisions[0].verdict == itf.FAIL and "mystery_kind" in decisions[0].detail
    assert decisions[1].verdict == itf.PASS


def test_batch_contains_a_missing_now_iso_instead_of_aborting():
    decisions = itf.verify_lane_receipts(
        [itf.LaneSubmission(itf.KIND_COMPUTE_CPU, FX.cpu_receipt(), LANE_CPU)],
        key_registry=FX.registry, source_epoch=SOURCE_EPOCH,
        consumption_ledger=itf.NO_REPLAY_LEDGER,
    )
    assert decisions[0].verdict == itf.FAIL and "now_iso" in decisions[0].detail


# --------------------------------------------------------------------------- #
# The replay decision is explicit
# --------------------------------------------------------------------------- #

def test_batch_verification_requires_an_explicit_replay_decision():
    with pytest.raises(itf.IntegratedFeedError, match="explicit replay decision"):
        itf.verify_lane_receipts(
            [itf.LaneSubmission(itf.KIND_COMPUTE_CPU, FX.cpu_receipt(), LANE_CPU)],
            key_registry=FX.registry, source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO,
            consumption_ledger=None,
        )


def test_one_receipt_in_two_lanes_is_consumed_once_by_the_ledger(tmp_path):
    ledger = ConsumptionLedger(str(tmp_path / "ledger.sqlite"))
    receipt = FX.cpu_receipt(subject="5Doubler", work_units="9")
    decisions = itf.verify_lane_receipts(
        [
            itf.LaneSubmission(itf.KIND_COMPUTE_CPU, receipt, LANE_CPU),
            itf.LaneSubmission(itf.KIND_COMPUTE_CPU, receipt, LANE_DISTILL),
        ],
        key_registry=FX.registry, source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO,
        consumption_ledger=ledger,
    )
    assert decisions[0].verdict == itf.PASS
    assert decisions[1].verdict == itf.FAIL
    assert ledger.size() == 1


def test_one_receipt_in_two_lanes_is_credited_once_without_a_ledger():
    """The in-batch dedup holds even on the explicit no-ledger path."""
    receipt = FX.cpu_receipt(subject="5Doubler", work_units="9")
    decisions = itf.verify_lane_receipts(
        [
            itf.LaneSubmission(itf.KIND_COMPUTE_CPU, receipt, LANE_CPU),
            itf.LaneSubmission(itf.KIND_COMPUTE_CPU, receipt, LANE_DISTILL),
        ],
        key_registry=FX.registry, source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO,
        consumption_ledger=itf.NO_REPLAY_LEDGER,
    )
    assert [d.verdict for d in decisions] == [itf.PASS, itf.FAIL]
    assert "already credited in lane" in decisions[1].detail


# --------------------------------------------------------------------------- #
# One epoch, all four hazards at once
# --------------------------------------------------------------------------- #

def test_one_epoch_survives_malformed_reused_burn_subject_and_unknown_lane(monkeypatch):
    resolved = _resolved()

    real_verify = cr.verify_receipt

    def verify(receipt, *args, **kwargs):
        if receipt["subject_hotkey"] == "5Poison":
            raise KeyError("advisory_ids")
        return real_verify(receipt, *args, **kwargs)

    monkeypatch.setattr(cr, "verify_receipt", verify)

    good = FX.cpu_receipt(subject="5Good", work_units="12")
    reused = FX.distill_receipt(subject="5Reuser", passed=6, graded=6)
    burn_subject = FX.cpu_receipt(subject=BURN_HOTKEY, work_units="99")
    malformed = FX.cpu_receipt(subject="5Poison", work_units="50")

    decisions = itf.verify_lane_receipts(
        [
            itf.LaneSubmission(itf.KIND_COMPUTE_CPU, good, LANE_CPU),
            itf.LaneSubmission(itf.KIND_COMPUTE_CPU, malformed, LANE_CPU),
            itf.LaneSubmission(itf.KIND_DISTILL, reused, LANE_DISTILL),
            itf.LaneSubmission(itf.KIND_COMPUTE_CPU, burn_subject, LANE_CPU),
        ],
        key_registry=FX.registry, source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO,
        consumption_ledger=itf.NO_REPLAY_LEDGER,
    )
    # the same signed Distill receipt is also offered to the CPU lane, and a
    # decision is added for a lane the signed allocation config never heard of
    reused_decision = next(d for d in decisions if d.miner_hotkey == "5Reuser")
    decisions.append(
        itf.ReceiptDecision(
            LANE_CPU, itf.KIND_DISTILL, reused_decision.receipt_id, "5Reuser",
            itf.PASS, reused_decision.work_units, "verified",
        )
    )
    decisions.append(
        itf.ReceiptDecision(
            "cathedral_lane_that_does_not_exist", itf.KIND_COMPUTE_CPU,
            "receipt-sha256:" + "ee" * 32, "5Rogue", itf.PASS, Decimal("1000"),
        )
    )

    composed = itf.compose_integrated(resolved, decisions)
    audit = {(r["receipt_id"], r["lane"]): r for r in composed["audit"]["receipts"]}
    earners = {w["miner_hotkey"] for w in composed["feed"]["weights"]}

    # 1. the honest CPU receipt is credited and is an earner
    good_row = audit[(good["receipt_id"], LANE_CPU)]
    assert good_row["credited"] is True and "5Good" in earners

    # 2. the malformed one fails alone
    assert audit[(malformed["receipt_id"], LANE_CPU)]["verdict"] == itf.FAIL
    assert "5Poison" not in earners

    # 3. the reused receipt earns exactly once, in the lane that got it first
    assert audit[(reused["receipt_id"], LANE_DISTILL)]["credited"] is True
    assert audit[(reused["receipt_id"], LANE_CPU)]["credited"] is False
    assert "already credited in lane" in audit[(reused["receipt_id"], LANE_CPU)]["drop_reason"]

    # 4. the burn hotkey never becomes an earner
    burn_row = audit[(burn_subject["receipt_id"], LANE_CPU)]
    assert burn_row["credited"] is False and "burn hotkey" in burn_row["drop_reason"]

    # 5. the unknown lane earns nothing and does not abort the composition
    rogue_row = audit[("receipt-sha256:" + "ee" * 32, "cathedral_lane_that_does_not_exist")]
    assert rogue_row["credited"] is False
    assert "not in the allocation config" in rogue_row["drop_reason"]
    assert "5Rogue" not in earners

    # the burn hotkey appears in the vector only as the burn destination
    assert BURN_HOTKEY not in earners
    assert composed["feed"]["burn_snapshot"]["burn_hotkey"] == BURN_HOTKEY

    # the epoch still produced a real vector: honest earners only, and the audit
    # of every rejection is serialisable for the operator record
    assert earners == {"5Good", "5Reuser"}
    assert json.dumps(composed["audit"])
