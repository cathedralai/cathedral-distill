"""Tests for role separation and independent reward accounting.

The invariant under test:

    a participant's hardware must not make their recipe score higher, and
    their recipe's success must not increase their serving reward.
"""
from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import roles as rl  # noqa: E402

POOLS = rl.RewardPools(
    training=Decimal("0.50"), serving=Decimal("0.40"), burn=Decimal("0.10")
)


def _participant(coldkey, *role_pairs):
    return rl.Participant(coldkey=coldkey, hotkeys=dict(role_pairs))


# --------------------------------------------------------------------------- #
# Roles and identity
# --------------------------------------------------------------------------- #

def test_three_distinct_roles_with_public_labels():
    assert rl.ROLE_LABELS[rl.Role.SERVING_MINER] == "Compute Serving Miner"
    assert rl.ROLE_LABELS[rl.Role.TRAINING_MINER] == "Model Training Miner"
    assert rl.ROLE_LABELS[rl.Role.VALIDATOR] == "Cathedral Validator"


def test_participant_can_hold_both_roles():
    both = _participant(
        "cold-A",
        (rl.Role.SERVING_MINER, "5Hot1"),
        (rl.Role.TRAINING_MINER, "5Hot2"),
    )
    assert both.holds(rl.Role.SERVING_MINER)
    assert both.holds(rl.Role.TRAINING_MINER)
    assert not both.holds(rl.Role.VALIDATOR)


def test_coldkey_is_required():
    with pytest.raises(rl.RoleError, match="coldkey is required"):
        rl.Participant(coldkey="")


# --------------------------------------------------------------------------- #
# Separation of duties
# --------------------------------------------------------------------------- #

def test_self_evaluation_detected_across_different_hotkeys():
    # Hotkeys are cheap to mint, so a hotkey comparison would detect nothing.
    trainer = _participant("cold-A", (rl.Role.TRAINING_MINER, "5Hot1"))
    evaluator = _participant("cold-A", (rl.Role.SERVING_MINER, "5Hot2"))
    assert rl.is_self_evaluation(trainer, evaluator)
    with pytest.raises(rl.RoleError, match="score grinding"):
        rl.assert_independent_evaluator(trainer, evaluator)


def test_independent_evaluator_is_accepted():
    trainer = _participant("cold-A", (rl.Role.TRAINING_MINER, "5Hot1"))
    evaluator = _participant("cold-B", (rl.Role.SERVING_MINER, "5Hot2"))
    assert not rl.is_self_evaluation(trainer, evaluator)
    rl.assert_independent_evaluator(trainer, evaluator)


def test_requirement_can_be_relaxed_only_explicitly():
    same = _participant("cold-A", (rl.Role.TRAINING_MINER, "5Hot1"))
    # The hardware-free path has no second operator to hand the work to.
    rl.assert_independent_evaluator(same, same, required=False)
    with pytest.raises(rl.RoleError):
        rl.assert_independent_evaluator(same, same)


# --------------------------------------------------------------------------- #
# The independence invariant
# --------------------------------------------------------------------------- #

def test_serving_credit_cannot_change_training_payout():
    lean = rl.RewardLedger(POOLS)
    lean.credit_training("cold-A", Decimal("1"))
    lean.credit_serving("cold-A", Decimal("0.01"))

    heavy = rl.RewardLedger(POOLS)
    heavy.credit_training("cold-A", Decimal("1"))
    heavy.credit_serving("cold-A", Decimal("1"))

    # Hardware contribution differs 100x; the recipe reward is identical.
    assert lean.payout("cold-A")["training"] == heavy.payout("cold-A")["training"]


def test_training_success_cannot_change_serving_payout():
    loser = rl.RewardLedger(POOLS)
    loser.credit_serving("cold-A", Decimal("0.5"))
    loser.credit_training("cold-A", Decimal("0"))

    champion = rl.RewardLedger(POOLS)
    champion.credit_serving("cold-A", Decimal("0.5"))
    champion.credit_training("cold-A", Decimal("1"))

    # Holding the frontier does not enlarge the compute reward.
    assert loser.payout("cold-A")["serving"] == champion.payout("cold-A")["serving"]


def test_dual_role_receives_a_sum_never_a_bonus():
    ledger = rl.RewardLedger(POOLS)
    ledger.credit_serving("cold-A", Decimal("0.5"))
    ledger.credit_training("cold-A", Decimal("1"))
    payout = ledger.payout("cold-A")

    expected_serving = Decimal("0.5") * POOLS.serving
    expected_training = Decimal("1") * POOLS.training
    assert payout["serving"] == expected_serving
    assert payout["training"] == expected_training
    assert payout["total"] == expected_serving + expected_training


def test_two_participants_split_within_their_own_pool_only():
    ledger = rl.RewardLedger(POOLS)
    ledger.credit_serving("cold-A", Decimal("0.5"))
    ledger.credit_serving("cold-B", Decimal("0.5"))
    ledger.credit_training("cold-A", Decimal("1"))

    assert ledger.payout("cold-A")["serving"] == Decimal("0.5") * POOLS.serving
    assert ledger.payout("cold-B")["serving"] == Decimal("0.5") * POOLS.serving
    assert ledger.payout("cold-B")["training"] == Decimal("0")


# --------------------------------------------------------------------------- #
# Pools and settlement
# --------------------------------------------------------------------------- #

def test_pools_must_sum_to_exactly_one():
    with pytest.raises(rl.RoleError, match="sum to exactly 1"):
        rl.RewardPools(training=Decimal("0.5"), serving=Decimal("0.5"), burn=Decimal("0.1"))


def test_negative_pool_is_rejected():
    with pytest.raises(rl.RoleError, match="non-negative"):
        rl.RewardPools(training=Decimal("-0.1"), serving=Decimal("1"), burn=Decimal("0.1"))


def test_settlement_always_sums_to_one():
    ledger = rl.RewardLedger(POOLS)
    ledger.credit_serving("cold-A", Decimal("1"))
    ledger.credit_training("cold-B", Decimal("1"))
    settled = ledger.settle()
    assert sum(settled.values()) == Decimal("1")


def test_unallocated_pool_goes_to_burn_not_to_whoever_is_present():
    # Same stance the existing mechanism takes for an empty verified set.
    ledger = rl.RewardLedger(POOLS)
    ledger.credit_serving("cold-A", Decimal("1"))
    # No maintainer credited: that entire pool must burn.
    settled = ledger.settle()
    assert settled["burn"] == POOLS.burn + POOLS.training
    assert sum(settled.values()) == Decimal("1")


def test_empty_ledger_burns_everything():
    ledger = rl.RewardLedger(POOLS)
    assert ledger.settle()["burn"] == Decimal("1")


def test_over_allocated_pool_is_rejected():
    ledger = rl.RewardLedger(POOLS)
    ledger.credit_training("cold-A", Decimal("0.8"))
    ledger.credit_training("cold-B", Decimal("0.8"))
    with pytest.raises(rl.RoleError, match="exceed its pool"):
        ledger.settle()


def test_share_outside_unit_range_is_rejected():
    ledger = rl.RewardLedger(POOLS)
    with pytest.raises(rl.RoleError, match="within 0..1"):
        ledger.credit_serving("cold-A", Decimal("1.5"))


def test_repeated_credits_accumulate():
    ledger = rl.RewardLedger(POOLS)
    ledger.credit_serving("cold-A", Decimal("0.2"))
    ledger.credit_serving("cold-A", Decimal("0.3"))
    assert ledger.role_share(rl.Role.SERVING_MINER, "cold-A") == Decimal("0.5")


def test_report_is_publishable_and_itemised_by_role():
    ledger = rl.RewardLedger(POOLS)
    ledger.credit_serving("cold-A", Decimal("1"))
    ledger.credit_training("cold-B", Decimal("1"))
    report = ledger.as_report()
    assert report["schema"] == rl.LEDGER_SCHEMA
    keys = report["settlement"].keys()
    assert "serving_miner:cold-A" in keys
    assert "training_miner:cold-B" in keys
