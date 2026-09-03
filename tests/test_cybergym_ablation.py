"""Which runs get the weaker model: unguessable during the round, provable after it.

The ablation check only works if the harness cannot tell which runs are degraded, and is only
usable for consensus if every validator re-derives the same split. A public nonce would publish
the assignment to the harness; a screener-held secret alone would let the screener choose the
split after seeing results. Commit-then-reveal is what satisfies both, and these tests hold
each half of that.
"""
from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.cybergym_ablation import (  # noqa: E402
    ABLATION_FRACTION,
    AblationError,
    AblationPlan,
    ablation_commitment,
    assign_ablation,
    payable_tasks,
    verify_ablation,
)

SECRET = b"0123456789abcdef-round-secret"
OTHER = b"fedcba9876543210-other-secret"
TASKS = [f"sealedvuln:{i:016x}:0" for i in range(35)]


class TestTheSplitIsDeterministicUnderTheSecret:
    def test_the_same_secret_always_produces_the_same_split(self):
        assert assign_ablation(TASKS, secret=SECRET) == assign_ablation(TASKS, secret=SECRET)

    def test_input_order_does_not_change_it(self):
        """Two validators cannot disagree because they held the list differently."""
        assert (assign_ablation(TASKS, secret=SECRET)
                == assign_ablation(list(reversed(TASKS)), secret=SECRET))

    def test_a_different_secret_gives_a_different_split(self):
        assert (assign_ablation(TASKS, secret=SECRET).ablated
                != assign_ablation(TASKS, secret=OTHER).ablated)

    def test_the_fraction_is_honoured(self):
        plan = assign_ablation(TASKS, secret=SECRET)
        assert len(plan.ablated) == int(len(TASKS) * ABLATION_FRACTION)
        assert len(plan.ablated) + len(plan.payable) == len(TASKS)

    def test_every_task_lands_on_exactly_one_side(self):
        plan = assign_ablation(TASKS, secret=SECRET)
        assert set(plan.ablated) | set(plan.payable) == set(TASKS)
        assert not set(plan.ablated) & set(plan.payable)

    def test_the_split_is_not_a_prefix_of_the_input(self):
        """It must be keyed on the secret, not on position — otherwise the harness reads it
        straight off the dispatch order."""
        plan = assign_ablation(TASKS, secret=SECRET)
        assert set(plan.ablated) != set(TASKS[:len(plan.ablated)])


class TestCommitThenReveal:
    def test_the_commitment_reveals_nothing_about_the_split(self):
        """It is published before the round, so it must be domain-separated from the
        assignment derivation."""
        commitment = ablation_commitment(SECRET)
        plan = assign_ablation(TASKS, secret=SECRET)
        assert not any(t in commitment for t in plan.ablated)

    def test_an_honest_reveal_verifies(self):
        plan = assign_ablation(TASKS, secret=SECRET)
        verify_ablation(TASKS, plan, secret=SECRET)

    def test_a_secret_that_was_not_committed_to_is_refused(self):
        """Otherwise the screener picks the split after the results are known."""
        plan = assign_ablation(TASKS, secret=SECRET)
        with pytest.raises(AblationError, match="does not match the published commitment"):
            verify_ablation(TASKS, plan, secret=OTHER)

    def test_an_honest_secret_with_a_doctored_split_is_refused(self):
        """Checking only the commitment would let a screener reveal a genuine secret and
        report a different split beside it."""
        plan = assign_ablation(TASKS, secret=SECRET)
        doctored = AblationPlan(
            ablated=plan.ablated[:-1], payable=plan.payable + plan.ablated[-1:],
            commitment=plan.commitment)
        with pytest.raises(AblationError, match="not what the revealed secret produces"):
            verify_ablation(TASKS, doctored, secret=SECRET)

    def test_a_guessable_secret_is_refused(self):
        """A short secret is a published assignment."""
        with pytest.raises(AblationError, match="at least"):
            ablation_commitment(b"short")
        with pytest.raises(AblationError, match="at least"):
            assign_ablation(TASKS, secret=b"short")


class TestAblatedRunsNeverPay:
    def test_payable_excludes_the_ablated(self):
        """A task graded under a deliberately weakened model is not a fair measure of the
        harness, so paying on it would charge honest miners for our own test."""
        plan = assign_ablation(TASKS, secret=SECRET)
        assert set(payable_tasks(plan)).isdisjoint(plan.ablated)
        assert len(payable_tasks(plan)) == len(TASKS) - len(plan.ablated)

    def test_a_plan_cannot_double_book_a_task(self):
        with pytest.raises(AblationError, match="cannot be both"):
            AblationPlan(ablated=("a",), payable=("a",), commitment="sha256:" + "0" * 64)

    def test_both_arms_fill_within_about_two_rounds(self):
        """`screening.MIN_ARM_OBSERVATIONS` is 12 per arm; a 35-task round yields ~10
        ablated, so the screening accumulates rather than each round carrying it alone."""
        plan = assign_ablation(TASKS, secret=SECRET)
        assert len(plan.ablated) * 2 >= 12
        assert len(plan.payable) >= 12


class TestEdgesFailClosed:
    def test_repeated_task_ids_are_refused(self):
        with pytest.raises(AblationError, match="repeat"):
            assign_ablation(["a", "a"], secret=SECRET)

    def test_an_empty_round_is_an_empty_plan_not_a_crash(self):
        plan = assign_ablation([], secret=SECRET)
        assert plan.ablated == () and plan.payable == ()

    @pytest.mark.parametrize("bad", [Decimal("-0.1"), Decimal("1"), Decimal("1.5")])
    def test_an_impossible_fraction_is_refused(self, bad):
        with pytest.raises(AblationError, match="fraction"):
            assign_ablation(TASKS, secret=SECRET, fraction=bad)

    def test_a_zero_fraction_ablates_nothing(self):
        plan = assign_ablation(TASKS, secret=SECRET, fraction=Decimal(0))
        assert plan.ablated == () and len(plan.payable) == len(TASKS)
