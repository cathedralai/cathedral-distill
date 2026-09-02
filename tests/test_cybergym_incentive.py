"""What a harness is PAID under thin evidence.

The lane's supply is ~0.7 admissible bugs a day, evidence accrues per harness from its own
commitment, and at 30 binary tasks the standard error is near 9 points. So a raw solve rate
is the wrong thing to pay on: a newcomer has almost no evidence for weeks, and hard ranking
on tens of tasks mostly pays out noise.

Paying the lower confidence bound of a recency-weighted posterior answers both at once —
thin evidence widens the interval, which lowers the bound, which IS the warm-up rate. These
tests hold the properties that make that safe to put weight behind: it never pays for
nothing, never over-pays on luck, never lets age alone win, and never depends on the order a
validator happened to iterate in.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.cybergym_incentive import (  # noqa: E402
    CARRIED_PRIOR_MAX,
    HALF_LIFE_DAYS,
    Evidence,
    IncentiveError,
    Observation,
    carried_prior,
    credited_rate,
    rank_by_credited_rate,
    recency_weight,
    weigh,
)

NOW = datetime(2026, 9, 2, tzinfo=UTC)


def _obs(n, solved_fraction=0.5, age_days=1):
    solves = int(n * solved_fraction)
    return [
        Observation(f"t{i:04d}", i < solves, NOW - timedelta(days=age_days))
        for i in range(n)
    ]


def _rate(n, solved_fraction=0.5, **kw):
    return credited_rate(weigh(_obs(n, solved_fraction), as_of=NOW),
                         commitment_verified=True, **kw)


class TestItNeverPaysForNothing:
    def test_zero_evidence_credits_exactly_zero(self):
        """The prior is deliberately pessimistic rather than Jeffreys: under Jeffreys a
        harness with NO evidence is credited 0.146, which is real emission for having
        submitted nothing and a standing invitation to register garbage."""
        assert _rate(0) == Decimal(0)

    @pytest.mark.parametrize("n", [1, 5, 30, 91, 500])
    def test_a_harness_that_solves_nothing_is_credited_nothing(self, n):
        assert _rate(n, solved_fraction=0.0) == Decimal(0)

    def test_an_unverified_commitment_is_paid_zero(self):
        """`cybergym_stage1` records whether commit-then-draw was actually proven and says a
        consumer moving weight must refuse an unverified score. This is that consumer."""
        strong = weigh(_obs(91, 1.0), as_of=NOW)
        assert credited_rate(strong, commitment_verified=True) > Decimal("0.9")
        assert credited_rate(strong, commitment_verified=False) == Decimal(0)

    def test_the_verification_flag_cannot_be_forgotten(self):
        """It is a REQUIRED keyword — a caller who never thought about freshness cannot
        accidentally get paid behaviour."""
        with pytest.raises(TypeError):
            credited_rate(weigh(_obs(10), as_of=NOW))


class TestItNeverOverpaysOnLuck:
    @pytest.mark.parametrize("n", [1, 5, 10, 20, 30, 60, 91])
    def test_the_credited_rate_never_exceeds_the_observed_rate(self, n):
        """Conservative in the only safe direction: under-pay on uncertainty rather than
        over-pay on a lucky streak."""
        assert _rate(n, 0.5) <= Decimal("0.5")

    def test_a_perfect_but_tiny_sample_is_not_paid_as_perfect(self):
        """Three-for-three is not evidence of a perfect harness."""
        assert _rate(3, 1.0) < Decimal("0.5")

    def test_more_evidence_at_the_same_rate_pays_more(self):
        """The warm-up curve: belief, not the rate itself, is what grows."""
        rates = [_rate(n, 0.5) for n in (0, 5, 10, 20, 30, 60, 91)]
        assert rates == sorted(rates)
        assert rates[0] == 0 and rates[-1] > Decimal("0.41")

    def test_more_solves_at_the_same_evidence_pays_more(self):
        assert _rate(30, 0.2) < _rate(30, 0.5) < _rate(30, 0.9)

    def test_it_converges_toward_the_true_rate(self):
        assert Decimal("0.45") < _rate(2000, 0.5) <= Decimal("0.5")


class TestWarmUpMatchesTheMeasuredSupply:
    def test_about_four_to_five_weeks_of_supply_credits_most_of_the_true_rate(self):
        """z is calibrated so a true-50% harness reaches ~80% of its real rate after ~23
        tasks — about 4.7 weeks at the measured 0.7/day. A 95% bound would stretch that to
        13.5 weeks and price newcomers out of the lane for a quarter."""
        assert _rate(24, 0.5) >= Decimal("0.33")

    def test_a_newcomer_is_not_simply_locked_out(self):
        """Two weeks in (~10 tasks at the measured rate), a strong harness is already
        earning materially rather than waiting out a fixed probationary period."""
        assert _rate(10, 0.9) > Decimal("0.45")


class TestRecencyStopsAgeFromWinningOnItsOwn:
    def test_weight_halves_at_the_half_life(self):
        w = recency_weight(NOW - timedelta(days=float(HALF_LIFE_DAYS)), as_of=NOW)
        assert abs(w - Decimal("0.5")) < Decimal("1e-12")

    def test_a_fresh_observation_weighs_one(self):
        assert recency_weight(NOW, as_of=NOW) == Decimal(1)

    def test_old_evidence_fades(self):
        """Without decay, a harness committed a year ago accumulates a precision moat a
        better newcomer cannot cross, and the lane rewards age over capability."""
        fresh = weigh(_obs(30, 0.5, age_days=0), as_of=NOW).effective_total
        stale = weigh(_obs(30, 0.5, age_days=365), as_of=NOW).effective_total
        assert stale < fresh / 10

    def test_a_future_dated_observation_cannot_weigh_more_than_a_fresh_one(self):
        """Clock skew must not be able to inflate evidence."""
        assert recency_weight(NOW + timedelta(days=30), as_of=NOW) == Decimal(1)

    def test_an_ancient_harness_does_not_out_evidence_a_current_one(self):
        current = weigh(_obs(60, 0.5, age_days=10), as_of=NOW)
        ancient = weigh(_obs(300, 0.5, age_days=400), as_of=NOW)
        assert ancient.effective_total < current.effective_total


class TestImprovingAHarnessIsNotPunished:
    """A miner who improves must re-commit, which empties their eligible pool. Without a
    carry-over the lane would answer every improvement with weeks at zero — precisely
    backwards for a competition whose purpose is rising capability."""

    def test_a_proven_miner_keeps_earning_through_the_empty_weeks(self):
        carried = carried_prior(Decimal("0.45"), Decimal("91"))
        assert _rate(0) == 0
        assert _rate(0, carried=carried) > Decimal("0.2")

    def test_the_carry_is_capped(self):
        """Ten pseudo-observations, however long the history — a miner cannot coast."""
        modest = carried_prior(Decimal("0.5"), Decimal("10"))
        enormous = carried_prior(Decimal("0.5"), Decimal("100000"))
        assert modest == enormous
        assert sum(enormous) == CARRIED_PRIOR_MAX

    def test_real_evidence_overtakes_the_carry(self):
        """A miner who re-commits a WORSE harness is found out, not carried indefinitely."""
        carried = carried_prior(Decimal("0.9"), Decimal("91"))
        early = _rate(2, 0.0, carried=carried)
        later = _rate(40, 0.0, carried=carried)
        assert later < early

    def test_the_carry_is_a_rate_not_task_knowledge(self):
        """It is two scalars derived from a rate — structurally incapable of carrying which
        tasks were seen, so it cannot leak the corpus across a re-commitment."""
        solves, failures = carried_prior(Decimal("0.5"), Decimal("20"))
        assert isinstance(solves, Decimal) and isinstance(failures, Decimal)

    @pytest.mark.parametrize("bad", [Decimal("-0.1"), Decimal("1.1")])
    def test_an_impossible_previous_rate_is_refused(self, bad):
        with pytest.raises(IncentiveError, match="probability"):
            carried_prior(bad, Decimal("10"))


class TestDeterminismBecauseThisFeedsWeights:
    def test_observation_order_does_not_change_the_result(self):
        """Decimal addition is not associative at finite precision, so summing in iteration
        order would let two validators holding the same observations differ in the last
        digit — and this feeds weights."""
        rows = _obs(50, 0.5)
        assert weigh(rows, as_of=NOW) == weigh(list(reversed(rows)), as_of=NOW)

    def test_repeated_evaluation_is_identical(self):
        rows = _obs(40, 0.5)
        first = credited_rate(weigh(rows, as_of=NOW), commitment_verified=True)
        for _ in range(5):
            assert credited_rate(weigh(rows, as_of=NOW), commitment_verified=True) == first

    def test_the_result_is_decimal_not_float(self):
        """Floats would make cross-validator agreement libm-dependent."""
        assert isinstance(_rate(30), Decimal)

    def test_timezones_are_normalised(self):
        east = timezone(timedelta(hours=9))
        assert (recency_weight(NOW.astimezone(east), as_of=NOW)
                == recency_weight(NOW, as_of=NOW))

    def test_a_duplicated_task_is_refused(self):
        """Double-counting one task would inflate evidence and tighten the interval on
        strength that was never demonstrated."""
        rows = _obs(3) + [Observation("t0000", True, NOW)]
        with pytest.raises(IncentiveError, match="observed twice"):
            weigh(rows, as_of=NOW)


class TestRankingIsStable:
    def test_higher_credited_rates_come_first(self):
        ranked = rank_by_credited_rate(
            [("b", Decimal("0.2")), ("a", Decimal("0.9")), ("c", Decimal("0.5"))])
        assert [r[0] for r in ranked] == ["a", "c", "b"]

    def test_ties_break_deterministically_and_ungrindably(self):
        """Ties are COMMON by design — the bound collapses distinctions the evidence cannot
        support — so the tie-break must not be resubmit-until-lucky."""
        tied = [("z", Decimal("0.4")), ("a", Decimal("0.4")), ("m", Decimal("0.4"))]
        assert [r[0] for r in rank_by_credited_rate(tied)] == ["a", "m", "z"]
        assert rank_by_credited_rate(tied) == rank_by_credited_rate(list(reversed(tied)))


class TestInputsFailClosed:
    def test_a_naive_timestamp_is_refused(self):
        with pytest.raises(IncentiveError, match="timezone-aware"):
            Observation("t", True, datetime(2026, 9, 2))

    def test_a_non_bool_solved_is_refused(self):
        with pytest.raises(IncentiveError, match="solved must be a bool"):
            Observation("t", 1, NOW)

    def test_an_empty_task_id_is_refused(self):
        with pytest.raises(IncentiveError, match="task_id"):
            Observation("", True, NOW)

    def test_solves_cannot_exceed_the_total(self):
        with pytest.raises(IncentiveError, match="cannot exceed"):
            Evidence(effective_total=Decimal(1), effective_solves=Decimal(2))

    def test_negative_evidence_is_refused(self):
        with pytest.raises(IncentiveError, match="negative"):
            Evidence(effective_total=Decimal(-1), effective_solves=Decimal(0))

    def test_a_non_positive_half_life_is_refused(self):
        with pytest.raises(IncentiveError, match="half_life"):
            recency_weight(NOW - timedelta(days=1), as_of=NOW, half_life_days=Decimal(0))
