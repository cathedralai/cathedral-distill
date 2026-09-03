"""Calibrating the one screening number nobody has measured.

`RETENTION_LIMIT` decides when a harness looks like replay. Its default is a placeholder: nobody
has run a genuine agent against a weaker model and measured what it retains. These tests hold
the properties that make a calibration trustworthy — above all that an insufficient sample
returns NO recommendation rather than a number that merely looks measured.
"""
from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.cybergym_agent_screening import (  # noqa: E402
    TaskRun,
    Verdict,
    ablation_verdict,
)
from cathedral_distill.cybergym_calibration import (  # noqa: E402
    MIN_CALIBRATION_RUNS,
    calibrate,
    calibrate_from_pairs,
)


def _arms(n, full_fraction, ablated_fraction):
    return ([True] * int(n * full_fraction) + [False] * (n - int(n * full_fraction)),
            [True] * int(n * ablated_fraction) + [False] * (n - int(n * ablated_fraction)))


class TestItRefusesToGuess:
    def test_a_thin_sample_yields_no_recommendation(self):
        """A limit from a handful of runs sits wherever noise put it. Returning None is the
        honest answer; returning a number would look measured and would not be."""
        result = calibrate_from_pairs(*_arms(4, 0.75, 0.25))
        assert result.recommended_limit is None
        assert result.sufficient is False
        assert str(MIN_CALIBRATION_RUNS) in result.note

    def test_an_agent_that_solves_nothing_yields_no_recommendation(self):
        result = calibrate_from_pairs(*_arms(30, 0.0, 0.0))
        assert result.recommended_limit is None
        assert "any degradation to measure" in result.note

    def test_an_agent_that_barely_uses_the_model_is_reported_not_papered_over(self):
        """If honest retention plus margin reaches 1.0, ablation cannot separate this harness
        class from replay — that is a finding about the experiment, not a limit to ship."""
        result = calibrate_from_pairs(*_arms(30, 0.6, 0.6))
        assert result.recommended_limit is None
        assert "cannot separate it from replay" in result.note

    def test_the_summary_says_so_plainly(self):
        assert "NO RECOMMENDATION" in calibrate_from_pairs(*_arms(4, 0.75, 0.25)).summary()


class TestTheRecommendationIsConservativeAboutAccusing:
    def test_it_sits_above_observed_honest_retention(self):
        """Below it, the honest agents this was measured from would be flagged as cheats."""
        result = calibrate_from_pairs(*_arms(40, 0.75, 0.2))
        assert result.recommended_limit > result.retained_upper
        assert result.recommended_limit > result.retained

    def test_the_agents_it_was_measured_from_would_pass_their_own_limit(self):
        """The end-to-end property: calibrate on honest runs, then screen those same runs
        under the derived limit and they must not be flagged."""
        full, ablated = _arms(40, 0.75, 0.2)
        result = calibrate_from_pairs(full, ablated)
        runs = ([TaskRun(f"f{i}", s) for i, s in enumerate(full)]
                + [TaskRun(f"a{i}", s, ablated=True) for i, s in enumerate(ablated)])
        verdict = ablation_verdict(runs, retention_limit=result.recommended_limit)
        assert verdict.verdict is not Verdict.RECALL_SUSPECTED

    def test_a_replay_harness_is_still_caught_under_the_derived_limit(self):
        """The other end: the limit must stay below where replay sits (~1.0), or it catches
        nothing."""
        result = calibrate_from_pairs(*_arms(40, 0.75, 0.2))
        replay = ([TaskRun(f"f{i}", i < 30) for i in range(40)]
                  + [TaskRun(f"a{i}", i < 30, ablated=True) for i in range(40)])
        verdict = ablation_verdict(replay, retention_limit=result.recommended_limit)
        assert verdict.verdict is Verdict.RECALL_SUSPECTED

    def test_a_weaker_ablation_model_permits_a_lower_limit(self):
        """The more the ablation hurts an honest agent, the more room there is to separate."""
        gentle = calibrate_from_pairs(*_arms(40, 0.75, 0.5))
        harsh = calibrate_from_pairs(*_arms(40, 0.75, 0.1))
        assert harsh.recommended_limit < gentle.recommended_limit


class TestItMeasuresWhatItClaims:
    def test_retained_is_the_ratio_of_the_two_arms(self):
        result = calibrate_from_pairs(*_arms(40, 0.8, 0.4))
        assert abs(result.retained - Decimal("0.5")) < Decimal("0.01")

    def test_the_counts_are_reported_for_audit(self):
        result = calibrate_from_pairs(*_arms(40, 0.75, 0.2))
        assert (result.full_solves, result.full_total) == (30, 40)
        assert (result.ablated_solves, result.ablated_total) == (8, 40)

    def test_canary_runs_are_excluded(self):
        """They are deliberately harder and would depress whichever arm they landed in —
        matching the screening check this calibrates."""
        base = ([TaskRun(f"f{i}", i < 30) for i in range(40)]
                + [TaskRun(f"a{i}", i < 8, ablated=True) for i in range(40)])
        polluted = base + [TaskRun(f"c{i}", False, canary=True) for i in range(20)]
        assert calibrate(base).recommended_limit == calibrate(polluted).recommended_limit

    def test_the_note_scopes_the_result(self):
        """A calibration is valid for one model pair and task mix; shipping it as universal
        is how a measured number becomes a stale one."""
        assert "this model pair" in calibrate_from_pairs(*_arms(40, 0.75, 0.2)).note

    def test_empty_input_fails_closed(self):
        with pytest.raises(Exception):
            calibrate_from_pairs([], [])
