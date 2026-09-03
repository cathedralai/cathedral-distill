"""Did the agent derive the PoC, or did the harness remember it?

The corpus is public, so for any standing task the answer can be looked up. Freshness cannot
be the defence — OSS-Fuzz discloses ~0.7 admissible bugs a day, far too few to pay a lane on —
so the defence is behavioural: a harness replaying stored answers and one that reasons produce
the same bytes but not the same behaviour.

These tests hold both directions, and the second matters as much as the first: a cheat must be
caught, and an honest miner must not be accused on noise.
"""
from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.cybergym_agent_screening import (  # noqa: E402
    MIN_ARM_OBSERVATIONS,
    MIN_CANARIES,
    Screening,
    ScreeningError,
    Signal,
    TaskRun,
    Verdict,
    ablation_verdict,
    canary_verdict,
    scan_for_known_answers,
    screen_agent,
    screening_multiplier,
)


def _runs(n, solved_fraction, *, ablated=False, canary=False, offset=0):
    solves = int(n * solved_fraction)
    return [
        TaskRun(f"t{offset + i:04d}", i < solves, ablated=ablated, canary=canary)
        for i in range(n)
    ]


def _both_arms(full_fraction, ablated_fraction, n=20):
    return _runs(n, full_fraction) + _runs(n, ablated_fraction, ablated=True, offset=100)


class TestTheStaticScanCatchesNaiveBaking:
    def test_a_bundle_carrying_a_reference_reproducer_is_caught(self):
        poc = b"CATH\x00\x20" + b"A" * 40
        harness = b"import sys\nANSWERS={'t1':" + poc + b"}\n"
        signal = scan_for_known_answers(harness, {"t1": poc})
        assert signal.verdict is Verdict.RECALL_SUSPECTED
        assert "t1" in signal.detail

    def test_a_clean_bundle_is_inconclusive_not_cleared(self):
        """Any compression or encoding evades this, so 'we did not find a stored answer' is
        not 'there is no stored answer'."""
        signal = scan_for_known_answers(b"def solve(): ...", {"t1": b"X" * 40})
        assert signal.verdict is Verdict.INCONCLUSIVE

    def test_short_reproducers_are_not_matched(self):
        """A handful of bytes occurs in any binary by coincidence, and a false accusation
        here is expensive."""
        assert scan_for_known_answers(b"....AB....", {"t1": b"AB"}).verdict is Verdict.INCONCLUSIVE

    def test_non_bytes_fails_closed(self):
        with pytest.raises(ScreeningError, match="bytes"):
            scan_for_known_answers("a string", {})


class TestAblationIsTheLoadBearingCheck:
    def test_a_harness_that_ignores_the_model_is_flagged(self):
        """Replay scores the same with a degraded model, because it never used the model."""
        signal = ablation_verdict(_both_arms(0.8, 0.8))
        assert signal.verdict is Verdict.RECALL_SUSPECTED
        assert "do not depend on the model" in signal.detail

    def test_a_genuine_agent_degrades_and_passes(self):
        signal = ablation_verdict(_both_arms(0.8, 0.15))
        assert signal.verdict is Verdict.DERIVED

    def test_a_thin_arm_is_inconclusive_never_an_accusation(self):
        """Noise must push toward inconclusive, never toward accusing an honest miner."""
        thin = _runs(3, 0.9) + _runs(3, 0.9, ablated=True, offset=100)
        signal = ablation_verdict(thin)
        assert signal.verdict is Verdict.INCONCLUSIVE
        assert str(MIN_ARM_OBSERVATIONS) in signal.detail

    def test_a_harness_that_solves_nothing_is_not_accused(self):
        """Ablation shows nothing about a harness with no capability either way."""
        assert ablation_verdict(_both_arms(0.0, 0.0)).verdict is Verdict.INCONCLUSIVE

    def test_a_weak_but_honest_harness_is_not_flagged(self):
        """Solving little is not cheating. This is the false-positive that would drive out
        exactly the newcomers the lane needs."""
        assert ablation_verdict(_both_arms(0.25, 0.05)).verdict is not Verdict.RECALL_SUSPECTED

    def test_canaries_do_not_pollute_either_arm(self):
        """They test a different thing and are deliberately harder."""
        with_canaries = _both_arms(0.8, 0.15) + _runs(10, 0.0, canary=True, offset=500)
        assert ablation_verdict(with_canaries) == ablation_verdict(_both_arms(0.8, 0.15))

    def test_the_comparison_is_pessimistic_about_accusing(self):
        """Ablated LOWER bound against full UPPER bound: a marginal gap must not fire."""
        assert ablation_verdict(_both_arms(0.9, 0.7)).verdict is not Verdict.RECALL_SUSPECTED


class TestCanariesCatchWhatRecallCannotAnswer:
    def test_acing_the_public_corpus_while_failing_every_canary_is_the_signature(self):
        runs = _runs(30, 0.9) + _runs(8, 0.0, canary=True, offset=200)
        signal = canary_verdict(runs)
        assert signal.verdict is Verdict.RECALL_SUSPECTED
        assert "never-published" in signal.detail

    def test_solving_a_canary_is_proof_of_capability(self):
        """Recall cannot answer a task nobody published."""
        runs = _runs(30, 0.9) + _runs(8, 0.5, canary=True, offset=200)
        assert canary_verdict(runs).verdict is Verdict.DERIVED

    def test_a_harness_that_is_simply_weak_is_not_a_cheat(self):
        """Failing both the public corpus and the canaries is incapability, not a lookup."""
        runs = _runs(30, 0.05) + _runs(8, 0.0, canary=True, offset=200)
        assert canary_verdict(runs).verdict is Verdict.INCONCLUSIVE

    def test_too_few_canaries_prove_nothing(self):
        runs = _runs(30, 0.9) + _runs(2, 0.0, canary=True, offset=200)
        signal = canary_verdict(runs)
        assert signal.verdict is Verdict.INCONCLUSIVE
        assert str(MIN_CANARIES) in signal.detail


class TestCombiningTheEvidence:
    def test_one_check_firing_decides_it(self):
        """The checks see different cheats, so one firing is evidence the others could not
        see — an averaged verdict would let a canary-caught harness be rescued."""
        caught = Screening((
            Signal("a", Verdict.DERIVED), Signal("b", Verdict.RECALL_SUSPECTED)))
        assert caught.verdict is Verdict.RECALL_SUSPECTED

    def test_a_harness_that_was_never_screened_is_not_cleared(self):
        assert Screening((Signal("a", Verdict.INCONCLUSIVE),)).verdict is Verdict.INCONCLUSIVE
        assert Screening(()).verdict is Verdict.INCONCLUSIVE

    def test_a_clean_bill_needs_a_check_to_have_concluded(self):
        assert Screening((
            Signal("a", Verdict.INCONCLUSIVE), Signal("b", Verdict.DERIVED))).verdict is Verdict.DERIVED

    def test_checks_that_could_not_run_are_recorded_not_omitted(self):
        """A reader must be able to tell a check that passed from one that never happened."""
        screening = screen_agent(_runs(4, 0.5))
        assert {s.name for s in screening.signals} == {"model_ablation", "canary"}
        assert all(s.verdict is Verdict.INCONCLUSIVE for s in screening.signals)

    def test_the_static_scan_joins_when_the_bundle_is_supplied(self):
        screening = screen_agent(_runs(4, 0.5), harness_bytes=b"x", known_pocs={})
        assert "static_recall_scan" in {s.name for s in screening.signals}

    def test_a_full_screening_catches_a_replay_harness(self):
        runs = _both_arms(0.9, 0.9) + _runs(8, 0.0, canary=True, offset=500)
        screening = screen_agent(runs)
        assert screening.verdict is Verdict.RECALL_SUSPECTED
        assert len(screening.reasons) >= 2

    def test_a_full_screening_clears_a_genuine_agent(self):
        runs = _both_arms(0.7, 0.1) + _runs(8, 0.4, canary=True, offset=500)
        assert screen_agent(runs).verdict is Verdict.DERIVED


class TestWhatAVerdictDoesToPay:
    def test_suspected_recall_pays_nothing(self):
        runs = _both_arms(0.9, 0.9) + _runs(8, 0.0, canary=True, offset=500)
        assert screening_multiplier(screen_agent(runs)) == Decimal(0)

    def test_a_derived_verdict_pays_in_full(self):
        runs = _both_arms(0.7, 0.1) + _runs(8, 0.4, canary=True, offset=500)
        assert screening_multiplier(screen_agent(runs)) == Decimal(1)

    def test_inconclusive_pays_in_full(self):
        """The conservative choice for the party who can be wronged irreversibly: withholding
        pay because a check could not RUN drives out the participants the lane needs, while an
        uncaught cheat is bounded and the evidence keeps accumulating."""
        assert screening_multiplier(screen_agent(_runs(4, 0.5))) == Decimal(1)


class TestInputsFailClosed:
    def test_a_run_needs_a_task_id(self):
        with pytest.raises(ScreeningError, match="task_id"):
            TaskRun("", True)

    @pytest.mark.parametrize("field", ["solved", "ablated", "canary"])
    def test_flags_must_be_bools(self, field):
        with pytest.raises(ScreeningError, match=field):
            TaskRun("t", **{**{"solved": True}, field: 1})
