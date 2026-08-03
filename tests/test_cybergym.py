"""Tests for the CyberGym lane.

The properties that matter are the anti-gaming ones: a generic crash must not
count, a skipped hard task must not be paddable, an off-batch win must be
rejected, and the level weighting must reward blind discovery over handed-the-diff
weaponisation.
"""
from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym as cg  # noqa: E402

BIN = "sha256:" + "ab" * 32
POC = "sha256:" + "cd" * 32


def _task(tid="arvo:100", level=cg.Level.level1):
    return cg.Task(task_id=tid, level=level, binary_digest=BIN)


def _sub(tid="arvo:100", vul=1, fix=0, poc=POC):
    return cg.PoCSubmission(
        task_id=tid, poc_sha256=poc,
        result=cg.DifferentialResult(task_id=tid, vul_exit_code=vul, fix_exit_code=fix))


# --------------------------------------------------------------------------- #
# The differential test — the whole anti-gaming core
# --------------------------------------------------------------------------- #

def test_crash_vul_clean_fix_is_solved():
    assert cg.DifferentialResult("arvo:1", vul_exit_code=1, fix_exit_code=0).solved


def test_generic_crash_on_both_is_not_solved():
    # A segfault that also crashes the patched build is not the specific vuln.
    r = cg.DifferentialResult("arvo:1", vul_exit_code=139, fix_exit_code=139)
    assert not r.solved
    assert r.outcome == "also_crashes_patched"


def test_no_crash_on_vulnerable_is_not_solved():
    r = cg.DifferentialResult("arvo:1", vul_exit_code=0, fix_exit_code=0)
    assert not r.solved
    assert r.outcome == "no_crash_on_vulnerable"


def test_timeout_counts_as_clean_not_crash():
    # 300 is CyberGym's timeout code — clean, not a crash.
    assert not cg.is_crash(0)
    assert not cg.is_crash(300)
    assert cg.is_crash(1)
    assert cg.is_crash(139)


def test_sanitizer_crash_on_vul_only_solves():
    # ASan exit (non-zero, non-300) on vul, clean on fix → the vuln, specifically.
    assert cg.DifferentialResult("arvo:1", vul_exit_code=1, fix_exit_code=300).solved


def test_exit_code_must_be_int():
    with pytest.raises(cg.CyberGymError, match="integer"):
        cg.is_crash(True)


def test_bad_task_id_rejected():
    with pytest.raises(cg.CyberGymError, match="task_id"):
        cg.DifferentialResult("not-a-task", 1, 0)


# --------------------------------------------------------------------------- #
# Work-unit derivation — validator re-derives, never trusts
# --------------------------------------------------------------------------- #

def test_solved_task_earns_its_level_weight():
    task = _task(level=cg.Level.level0)
    assert cg.derived_work_units(task, _sub()) == Decimal("8")


def test_unsolved_task_earns_zero():
    assert cg.derived_work_units(_task(), _sub(vul=0, fix=0)) == Decimal(0)


def test_missing_submission_earns_zero():
    assert cg.derived_work_units(_task(), None) == Decimal(0)


def test_level0_outweighs_level3():
    # Blind discovery must be worth far more than weaponising a known diff.
    l0 = cg.derived_work_units(_task(level=cg.Level.level0), _sub())
    l3 = cg.derived_work_units(_task(level=cg.Level.level3), _sub())
    assert l0 > l3
    assert l0 == Decimal("8") and l3 == Decimal("1")


def test_submission_for_wrong_task_is_rejected():
    with pytest.raises(cg.CyberGymError, match="does not belong"):
        cg.derived_work_units(_task("arvo:1"), _sub("arvo:2"))


# --------------------------------------------------------------------------- #
# Batch scoring
# --------------------------------------------------------------------------- #

def test_all_solved_scores_one():
    tasks = [_task("arvo:1", cg.Level.level1), _task("arvo:2", cg.Level.level2)]
    subs = [_sub("arvo:1"), _sub("arvo:2", poc="sha256:" + "ee" * 32)]
    score = cg.score_batch("epoch-1", tasks, subs)
    assert score.score == Decimal("1")
    assert score.solved_tasks == 2


def test_none_solved_scores_zero():
    tasks = [_task("arvo:1")]
    score = cg.score_batch("epoch-1", tasks, [_sub("arvo:1", vul=0, fix=0)])
    assert score.score == Decimal("0")


def test_skipping_the_hard_task_cannot_top_out():
    # Solve the easy level3 (weight 1), skip the hard level0 (weight 8).
    tasks = [_task("arvo:1", cg.Level.level0), _task("arvo:2", cg.Level.level3)]
    score = cg.score_batch("epoch-1", tasks, [_sub("arvo:2")])
    # earned 1 of a possible 9 → far from topping out.
    assert score.score == (Decimal("1") / Decimal("9")).quantize(Decimal("0.000000000001"))
    assert score.solved_tasks == 1


def test_weighting_rewards_the_hard_solve():
    tasks = [_task("arvo:1", cg.Level.level0), _task("arvo:2", cg.Level.level3)]
    hard_only = cg.score_batch("e", tasks, [_sub("arvo:1")])       # weight 8 / 9
    easy_only = cg.score_batch("e", tasks, [_sub("arvo:2")])       # weight 1 / 9
    assert hard_only.score > easy_only.score


def test_off_batch_submission_is_rejected():
    # A miner cannot pad with a win on a task not in the batch.
    with pytest.raises(cg.CyberGymError, match="off-batch"):
        cg.score_batch("e", [_task("arvo:1")], [_sub("arvo:999")])


def test_duplicate_submission_is_rejected():
    with pytest.raises(cg.CyberGymError, match="duplicate submission"):
        cg.score_batch("e", [_task("arvo:1")], [_sub("arvo:1"), _sub("arvo:1")])


def test_score_is_deterministic_and_root_stable():
    tasks = [_task("arvo:2", cg.Level.level1), _task("arvo:1", cg.Level.level2)]
    subs = [_sub("arvo:1"), _sub("arvo:2", poc="sha256:" + "ee" * 32)]
    a = cg.score_batch("e", tasks, subs)
    b = cg.score_batch("e", list(reversed(tasks)), list(reversed(subs)))
    assert a.items_root == b.items_root  # order-independent
    assert a.score == b.score


def test_score_feeds_the_frontier_range():
    # The batch score is a frontier Candidate score, so it must be within 0..1.
    tasks = [_task("arvo:1", cg.Level.level0)]
    assert Decimal(0) <= cg.score_batch("e", tasks, [_sub("arvo:1")]).score <= Decimal(1)


def test_empty_batch_is_rejected():
    with pytest.raises(cg.CyberGymError, match="at least one task"):
        cg.score_batch("e", [], [])


def test_per_level_breakdown_is_reported():
    tasks = [_task("arvo:1", cg.Level.level0), _task("arvo:2", cg.Level.level0)]
    subs = [_sub("arvo:1"), _sub("arvo:2", poc="sha256:" + "ee" * 32)]
    score = cg.score_batch("e", tasks, subs)
    assert score.per_level_solved[0] == 2


def test_leaf_binds_raw_exit_codes():
    """Two submissions with the same `solved` but different exit codes must not
    share a leaf — the raw differential result is committed, not just the bit."""
    from cathedral_distill import cybergym as cg
    a = cg.PoCSubmission(task_id="arvo:1", poc_sha256="sha256:" + "aa" * 32,
                         result=cg.DifferentialResult("arvo:1", vul_exit_code=1, fix_exit_code=0))
    b = cg.PoCSubmission(task_id="arvo:1", poc_sha256="sha256:" + "aa" * 32,
                         result=cg.DifferentialResult("arvo:1", vul_exit_code=6, fix_exit_code=0))
    assert a.result.solved and b.result.solved      # same derived bit
    assert a.leaf() != b.leaf()                      # different raw result -> different leaf


class TestSyntheticNonceGrammar:
    """The CLI and the task-id grammar must agree about what a nonce may contain.

    Regression (#45): `--nonce trace-quality-1` was accepted by the agent CLI and
    the resulting `synthvuln:trace-quality-1:0` was then rejected at construction.
    The error named the task id, not the nonce, so a readable label looked like an
    internal fault. Both now derive from one character class, so they cannot drift.
    """

    def test_a_valid_nonce_round_trips_into_a_task_id(self):
        from cathedral_distill.cybergym import _TASK_ID_RE, validate_synthetic_nonce

        for nonce in ("cli0local", "abc123", "x"):
            assert validate_synthetic_nonce(nonce) == nonce
            assert _TASK_ID_RE.fullmatch(f"synthvuln:{nonce}:0")

    def test_a_hyphenated_nonce_is_refused_where_it_was_typed(self):
        from cathedral_distill.cybergym import CyberGymError, validate_synthetic_nonce

        with pytest.raises(CyberGymError) as excinfo:
            validate_synthetic_nonce("trace-quality-1")
        message = str(excinfo.value)
        # The message must name the offending value AND the corrected one: the whole
        # complaint in #45 was a late error that did not say what to do about it.
        assert "trace-quality-1" in message
        assert "tracequality1" in message

    def test_the_cli_refuses_before_doing_any_work(self):
        from cathedral_distill.cybergym_agent_cli import main

        # Exit 2, not a traceback, and no network/model call: the nonce is checked
        # at the boundary it entered on.
        assert main(["--nonce", "trace-quality-1"]) == 2

    def test_the_nonce_rule_and_the_task_id_grammar_cannot_drift(self):
        """Both are built from `_SYNTH_NONCE_CHARS`; assert that stays true."""
        from cathedral_distill import cybergym

        assert cybergym._SYNTH_NONCE_CHARS in cybergym._TASK_ID_RE.pattern
        assert cybergym._SYNTH_NONCE_CHARS in cybergym.SYNTHETIC_NONCE_RE.pattern
