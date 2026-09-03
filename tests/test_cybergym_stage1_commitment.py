"""Commit-then-draw, made real (#136).

`evaluate_harness` refused a dispatch whose `model_commitment` was not the harness's digest
and the docstring called that commit-then-draw. It is not: the equality proves the dispatch
is LABELLED with this harness, not that the batch was drawn after the harness was frozen.
Nor could it be fixed in the nonce — `derive_epoch_batch_nonce` deliberately excludes the
commitment so every miner gets the SAME batch, and a common frontier cannot bind a per-miner
commitment.

The property that actually rules out tuning is an ORDERING: the harness was committed at a
block preceding the anchor block the batch was drawn from. These tests hold that ordering,
and — just as important — hold the line that an UNCHECKED claim is never presented as a
checked one.

Hardware-free: the crash backend is injected.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym_protocol as cp  # noqa: E402
from cathedral_distill import cybergym_stage1 as s1  # noqa: E402
from cathedral_distill.cybergym_verifier import poc_digest  # noqa: E402


def _dg(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


HARNESS = _dg("harness-v1")
TASKS = (("arvo:1", 0),)
ANCHOR = 5_000


def _dispatch(model_commitment=HARNESS):
    tasks = tuple(
        cp.DispatchedTask(task_id=tid, level=lvl, binary_digest=_dg(tid), context={})
        for tid, lvl in TASKS
    )
    return cp.DispatchMessage(
        network="finney", netuid=39, source_epoch=11, batch_id="batch-1", nonce="nonce",
        miner_hotkey="5Miner", model_commitment=model_commitment,
        valid_from_block=100, valid_until_block=460, tasks=tasks,
    )


def _submission(commitment_block=None):
    return s1.HarnessSubmission(
        miner_hotkey="5Miner", harness_digest=HARNESS, version="v1",
        commitment_block=commitment_block)


def _exploit(task_id: str) -> bytes:
    return b"exploit-" + task_id.encode()


def _backend(task_id, poc, mode):
    return 1 if mode == "vul" else 0


def _runner(submission, task, artifact):
    return _exploit(task.task_id)


def _evaluate(commitment_block=None, anchor_block=None):
    return s1.evaluate_harness(
        _submission(commitment_block), _dispatch(),
        runner=_runner, backend=_backend, anchor_block=anchor_block)


class TestTheOrderingIsEnforced:
    def test_a_harness_committed_before_the_anchor_is_verified(self):
        score = _evaluate(commitment_block=ANCHOR - 1, anchor_block=ANCHOR)
        assert score.commitment_verified is True
        assert score.solved == 1

    def test_a_harness_committed_after_the_anchor_is_refused(self):
        """The batch was drawable before the harness was frozen, so the score is not
        evidence of untuned capability — it is refused, not merely marked."""
        with pytest.raises(s1.HarnessError, match="does not precede"):
            _evaluate(commitment_block=ANCHOR + 1, anchor_block=ANCHOR)

    def test_committing_in_the_anchor_block_itself_is_refused(self):
        """Strictly less-than: a harness committed IN the anchor block is not provably
        ignorant of what that block drew, and a loose boundary is not a rule."""
        with pytest.raises(s1.HarnessError, match="does not precede"):
            _evaluate(commitment_block=ANCHOR, anchor_block=ANCHOR)


class TestAnUncheckedClaimIsNeverPresentedAsChecked:
    """The core of #136: the failure was not only a missing check, it was a docstring
    claiming a property nothing established. Absence must be visible in the output."""

    def test_without_an_anchor_the_score_is_unverified_not_refused(self):
        score = _evaluate(commitment_block=ANCHOR - 1, anchor_block=None)
        assert score.commitment_verified is False
        assert score.solved == 1  # still graded; only the freshness claim is withheld

    def test_without_a_commitment_block_the_score_is_unverified(self):
        assert _evaluate(commitment_block=None, anchor_block=ANCHOR).commitment_verified is False

    def test_the_default_is_unverified(self):
        """Never presumed. A score constructed without saying so is not verified."""
        assert s1.HarnessScore("5Miner", HARNESS, 0, ()).commitment_verified is False
        assert _evaluate().commitment_verified is False

    def test_a_verified_score_cannot_tie_with_an_unverified_one(self):
        """It rides in the consensus digest, so the distinction survives to any consumer
        comparing scores rather than living only in a docstring."""
        verified = _evaluate(commitment_block=ANCHOR - 1, anchor_block=ANCHOR)
        unverified = _evaluate()
        assert verified.solved == unverified.solved
        assert s1.consensus_digest(verified) != s1.consensus_digest(unverified)


class TestTheProofSurvivesIntoTheAttestedRecord:
    def test_the_commitment_block_is_carried_and_attested(self):
        score = _evaluate(commitment_block=ANCHOR - 1, anchor_block=ANCHOR)
        execution = s1.execution_from_score(score, _dispatch())
        assert execution.commitment_block == ANCHOR - 1
        # inside digest(), so the enclave attests it like everything else
        other_score = _evaluate(commitment_block=ANCHOR - 2, anchor_block=ANCHOR)
        assert execution.digest() != s1.execution_from_score(other_score, _dispatch()).digest()

    def test_the_block_cannot_diverge_from_the_submission(self):
        """`execution_from_score` reads the height off the SCORE. A caller-supplied block
        could name an earlier commitment than the submission had, and a re-grader would then
        verify a commitment that never happened."""
        import inspect
        assert "commitment_block" not in inspect.signature(s1.execution_from_score).parameters
        late = _evaluate(commitment_block=9999, anchor_block=None)   # unverified
        assert s1.execution_from_score(late, _dispatch()).commitment_block == 9999

    def test_a_hand_built_score_claiming_a_proof_it_cannot_carry_is_refused(self):
        forged = s1.HarnessScore("5Miner", HARNESS, 1, (), commitment_verified=True)
        with pytest.raises(s1.HarnessError, match="would drop the proof"):
            s1.execution_from_score(forged, _dispatch())

    def test_a_re_grader_reaches_the_same_verdict(self):
        """The whole point of carrying it: producer and validator agree on freshness."""
        score = _evaluate(commitment_block=ANCHOR - 1, anchor_block=ANCHOR)
        execution = s1.execution_from_score(score, _dispatch())
        regraded = s1.grade_committed_execution(
            execution, _dispatch(), backend=_backend,
            exploit_provider=lambda t: _exploit(t), anchor_block=ANCHOR)
        assert regraded.commitment_verified is True
        assert s1.consensus_digest(regraded) == s1.consensus_digest(score)


class TestTheGradingPathEnforcesItToo:
    def _execution(self, commitment_block):
        return s1.HarnessExecution(
            miner_hotkey="5Miner", harness_digest=HARNESS, batch_id="batch-1",
            commitment_block=commitment_block,
            runs=(s1.CommittedRun("arvo:1", poc_digest(_exploit("arvo:1"))),))

    def test_a_late_commitment_is_refused_at_grading(self):
        with pytest.raises(s1.HarnessError, match="does not precede"):
            s1.grade_committed_execution(
                self._execution(ANCHOR + 1), _dispatch(), backend=_backend,
                exploit_provider=lambda t: _exploit(t), anchor_block=ANCHOR)

    def test_a_record_without_a_commitment_block_grades_unverified(self):
        score = s1.grade_committed_execution(
            self._execution(None), _dispatch(), backend=_backend,
            exploit_provider=lambda t: _exploit(t), anchor_block=ANCHOR)
        assert score.solved == 1 and score.commitment_verified is False


class TestBlockHeightsAreValidated:
    @pytest.mark.parametrize("bad", [-1, True, 1.5, "5000"])
    def test_a_bad_commitment_block_is_refused(self, bad):
        with pytest.raises(s1.HarnessError, match="commitment_block"):
            _submission(commitment_block=bad)

    @pytest.mark.parametrize("bad", [-1, True, 2.5, "5000"])
    def test_a_bad_anchor_block_is_refused(self, bad):
        with pytest.raises(s1.HarnessError, match="anchor_block"):
            _evaluate(commitment_block=1, anchor_block=bad)

    def test_block_zero_is_a_real_height(self):
        """Genesis is a valid commitment height; `if not block` would wrongly drop it."""
        assert _submission(commitment_block=0).commitment_block == 0
        assert _evaluate(commitment_block=0, anchor_block=1).commitment_verified is True
