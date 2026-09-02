"""Stage 1 consensus: one authoritative run, deterministic re-grading (#137).

`rank_harnesses` re-executed the harness at grade time and nothing required the harness to be
deterministic, so two honest validators could rank miners differently the moment this touched
weights. An enforced reproducibility contract for per-validator re-execution is not available:
the harness is a reasoning agent that must reach a model, and LLM sampling is not bit-identical
across independent runs. The half that IS deterministic is the differential — and #153/#166 made
that a guarantee rather than a hope.

So the harness runs ONCE, its per-task output is committed by digest, and every validator grades
those committed bytes. These tests hold that seam: divergence must be reproducible on the
execution path and impossible on the grading path.

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
TASKS = (("arvo:1", 0), ("arvo:2", 2))


def _dispatch(model_commitment=HARNESS, task_levels=TASKS, batch_id="batch-1",
              miner_hotkey="5Miner"):
    tasks = tuple(
        cp.DispatchedTask(task_id=tid, level=lvl, binary_digest=_dg(tid), context={})
        for tid, lvl in task_levels
    )
    return cp.DispatchMessage(
        network="finney", netuid=39, source_epoch=11, batch_id=batch_id, nonce="nonce",
        miner_hotkey=miner_hotkey, model_commitment=model_commitment,
        valid_from_block=100, valid_until_block=460, tasks=tasks,
    )


def _submission(digest=HARNESS):
    return s1.HarnessSubmission(miner_hotkey="5Miner", harness_digest=digest, version="v1")


def _solving_backend(solving: set[bytes]):
    """vul crashes and fix is clean exactly for the listed exploit bytes."""
    def backend(task_id, poc, mode):
        if poc in solving:
            return 1 if mode == "vul" else 0
        return 0
    return backend


def _exploit(task_id: str) -> bytes:
    return b"exploit-" + task_id.encode()


def _execution(runs, *, harness_digest=HARNESS, batch_id="batch-1", miner_hotkey="5Miner"):
    return s1.HarnessExecution(
        miner_hotkey=miner_hotkey, harness_digest=harness_digest, batch_id=batch_id,
        runs=tuple(runs),
    )


def _committed_all_solving():
    """The committed record of a run that produced a solving exploit for every task."""
    return _execution(
        s1.CommittedRun(task_id=tid, exploit_sha256=poc_digest(_exploit(tid)))
        for tid, _ in TASKS
    )


def _provider(mapping):
    return lambda task_id: mapping.get(task_id)


class TestTheProblemIsReal:
    """A nondeterministic harness makes `evaluate_harness` disagree with itself. This is the
    divergence #137 is about; it is pinned so the fix cannot be mistaken for a no-op."""

    def test_two_evaluations_of_one_nondeterministic_harness_disagree(self):
        # One harness, two runs: sampling landed well the first time and badly the second.
        outcomes = iter([True, True, False, False])

        def runner(submission, task, artifact):
            return _exploit(task.task_id) if next(outcomes) else None

        backend = _solving_backend({_exploit(t) for t, _ in TASKS})
        first = s1.evaluate_harness(_submission(), _dispatch(), runner=runner, backend=backend)
        second = s1.evaluate_harness(_submission(), _dispatch(), runner=runner, backend=backend)
        assert (first.solved, second.solved) == (2, 0)
        assert s1.consensus_digest(first) != s1.consensus_digest(second)


class TestGradingCommittedBytesCannotDiverge:
    def test_two_validators_derive_identical_scores_and_digests(self):
        execution = _committed_all_solving()
        provider = _provider({tid: _exploit(tid) for tid, _ in TASKS})
        backend = _solving_backend({_exploit(t) for t, _ in TASKS})

        a = s1.grade_committed_execution(
            execution, _dispatch(), backend=backend, exploit_provider=provider)
        b = s1.grade_committed_execution(
            execution, _dispatch(), backend=backend, exploit_provider=provider)
        assert a == b
        assert s1.consensus_digest(a) == s1.consensus_digest(b)
        assert a.solved == 2

    def test_it_takes_no_runner_at_all(self):
        """The structural guarantee: there is no seam for the harness to run again on."""
        import inspect
        assert "runner" not in inspect.signature(s1.grade_committed_execution).parameters

    def test_a_nonsolving_exploit_scores_zero_not_an_error(self):
        execution = _committed_all_solving()
        provider = _provider({tid: _exploit(tid) for tid, _ in TASKS})
        score = s1.grade_committed_execution(
            execution, _dispatch(), backend=_solving_backend(set()), exploit_provider=provider)
        assert score.solved == 0
        assert all(r.reason == "no_crash_on_vulnerable" for r in score.results)


class TestBindingsFailClosedBeforeAnythingIsGraded:
    def test_an_execution_for_another_harness_is_refused(self):
        """Commit-then-draw: the same contract `evaluate_harness` enforces."""
        execution = _execution([], harness_digest=_dg("other-harness"))
        with pytest.raises(s1.HarnessError, match="commit-then-draw"):
            s1.grade_committed_execution(
                execution, _dispatch(), backend=_solving_backend(set()),
                exploit_provider=_provider({}))

    def test_an_execution_for_another_batch_is_refused(self):
        """Otherwise a strong run on an easy batch is replayed against a harder one."""
        execution = _execution([], batch_id="batch-OTHER")
        with pytest.raises(s1.HarnessError, match="batch"):
            s1.grade_committed_execution(
                execution, _dispatch(), backend=_solving_backend(set()),
                exploit_provider=_provider({}))

    def test_an_execution_for_another_miner_is_refused(self):
        execution = _execution([], miner_hotkey="5Someone")
        with pytest.raises(s1.HarnessError, match="different miner"):
            s1.grade_committed_execution(
                execution, _dispatch(), backend=_solving_backend(set()),
                exploit_provider=_provider({}))


class TestACommitmentThatDoesNotHoldCannotEarn:
    def test_substituted_bytes_are_refused_not_credited(self):
        """The attack the commitment exists to stop: the bytes graded are not the bytes
        attested. It must score unsolved even though the substitute genuinely solves."""
        execution = _committed_all_solving()
        substitute = b"a-different-exploit"
        backend = _solving_backend({substitute})  # the substitute WOULD solve
        score = s1.grade_committed_execution(
            execution, _dispatch(), backend=backend,
            exploit_provider=_provider({tid: substitute for tid, _ in TASKS}))
        assert score.solved == 0
        assert all(r.reason == s1.REASON_DIGEST_MISMATCH for r in score.results)

    def test_an_unavailable_exploit_scores_unsolved(self):
        execution = _committed_all_solving()
        score = s1.grade_committed_execution(
            execution, _dispatch(), backend=_solving_backend(set()),
            exploit_provider=_provider({}))
        assert score.solved == 0
        assert all(r.reason == s1.REASON_EXPLOIT_MISSING for r in score.results)

    def test_a_committed_no_output_scores_unsolved(self):
        execution = _execution(
            s1.CommittedRun(task_id=tid, exploit_sha256=None) for tid, _ in TASKS)
        score = s1.grade_committed_execution(
            execution, _dispatch(), backend=_solving_backend(set()),
            exploit_provider=_provider({}))
        assert score.solved == 0
        assert all(r.reason == s1.REASON_NO_EXPLOIT for r in score.results)

    def test_a_task_missing_from_the_execution_scores_unsolved(self):
        """Dropping a task must not shrink the denominator — `dispatched` follows the
        DISPATCH, so omitting hard tasks cannot raise a solve rate."""
        execution = _execution([
            s1.CommittedRun(task_id="arvo:1", exploit_sha256=poc_digest(_exploit("arvo:1")))])
        score = s1.grade_committed_execution(
            execution, _dispatch(), backend=_solving_backend({_exploit("arvo:1")}),
            exploit_provider=_provider({"arvo:1": _exploit("arvo:1")}))
        assert score.dispatched == 2
        assert score.solved == 1
        missing = [r for r in score.results if r.task_id == "arvo:2"]
        assert missing[0].reason == s1.REASON_NOT_IN_EXECUTION

    def test_one_bad_row_does_not_discard_the_honest_rest(self):
        execution = _execution([
            s1.CommittedRun(task_id="arvo:1", exploit_sha256=poc_digest(_exploit("arvo:1"))),
            s1.CommittedRun(task_id="arvo:2", exploit_sha256=poc_digest(_exploit("arvo:2"))),
        ])
        score = s1.grade_committed_execution(
            execution, _dispatch(),
            backend=_solving_backend({_exploit("arvo:1"), b"wrong"}),
            exploit_provider=_provider({"arvo:1": _exploit("arvo:1"), "arvo:2": b"wrong"}))
        assert score.solved == 1
        assert [r.reason for r in score.results][1] == s1.REASON_DIGEST_MISMATCH


class TestTheConsensusDigestReportsOnlyRealDisagreement:
    def _score(self, **overrides):
        base = dict(log_sha256=None, exit_reason="", duration_ms=None)
        base.update(overrides)
        return s1.HarnessScore(
            miner_hotkey="5Miner", harness_digest=HARNESS, dispatched=1,
            results=(s1.HarnessResult("arvo:1", True, poc_digest(b"x"), "solved", **base),))

    def test_validator_local_fields_do_not_change_it(self):
        """Wall time is validator-local; the log reference and terminal reason describe how
        the run went, not what it scored. Folding them in would report divergence where the
        rank does not differ."""
        assert (s1.consensus_digest(self._score(duration_ms=10))
                == s1.consensus_digest(self._score(duration_ms=999_999)))
        assert (s1.consensus_digest(self._score(log_sha256=_dg("a")))
                == s1.consensus_digest(self._score(log_sha256=_dg("b"))))
        assert (s1.consensus_digest(self._score(exit_reason="solved"))
                == s1.consensus_digest(self._score(exit_reason="")))

    @pytest.mark.parametrize("field,value", [
        ("solved", False), ("exploit_sha256", poc_digest(b"other")), ("reason", "other"),
    ])
    def test_a_ranking_relevant_difference_does_change_it(self, field, value):
        base = s1.HarnessResult("arvo:1", True, poc_digest(b"x"), "solved")
        from dataclasses import replace
        changed = s1.HarnessScore(
            miner_hotkey="5Miner", harness_digest=HARNESS, dispatched=1,
            results=(replace(base, **{field: value}),))
        assert s1.consensus_digest(self._score()) != s1.consensus_digest(changed)

    def test_row_order_does_not_change_it(self):
        rows = (s1.HarnessResult("arvo:1", True, poc_digest(b"x"), "solved"),
                s1.HarnessResult("arvo:2", False, None, "no_crash_on_vulnerable"))
        forward = s1.HarnessScore("5Miner", HARNESS, 2, rows)
        reversed_ = s1.HarnessScore("5Miner", HARNESS, 2, tuple(reversed(rows)))
        assert s1.consensus_digest(forward) == s1.consensus_digest(reversed_)

    def test_the_identity_being_ranked_is_covered(self):
        mine = s1.HarnessScore("5Miner", HARNESS, 1, ())
        theirs = s1.HarnessScore("5Other", HARNESS, 1, ())
        assert s1.consensus_digest(mine) != s1.consensus_digest(theirs)


class TestTheProducerRecord:
    def test_a_graded_run_projects_onto_a_committable_execution(self):
        backend = _solving_backend({_exploit(t) for t, _ in TASKS})

        def runner(submission, task, artifact):
            return _exploit(task.task_id)

        score = s1.evaluate_harness(_submission(), _dispatch(), runner=runner, backend=backend)
        execution = s1.execution_from_score(score, _dispatch())
        assert execution.harness_digest == HARNESS
        assert execution.batch_id == "batch-1"
        assert {r.task_id for r in execution.runs} == {t for t, _ in TASKS}
        regraded = s1.grade_committed_execution(
            execution, _dispatch(), backend=backend,
            exploit_provider=_provider({tid: _exploit(tid) for tid, _ in TASKS}))
        assert s1.consensus_digest(regraded) == s1.consensus_digest(score)


    def test_a_score_for_another_miner_cannot_be_committed(self):
        """Fail where the batch it was graded against is still in hand, not later."""
        score = s1.HarnessScore("5Someone", HARNESS, 0, ())
        with pytest.raises(s1.HarnessError, match="different miners"):
            s1.execution_from_score(score, _dispatch())


class TestTheExecutionDigestIsWhatGetsAttested:
    """'Run once with ATTESTED committed bytes' needs ONE value to attest — the enclave binds
    this into its quote, so a validator checks it is grading what the hardware signed."""

    def test_it_is_stable_and_order_insensitive(self):
        runs = [s1.CommittedRun("arvo:1", poc_digest(b"a")),
                s1.CommittedRun("arvo:2", poc_digest(b"b"))]
        assert _execution(runs).digest() == _execution(list(reversed(runs))).digest()

    @pytest.mark.parametrize("kwargs", [
        {"harness_digest": _dg("other")}, {"batch_id": "batch-2"}, {"miner_hotkey": "5Other"},
    ])
    def test_every_binding_is_covered(self, kwargs):
        runs = [s1.CommittedRun("arvo:1", poc_digest(b"a"))]
        assert _execution(runs).digest() != _execution(runs, **kwargs).digest()

    def test_a_changed_committed_exploit_changes_it(self):
        assert (_execution([s1.CommittedRun("arvo:1", poc_digest(b"a"))]).digest()
                != _execution([s1.CommittedRun("arvo:1", poc_digest(b"b"))]).digest())

    def test_it_is_a_well_formed_digest(self):
        assert s1._DIGEST_RE.match(_committed_all_solving().digest())


class TestTheRecordRefusesMalformedInput:
    def test_repeated_task_ids_are_refused(self):
        """Two runs for one task would let a re-grader pick whichever scored better."""
        with pytest.raises(s1.HarnessError, match="ids repeat"):
            _execution([s1.CommittedRun("arvo:1", None), s1.CommittedRun("arvo:1", None)])

    @pytest.mark.parametrize("bad", ["", "sha256:xyz", "deadbeef", "sha256:" + "g" * 64])
    def test_a_malformed_exploit_digest_is_refused(self, bad):
        with pytest.raises(s1.HarnessError, match="exploit_sha256"):
            s1.CommittedRun(task_id="arvo:1", exploit_sha256=bad)

    def test_a_malformed_harness_digest_is_refused(self):
        with pytest.raises(s1.HarnessError, match="harness_digest"):
            _execution([], harness_digest="not-a-digest")

    def test_a_run_needs_a_task_id(self):
        with pytest.raises(s1.HarnessError, match="task_id"):
            s1.CommittedRun(task_id="", exploit_sha256=None)
