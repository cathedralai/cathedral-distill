"""Stage 1 harness-capability competition: run a committed general harness on a
fresh sealed batch and score it by GENUINE solves, using the same differential
verifier as the reward path. No traces are collected in Stage 1.

Hardware-free: the harness runner and the crash backend are both injected, so no
CyberGym binaries or TDX enclave are needed to exercise the scoring wiring.
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


def _dispatch(model_commitment=HARNESS, task_levels=(("arvo:1", 0), ("arvo:2", 2))):
    tasks = tuple(
        cp.DispatchedTask(task_id=tid, level=lvl, binary_digest=_dg(tid), context={})
        for tid, lvl in task_levels
    )
    return cp.DispatchMessage(
        network="finney", netuid=39, source_epoch=11, batch_id="batch-1", nonce="nonce",
        miner_hotkey="5Miner", model_commitment=model_commitment,
        valid_from_block=100, valid_until_block=460, tasks=tasks,
    )


def _submission(digest=HARNESS):
    return s1.HarnessSubmission(miner_hotkey="5Miner", harness_digest=digest, version="v1")


def _runner(produce_for):
    """A fake harness: emits exploit bytes for the listed task_ids, nothing else."""
    def run(submission, task, artifact):
        return b"exploit-" + task.task_id.encode() if task.task_id in produce_for else None
    return run


def _backend(crash_ids):
    """Injected differential: crash the vul build (only) for the listed task_ids."""
    def run(task_id, poc, mode):
        return 1 if (task_id in crash_ids and mode == "vul") else 0
    return run


# --------------------------------------------------------------------------- #
# Submission validation — fails closed
# --------------------------------------------------------------------------- #

def test_submission_rejects_bad_digest():
    with pytest.raises(s1.HarnessError):
        s1.HarnessSubmission(miner_hotkey="5Miner", harness_digest="deadbeef", version="v1")


def test_submission_rejects_empty_hotkey():
    with pytest.raises(s1.HarnessError):
        s1.HarnessSubmission(miner_hotkey="", harness_digest=HARNESS, version="v1")


def test_submission_rejects_bad_version():
    with pytest.raises(s1.HarnessError):
        s1.HarnessSubmission(miner_hotkey="5Miner", harness_digest=HARNESS, version="")
    with pytest.raises(s1.HarnessError):
        s1.HarnessSubmission(miner_hotkey="5Miner", harness_digest=HARNESS, version="x" * 33)


# --------------------------------------------------------------------------- #
# evaluate_harness — genuine solves only
# --------------------------------------------------------------------------- #

def test_scores_only_genuine_solves():
    # Harness emits an exploit for both tasks, but only arvo:1 actually crashes.
    score = s1.evaluate_harness(
        _submission(), _dispatch(),
        runner=_runner({"arvo:1", "arvo:2"}), backend=_backend({"arvo:1"}),
    )
    assert score.dispatched == 2
    assert score.solved == 1
    assert score.solve_rate == pytest.approx(0.5)
    by_id = {r.task_id: r for r in score.results}
    assert by_id["arvo:1"].solved is True
    assert by_id["arvo:1"].exploit_sha256 == poc_digest(b"exploit-arvo:1")
    assert by_id["arvo:2"].solved is False  # produced, but did not crash the vul build


def test_no_output_is_not_a_solve():
    score = s1.evaluate_harness(
        _submission(), _dispatch(),
        runner=_runner({"arvo:1"}), backend=_backend({"arvo:1", "arvo:2"}),
    )
    by_id = {r.task_id: r for r in score.results}
    assert by_id["arvo:1"].solved is True
    assert by_id["arvo:2"].solved is False
    assert by_id["arvo:2"].exploit_sha256 is None
    assert by_id["arvo:2"].reason == "harness_produced_no_exploit"


def test_empty_batch_scores_zero():
    score = s1.evaluate_harness(
        _submission(), _dispatch(task_levels=()),
        runner=_runner(set()), backend=_backend(set()),
    )
    assert score.dispatched == 0
    assert score.solved == 0
    assert score.solve_rate == 0


# --------------------------------------------------------------------------- #
# Commit-then-draw — enforced here, fails closed
# --------------------------------------------------------------------------- #

def test_rejects_dispatch_not_committed_to_harness():
    # The batch was frozen to a DIFFERENT commitment, so the harness could have
    # been tuned to its own graded set. Refuse to score it.
    other = _dispatch(model_commitment=_dg("some-other-model"))
    with pytest.raises(s1.HarnessError):
        s1.evaluate_harness(
            _submission(), other,
            runner=_runner({"arvo:1"}), backend=_backend({"arvo:1"}),
        )


# --------------------------------------------------------------------------- #
# Artifact plumbing — the harness only ever sees the challenge artifact
# --------------------------------------------------------------------------- #

def test_artifact_provider_is_queried_per_task():
    seen: list[str] = []

    def provider(task_id: str) -> bytes:
        seen.append(task_id)
        return b"challenge-" + task_id.encode()

    def run(submission, task, artifact):
        assert artifact == b"challenge-" + task.task_id.encode()
        return b"exploit-" + task.task_id.encode()

    s1.evaluate_harness(
        _submission(), _dispatch(), runner=run, backend=_backend({"arvo:1"}),
        artifact_provider=provider,
    )
    assert seen == ["arvo:1", "arvo:2"]


# --------------------------------------------------------------------------- #
# Ranking — most genuine solves first, deterministic
# --------------------------------------------------------------------------- #

def test_rank_orders_by_solves_then_digest():
    a = s1.HarnessScore("m1", _dg("aaa"), dispatched=3,
                        results=(s1.HarnessResult("t1", True, "sha256:x", "solved"),))
    b = s1.HarnessScore("m2", _dg("bbb"), dispatched=3, results=(
        s1.HarnessResult("t1", True, "sha256:x", "solved"),
        s1.HarnessResult("t2", True, "sha256:y", "solved"),
    ))
    c = s1.HarnessScore("m3", _dg("ccc"), dispatched=3, results=())
    ranked = s1.rank_harnesses([a, b, c])
    assert [s.miner_hotkey for s in ranked] == ["m2", "m1", "m3"]


def test_rank_tie_breaks_on_digest():
    # Equal solve counts → deterministic ascending-digest order (ungrindable by
    # resubmitting under a fresh hotkey).
    d1, d2 = _dg("aaa"), _dg("zzz")
    one = s1.HarnessScore("m1", d1, dispatched=1,
                          results=(s1.HarnessResult("t1", True, "sha256:x", "solved"),))
    two = s1.HarnessScore("m2", d2, dispatched=1,
                          results=(s1.HarnessResult("t1", True, "sha256:x", "solved"),))
    ranked = s1.rank_harnesses([two, one])
    assert [s.harness_digest for s in ranked] == sorted([d1, d2])
