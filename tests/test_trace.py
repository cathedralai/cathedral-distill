"""Tests for cathedral_trace_v1.

The properties that matter: an unverified trace cannot become training data, a
trace that only observed cannot claim success, and steps that cannot be replayed
are excluded from evaluation rather than silently accepted.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import trace as tr  # noqa: E402

IMAGE = "ghcr.io/cathedralai/desktop@sha256:" + "ab" * 32


def _obs(n=0):
    return tr.Observation(kind="app_state", digest="sha256:" + f"{n:064x}",
                          summary=f"window with {n} elements", element_count=n)


def _steps(coordinate_only=False, observe_only=False):
    steps = [tr.Step(step=0, reasoning="Observe the app before acting on it.",
                     tool="get_app_state", observation=_obs(12))]
    if not observe_only:
        if coordinate_only:
            steps.append(tr.Step(
                step=1, reasoning="No accessibility element exposed, falling back to pixels.",
                tool="click", coordinates={"x": 400, "y": 300}, observation=_obs(12)))
        else:
            steps.append(tr.Step(
                step=1,
                reasoning="The toolbar exposes both Save and Save As; the task says "
                          "overwrite, so the plain Save at index 12 is correct.",
                tool="click", element_index=12, observation=_obs(12)))
    steps.append(tr.Step(step=len(steps), reasoning="Title bar no longer shows a "
                         "modified marker, so the file was written.",
                         tool="done", outcome_claim="titlebar shows saved state"))
    return steps


def _trace(passed=True, **kw):
    opts = dict(coordinate_only=False, observe_only=False)
    opts.update({k: kw.pop(k) for k in list(kw) if k in opts})
    # `steps` may legitimately be an empty list, so test for presence rather
    # than truthiness.
    steps = kw.pop("steps") if "steps" in kw else _steps(**opts)
    kw.setdefault("desktop_image", IMAGE)
    return tr.Trace(
        task_id="task-001", goal="Save the open document",
        steps=steps,
        predicate=tr.Predicate(kind="file_exists", detail={"path": "/tmp/doc.txt"},
                               passed=passed, observed="file present"),
        teacher_id="yunwu/kimi-k2.6/relay-2026-07",
        outcome="done", recorded_at="2026-07-27T04:00:00Z", **kw)


# --------------------------------------------------------------------------- #
# Trainability
# --------------------------------------------------------------------------- #

def test_passing_trace_is_trainable():
    assert _trace().trainable()


def test_failed_predicate_is_never_trainable():
    assert not _trace(passed=False).trainable()
    assert list(tr.to_training_rows(_trace(passed=False))) == []


def test_observe_only_trace_cannot_claim_success():
    # A passing predicate is not enough: the agent must have changed something.
    t = _trace(observe_only=True)
    assert t.predicate.passed
    assert not t.trainable()


def test_terminal_step_requires_an_outcome_claim():
    with pytest.raises(tr.TraceError, match="outcome_claim"):
        tr.Step(step=0, reasoning="finished the task somehow", tool="done")


# --------------------------------------------------------------------------- #
# Replayability
# --------------------------------------------------------------------------- #

def test_semantic_step_is_replayable():
    # the click and the done; the get_app_state observation is not an item
    assert len(_trace().replayable_steps()) == 2


def test_deciding_to_stop_is_gradeable():
    """A model that never stops is the documented collapse mode."""
    tools = [s.tool for s in _trace().replayable_steps()]
    assert "done" in tools


def test_coordinate_only_step_is_excluded():
    t = _trace(coordinate_only=True)
    assert [s.tool for s in t.replayable_steps()] == ["done"]
    # Still trainable — it did act — but it yields no evaluation items.
    assert t.trainable()


def test_observations_are_never_eval_items():
    for step in _trace().replayable_steps():
        assert not step.is_observation


# --------------------------------------------------------------------------- #
# Integrity
# --------------------------------------------------------------------------- #

def test_desktop_image_must_be_digest_pinned():
    with pytest.raises(tr.TraceError, match="pinned by digest"):
        _trace(desktop_image="ghcr.io/cathedralai/desktop:latest")


def test_step_indices_must_be_contiguous():
    steps = _steps()
    broken = [steps[0], tr.Step(step=7, reasoning="out of order step here",
                                tool="click", element_index=1), steps[-1]]
    with pytest.raises(tr.TraceError, match="contiguous"):
        _trace(steps=broken)


def test_empty_trace_is_rejected():
    with pytest.raises(tr.TraceError, match="at least one step"):
        _trace(steps=[])


def test_trace_id_is_content_addressed():
    assert _trace().trace_id == _trace().trace_id
    other = _trace()
    assert tr.Trace(
        task_id="task-002", goal=other.goal, steps=other.steps,
        predicate=other.predicate, teacher_id=other.teacher_id,
        desktop_image=other.desktop_image, outcome=other.outcome,
        recorded_at=other.recorded_at).trace_id != other.trace_id


def test_step_hash_covers_reasoning():
    a = tr.Step(step=0, reasoning="Clicked Save because the task says overwrite.",
                tool="click", element_index=3)
    b = tr.Step(step=0, reasoning="Clicked Save for some other reason entirely.",
                tool="click", element_index=3)
    assert a.step_hash() != b.step_hash()


def test_observation_digest_must_be_sha256():
    with pytest.raises(tr.TraceError, match="sha256"):
        tr.Observation(kind="app_state", digest="deadbeef", summary="x")


# --------------------------------------------------------------------------- #
# Training rows
# --------------------------------------------------------------------------- #

def test_training_rows_carry_goal_history_and_reasoning():
    rows = list(tr.to_training_rows(_trace()))
    assert len(rows) == 2
    row = rows[0]
    assert row["goal"] == "Save the open document"
    assert "Save As" in row["target_reasoning"]
    assert row["target_action"]["element_index"] == 12
    # History holds the prior observation step, without its pixels.
    assert row["history"][0]["tool"] == "get_app_state"


def test_history_grows_but_carries_no_stale_observations():
    steps = [
        tr.Step(step=0, reasoning="Observe first, indices renumber constantly.",
                tool="get_app_state", observation=_obs(5)),
        tr.Step(step=1, reasoning="Activate the file menu at index 2 to reach Save.",
                tool="click", element_index=2, observation=_obs(5)),
        tr.Step(step=2, reasoning="Save entry is index 7 within the opened menu.",
                tool="click", element_index=7, observation=_obs(9)),
        tr.Step(step=3, reasoning="Titlebar modified marker is gone.",
                tool="done", outcome_claim="saved"),
    ]
    rows = list(tr.to_training_rows(_trace(steps=steps)))
    assert len(rows) == 3
    assert len(rows[1]["history"]) == 2
    assert all("observation" not in h for h in rows[1]["history"])


def test_corpus_stats_report_what_survives():
    stats = tr.corpus_stats([_trace(), _trace(passed=False),
                             _trace(coordinate_only=True)])
    assert stats["traces"] == 3
    assert stats["trainable"] == 2          # the failed-predicate one is out
    # trace 1 gives click+done, the coordinate-only trace gives done alone,
    # and the failed-predicate trace gives nothing.
    assert stats["training_rows"] == 3
    assert stats["coordinate_only_steps"] == 1
    assert stats["predicate_pass_rate"] == pytest.approx(2 / 3, abs=1e-4)
