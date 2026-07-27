"""Desktop traces: `cathedral_trace_v1`.

A trace is one attempt at one desktop task — the observations the agent saw, the
actions it chose, why it chose them, and whether the task's predicate passed.

The same artifact serves both halves of the track, which is the point:

- **training data** — each step becomes `(observation, goal, history) -> action`
- **evaluation items** — the *same* steps, replayed, with the recorded action as
  ground truth

That duality is what makes computer use measurable at all. Driving a live
desktop is not reproducible: window managers race, animations land differently,
focus wanders. We measured the analogous problem on a hosted relay, where the
same model at temperature 0 gave different answers across calls and five of
seven apparent failures passed on retry. A leaderboard built on live desktop
scoring would be measuring the desktop.

So the desktop runs **once**, during generation, where nondeterminism is
harmless — a flaky episode simply fails its predicate and is discarded.
Evaluation then replays frozen observations, which is exactly as deterministic
as any other sealed set.

Two rules the schema enforces rather than documents:

**Only predicate-passing traces are trainable.** `trainable()` returns False
otherwise. Today's benchmark showed a student can exceed its teacher when the
corpus is filtered to verified-correct demonstrations; the same filter applies
here, and a trace that merely *claims* success is the most damaging row a corpus
can contain.

**Coordinate-only steps are marked, not silently accepted.** An action targeted
by pixel cannot be replayed at a different resolution or after a window moves,
so it is weak as training data and unusable as an eval item.
`replayable_steps()` counts what actually survives.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Sequence

TRACE_SCHEMA = "cathedral_trace_v1"
STEP_DOMAIN = b"cathedral-trace-step-v1\x00"
TRACE_DOMAIN = b"cathedral-trace-v1\x00"

MAX_STEPS = 200
MAX_REASONING_CHARS = 4000

# Tools that observe without changing desktop state. A trace made only of these
# accomplished nothing, whatever its predicate says.
OBSERVATION_TOOLS = frozenset(
    {"get_app_state", "screenshot", "list_windows", "list_apps", "focused_window"}
)
TERMINAL_TOOLS = frozenset({"done", "blocked"})


class TraceError(ValueError):
    """Raised when a trace or step is malformed."""


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class Observation:
    """What the agent could see when it chose an action.

    Stored by digest plus a compact summary rather than by raw pixels: a corpus
    of full screenshots is enormous, and the digest is what binds an action to
    the exact input it was chosen from.
    """

    kind: str  # app_state | screenshot | window_list
    digest: str
    summary: str
    element_count: int = 0

    def __post_init__(self) -> None:
        if not self.digest.startswith("sha256:"):
            raise TraceError("observation digest must be sha256:")


@dataclass(frozen=True)
class Step:
    """One action, with the reasoning that produced it."""

    step: int
    reasoning: str
    tool: str
    observation: Observation | None = None
    element_index: int | None = None
    selector: str | None = None
    coordinates: Mapping[str, int] | None = None
    text: str | None = None
    keys: str | None = None
    target_window: str | None = None
    action_name: str | None = None
    outcome_claim: str | None = None

    def __post_init__(self) -> None:
        if self.step < 0:
            raise TraceError("step index must be non-negative")
        if len(self.reasoning) > MAX_REASONING_CHARS:
            raise TraceError("reasoning exceeds maximum length")
        if self.tool in TERMINAL_TOOLS and not self.outcome_claim:
            raise TraceError(f"{self.tool} requires an outcome_claim")

    @property
    def is_observation(self) -> bool:
        return self.tool in OBSERVATION_TOOLS

    @property
    def is_terminal(self) -> bool:
        return self.tool in TERMINAL_TOOLS

    @property
    def semantically_targeted(self) -> bool:
        """Whether this step can be replayed on a different desktop layout.

        Element indices and selectors survive a window moving; raw coordinates
        do not. Observation and terminal steps need no target at all.
        """
        if self.is_observation or self.is_terminal:
            return True
        return self.element_index is not None or bool(self.selector)

    def as_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "step": self.step,
            "reasoning": self.reasoning,
            "action": {
                "tool": self.tool,
                "element_index": self.element_index,
                "selector": self.selector,
                "coordinates": dict(self.coordinates) if self.coordinates else None,
                "text": self.text,
                "keys": self.keys,
                "target_window": self.target_window,
                "action_name": self.action_name,
                "outcome_claim": self.outcome_claim,
            },
        }
        if self.observation is not None:
            body["observation"] = {
                "kind": self.observation.kind,
                "digest": self.observation.digest,
                "summary": self.observation.summary,
                "element_count": self.observation.element_count,
            }
        return body

    def step_hash(self) -> str:
        return "sha256:" + hashlib.sha256(
            STEP_DOMAIN + _canonical(self.as_dict())
        ).hexdigest()


@dataclass(frozen=True)
class Predicate:
    """The task's success test, evaluated against desktop state, not agent claims."""

    kind: str  # file_exists | file_hash | element_state | process_running | custom
    detail: Mapping[str, Any]
    passed: bool
    observed: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": dict(self.detail),
            "passed": self.passed,
            "observed": self.observed,
        }


@dataclass(frozen=True)
class Trace:
    """One complete episode."""

    task_id: str
    goal: str
    steps: Sequence[Step]
    predicate: Predicate
    teacher_id: str
    desktop_image: str
    outcome: str  # done | blocked | exhausted
    recorded_at: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.task_id or not self.goal:
            raise TraceError("task_id and goal are required")
        if not self.steps:
            raise TraceError("a trace must contain at least one step")
        if len(self.steps) > MAX_STEPS:
            raise TraceError("trace exceeds maximum steps")
        if not self.desktop_image.count("@sha256:"):
            # The environment is part of the measurement. A tag can be
            # repointed; a digest cannot, so a trace recorded against a tag
            # cannot be reproduced later.
            raise TraceError("desktop_image must be pinned by digest")
        expected = list(range(len(self.steps)))
        if [s.step for s in self.steps] != expected:
            raise TraceError("step indices must be contiguous from zero")

    def trainable(self) -> bool:
        """Whether this trace may enter a corpus.

        Requires a passing predicate and at least one action that changed
        something. An agent that only observed and then declared success is the
        exact failure the filter exists to catch.
        """
        if not self.predicate.passed:
            return False
        return any(
            not step.is_observation and not step.is_terminal for step in self.steps
        )

    def replayable_steps(self) -> list[Step]:
        """Steps usable as evaluation items, and as training rows.

        Excludes observations, which have nothing to predict, and
        coordinate-only steps, which cannot be replayed on a different layout.

        Terminal steps are deliberately *included*. Choosing to stop is a real
        decision and a gradeable one: a model that never emits `done` runs until
        its budget dies, which is the documented collapse mode for
        chain-of-thought-distilled students. Training and evaluation share this
        filter so the two can never drift apart.
        """
        return [
            step
            for step in self.steps
            if not step.is_observation and step.semantically_targeted
        ]

    def as_dict(self) -> dict[str, Any]:
        body = {
            "schema": TRACE_SCHEMA,
            "task_id": self.task_id,
            "goal": self.goal,
            "teacher_id": self.teacher_id,
            "desktop_image": self.desktop_image,
            "outcome": self.outcome,
            "recorded_at": self.recorded_at,
            "predicate": self.predicate.as_dict(),
            "steps": [step.as_dict() for step in self.steps],
            "metadata": dict(self.metadata),
        }
        body["trace_id"] = "sha256:" + hashlib.sha256(
            TRACE_DOMAIN + _canonical(body)
        ).hexdigest()
        return body

    @property
    def trace_id(self) -> str:
        return self.as_dict()["trace_id"]


def to_training_rows(trace: Trace) -> Iterator[dict[str, Any]]:
    """Expand a trace into `(context) -> action` training rows.

    History is carried as prior reasoning and actions rather than prior
    observations: replaying stale screenshots would bloat context and teach the
    student to attend to a screen that has since changed.
    """
    if not trace.trainable():
        return
    eligible = {id(step) for step in trace.replayable_steps()}
    history: list[dict[str, Any]] = []
    for step in trace.steps:
        if id(step) in eligible:
            yield {
                "task_id": trace.task_id,
                "goal": trace.goal,
                "step": step.step,
                "observation": (
                    step.observation.summary if step.observation else ""
                ),
                "observation_digest": (
                    step.observation.digest if step.observation else ""
                ),
                "history": list(history),
                "target_reasoning": step.reasoning,
                "target_action": step.as_dict()["action"],
                "trace_id": trace.trace_id,
            }
        history.append(
            {"step": step.step, "tool": step.tool, "reasoning": step.reasoning}
        )


def corpus_stats(traces: Sequence[Trace]) -> dict[str, Any]:
    """Summary of what a set of traces is actually worth."""
    trainable = [t for t in traces if t.trainable()]
    rows = sum(len(list(to_training_rows(t))) for t in trainable)
    coordinate_only = sum(
        1
        for t in traces
        for s in t.steps
        if not s.is_observation and not s.is_terminal and not s.semantically_targeted
    )
    return {
        "traces": len(traces),
        "trainable": len(trainable),
        "predicate_pass_rate": (
            round(len(trainable) / len(traces), 4) if traces else 0.0
        ),
        "training_rows": rows,
        "coordinate_only_steps": coordinate_only,
        "teachers": sorted({t.teacher_id for t in traces}),
    }
