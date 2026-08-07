"""The trace-submission contract and its structural quality gate.

A verified PoC proves a bug was found. The *reasoning trace* that produced it —
how the agent navigated the code, why it chose that input — is the training
feedstock for the next student, and it is often worth more than any single
model. But a subnet pays for a *score*, so a flat
"bonus for any trace" pays a two-step garbage trace as much as a real reasoning
chain, and the corpus fills with noise.

This module is the gate. It is deliberately **structural**, not semantic: it
checks shape (step count, tool coverage, reasoning length, concrete file
references, no padded loops) with no model in the loop. That matters twice —
it is cheap to run on every submission, and it cannot itself be gamed by spending
compute, because there is no model to fool. Real quality filtering (does the
reasoning actually lead to the PoC?) happens later, at corpus-curation time, on
the already-verified subset.

The bonus only pays a trace that clears the floor. Two things ride alongside it:
the reuse **licence** must be explicit (or the corpus cannot be trained on), and
the **model attribution** must be sealed (or a miner can claim a small open model
produced a trace a frontier API generated, poisoning the model-attribution the
whole distillation loop depends on).
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Sequence

TRACE_SUBMISSION_SCHEMA = "cathedral_trace_submission_v1"
TRACE_SUBMISSION_DOMAIN = b"cathedral-trace-submission-v1\x00"

# A file:line reference, e.g. "valid.c:1897" — evidence the agent reasoned over
# actual source rather than emitting plausible prose.
_FILE_REF_RE = re.compile(r"[A-Za-z0-9_./-]+\.[A-Za-z0-9_]+:\d+")

# Sentence boundaries for the padding check. Deliberately crude: this is a
# structural floor, not a parser.
_SENTENCE_SPLIT_RE = re.compile(r"[;.]")
_MIN_SENTENCE_WORDS = 5


@dataclass(frozen=True)
class TraceQualityPolicy:
    """The structural floor. Set once, pinned; a mechanism parameter, not a knob."""

    min_steps: int = 5
    required_actions: frozenset[str] = frozenset({"read_file", "write_poc"})
    min_reasoning_tokens: int = 200
    min_file_refs: int = 2
    max_action_repeat: int = 3
    # How many times one sentence may repeat INSIDE a single step's thought.
    # min_reasoning_tokens counts words, so it is cleared by repeating a
    # sentence until the count is met. This is the same padding trick that
    # max_action_repeat already catches on the action field, applied to the
    # text field instead.
    #
    # Measured across the 161 traces this suite builds: 158 never repeat a
    # sentence within a step at all, and the padded ones sit at 6, 9 and 19.
    # A cap of 2 sits in that gap with room on both sides, so it is not
    # tuned to squeeze between adjacent samples.
    max_sentence_repeat: int = 2


@dataclass(frozen=True)
class TraceStep:
    """One step of the agent's trajectory."""

    step: int
    thought: str
    action: str
    output: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "thought": self.thought,
            "action": self.action,
            "output": self.output,
        }


@dataclass(frozen=True)
class TraceQualityResult:
    """Whether a trace clears the floor, and if not, exactly why."""

    passed: bool
    failures: tuple[str, ...] = field(default_factory=tuple)

    @property
    def reason(self) -> str:
        return "trace_ok" if self.passed else ",".join(self.failures)


def check_trace_quality(
    steps: Sequence[TraceStep], policy: TraceQualityPolicy = TraceQualityPolicy()
) -> TraceQualityResult:
    """Run the structural floor. All checks are cheap and model-free."""
    failures: list[str] = []

    if len(steps) < policy.min_steps:
        failures.append("too_few_steps")

    actions = [s.action for s in steps]
    missing = sorted(policy.required_actions - set(actions))
    if missing:
        failures.append("missing_actions:" + "+".join(missing))

    reasoning_tokens = sum(len(s.thought.split()) for s in steps)
    if reasoning_tokens < policy.min_reasoning_tokens:
        failures.append("thin_reasoning")

    file_refs = sum(len(_FILE_REF_RE.findall(s.thought)) for s in steps)
    if file_refs < policy.min_file_refs:
        failures.append("no_file_references")

    # A padded loop: the same action repeated more than the cap. Catches the
    # "grep the same thing 20 times to inflate step count" trick.
    if actions:
        worst = max(actions.count(a) for a in set(actions))
        if worst > policy.max_action_repeat:
            failures.append("repeated_action")

    # Padded prose: the token floor above is a word count, so it is cleared by
    # repeating one sentence until the count is met. Catches the text-field
    # equivalent of the repeated_action trick. Only sentences long enough to
    # carry content are counted, so punctuation and short connectives do not
    # trip it.
    for step in steps:
        sentences = [
            part.strip().lower()
            for part in _SENTENCE_SPLIT_RE.split(step.thought)
            if len(part.split()) >= _MIN_SENTENCE_WORDS
        ]
        if not sentences:
            continue
        if max(sentences.count(s) for s in set(sentences)) > policy.max_sentence_repeat:
            failures.append("padded_reasoning")
            break

    return TraceQualityResult(passed=not failures, failures=tuple(failures))


@dataclass(frozen=True)
class TraceSubmission:
    """A trace offered alongside a PoC, with attribution and a reuse licence.

    Content-addressed so the corpus can dedupe and cite it without re-reading the
    body. The `model_seal` binds which model produced the trace to a fresh
    attestation quote — without it, model attribution is a miner's unverified
    claim.
    """

    task_id: str
    poc_sha256: str
    model_id: str
    steps: Sequence[TraceStep]
    licence: str  # explicit reuse grant, e.g. "cathedral-corpus-v1"
    model_seal: str | None = None  # sha256 of the attestation binding model→run

    def __post_init__(self) -> None:
        if not self.task_id or not self.model_id:
            raise ValueError("task_id and model_id are required")
        if not self.licence:
            # No licence, no reuse: the corpus cannot legally train on it, so it
            # is worthless as training data and must be refused as a bonus.
            raise ValueError("a trace submission must carry an explicit reuse licence")
        if not self.steps:
            raise ValueError("a trace submission must have steps")

    def quality(self, policy: TraceQualityPolicy = TraceQualityPolicy()) -> TraceQualityResult:
        return check_trace_quality(self.steps, policy)

    def is_trainable(self, policy: TraceQualityPolicy = TraceQualityPolicy()) -> bool:
        """Whether this trace may enter the corpus and earn the bonus.

        Requires the structural floor AND a model seal — the corpus is only worth
        training on if it knows which model wrote each row.
        """
        return self.quality(policy).passed and bool(self.model_seal)

    def trace_id(self) -> str:
        body = json.dumps(
            {
                "schema": TRACE_SUBMISSION_SCHEMA,
                "task_id": self.task_id,
                "poc_sha256": self.poc_sha256,
                "model_id": self.model_id,
                "steps": [s.as_dict() for s in self.steps],
                "licence": self.licence,
                "model_seal": self.model_seal,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(
            TRACE_SUBMISSION_DOMAIN + body.encode()
        ).hexdigest()


# Bonus fractions for trace and seal submission. A trace only pays if it clears
# the floor; a seal only pays if present. These are added to the base pass score
# by the scoring layer, and gate on the checks above rather than on mere presence.
TRACE_BONUS = float("0.20")
SEAL_BONUS = float("0.10")


def submission_bonus(
    submission: TraceSubmission | None,
    policy: TraceQualityPolicy = TraceQualityPolicy(),
) -> float:
    """The bonus a submission earns: gated on quality, not mere presence."""
    if submission is None:
        return 0.0
    bonus = 0.0
    if submission.quality(policy).passed:
        bonus += TRACE_BONUS  # only a floor-clearing trace pays
    if submission.model_seal:
        bonus += SEAL_BONUS
    return bonus
