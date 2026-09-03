"""Measure the one screening number nobody has measured: how far a real agent degrades.

`cybergym_agent_screening.RETENTION_LIMIT` decides when a harness looks like it is replaying
stored answers rather than reasoning: it flags when the ablated arm retains at least that share
of the full-model solve rate. The default 0.8 is a placeholder. Nobody has run a genuine
Qwen3.8-27B agent against a weaker model and measured what it actually retains, so the number
is currently a guess wearing the clothes of a threshold, and a guess must not gate payment.

This module turns that into an experiment. Feed it the same runs the screener produces — the
harness on the pinned model, and the harness on a deliberately weaker one — and it reports what
honest agents actually retain, with the interval around it, and what limit that implies.

**The limit sits between honest and replay, and both ends matter.** A replay harness retains
~1.0: its answers never came from the model, so degrading the model changes nothing. An honest
agent retains something lower, and the gap between them is the entire signal. Setting the limit
just above what honest agents retain catches replay while leaving honest agents alone; setting
it near 1.0 catches nothing; setting it at or below honest retention accuses the innocent, which
is the expensive direction.

So the recommendation is deliberately conservative about ACCUSING: it is placed above the UPPER
bound of observed honest retention, not above the point estimate, plus a margin. A limit derived
from a handful of runs would sit wherever noise happened to put it, so
:attr:`Calibration.sufficient` reports whether the sample can carry the conclusion, and a
recommendation from an insufficient sample is returned as ``None`` rather than as a number that
looks measured.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext
from typing import Iterable, Sequence

from cathedral_distill.cybergym_agent_screening import (
    MIN_ARM_OBSERVATIONS,
    MIN_FULL_CAPABILITY,
    ScreeningError,
    TaskRun,
    _rate_bounds,
)

_PRECISION = 34
_ZERO = Decimal(0)
_ONE = Decimal(1)

#: Headroom between the honest agents' worst-case retention and the limit. Absorbs the drift a
#: single experiment cannot see: a different task mix, a model provider's silent revision, an
#: agent architecture that leans on the model less. Too small and honest miners trip it on a
#: bad week; too large and it stops separating anything.
SAFETY_MARGIN = Decimal("0.1")

#: Runs required on EACH arm before a recommendation is offered at all. Matches the screening
#: check's own minimum: a limit derived from fewer runs than the check needs to fire would be
#: calibrating against noise.
MIN_CALIBRATION_RUNS = MIN_ARM_OBSERVATIONS


@dataclass(frozen=True)
class Calibration:
    """What an honest agent actually retained, and what limit that supports."""

    full_solves: int
    full_total: int
    ablated_solves: int
    ablated_total: int
    retained: Decimal          # point estimate, ablated rate / full rate
    retained_upper: Decimal    # pessimistic: honest agents might retain this much
    recommended_limit: Decimal | None
    sufficient: bool
    note: str = ""

    def summary(self) -> str:
        head = (
            f"full {self.full_solves}/{self.full_total}, "
            f"ablated {self.ablated_solves}/{self.ablated_total}, "
            f"retained {self.retained:.3f} (upper {self.retained_upper:.3f})"
        )
        if self.recommended_limit is None:
            return f"{head}\n  NO RECOMMENDATION: {self.note}"
        return f"{head}\n  recommended RETENTION_LIMIT = {self.recommended_limit:.2f}\n  {self.note}"


def calibrate(
    runs: Iterable[TaskRun], *,
    z: Decimal = Decimal("1.0"),
    margin: Decimal = SAFETY_MARGIN,
    min_runs: int = MIN_CALIBRATION_RUNS,
) -> Calibration:
    """Measure honest retention from paired runs and recommend a limit.

    ``runs`` must come from harnesses believed HONEST — the point is to learn what genuine
    reasoning looks like. Feeding it a replay harness would measure the cheat and recommend a
    limit that legitimises it, so the caller owns that judgement and the note says so.

    Canary runs are excluded, matching the screening check they calibrate.
    """
    rows = [r for r in runs if not r.canary]
    full = [r for r in rows if not r.ablated]
    ablated = [r for r in rows if r.ablated]
    full_solves = sum(1 for r in full if r.solved)
    ablated_solves = sum(1 for r in ablated if r.solved)

    if len(full) < min_runs or len(ablated) < min_runs:
        return Calibration(
            full_solves, len(full), ablated_solves, len(ablated), _ZERO, _ZERO, None, False,
            f"needs {min_runs} runs per arm, have {len(full)} full and {len(ablated)} ablated",
        )

    full_low, full_high = _rate_bounds(full_solves, len(full), z)
    _, ablated_high = _rate_bounds(ablated_solves, len(ablated), z)
    # Same capability floor the screening check applies, so the calibration cannot recommend a
    # limit from an agent the check would refuse to judge. Diagnosed separately from the
    # "barely uses the model" case below: an operator told the wrong one would go and pick a
    # weaker ablation model when the real problem is that the agent solves nothing at all.
    if full_low < MIN_FULL_CAPABILITY:
        return Calibration(
            full_solves, len(full), ablated_solves, len(ablated), _ZERO, _ZERO, None, False,
            f"the agent solves too little with a full model ({full_solves}/{len(full)}) for "
            "there to be any degradation to measure; calibrate on a harness that works",
        )
    with localcontext() as ctx:
        ctx.prec = _PRECISION
        full_mean = (full_low + full_high) / Decimal(2)
        retained = (Decimal(ablated_solves) / Decimal(len(ablated))) / (
            Decimal(full_solves) / Decimal(len(full))
        ) if full_solves else _ZERO
        # Pessimistic about accusing: how much might an honest agent retain on a good day?
        retained_upper = ablated_high / full_mean
        limit = retained_upper + margin

    if limit >= _ONE:
        return Calibration(
            full_solves, len(full), ablated_solves, len(ablated), retained, retained_upper,
            None, False,
            "honest retention plus margin reaches 1.0: this agent barely uses the model, so "
            "ablation cannot separate it from replay. Use a weaker ablation model, or rely on "
            "the canary check for this harness class",
        )
    return Calibration(
        full_solves, len(full), ablated_solves, len(ablated), retained, retained_upper,
        limit, True,
        "placed above the UPPER bound of observed honest retention plus a margin, so noise "
        "pushes toward letting an honest harness through rather than accusing it. Valid for "
        "this model pair and task mix only — re-run when either changes",
    )


def calibrate_from_pairs(
    solved_full: Sequence[bool], solved_ablated: Sequence[bool], **kwargs
) -> Calibration:
    """Convenience for an operator holding two lists of outcomes rather than TaskRun rows."""
    if not solved_full or not solved_ablated:
        raise ScreeningError("both arms need outcomes")
    runs = [TaskRun(f"full-{i:04d}", bool(s)) for i, s in enumerate(solved_full)]
    runs += [TaskRun(f"abl-{i:04d}", bool(s), ablated=True) for i, s in enumerate(solved_ablated)]
    return calibrate(runs, **kwargs)
