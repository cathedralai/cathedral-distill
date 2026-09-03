"""What a harness is PAID, given thin and unevenly-distributed evidence.

Two facts about this lane make a raw solve rate the wrong thing to pay on, and both are
measured rather than assumed:

* **Supply is thin.** Fresh admissible bugs arrive at roughly 0.7 a day (~20 a month), so a
  round carries tens of tasks, not thousands. At 30 binary tasks the standard error on a
  solve rate is near 9 points — two harnesses within 10 points of each other are
  indistinguishable, and ranking hard on that mostly pays out noise.
* **Evidence accrues per harness, from its own commitment.** A task is eligible only if it
  was disclosed after the harness committed (``oss_fuzz_supply.eligible_for``), so a fresh
  harness starts with an empty pool and accrues ~20 tasks a month. A newcomer has almost no
  evidence for weeks. Paying their 3-task score as though it were a 30-task score is wrong;
  paying them nothing for six weeks is a hostile onboarding.

Both are the same problem — *how much do we believe this rate?* — so both get one answer: pay
the **lower confidence bound** of the posterior solve rate, over **recency-weighted** evidence.

    credited = max(0, posterior_mean - z * posterior_sd)

That single expression does the work of the two mechanisms this module replaces. Thin
evidence widens the interval, which lowers the bound, which IS the reduced warm-up rate — no
separate warm-up schedule to tune or game. As evidence accrues the interval tightens and the
credited rate rises to meet the true one. It is conservative in the only safe direction: we
under-pay on uncertainty rather than over-pay on luck.

**Every constant here is calibrated against the measured supply, not chosen for looks.**

* ``HALF_LIFE_DAYS = 90``. Observations decay with age, so the effective sample reaches a
  steady state of ``rate * H / ln2`` — at 0.7/day that is ~91 tasks, giving a standard error
  near 5 points, about double the resolution of one 30-task round. Decay is also what stops
  incumbency compounding: without it a harness committed a year ago accumulates a precision
  moat a better newcomer cannot cross, and the lane would reward age over capability.
* ``Z = 1.0``. Calibrated so a true-50% harness is credited 80% of its real rate after ~23
  tasks — about 4.7 weeks at the measured arrival rate, matching the warm-up the supply
  analysis predicted. z=1.645 (95% one-sided) would stretch that to 13.5 weeks, which prices
  new entrants out of the lane for a quarter.
* ``PRIOR = Beta(0.5, 5.0)``, deliberately pessimistic rather than the usual Jeffreys
  ``Beta(0.5, 0.5)``. Under Jeffreys a harness with **zero** evidence is credited 0.146 —
  real emission for having submitted nothing, which is a standing invitation to register
  garbage. This prior credits exactly **0.000** at zero evidence and at any amount of
  evidence with no solves, and costs only ~6% of the steady-state evidence weight.

**Determinism is a hard requirement, not a nicety.** This feeds weights, so two validators
must compute bit-identical results. `math.exp`/`math.sqrt` are libm-dependent and may differ
across platforms; `Decimal` power and square root are correctly rounded by specification. All
arithmetic here therefore runs in `Decimal` under a pinned context.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, localcontext
from typing import Iterable, Sequence

#: Pinned so every validator's arithmetic agrees exactly. Do not widen casually: changing it
#: changes credited rates, which is a mechanism change, not a refactor.
_PRECISION = 34

HALF_LIFE_DAYS = Decimal("90")
Z = Decimal("1.0")

#: Beta prior. Pessimistic on purpose — see the module docstring on why Jeffreys pays 0.146
#: for nothing.
PRIOR_SOLVES = Decimal("0.5")
PRIOR_FAILURES = Decimal("5.0")

#: Ceiling on evidence carried across a re-commitment. A miner who improves their harness
#: must re-commit, which empties their eligible pool; without a carry-over the lane would
#: punish every improvement with weeks at zero, which is precisely backwards for a
#: competition whose purpose is rising capability. The carry is the MINER's demonstrated
#: rate, not task knowledge, so it leaks nothing. Capped so a miner cannot coast: ten
#: pseudo-observations are swamped within a fortnight of real ones.
CARRIED_PRIOR_MAX = Decimal("10")

_ZERO = Decimal(0)
_ONE = Decimal(1)
_HALF = Decimal("0.5")


class IncentiveError(ValueError):
    """Payment inputs are malformed. Fails closed — never silently pays a default."""


@dataclass(frozen=True)
class Observation:
    """One graded eligible task: did this harness solve it, and when was it disclosed?

    Dated by DISCLOSURE, not by when it was graded. Grading time is an operational detail a
    validator could vary; disclosure is the auditable git-add timestamp the eligibility rule
    already turns on, so two validators weigh the same observation identically.
    """

    task_id: str
    solved: bool
    disclosed_at: datetime

    def __post_init__(self) -> None:
        if not self.task_id:
            raise IncentiveError("an observation needs a task_id")
        if not isinstance(self.solved, bool):
            raise IncentiveError("solved must be a bool")
        if self.disclosed_at.tzinfo is None:
            raise IncentiveError("disclosed_at must be timezone-aware (UTC)")


@dataclass(frozen=True)
class Evidence:
    """Recency-weighted totals: how much evidence there is, and how much of it solved."""

    effective_total: Decimal
    effective_solves: Decimal
    observations: int = 0

    def __post_init__(self) -> None:
        if self.effective_total < 0 or self.effective_solves < 0:
            raise IncentiveError("effective counts cannot be negative")
        if self.effective_solves > self.effective_total:
            raise IncentiveError("effective solves cannot exceed the effective total")


def recency_weight(disclosed_at: datetime, *, as_of: datetime,
                   half_life_days: Decimal = HALF_LIFE_DAYS) -> Decimal:
    """``0.5 ** (age / half_life)`` — an observation's weight, in Decimal for determinism.

    A future-dated observation weighs 1 rather than more: a clock skew must never be able to
    inflate evidence above a fresh observation's worth.
    """
    if disclosed_at.tzinfo is None or as_of.tzinfo is None:
        raise IncentiveError("both timestamps must be timezone-aware (UTC)")
    if half_life_days <= 0:
        raise IncentiveError("half_life_days must be positive")
    seconds = Decimal((as_of.astimezone(UTC) - disclosed_at.astimezone(UTC)).total_seconds())
    if seconds <= 0:
        return _ONE
    with localcontext() as ctx:
        ctx.prec = _PRECISION
        age_days = seconds / Decimal(86400)
        return _HALF ** (age_days / half_life_days)


def weigh(observations: Iterable[Observation], *, as_of: datetime,
          half_life_days: Decimal = HALF_LIFE_DAYS) -> Evidence:
    """Collapse graded tasks into recency-weighted evidence.

    Observations are summed in TASK-ID ORDER, not iteration order. Decimal addition is not
    associative at finite precision, so two validators holding the same observations in
    different orders could otherwise differ in the last digit — and this feeds weights.
    """
    rows = sorted(observations, key=lambda o: o.task_id)
    seen: set[str] = set()
    with localcontext() as ctx:
        ctx.prec = _PRECISION
        total = solves = _ZERO
        for row in rows:
            if row.task_id in seen:
                raise IncentiveError(f"task {row.task_id} observed twice; evidence would double-count")
            seen.add(row.task_id)
            weight = recency_weight(row.disclosed_at, as_of=as_of, half_life_days=half_life_days)
            total += weight
            if row.solved:
                solves += weight
        return Evidence(effective_total=total, effective_solves=solves, observations=len(rows))


def carried_prior(previous_rate: Decimal, previous_evidence: Decimal,
                  *, cap: Decimal = CARRIED_PRIOR_MAX) -> tuple[Decimal, Decimal]:
    """Pseudo-counts a re-committed harness inherits from the miner's previous one.

    Returns ``(pseudo_solves, pseudo_failures)``. The weight carried is the previous
    evidence capped at ``cap``, so a strong history helps a new harness through its empty
    weeks without letting anyone coast: ten pseudo-observations are outweighed by real ones
    within a fortnight at the measured arrival rate.

    What carries is a RATE — the miner's demonstrated capability — never task knowledge, so
    this cannot leak the corpus across a re-commitment.
    """
    if not (_ZERO <= previous_rate <= _ONE):
        raise IncentiveError("previous_rate must be a probability in [0, 1]")
    if previous_evidence < 0:
        raise IncentiveError("previous_evidence cannot be negative")
    with localcontext() as ctx:
        ctx.prec = _PRECISION
        weight = min(previous_evidence, cap)
        return previous_rate * weight, (_ONE - previous_rate) * weight


def credited_rate(
    evidence: Evidence,
    *,
    commitment_verified: bool,
    carried: tuple[Decimal, Decimal] | None = None,
    z: Decimal = Z,
) -> Decimal:
    """The solve rate this harness is PAID on: the posterior's lower confidence bound.

    ``commitment_verified`` is required and is not advisory. `cybergym_stage1` records
    whether commit-then-draw was actually proven for a score and states that a consumer
    moving weight must refuse an unverified one — this is that consumer, so an unverified
    score is paid **zero**. Making it a required keyword means the check cannot be
    forgotten by a caller who simply did not think about it.

    The bound is floored at zero: a posterior whose mean sits inside its own uncertainty
    band describes a harness we cannot distinguish from one that solves nothing, and the
    honest payment for that is nothing.
    """
    if not isinstance(commitment_verified, bool):
        raise IncentiveError("commitment_verified must be a bool")
    if not commitment_verified:
        # Not a low rate — no rate. The freshness the score depends on was never proven.
        return _ZERO
    if z < 0:
        raise IncentiveError("z cannot be negative")
    prior_solves, prior_failures = carried or (_ZERO, _ZERO)
    if prior_solves < 0 or prior_failures < 0:
        raise IncentiveError("carried pseudo-counts cannot be negative")

    with localcontext() as ctx:
        ctx.prec = _PRECISION
        alpha = evidence.effective_solves + PRIOR_SOLVES + prior_solves
        beta = (evidence.effective_total - evidence.effective_solves) + PRIOR_FAILURES + prior_failures
        total = alpha + beta
        mean = alpha / total
        variance = (alpha * beta) / (total * total * (total + _ONE))
        bound = mean - z * variance.sqrt()
        return bound if bound > _ZERO else _ZERO


def rank_by_credited_rate(
    rates: Sequence[tuple[str, Decimal]],
) -> list[tuple[str, Decimal]]:
    """Order miners by credited rate, highest first, with a deterministic tie-break.

    Ties break on the identity string so the order is stable and ungrindable by resubmitting
    under a fresh hotkey — the same discipline `cybergym_stage1.rank_harnesses` uses. Ties
    are COMMON here by design: the lower bound deliberately collapses distinctions the
    evidence cannot support, so several thin-evidence miners legitimately share a rate.
    """
    return sorted(rates, key=lambda row: (-row[1], row[0]))
