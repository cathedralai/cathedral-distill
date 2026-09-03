"""Did the agent DERIVE this PoC, or did the harness REMEMBER it?

The corpus is public. CyberGym publishes its ground-truth reproducers and ARVO's images bake
theirs at ``/tmp/poc``, so for any task in the standing corpus the answer can simply be looked
up. The earlier answer to this was freshness — pay only on bugs disclosed after the harness
committed — and measurement killed it: OSS-Fuzz discloses about 0.7 admissible bugs a day, so
a lane paying only on fresh bugs has almost nothing to pay on. Freshness cannot carry this.

So the defence moves from WHEN the bug became public to WHERE the answer came from. A harness
that replays a stored PoC and one that reasons its way to it produce the same bytes; they do
not produce the same *behaviour*, and behaviour is what we can observe, because the agent runs
on our screener against a model we serve.

Four checks, and their honest strengths:

* **Static recall scan** (:func:`scan_for_known_answers`) — the corpus's reference PoCs are
  public, so we hold them: a harness bundle that literally contains one has been caught before
  it runs. Cheap and decisive against naive baking; defeated by compression or obfuscation, so
  it is a floor, never the whole gate.
* **Model-ablation sensitivity** (:func:`ablation_verdict`) — THE load-bearing check. We serve
  the pinned model, so we can serve a WEAKER one on a random subset of tasks without telling
  the harness which. A genuine agent's solve rate falls when its reasoning gets worse; a
  harness replaying stored answers scores the same either way, because it never needed the
  model. Evading this requires deliberately failing on the ablated runs, which requires
  identifying them — and a quietly weaker model looks exactly like a model having a bad day.
* **Canary tasks** (:func:`canary_verdict`) — a handful of never-public tasks mixed into a
  round. Recall cannot answer them, so acing the public corpus while failing the canaries is
  the signature of a lookup. This is where scarce fresh supply actually belongs: catching a
  cheat needs a few canaries per round, not thirty paying tasks, and 0.7 a day is plenty.
* **Task blinding** (assumed, enforced elsewhere) — the harness never sees a catalog id,
  project name or upstream identifier (``cybergym_sealed``, ``reseal_task.genericise_disclosure``),
  so a lookup table has no key to index on. Free, and it forces any cheat up to content
  matching rather than id matching.

**What this module does not claim.** None of these is a proof. A sufficiently determined
harness that obfuscates its table, detects ablation, and abstains on canaries defeats all of
them — the checks make cheating expensive and detectable, they do not make it impossible.
They are therefore composed as EVIDENCE, not as a single boolean: a verdict carries what was
observed and how much of it, and thin evidence yields ``INCONCLUSIVE`` rather than either
verdict. Rejecting an honest miner is as damaging as paying a cheat, so nothing here rejects
on a small sample.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, localcontext
from enum import Enum
from typing import Iterable, Mapping, Sequence

_PRECISION = 34
_ZERO = Decimal(0)
_ONE = Decimal(1)

#: Beta prior for the two solve-rate arms compared below. Uniform rather than the payment
#: module's pessimistic prior: here we are comparing two rates for a DIFFERENCE, not deciding
#: what to pay, and a prior that drags both arms toward zero would mask the very gap the
#: ablation test exists to see.
_PRIOR_A = Decimal("1")
_PRIOR_B = Decimal("1")

#: Fraction of full-model capability a harness may retain under ablation before it looks like
#: recall. 0.8 means "kept 80% of its solve rate without a capable model".
#:
#: **This is a declared mechanism parameter and it is NOT yet empirically calibrated.** How far
#: a genuine agent degrades under a weaker model is a measurable quantity and nobody has
#: measured it here. Until real harnesses have been run on both arms, treat a flag as a
#: reason to LOOK, not as grounds to withhold payment.
RETENTION_LIMIT = Decimal("0.8")

#: Minimum observations on EACH arm before an ablation verdict is anything but inconclusive.
#: Below this the comparison is noise, and a false rejection costs an honest miner their lane.
MIN_ARM_OBSERVATIONS = 12

#: Minimum canaries before their absence of solves means anything. Solving zero of two proves
#: nothing about a harness; zero of eight against a strong public rate is a signature.
MIN_CANARIES = 5

#: The full-model arm must show at least this much demonstrable capability (lower bound) before
#: ablation says anything. A harness that solves nothing with a good model also solves nothing
#: with a bad one, and the ratio between two near-zero rates is noise, not evidence.
MIN_FULL_CAPABILITY = Decimal("0.05")


class Verdict(str, Enum):
    """What the evidence supports. INCONCLUSIVE is a first-class answer, not a failure."""

    DERIVED = "derived"            # behaves like an agent that reasons
    RECALL_SUSPECTED = "recall_suspected"
    INCONCLUSIVE = "inconclusive"  # not enough evidence to say either way


class ScreeningError(ValueError):
    """Screening inputs are malformed. Fails closed — never a silent pass."""


@dataclass(frozen=True)
class TaskRun:
    """One task the harness was run on, and the conditions it ran under."""

    task_id: str
    solved: bool
    ablated: bool = False   # served the weaker model
    canary: bool = False    # a never-public task

    def __post_init__(self) -> None:
        if not self.task_id:
            raise ScreeningError("a run needs a task_id")
        for name in ("solved", "ablated", "canary"):
            if not isinstance(getattr(self, name), bool):
                raise ScreeningError(f"{name} must be a bool")


@dataclass(frozen=True)
class Signal:
    """One check's outcome, with the numbers behind it so a decision can be audited."""

    name: str
    verdict: Verdict
    detail: str = ""
    observations: int = 0


@dataclass(frozen=True)
class Screening:
    """Everything observed about one harness, and what it adds up to."""

    signals: tuple[Signal, ...] = field(default_factory=tuple)

    @property
    def verdict(self) -> Verdict:
        """Any single RECALL_SUSPECTED decides it; otherwise DERIVED needs a real signal.

        Deliberately asymmetric. The checks look for different cheats, so one firing is
        evidence the others simply could not see — an averaged verdict would let a harness
        that is caught cold by the canaries be rescued by passing an ablation it evaded.
        A clean bill needs at least one check to have actually concluded, so a harness that
        was never meaningfully screened reads INCONCLUSIVE rather than DERIVED.
        """
        if any(s.verdict is Verdict.RECALL_SUSPECTED for s in self.signals):
            return Verdict.RECALL_SUSPECTED
        if any(s.verdict is Verdict.DERIVED for s in self.signals):
            return Verdict.DERIVED
        return Verdict.INCONCLUSIVE

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(f"{s.name}: {s.detail}" for s in self.signals if s.detail)


def _rate_bounds(solves: int, total: int, z: Decimal) -> tuple[Decimal, Decimal]:
    """(lower, upper) bound of the Beta posterior solve rate. Decimal for determinism."""
    with localcontext() as ctx:
        ctx.prec = _PRECISION
        a = Decimal(solves) + _PRIOR_A
        b = Decimal(total - solves) + _PRIOR_B
        n = a + b
        mean = a / n
        sd = ((a * b) / (n * n * (n + _ONE))).sqrt()
        low = mean - z * sd
        high = mean + z * sd
        return (low if low > _ZERO else _ZERO), (high if high < _ONE else _ONE)


def scan_for_known_answers(
    harness_bytes: bytes, known_pocs: Mapping[str, bytes], *, min_length: int = 16,
) -> Signal:
    """Look for the corpus's public reference PoCs sitting inside the submitted harness.

    The corpus is public, so we hold every reference reproducer; a bundle that carries one
    verbatim has been caught before it ever runs. Short reproducers are skipped
    (``min_length``): a handful of bytes can occur in any binary by coincidence, and a false
    accusation here is expensive.

    Decisive when it fires and worth nothing when it does not — any compression, encoding or
    generation-on-the-fly evades it. It returns INCONCLUSIVE rather than DERIVED on a clean
    scan, because "we did not find a stored answer" is not "there is no stored answer".
    """
    if not isinstance(harness_bytes, (bytes, bytearray)):
        raise ScreeningError("harness_bytes must be bytes")
    blob = bytes(harness_bytes)
    hits = sorted(
        task_id for task_id, poc in known_pocs.items()
        if isinstance(poc, (bytes, bytearray)) and len(poc) >= min_length and bytes(poc) in blob
    )
    if hits:
        return Signal(
            "static_recall_scan", Verdict.RECALL_SUSPECTED,
            f"harness contains the reference reproducer for {len(hits)} task(s): "
            f"{', '.join(hits[:5])}{' ...' if len(hits) > 5 else ''}",
            observations=len(known_pocs),
        )
    return Signal(
        "static_recall_scan", Verdict.INCONCLUSIVE,
        "no stored reproducer found verbatim, which does not rule one out",
        observations=len(known_pocs),
    )


def ablation_verdict(
    runs: Iterable[TaskRun], *,
    retention_limit: Decimal = RETENTION_LIMIT,
    min_arm: int = MIN_ARM_OBSERVATIONS,
    z: Decimal = Decimal("1.0"),
) -> Signal:
    """Compare solve rates with and without a capable model.

    A genuine agent gets worse when its reasoning gets worse. A harness replaying stored
    answers does not, because it never used the model. So the comparison is between the
    ablated arm's LOWER bound and the full arm's UPPER bound: we flag only when even a
    pessimistic reading of the ablated runs and a generous reading of the full runs still
    show capability being retained. That asymmetry is deliberate — it means noise pushes
    toward INCONCLUSIVE, never toward accusing an honest miner.

    Canary runs are excluded: they test a different thing and are deliberately harder, so
    mixing them would depress whichever arm they landed in.
    """
    rows = [r for r in runs if not r.canary]
    full = [r for r in rows if not r.ablated]
    ablated = [r for r in rows if r.ablated]
    if len(full) < min_arm or len(ablated) < min_arm:
        return Signal(
            "model_ablation", Verdict.INCONCLUSIVE,
            f"needs {min_arm} runs per arm, have {len(full)} full and {len(ablated)} ablated",
            observations=len(rows),
        )
    full_solves = sum(1 for r in full if r.solved)
    ablated_solves = sum(1 for r in ablated if r.solved)
    full_low, full_high = _rate_bounds(full_solves, len(full), z)
    ablated_low, _ = _rate_bounds(ablated_solves, len(ablated), z)

    if full_low < MIN_FULL_CAPABILITY:
        return Signal(
            "model_ablation", Verdict.INCONCLUSIVE,
            f"the harness solves too little with a full model "
            f"({full_solves}/{len(full)}) for ablation to show anything",
            observations=len(rows),
        )
    with localcontext() as ctx:
        ctx.prec = _PRECISION
        # Ablated LOWER bound against the full arm's CENTRAL estimate. Comparing it against
        # the full UPPER bound instead would double-count the conservatism — both arms
        # widened away from each other — and a harness scoring IDENTICALLY on both arms then
        # slips under the limit, which is precisely the case this check exists to catch.
        retained = ablated_low / ((full_low + full_high) / Decimal(2))
    if retained >= retention_limit:
        return Signal(
            "model_ablation", Verdict.RECALL_SUSPECTED,
            f"kept {retained:.2f} of its solve rate with a degraded model "
            f"({ablated_solves}/{len(ablated)} ablated vs {full_solves}/{len(full)} full): "
            "the answers do not depend on the model",
            observations=len(rows),
        )
    return Signal(
        "model_ablation", Verdict.DERIVED,
        f"solve rate fell under a degraded model (retained {retained:.2f}), which is what a "
        "harness that actually reasons does",
        observations=len(rows),
    )


def canary_verdict(
    runs: Iterable[TaskRun], *, min_canaries: int = MIN_CANARIES, z: Decimal = Decimal("1.0"),
) -> Signal:
    """Compare the public corpus against tasks whose answers were never published.

    Recall cannot answer a task nobody has published, so a harness that aces the public
    corpus and fails every canary is showing the signature of a lookup rather than a
    capability. Flagged only when the public rate is genuinely strong AND no canary was
    solved: a harness that is simply weak everywhere fails both and is not a cheat.
    """
    rows = list(runs)
    canaries = [r for r in rows if r.canary]
    public = [r for r in rows if not r.canary]
    if len(canaries) < min_canaries or not public:
        return Signal(
            "canary", Verdict.INCONCLUSIVE,
            f"needs {min_canaries} canaries, have {len(canaries)}",
            observations=len(canaries),
        )
    canary_solves = sum(1 for r in canaries if r.solved)
    public_solves = sum(1 for r in public if r.solved)
    public_low, _ = _rate_bounds(public_solves, len(public), z)
    if canary_solves == 0 and public_low > Decimal("0.25"):
        return Signal(
            "canary", Verdict.RECALL_SUSPECTED,
            f"solved {public_solves}/{len(public)} public tasks but 0/{len(canaries)} "
            "never-published ones: the capability does not survive leaving the public corpus",
            observations=len(canaries),
        )
    if canary_solves > 0:
        return Signal(
            "canary", Verdict.DERIVED,
            f"solved {canary_solves}/{len(canaries)} never-published tasks, which recall "
            "cannot do",
            observations=len(canaries),
        )
    return Signal(
        "canary", Verdict.INCONCLUSIVE,
        f"solved no canaries, but the public rate ({public_solves}/{len(public)}) is too weak "
        "to distinguish a lookup from a harness that simply does not solve much",
        observations=len(canaries),
    )


def screen_agent(
    runs: Sequence[TaskRun], *,
    harness_bytes: bytes | None = None,
    known_pocs: Mapping[str, bytes] | None = None,
) -> Screening:
    """Run every applicable check and collect the evidence.

    Checks that cannot run (no harness bytes to scan, too few runs on an arm) contribute an
    INCONCLUSIVE signal rather than being silently omitted, so a reader can tell the
    difference between a check that passed and a check that never happened.
    """
    signals: list[Signal] = []
    if harness_bytes is not None and known_pocs is not None:
        signals.append(scan_for_known_answers(harness_bytes, known_pocs))
    signals.append(ablation_verdict(runs))
    signals.append(canary_verdict(runs))
    return Screening(signals=tuple(signals))


def screening_multiplier(screening: Screening) -> Decimal:
    """What a screening verdict does to pay: 1 for derived, 0 for suspected recall.

    INCONCLUSIVE pays in full. That is deliberate and it is the conservative choice for the
    party who can be wronged irreversibly: withholding pay from an honest miner because a
    check could not run drives out exactly the participants the lane needs, while a cheat that
    screening has not yet caught is a bounded, recoverable loss that the canaries and ablation
    will catch as evidence accumulates. Compose it with
    ``cybergym_incentive.credited_rate``, which is already conservative about thin evidence.
    """
    if screening.verdict is Verdict.RECALL_SUSPECTED:
        return _ZERO
    return _ONE
