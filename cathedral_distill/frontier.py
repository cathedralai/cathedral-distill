"""King-of-the-hill frontier ownership, and the gates that precede it.

Emissions recur every epoch; "improvement over baseline" is a one-time quantity.
Paying deltas therefore makes sandbagging optimal — split one real gain into
several small releases and collect repeatedly — and it makes payouts shrink for
every maintainer who arrives later.

So nothing is paid for a delta. A track has a reigning champion, the champion
earns for **holding** the frontier, and the crown moves only when a candidate
clears every gate and beats the incumbent by a margin. This is `sat-king`'s
existing shape: *"crowning a new king = a new digest in the current-champion
manifest; the image contract never changes."*

Two rules deserve their reasons stated, because both look like details and
neither is:

**Ties keep the incumbent.** Otherwise the cheapest attack on this mechanism is
plagiarism: resubmit the champion's checkpoint, score identically, take the
crown for free. Strict-greater plus a margin means a challenger has to actually
be better.

**Gates are boolean and all required.** A failed gate makes the score
irrelevant — it is not a penalty term to be traded off. Any criterion a validator
cannot derive must not be a weight, because a weight that cannot be derived is a
weight attacked by attacking the measurement.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Mapping, Sequence

FRONTIER_SCHEMA = "cathedral_track_frontier_v1"

# Every gate must pass. Names are stable: they appear in reasons and receipts.
GATE_ATTESTED_RECEIPT = "attested_receipt"
GATE_TEACHER_PERMITTED = "teacher_permitted"
GATE_REPRODUCED = "reproduced"
GATE_WITHIN_COST = "within_cost_ceiling"
GATE_NO_CONTAMINATION = "no_contamination"
GATE_WITHIN_LATENCY = "within_latency_budget"
GATE_REGISTERED_BUNDLE = "registered_bundle"
GATE_INDEPENDENT_EVALUATOR = "independent_evaluator"

REQUIRED_GATES: tuple[str, ...] = (
    GATE_ATTESTED_RECEIPT,
    GATE_TEACHER_PERMITTED,
    GATE_REPRODUCED,
    GATE_WITHIN_COST,
    GATE_NO_CONTAMINATION,
    GATE_WITHIN_LATENCY,
    GATE_REGISTERED_BUNDLE,
    GATE_INDEPENDENT_EVALUATOR,
)


class FrontierError(ValueError):
    """Raised on malformed frontier input."""


@dataclass(frozen=True)
class TrackPolicy:
    """Per-track rules. Set once, changed only as a reviewed mechanism change."""

    track: str
    # A challenger must exceed the champion by at least this much. Without a
    # margin, evaluation noise flips the crown every epoch and nobody can build
    # a business on holding it.
    min_margin: Decimal = Decimal("0.005")
    max_cost_usd: Decimal = Decimal("100")
    max_latency_p50_ms: Decimal = Decimal("5000")
    # The floor an unseated track pays nothing below: a first champion still has
    # to be better than useless.
    min_score_to_crown: Decimal = Decimal("0")

    def __post_init__(self) -> None:
        if not self.track:
            raise FrontierError("track is required")
        if self.min_margin < 0:
            raise FrontierError("min_margin must be non-negative")


@dataclass(frozen=True)
class Candidate:
    """One submission, already evaluated on the sealed set."""

    miner_hotkey: str
    bundle_digest: str
    checkpoint_digest: str
    receipt_id: str
    score: Decimal
    latency_p50_ms: Decimal
    cost_usd: Decimal
    submitted_at: datetime
    # Which sealed item set this score was measured on. Two scores are only
    # comparable when they were measured on the SAME batch — otherwise the crown
    # turns on which items each happened to draw. Empty means "unbatched", which
    # is only safe for a static set that never rotates.
    batch_id: str = ""
    attested: bool = False
    teacher_permitted: bool = False
    reproduced: bool = False
    contamination_detected: bool = True
    registered_bundle: bool = False
    # False when the evaluating compute provider shares a coldkey with the
    # maintainer. TDX keeps the sealed set unreadable either way, but an
    # operator who controls the machine can re-run the eval and submit only its
    # best result. See roles.assert_independent_evaluator.
    independent_evaluator: bool = False

    def __post_init__(self) -> None:
        if not Decimal(0) <= self.score <= Decimal(1):
            raise FrontierError("score must be within 0..1")


@dataclass(frozen=True)
class Champion:
    """The reigning holder of a track's frontier."""

    track: str
    miner_hotkey: str
    bundle_digest: str
    checkpoint_digest: str
    receipt_id: str
    score: Decimal
    crowned_at: datetime
    # The batch the champion's *current* score was measured on. Refreshed every
    # time the incumbent is re-scored on a new batch (see `rescored`), so a
    # challenger is always compared against a same-batch number.
    batch_id: str = ""

    def as_manifest(self) -> dict[str, object]:
        """The current-champion manifest, mirroring sat-king's shape."""
        return {
            "schema": FRONTIER_SCHEMA,
            "track": self.track,
            "miner_hotkey": self.miner_hotkey,
            "bundle_digest": self.bundle_digest,
            "checkpoint_digest": self.checkpoint_digest,
            "receipt_id": self.receipt_id,
            "score": str(self.score),
            "crowned_at": self.crowned_at.isoformat(),
            "batch_id": self.batch_id,
        }

    def rescored(self, score: Decimal, batch_id: str, receipt_id: str) -> "Champion":
        """The same champion, its score refreshed on a new batch.

        Identity (miner, bundle, checkpoint, crowned_at) is preserved — it is the
        *same model still holding the crown* — but the score now reflects the
        current batch, so a challenger on that batch is judged fairly. The receipt
        of the fresh evaluation replaces the stale one.
        """
        return Champion(
            track=self.track,
            miner_hotkey=self.miner_hotkey,
            bundle_digest=self.bundle_digest,
            checkpoint_digest=self.checkpoint_digest,
            receipt_id=receipt_id,
            score=score,
            crowned_at=self.crowned_at,
            batch_id=batch_id,
        )


@dataclass(frozen=True)
class GateResult:
    """Why a candidate is or is not eligible."""

    passed: bool
    failures: tuple[str, ...] = field(default_factory=tuple)

    @property
    def reason(self) -> str:
        return "eligible" if self.passed else ",".join(self.failures)


def evaluate_gates(candidate: Candidate, policy: TrackPolicy) -> GateResult:
    """Run every gate. All must pass; a single failure makes the score moot."""
    failures: list[str] = []
    if not candidate.attested:
        failures.append(GATE_ATTESTED_RECEIPT)
    if not candidate.teacher_permitted:
        failures.append(GATE_TEACHER_PERMITTED)
    if not candidate.reproduced:
        failures.append(GATE_REPRODUCED)
    if candidate.cost_usd > policy.max_cost_usd:
        failures.append(GATE_WITHIN_COST)
    if candidate.contamination_detected:
        failures.append(GATE_NO_CONTAMINATION)
    if candidate.latency_p50_ms > policy.max_latency_p50_ms:
        # A student that scores well but cannot serve inside the CPU envelope is
        # worthless to a business whose only confidential profile is TDX CPU.
        failures.append(GATE_WITHIN_LATENCY)
    if not candidate.registered_bundle:
        failures.append(GATE_REGISTERED_BUNDLE)
    if not candidate.independent_evaluator:
        failures.append(GATE_INDEPENDENT_EVALUATOR)
    return GateResult(passed=not failures, failures=tuple(failures))


@dataclass(frozen=True)
class ChampionRescore:
    """A fresh evaluation of the reigning champion on the current batch.

    The validator re-runs the incumbent's model on the challenger's exact batch
    and passes the result here. This is the paired-evaluation input: without it,
    `submit` cannot compare a challenger against an incumbent whose score is from
    a rotated-away batch, and will refuse.
    """

    score: Decimal
    batch_id: str
    receipt_id: str

    def __post_init__(self) -> None:
        if not Decimal(0) <= self.score <= Decimal(1):
            raise FrontierError("rescore score must be within 0..1")
        if not self.batch_id:
            raise FrontierError("a rescore must name the batch it was measured on")


@dataclass(frozen=True)
class CrownDecision:
    """The outcome of judging one candidate against the reigning champion."""

    crowned: bool
    reason: str
    champion: Champion | None
    gates: GateResult


def judge(
    candidate: Candidate,
    champion: Champion | None,
    policy: TrackPolicy,
) -> CrownDecision:
    """Decide whether a candidate takes the crown. Incumbent wins every tie."""
    gates = evaluate_gates(candidate, policy)
    if not gates.passed:
        return CrownDecision(False, f"gates_failed:{gates.reason}", champion, gates)

    if candidate.score < policy.min_score_to_crown:
        return CrownDecision(False, "below_track_floor", champion, gates)

    if champion is not None:
        # Paired comparison: the two scores must have been measured on the SAME
        # batch. If the incumbent's score is stale (a batch has rotated since it
        # was last scored), the comparison is meaningless — the challenger might
        # win only because it drew easier items. Refuse until the caller
        # re-scores the incumbent on this batch (Frontier.submit does this).
        if candidate.batch_id != champion.batch_id:
            return CrownDecision(
                False, "champion_not_scored_on_this_batch", champion, gates
            )
        required = champion.score + policy.min_margin
        if candidate.score < required:
            # Covers both "worse" and "tied": a challenger must be better by the
            # margin, so resubmitting the champion's own checkpoint gains nothing.
            return CrownDecision(False, "did_not_beat_frontier", champion, gates)

    crowned = Champion(
        track=policy.track,
        miner_hotkey=candidate.miner_hotkey,
        bundle_digest=candidate.bundle_digest,
        checkpoint_digest=candidate.checkpoint_digest,
        receipt_id=candidate.receipt_id,
        score=candidate.score,
        crowned_at=candidate.submitted_at,
        batch_id=candidate.batch_id,
    )
    return CrownDecision(True, "crowned", crowned, gates)


class Frontier:
    """Champions per track, plus the emission split for holding them."""

    def __init__(self, policies: Sequence[TrackPolicy]) -> None:
        if not policies:
            raise FrontierError("at least one track policy is required")
        self._policies = {p.track: p for p in policies}
        self._champions: dict[str, Champion] = {}

    def policy(self, track: str) -> TrackPolicy:
        policy = self._policies.get(track)
        if policy is None:
            raise FrontierError(f"unknown track: {track}")
        return policy

    def champion(self, track: str) -> Champion | None:
        return self._champions.get(track)

    def submit(
        self,
        track: str,
        candidate: Candidate,
        *,
        champion_rescore: ChampionRescore | None = None,
    ) -> CrownDecision:
        """Judge a challenger, re-scoring the incumbent on its batch first.

        When a champion exists and the challenger carries a `batch_id`, a paired
        comparison is required: pass `champion_rescore` — the incumbent's model
        re-evaluated on the challenger's exact batch — and the stored champion is
        refreshed to that score before judging. Omitting it (or supplying one for
        a different batch) makes `judge` refuse with
        `champion_not_scored_on_this_batch`, which is the safe default: a crown is
        never awarded on a cross-batch comparison.

        The refreshed incumbent is persisted even when the challenger loses, so
        the champion's stored score always reflects the most recent batch it was
        measured on.
        """
        policy = self.policy(track)
        champion = self._champions.get(track)

        if (
            champion is not None
            and candidate.batch_id
            and champion_rescore is not None
            and champion_rescore.batch_id == candidate.batch_id
        ):
            champion = champion.rescored(
                champion_rescore.score,
                champion_rescore.batch_id,
                champion_rescore.receipt_id,
            )
            self._champions[track] = champion  # keep the incumbent current

        decision = judge(candidate, champion, policy)
        if decision.crowned and decision.champion is not None:
            self._champions[track] = decision.champion
        return decision

    def emission_shares(
        self,
        *,
        burn_fraction: Decimal = Decimal("0.10"),
        serving_fraction: Decimal = Decimal("0"),
    ) -> dict[str, Decimal]:
        """Split one epoch's emission across champions, serving, and burn.

        `burn_fraction` defaults to Cathedral's contractual 10%
        (`MECHANISM_BURN_FRACTION`). An empty champion set pays everything to
        burn rather than to anyone unverified — the same stance the existing
        mechanism takes for an empty verified set.
        """
        if not Decimal(0) <= burn_fraction <= Decimal(1):
            raise FrontierError("burn_fraction must be within 0..1")
        if not Decimal(0) <= serving_fraction <= Decimal(1):
            raise FrontierError("serving_fraction must be within 0..1")
        if burn_fraction + serving_fraction > Decimal(1):
            raise FrontierError("burn plus serving cannot exceed the whole emission")

        shares: dict[str, Decimal] = {"burn": burn_fraction}
        if serving_fraction:
            shares["serving"] = serving_fraction

        remaining = Decimal(1) - burn_fraction - serving_fraction
        held = sorted(self._champions)
        if not held or remaining <= 0:
            shares["burn"] = burn_fraction + max(remaining, Decimal(0))
            return shares

        per_track = remaining / Decimal(len(held))
        for track in held:
            shares[f"champion:{track}"] = per_track
        return shares
