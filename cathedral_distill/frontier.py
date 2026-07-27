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
    # Reserved cross-batch guard. Within one sealed batch the crown is decided by
    # strict argmax (see `judge`) because there is no measurement noise between
    # candidates graded on identical items; the margin is retained for a future
    # cross-batch comparison path and is NOT applied to same-batch paired
    # evaluation, where applying it made the outcome submission-order dependent.
    min_margin: Decimal = Decimal("0.005")
    max_cost_usd: Decimal = Decimal("100")
    max_latency_p50_ms: Decimal = Decimal("5000")
    # The floor an unseated track pays nothing below. This must be *nonzero*: a
    # zero floor would crown a model that answers nothing, and pay it for holding
    # a frontier that measures no capability. Every track states its own floor.
    min_score_to_crown: Decimal = Decimal("0.05")
    # How long a crown stays payable without a fresh proof-of-life re-evaluation.
    # Past this, the champion is stale and pays burn until it is revalidated on a
    # current shard. Bounds how long a since-degraded or vanished model earns.
    crown_ttl_s: int = 86_400

    def __post_init__(self) -> None:
        if not self.track:
            raise FrontierError("track is required")
        if self.min_margin < 0:
            raise FrontierError("min_margin must be non-negative")
        if self.min_score_to_crown <= 0:
            raise FrontierError("min_score_to_crown must be a nonzero qualification floor")
        if self.crown_ttl_s <= 0:
            raise FrontierError("crown_ttl_s must be positive")


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
    # Provenance: only `derive_candidate` sets this true, after computing every
    # gate from verified evidence. A hand-built `Candidate` (all-true booleans,
    # a made-up receipt string) has it false, and `judge` refuses to crown it —
    # so a caller cannot assert its way onto the frontier.
    evidence_verified: bool = False

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
    # Proof-of-life. `revalidated_at` is when the crown was last re-evaluated on
    # a current shard; a crown older than its track's TTL is stale and pays burn.
    # `revoked`/`available`/`contaminated` are the other ways a crown stops
    # earning without being unseated by a better model.
    revalidated_at: datetime | None = None
    revoked: bool = False
    available: bool = True
    contaminated: bool = False

    def _last_life(self) -> datetime:
        return self.revalidated_at or self.crowned_at

    def is_live(self, now: datetime, ttl_s: int) -> bool:
        """Whether this crown may earn: not revoked, available, uncontaminated,
        and revalidated within the TTL. A crown that misses revalidation, is
        revoked, goes unavailable, or is flagged contaminated pays burn."""
        if self.revoked or not self.available or self.contaminated:
            return False
        return (now - self._last_life()).total_seconds() <= ttl_s

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
            "revalidated_at": self._last_life().isoformat(),
            "revoked": self.revoked,
            "available": self.available,
            "contaminated": self.contaminated,
        }

    def rescored(
        self, score: Decimal, batch_id: str, receipt_id: str, *, revalidated_at: datetime
    ) -> "Champion":
        """The same champion, its score refreshed on a new batch.

        Identity (miner, bundle, checkpoint, crowned_at) is preserved — it is the
        *same model still holding the crown* — but the score now reflects the
        current batch, so a challenger on that batch is judged fairly. The receipt
        of the fresh evaluation replaces the stale one. A re-score IS a fresh
        proof-of-life, so `revalidated_at` advances to when it ran — otherwise a
        champion re-scored every epoch could still age past its TTL and pay burn.
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
            revalidated_at=revalidated_at,
            revoked=self.revoked,
            available=self.available,
            contaminated=self.contaminated,
        )

    def with_liveness(
        self,
        *,
        revalidated_at: datetime | None = None,
        revoked: bool | None = None,
        available: bool | None = None,
        contaminated: bool | None = None,
    ) -> "Champion":
        """Return a copy with liveness fields updated (proof-of-life, revocation,
        availability, contamination). Identity and score are untouched."""
        from dataclasses import replace
        return replace(
            self,
            revalidated_at=revalidated_at if revalidated_at is not None else self.revalidated_at,
            revoked=self.revoked if revoked is None else revoked,
            available=self.available if available is None else available,
            contaminated=self.contaminated if contaminated is None else contaminated,
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
class CandidateEvidence:
    """The raw, verifiable inputs a candidate's gates are DERIVED from.

    The boolean gates on `Candidate` are convenient but attackable: a caller can
    set them all true. `derive_candidate` instead computes each gate from
    evidence a validator can check — the signed eval receipt, the teacher
    registry, the bundle registry, the evaluator's coldkey, an independent
    reproduction receipt, and the canary outcome — so no gate can be asserted
    into existence. Missing or failing evidence fails that gate closed.
    """

    receipt: Mapping[str, object]
    miner_hotkey: str
    submitted_at: datetime
    cost_usd: Decimal
    batch_id: str = ""
    teacher_registry: object | None = None
    teacher_id: str = ""
    licence_checked_at: datetime | None = None
    bundle_registry: object | None = None
    bundle_digest: str = ""
    training_participant: object | None = None
    evaluator_participant: object | None = None
    reproduction_receipt: Mapping[str, object] | None = None
    # Canary outcome: how many canary items the model passed, out of how many,
    # and the rate an uncontaminated model would pass by chance. A canary's
    # answer is not derivable from public data, so passing above chance means the
    # sealed set was seen. No canary evidence fails the gate closed.
    canary_passed: int = 0
    canary_total: int = 0
    canary_chance_rate: Decimal = Decimal("0.25")
    # The result of the RAW attestation verification (Polaris/TDX quote + policy),
    # supplied by the verifier — NOT inferred from the receipt's attestation kind.
    # A structurally valid `kind: "tdx"` receipt is not creditable unless the raw
    # quote actually verified; this must be True for the attested gate to pass.
    attestation_verified: bool | None = None


def _reproduction_ok(
    receipt: Mapping[str, object], reproduction: Mapping[str, object] | None
) -> bool:
    """A second, independently-evaluated receipt that reproduces the result:
    same sealed set, same checkpoint, same graded items_root, different
    evaluator. Anything less does not clear the reproduced gate."""
    from cathedral_distill import eval_receipt as er

    if reproduction is None:
        return False
    try:
        original = er.validate_receipt(receipt)
        replay = er.validate_receipt(reproduction)
    except er.EvalReceiptError:
        return False
    if not er.creditable_as_verified_work(reproduction):
        return False
    return (
        replay["evalset"]["plaintext_digest"] == original["evalset"]["plaintext_digest"]
        and replay["model"]["weights_digest"] == original["model"]["weights_digest"]
        and replay["score"]["items_root"] == original["score"]["items_root"]
        and replay["validator_hotkey"] != original["validator_hotkey"]
    )


def _canary_contaminated(evidence: CandidateEvidence) -> bool:
    """Contaminated when the canary pass rate exceeds chance (the set was seen),
    or when there is no canary evidence at all (cannot assert clean)."""
    if evidence.canary_total <= 0:
        return True
    observed = Decimal(evidence.canary_passed) / Decimal(evidence.canary_total)
    return observed > evidence.canary_chance_rate


def derive_candidate(evidence: CandidateEvidence, policy: TrackPolicy) -> Candidate:
    """Build a `Candidate` whose gates are derived from verified evidence.

    This is the production path: `Frontier.submit(derive_candidate(evidence,
    policy))`. Each gate is computed by an actual check, never taken on trust, so
    an attacker cannot pass all-true booleans. A malformed receipt raises; a
    check without evidence fails that gate closed.
    """
    from cathedral_distill import eval_receipt as er
    from cathedral_distill import roles as ro
    from cathedral_distill.teacher_registry import PURPOSE_DISTILLATION

    receipt = er.validate_receipt(evidence.receipt)  # raises on malformed -> fail closed
    score_block = receipt["score"]

    # Creditable requires BOTH a non-"none" attested receipt AND the raw quote
    # verification result. A structurally valid tdx receipt whose quote never
    # verified is not attested — the kind is a claim, not a proof.
    attested = (
        er.creditable_as_verified_work(evidence.receipt)
        and evidence.attestation_verified is True
    )

    teacher_permitted = bool(
        evidence.teacher_registry is not None
        and evidence.teacher_id
        and evidence.licence_checked_at is not None
        and evidence.teacher_registry.is_permitted(
            evidence.teacher_id, purpose=PURPOSE_DISTILLATION, at=evidence.licence_checked_at
        )
    )
    registered_bundle = bool(
        evidence.bundle_registry is not None
        and evidence.bundle_digest
        and evidence.bundle_registry.is_registered_by(
            evidence.bundle_digest, evidence.miner_hotkey
        )
    )
    independent_evaluator = bool(
        evidence.training_participant is not None
        and evidence.evaluator_participant is not None
        and not ro.is_self_evaluation(
            evidence.training_participant, evidence.evaluator_participant
        )
    )
    reproduced = _reproduction_ok(evidence.receipt, evidence.reproduction_receipt)
    contamination_detected = _canary_contaminated(evidence)

    return Candidate(
        miner_hotkey=evidence.miner_hotkey,
        bundle_digest=evidence.bundle_digest,
        checkpoint_digest=str(receipt["model"]["weights_digest"]),
        receipt_id=str(receipt["receipt_id"]),
        score=Decimal(str(score_block["score"])),
        latency_p50_ms=Decimal(str(score_block["latency_p50_ms"])),
        cost_usd=evidence.cost_usd,
        submitted_at=evidence.submitted_at,
        batch_id=evidence.batch_id,
        attested=attested,
        teacher_permitted=teacher_permitted,
        reproduced=reproduced,
        contamination_detected=contamination_detected,
        registered_bundle=registered_bundle,
        independent_evaluator=independent_evaluator,
        evidence_verified=True,  # provenance: this candidate came through the evidence path
    )


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
    if not candidate.evidence_verified:
        # A raw Candidate was never checked against evidence. Refuse it before any
        # gate or score is considered — the frontier only judges candidates that
        # came through `derive_candidate`.
        return CrownDecision(False, "unverified_candidate", champion, GateResult(False))

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
        # Order-independent crown. On ONE sealed batch there is no measurement
        # noise between candidates — both were graded on identical items — so the
        # strictly higher score wins, and an exact score tie resolves by a
        # deterministic key (checkpoint_digest), never by who submitted first.
        # This is what makes the frontier converge to the same champion whatever
        # order validators observe submissions in. Re-submitting the champion's
        # own checkpoint ties its key exactly, so it never unseats the incumbent.
        challenger_wins = candidate.score > champion.score or (
            candidate.score == champion.score
            and candidate.checkpoint_digest < champion.checkpoint_digest
        )
        if not challenger_wins:
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

    def set_liveness(
        self,
        track: str,
        *,
        revalidated_at: datetime | None = None,
        revoked: bool | None = None,
        available: bool | None = None,
        contaminated: bool | None = None,
    ) -> None:
        """Record a proof-of-life, revocation, availability, or contamination
        signal for a track's champion. This is how a validator marks a crown
        that missed revalidation, was revoked, went unreachable, or was caught
        contaminated — all of which stop it earning (see `emission_shares`)."""
        champion = self._champions.get(track)
        if champion is None:
            raise FrontierError(f"no champion for track: {track}")
        self._champions[track] = champion.with_liveness(
            revalidated_at=revalidated_at, revoked=revoked,
            available=available, contaminated=contaminated,
        )

    def live_champions(self, now: datetime | None = None) -> dict[str, Champion]:
        """Champions currently eligible to earn. A revoked, unavailable, or
        contaminated crown is always excluded; when `now` is given, a crown past
        its track TTL (missed revalidation) is excluded too."""
        live: dict[str, Champion] = {}
        for track, champion in self._champions.items():
            if champion.revoked or not champion.available or champion.contaminated:
                continue
            if now is not None and not champion.is_live(now, self.policy(track).crown_ttl_s):
                continue
            live[track] = champion
        return live

    def state(self) -> dict[str, object]:
        """Canonical, order-independent frontier state.

        Two validators that applied the same crown decisions produce a
        byte-identical state and the same `state_digest`, regardless of restart
        time or the order they observed submissions — the frontier is data, not
        process-local history. `from_state` reconstructs it.
        """
        return {
            "schema": FRONTIER_SCHEMA,
            "champions": [
                self._champions[track].as_manifest()
                for track in sorted(self._champions)
            ],
        }

    def state_digest(self) -> str:
        import hashlib
        import json
        body = json.dumps(self.state(), sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(b"cathedral-frontier-state-v1\x00" + body).hexdigest()

    @classmethod
    def from_state(
        cls, policies: Sequence[TrackPolicy], state: Mapping[str, object]
    ) -> "Frontier":
        """Deterministically reconstruct a frontier from canonical state, so a
        restarted or newly-joined validator converges on the same champions."""
        frontier = cls(policies)
        if state.get("schema") != FRONTIER_SCHEMA:
            raise FrontierError("unsupported frontier state schema")
        champions = state.get("champions", [])
        if not isinstance(champions, list):
            raise FrontierError("frontier state champions must be a list")
        for entry in champions:
            track = str(entry["track"])
            if track not in frontier._policies:
                raise FrontierError(f"frontier state names an unknown track: {track}")
            if track in frontier._champions:
                raise FrontierError(f"frontier state repeats track: {track}")
            frontier._champions[track] = Champion(
                track=track,
                miner_hotkey=str(entry["miner_hotkey"]),
                bundle_digest=str(entry["bundle_digest"]),
                checkpoint_digest=str(entry["checkpoint_digest"]),
                receipt_id=str(entry["receipt_id"]),
                score=Decimal(str(entry["score"])),
                crowned_at=datetime.fromisoformat(str(entry["crowned_at"])),
                batch_id=str(entry.get("batch_id", "")),
                revalidated_at=datetime.fromisoformat(str(entry["revalidated_at"]))
                if entry.get("revalidated_at") else None,
                revoked=bool(entry.get("revoked", False)),
                available=bool(entry.get("available", True)),
                contaminated=bool(entry.get("contaminated", False)),
            )
        return frontier

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
                revalidated_at=candidate.submitted_at,  # the rescore is proof-of-life
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
        now: datetime | None = None,
    ) -> dict[str, Decimal]:
        """Split one epoch's emission across LIVE champions, serving, and burn.

        `burn_fraction` defaults to Cathedral's contractual 10%
        (`MECHANISM_BURN_FRACTION`). Only live champions earn: a revoked,
        unavailable, or contaminated crown never pays, and — when `now` is given
        — a crown past its track TTL (missed revalidation) does not either. An
        empty *live* champion set pays everything to burn rather than to anyone
        unverified, the same stance the existing mechanism takes for an empty
        verified set. Production always passes `now` so a stale crown burns.
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
        held = sorted(self.live_champions(now))
        if not held or remaining <= 0:
            # Unpaid mass (no live champion, or nothing left after serving) falls
            # to burn, never to an unverified or stale holder.
            shares["burn"] = burn_fraction + max(remaining, Decimal(0))
            return shares

        per_track = remaining / Decimal(len(held))
        for track in held:
            shares[f"champion:{track}"] = per_track
        return shares
