"""A runnable CyberGym validator service — the transport-agnostic delivery loop.

`cybergym_protocol` is pure functions; `cybergym_validator.run_epoch` is the pure
scorer. This is the missing stateful glue that makes them a *running* validator: it
serves each miner its sealed batch, accepts POSTed submissions, verifies them into
the corpus, and — at epoch close — scores the collected solves through `run_epoch`,
persists them to the `cybergym_scores` table, and composes the lane contribution.

    validator.dispatch_for(miner, commitment)  → DispatchMessage   (serve a batch)
    validator.submit(envelope)                 → SubmissionOutcome  (verify → corpus)
    validator.score_epoch(issued_at)           → [MinerResult]      (score → persist)
    validator.compose_lane(allocation)         → Lane               (→ compose_vector)

`handle_dispatch` / `handle_submit` are transport-agnostic (dict in, dict out) so
any wire binding is a thin wrapper — `cybergym_http` is the stdlib one. The crash
backend is injected, so the whole service runs end-to-end with no CyberGym binaries.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill.attestation import AttestationPolicy
from cathedral_distill.cybergym import DEFAULT_LEVEL_WEIGHTS, Level
from cathedral_distill.cybergym_holdout import Holdout
from cathedral_distill.cybergym_protocol import (
    DispatchMessage,
    ProtocolError,
    SubmissionEnvelope,
    SubmissionOutcome,
    dispatch,
    process_submission,
)
from cathedral_distill.cybergym_scores import CyberGymScoreStore, CyberGymSolveStore
from cathedral_distill.cybergym_validator import (
    ChainContext,
    EmissionGatePolicy,
    MinerCommit,
    MinerResult,
    run_epoch,
)
from cathedral_distill.lane_feed import Lane, LaneContribution
from cathedral_distill.trace_submission import TraceQualityPolicy

CYBERGYM_LANE = "cathedral_cybergym"


@dataclass
class _MinerState:
    model_commitment: str
    # None for state recovered from the solve store after a restart: the dispatch
    # message itself is not needed to score (run_epoch re-draws the batch from the
    # chain-anchored nonce), only to accept NEW submissions.
    dispatch: DispatchMessage | None
    pocs: dict[str, bytes] = field(default_factory=dict)  # task_id -> solved PoC bytes


class CyberGymService:
    """A running CyberGym validator over one holdout + finalized chain context.

    Transport-free: call the methods directly, or mount `handle_dispatch`/
    `handle_submit` behind any HTTP/axon shim.

    Durability: accepted solves are written through to `solve_store` as they are
    accepted and rehydrated at construction, so a restart mid-epoch resumes with
    the same scoring input (`run_epoch` re-draws each batch from the chain-anchored
    nonce, so the commitment plus the PoC bytes are all it needs). The *dispatch*
    messages are still in-memory only: after a restart a miner must re-request its
    batch (same commitment, same nonce, same batch) before it can submit again.
    `compose_lane` refuses to publish while durable evidence shows solves this run
    did not score, so a lost epoch is loud instead of a silent forced burn.
    """

    def __init__(
        self,
        holdout: Holdout,
        chain: ChainContext,
        *,
        backend,
        corpus_store,
        score_store: CyberGymScoreStore,
        solve_store: CyberGymSolveStore | None = None,
        solve_durability_required: bool = True,
        validator_hotkey: str,
        private_key: Ed25519PrivateKey,
        signing_key_id: str,
        batch_size: int,
        cutoff,
        as_of,
        level_weights: Mapping[Level, Decimal] = DEFAULT_LEVEL_WEIGHTS,
        trace_policy: TraceQualityPolicy = TraceQualityPolicy(),
        attestation_policy: AttestationPolicy | None = None,
        attestation_now: datetime | None = None,
        attestation_required: bool = True,
        gate_policy: EmissionGatePolicy | None = None,
        gates_required: bool = True,
        credit_synthetic_tasks: bool = False,
    ) -> None:
        # Fail closed: Intel-TDX attestation is a MANDATORY control for this track,
        # so the running service refuses to start without an attestation policy
        # unless the operator EXPLICITLY opts out (attestation_required=False) for
        # the hardware-free dev/test path — and even then it says so loudly. A
        # forgotten kwarg must never silently credit unattested solves.
        if attestation_policy is None:
            if attestation_required:
                raise ProtocolError(
                    "CyberGym requires an Intel-TDX attestation policy: pass "
                    "attestation_policy=..., or attestation_required=False for the "
                    "hardware-free dev/test path (which credits UNATTESTED solves)."
                )
            import warnings
            warnings.warn(
                "CyberGymService running WITHOUT Intel-TDX attestation enforcement "
                "(attestation_required=False): every solved PoC is credited with no "
                "attestation. Dev/test only — never in production.",
                stacklevel=2,
            )
        # Fail closed on durability too. Accepted solves lived only in memory
        # until epoch close, so a restart mid-epoch lost them all while the corpus
        # rows survived, and the lane published a forced-burn vector: every miner
        # paid for the validator's restart. A running service therefore needs a
        # solve store, or an explicit opt-out that says what is being given up.
        if solve_store is None:
            if solve_durability_required:
                raise ProtocolError(
                    "CyberGym requires a durable solve store: pass "
                    "solve_store=CyberGymSolveStore(path), or "
                    "solve_durability_required=False for the ephemeral dev/test path "
                    "(a restart before epoch close then loses every accepted solve, and "
                    "the service will REFUSE to compose the lane rather than publish a "
                    "silent forced burn)."
                )
            import warnings
            warnings.warn(
                "CyberGymService running WITHOUT a durable solve store "
                "(solve_durability_required=False): accepted solves live in memory "
                "only, so a restart before epoch close loses them. Dev/test only.",
                stacklevel=2,
            )
        # And fail closed on the anti-gaming gates, for the same reason: the
        # emission path (score_epoch -> run_epoch -> cybergym_scores -> adapter) is
        # what pays, so a forgotten gate policy must not quietly pay an
        # unregistered model commitment.
        if gate_policy is None and gates_required:
            raise ProtocolError(
                "CyberGym requires an anti-gaming gate policy on the emission path: "
                "pass gate_policy=EmissionGatePolicy(bundle_registry=...), or "
                "gates_required=False for the dev/test path (which persists scores "
                "with NO registered-bundle or contamination gate)."
            )
        self.holdout = holdout
        self.chain = chain
        self._backend = backend
        self._corpus = corpus_store
        self._scores = score_store
        self._solves = solve_store
        self._validator_hotkey = validator_hotkey
        self._private_key = private_key
        self._signing_key_id = signing_key_id
        self._batch_size = batch_size
        self._cutoff = cutoff
        self._as_of = as_of
        self._weights = level_weights
        self._trace_policy = trace_policy
        # When set, a submission must carry a valid Intel-TDX attestation bound to
        # it (cybergym_attest) to be creditable; None keeps the hardware-free path.
        self._attestation_policy = attestation_policy
        self._attestation_now = attestation_now
        self._gate_policy = gate_policy
        self._gates_required = gates_required
        # Synthetic tasks are graded but not rewarded by default: their artifact
        # renders the answer (see cybergym_synthetic.is_synthetic_task). True is an
        # explicit unsafe-for-rewards override.
        self._credit_synthetic_tasks = credit_synthetic_tasks
        self._miners: dict[str, _MinerState] = {}
        self._by_batch: dict[str, str] = {}  # batch_id -> miner_hotkey
        self._dispatched: set[str] = set()   # task_ids actually served this epoch
        self._results: list[MinerResult] = []
        self._scored_miners: set[str] = set()  # miners this process actually scored
        self._restore_solves()

    # -- crash recovery ---------------------------------------------------- #
    def _restore_solves(self) -> None:
        """Rehydrate this epoch's accepted solves from the durable solve store.

        Byte-identical recovery: `run_epoch` re-draws each miner's batch from the
        chain-anchored nonce (derived from its hotkey and committed model), so the
        model commitment plus the accepted PoC bytes are the complete input. A
        restarted service scores exactly what the killed one would have.
        """
        if self._solves is None:
            return
        for miner_hotkey, (commitment, pocs) in self._solves.commits(
            self.chain.source_epoch
        ).items():
            self._miners[miner_hotkey] = _MinerState(commitment, None, dict(pocs))

    # -- dispatch (validator -> miner) ------------------------------------- #
    def dispatch_for(self, miner_hotkey: str, model_commitment: str) -> DispatchMessage:
        """Draw and serve this miner's sealed batch, remembering it for `submit`."""
        message = dispatch(
            self.holdout.pool, self.chain,
            miner_hotkey=miner_hotkey, model_commitment=model_commitment,
            cutoff=self._cutoff, as_of=self._as_of, batch_size=self._batch_size,
            context_provider=self.holdout.context_provider,
        )
        # A repeat dispatch must not silently erase accepted solves. Same committed
        # model -> same nonce -> same batch, so the solves already accepted this
        # epoch still belong to it and are kept. A different commitment is a
        # different batch, so the old solves are for other tasks: drop them, and
        # drop them durably, or a later restart would resurrect them.
        previous = self._miners.get(miner_hotkey)
        if previous is not None and previous.model_commitment == model_commitment:
            self._miners[miner_hotkey] = _MinerState(
                model_commitment, message, dict(previous.pocs)
            )
        else:
            if previous is not None and self._solves is not None:
                self._solves.forget_miner(
                    epoch=self.chain.source_epoch, miner_hotkey=miner_hotkey
                )
            self._miners[miner_hotkey] = _MinerState(model_commitment, message)
        self._by_batch[message.batch_id] = miner_hotkey
        self._dispatched.update(t.task_id for t in message.tasks)
        return message

    # -- submit (miner -> validator) --------------------------------------- #
    def submit(self, envelope: SubmissionEnvelope) -> SubmissionOutcome:
        """Verify one submission against the batch we dispatched, and corpus it."""
        miner_hotkey = self._by_batch.get(envelope.batch_id)
        if miner_hotkey is None:
            raise ProtocolError("submission references an unknown or expired batch")
        if envelope.miner_hotkey != miner_hotkey:
            raise ProtocolError("submission hotkey does not own this batch")
        state = self._miners[miner_hotkey]
        outcome = process_submission(
            envelope, state.dispatch, self._backend,
            trace_policy=self._trace_policy, weights=self._weights,
            attestation_policy=self._attestation_policy, now=self._attestation_now,
        )
        self._corpus.record(outcome)
        if outcome.creditable:
            # Only an attested solve enters the reward pool: score_epoch re-derives
            # each miner's units from exactly these PoCs, so an unattested (or
            # unverifiable-attestation) solve earns nothing even though it crashed.
            try:
                poc = base64.b64decode(envelope.poc_base64, validate=True)
            except (ValueError, TypeError) as exc:  # pragma: no cover - process_submission already checked
                raise ProtocolError("PoC is not valid base64") from exc
            state.pocs[envelope.task_id] = poc
            # Durable before acknowledged: the miner is told this solve counted, so
            # it has to survive a restart between now and epoch close.
            if self._solves is not None:
                self._solves.record(
                    epoch=self.chain.source_epoch, miner_hotkey=miner_hotkey,
                    model_commitment=state.model_commitment,
                    task_id=envelope.task_id, poc=poc,
                )
        return outcome

    # -- artifact (validator -> miner): the vulnerable program to analyse --- #
    def artifact_for(self, task_id: str) -> str:
        """Return the vulnerable program a miner must analyse for a dispatched task.

        This is the 'binary'/'repo' a CyberGym miner needs — over the wire a miner
        has only metadata otherwise, so a blind (level-0) task is unsolvable without
        it. Guarded to tasks THIS service actually dispatched: the holdout is
        secret, so the service must never generate-and-reveal a program for a task
        it did not draw (that would turn the artifact route into a holdout oracle).
        For a synthetic task the artifact is the generated source; for a real
        corpus task it is fetched out of band by `binary_digest` (not inline), so
        this raises directing the miner there.
        """
        if task_id not in self._dispatched:
            raise ProtocolError("no such dispatched task")
        provider = getattr(self.holdout.pool, "artifact", None)
        program = provider(task_id) if provider is not None else None
        if program is None:
            raise ProtocolError(
                "no inline artifact for this task; fetch the build out of band by binary_digest"
            )
        return str(program)

    # -- transport-agnostic handlers --------------------------------------- #
    def handle_artifact(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """{task_id} -> {task_id, program} (or {error}). Never raises."""
        if not isinstance(request, Mapping):
            return {"error": "artifact request must be an object"}
        task_id = request.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            return {"error": "task_id is required"}
        try:
            return {"task_id": task_id, "program": self.artifact_for(task_id)}
        except (ProtocolError, ValueError) as exc:
            return {"error": str(exc)}

    def handle_dispatch(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """{miner_hotkey, model_commitment} -> DispatchMessage dict (or {error})."""
        if not isinstance(request, Mapping):
            return {"error": "dispatch request must be an object"}
        miner = request.get("miner_hotkey")
        commitment = request.get("model_commitment")
        if not isinstance(miner, str) or not miner:
            return {"error": "miner_hotkey is required"}
        if not isinstance(commitment, str) or not commitment:
            return {"error": "model_commitment is required"}
        try:
            return self.dispatch_for(miner, commitment).to_dict()
        except (ProtocolError, ValueError) as exc:
            return {"error": str(exc)}

    def handle_submit(self, body: bytes | str) -> dict[str, Any]:
        """A POSTed SubmissionEnvelope -> a verdict dict (never raises)."""
        try:
            envelope = SubmissionEnvelope.from_json(body)
            outcome = self.submit(envelope)
        except (ProtocolError, ValueError) as exc:
            return {"accepted": False, "error": str(exc)}
        return {
            "accepted": True,
            "task_id": outcome.task_id,
            "solved": outcome.solved,
            "attested": outcome.attested,
            "creditable": outcome.creditable,
            "trainable": outcome.trainable,
            "reason": outcome.reason,
            "work_units": str(outcome.work_units),
            "bonus": outcome.bonus,
            "poc_sha256": outcome.poc_sha256,
        }

    # -- scoring + composition (epoch close) ------------------------------- #
    def score_epoch(self, *, issued_at: str) -> list[MinerResult]:
        """Score every dispatched miner on its collected solves and persist.

        Reuses the canonical `run_epoch` scorer (it re-draws each miner's batch
        from the same chain-anchored nonce and re-verifies, so the persisted score
        is the one any peer validator would derive). Records to `cybergym_scores`.
        """
        # Only miners with at least one verified solve are scored — a miner that
        # solved nothing has no rewardable units and no receipt to persist.
        miners = [
            MinerCommit(miner_hotkey=hk, model_commitment=st.model_commitment, pocs=dict(st.pocs))
            for hk, st in self._miners.items() if st.pocs
        ]
        self._results = run_epoch(
            miners, self.holdout.pool, self.chain,
            validator_hotkey=self._validator_hotkey, private_key=self._private_key,
            signing_key_id=self._signing_key_id, backend=self._backend,
            score_store=self._scores, cutoff=self._cutoff, as_of=self._as_of,
            issued_at=issued_at, batch_size=self._batch_size, level_weights=self._weights,
            gate_policy=self._gate_policy, gates_required=self._gates_required,
            credit_synthetic_tasks=self._credit_synthetic_tasks,
        )
        self._scored_miners.update(m.miner_hotkey for m in miners)
        return self._results

    def lost_durable_solvers(self) -> set[str]:
        """Miners with durable evidence of accepted solves this process cannot score.

        The corpus rows and the solve store outlive the process; the in-memory
        scoring state does not. A miner that appears in durable evidence but has
        neither a persisted score nor recoverable in-memory solves has had its
        epoch's work destroyed by the restart, and composing would burn its share.
        """
        epoch = self.chain.source_epoch
        durable_solvers = {row["miner_hotkey"] for row in self._corpus.rows(source_epoch=epoch)}
        if self._solves is not None:
            durable_solvers |= set(self._solves.commits(epoch))
        recoverable = {hk for hk, st in self._miners.items() if st.pocs}
        return durable_solvers - recoverable - set(self._scores.epoch_scores(epoch))

    def pending_solvers(self) -> set[str]:
        """Miners holding accepted solves that this run has not scored yet."""
        return {
            hk for hk, st in self._miners.items()
            if st.pocs and hk not in self._scored_miners
        }

    def compose_lane(self, *, allocation: Decimal, lane_id: str = CYBERGYM_LANE) -> Lane:
        """Build this epoch's lane from the persisted verified scores.

        Refuses rather than publishing an under-credited vector. Two ways the lane
        would otherwise be quietly wrong, both of which look identical to "nobody
        solved anything" once the vector is published:

          * solves destroyed by a restart (no durable solve store), and
          * accepted solves that were never scored (composing before `score_epoch`).

        Silence is the failure being fixed, so this raises and the operator decides.
        """
        lost = self.lost_durable_solvers()
        if lost:
            raise ProtocolError(
                "refusing to compose the CyberGym lane: durable evidence shows "
                f"{len(lost)} miner(s) solved epoch {self.chain.source_epoch} but this "
                f"run cannot score them ({', '.join(sorted(lost))}). Restart with the same "
                "solve_store to recover the epoch; publishing now would forcibly burn "
                "their share."
            )
        pending = self.pending_solvers()
        if pending:
            raise ProtocolError(
                "refusing to compose the CyberGym lane: "
                f"{len(pending)} miner(s) have accepted solves that were never scored "
                f"({', '.join(sorted(pending))}). Call score_epoch first."
            )
        return compose_scores_lane(
            self._scores, self.chain.source_epoch, allocation=allocation, lane_id=lane_id
        )


def compose_results_lane(
    results: Sequence[MinerResult],
    *,
    allocation: Decimal,
    lane_id: str = CYBERGYM_LANE,
) -> Lane:
    """Compose a lane straight from `run_epoch` results, refusing gated-out ones.

    The durable route is `compose_scores_lane` (the store is the record of what was
    paid). This exists because callers do compose the returned results directly, and
    when they do, a non-creditable `MinerResult` must be refused rather than
    silently contributing: a failed gate means the miner earns nothing, through
    every route.
    """
    contributions = []
    for result in results:
        if not result.creditable:
            continue
        units = Decimal(str(result.contribution["work_units"]))
        if units <= 0:
            continue
        contributions.append(
            LaneContribution(
                str(result.contribution["miner_hotkey"]),
                str(result.contribution["receipt_id"]),
                units,
            )
        )
    return Lane(lane_id, allocation, contributions)


def compose_scores_lane(
    score_store: CyberGymScoreStore,
    epoch: int,
    *,
    allocation: Decimal,
    lane_id: str = CYBERGYM_LANE,
) -> Lane:
    """Turn the persisted `cybergym_scores` for an epoch into a `lane_feed.Lane`.

    This is the store->compose bridge: `score_store` is the durable writer the
    external mechanism adapter reads; this reads the same rows into the in-repo
    `compose_vector` path, so a validator can compose the signed vector directly
    from what it persisted. A miner with zero verified units contributes nothing.
    """
    contributions = [
        LaneContribution(row["miner_hotkey"], row["receipt_id"], Decimal(row["earned_units"]))
        for row in score_store.contributions(epoch)
        if Decimal(row["earned_units"]) > 0
    ]
    return Lane(lane_id, allocation, contributions)


__all__ = [
    "CyberGymService", "compose_scores_lane", "compose_results_lane", "CYBERGYM_LANE",
]
