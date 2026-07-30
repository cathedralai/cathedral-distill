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
import hashlib
from dataclasses import dataclass, field, replace
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
from cathedral_distill.cybergym_scores import (
    EPOCH_CLOSED,
    EPOCH_INCOMPLETE,
    CyberGymScoreError,
    CyberGymScoreStore,
    CyberGymSolveStore,
)
from cathedral_distill.cybergym_validator import (
    ChainContext,
    EmissionGatePolicy,
    MinerCommit,
    MinerResult,
    emission_gate_policy_manifest,
    run_epoch,
)
from cathedral_distill.cybergym_synthetic import is_synthetic_task
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
        self._scoring_pass_ran = False         # whether score_epoch ran in this process
        # miner_hotkey -> why its durable solves cannot be scored this epoch
        self._unscorable: dict[str, str] = {}
        self._pin_epoch_manifest()
        self._restore_solves()

    # -- crash recovery ---------------------------------------------------- #
    def epoch_manifest(self) -> dict[str, object]:
        """Every input that decides what this epoch draws and what it signs.

        Recovering the accepted PoCs is not enough for byte-identical scoring: the
        batch nonce is derived from the finalized block and block hash, and the
        receipt binds the network, netuid, block window, validator identity and
        signing key. A restart that resumed the same `source_epoch` under a
        different anchor drew a different batch and signed a different receipt, and
        nothing noticed. This manifest is what makes "the same epoch" checkable.
        """
        def stamp(value: object) -> object:
            return value.isoformat() if hasattr(value, "isoformat") else value

        return {
            "schema": "cathedral_cybergym_epoch_manifest_v1",
            "source_epoch": int(self.chain.source_epoch),
            "network": str(self.chain.network),
            "netuid": int(self.chain.netuid),
            "block": int(self.chain.block),
            "block_hash": str(self.chain.block_hash),
            "valid_from_block": int(self.chain.valid_from_block),
            "valid_until_block": int(self.chain.valid_until_block),
            "batch_size": int(self._batch_size),
            "cutoff": stamp(self._cutoff),
            "as_of": stamp(self._as_of),
            "validator_hotkey": str(self._validator_hotkey),
            "signing_key_id": str(self._signing_key_id),
            "signing_public_key_digest": (
                "sha256:"
                + hashlib.sha256(
                    self._private_key.public_key().public_bytes_raw()
                ).hexdigest()
            ),
            "level_weights": {str(int(level)): str(w) for level, w in self._weights.items()},
            "credit_synthetic_tasks": bool(self._credit_synthetic_tasks),
            "gates_required": bool(self._gates_required),
            "gate_policy": emission_gate_policy_manifest(self._gate_policy),
        }

    def _pin_epoch_manifest(self) -> None:
        """Pin the epoch's inputs on first run; refuse a restart that changed them."""
        if self._solves is None:
            return
        try:
            self._solves.record_manifest(self.chain.source_epoch, self.epoch_manifest())
        except CyberGymScoreError as exc:
            raise ProtocolError(
                f"refusing to resume CyberGym epoch {self.chain.source_epoch}: {exc}"
            ) from exc

    def _mark_unscorable(self, miner_hotkey: str, reason: str) -> None:
        """Record that a miner's durable solves for this epoch cannot be scored."""
        self._unscorable[miner_hotkey] = reason
        if self._solves is not None:
            self._solves.record_unscorable(
                epoch=self.chain.source_epoch, miner_hotkey=miner_hotkey, reason=reason
            )

    def _clear_unscorable(self, miner_hotkey: str) -> None:
        """A miner that has produced a fresh accepted solve is scoreable again."""
        if self._unscorable.pop(miner_hotkey, None) is None and self._solves is None:
            return
        if self._solves is not None:
            self._solves.clear_unscorable(
                epoch=self.chain.source_epoch, miner_hotkey=miner_hotkey
            )

    def acknowledge_unscorable_solves(self, *, reason: str) -> set[str]:
        """Operator override: accept that some durable solves cannot be scored.

        A fail-closed control an operator cannot clear is its own outage. This is the
        clearing mechanism for the case the refusal is genuinely about: this
        validator cannot reconstruct part of its own epoch (it ran without a durable
        solve store, or the store was lost). It records the acknowledgement, with the
        operator's reason, in the same durable stores the refusal reads, so the
        refusal does not come back after the next restart.

        It DELETES NOTHING. The corpus rows and any solve rows stay exactly where
        they are; only the fact that they cannot be scored is recorded. The affected
        miners earn nothing for this epoch, which is the honest outcome, and the rest
        of the lane composes.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ProtocolError(
                "an acknowledgement must carry a reason, which lands in the epoch's "
                "audit trail"
            )
        lost = self.lost_durable_solvers()
        for miner_hotkey in sorted(lost):
            self._mark_unscorable(miner_hotkey, f"operator acknowledged: {reason}")
        if lost and self._scoring_pass_ran:
            # A scoring pass already ran, so the epoch's recorded state is stale.
            self._scores.mark_epoch(
                self.chain.source_epoch, state=EPOCH_CLOSED,
                detail=(
                    f"operator acknowledged {len(lost)} unscorable solve set(s) "
                    f"({', '.join(sorted(lost))}): {reason}"
                ),
                scored_miners=len(self._scored_miners),
            )
        return lost

    def _restore_solves(self) -> None:
        """Rehydrate this epoch's accepted solves from the durable solve store.

        Byte-identical recovery: `run_epoch` re-draws each miner's batch from the
        chain-anchored nonce (derived from its hotkey and committed model), so the
        model commitment plus the accepted PoC bytes are the complete input, GIVEN
        the same epoch anchor, which `_pin_epoch_manifest` is what enforces.
        """
        if self._solves is None:
            return
        self._unscorable.update(self._solves.unscorable(self.chain.source_epoch))
        for miner_hotkey, (commitment, pocs) in self._solves.commits(
            self.chain.source_epoch
        ).items():
            self._miners[miner_hotkey] = _MinerState(commitment, None, dict(pocs))

    # -- dispatch (validator -> miner) ------------------------------------- #
    def dispatch_for(self, miner_hotkey: str, model_commitment: str, *,
                     authenticated_caller: str | None = None) -> DispatchMessage:
        """Draw and serve this miner's sealed batch, remembering it for `submit`.

        `authenticated_caller` is the identity the TRANSPORT proved made this call
        (a Bittensor axon's `synapse.dendrite.hotkey`, or a signature the reference
        server verifies) — never a value from the request body. Dispatch is
        caller-bound: a re-commit that would ABANDON already-accepted solves must be
        proven to come from the hotkey owner. Without that proof the destructive path
        is refused, so an unauthenticated request cannot re-dispatch a victim's public
        hotkey with a different commitment to delete that miner's verified solves.
        """
        if authenticated_caller is not None and authenticated_caller != miner_hotkey:
            raise ProtocolError(
                f"authenticated caller {authenticated_caller!r} may not dispatch for "
                f"{miner_hotkey!r}")
        previous = self._miners.get(miner_hotkey)
        # A commitment change abandons the previous batch. When accepted solves would
        # be dropped, require the caller to be the miner — otherwise this is a
        # reward-denial attack, not a self-re-commit. Checked BEFORE drawing, so an
        # unauthorized call has no side effects at all.
        if (previous is not None and previous.model_commitment != model_commitment
                and previous.pocs and authenticated_caller != miner_hotkey):
            raise ProtocolError(
                f"re-committing for {miner_hotkey!r} would abandon {len(previous.pocs)} "
                "accepted solve(s); a commitment change that drops solves must be "
                "authenticated as the miner, not an arbitrary dispatch request")
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
        if previous is not None and previous.model_commitment == model_commitment:
            self._miners[miner_hotkey] = _MinerState(
                model_commitment, message, dict(previous.pocs)
            )
        else:
            if previous is not None:
                if self._solves is not None:
                    self._solves.forget_miner(
                        epoch=self.chain.source_epoch, miner_hotkey=miner_hotkey
                    )
                if previous.pocs:
                    # This miner (authenticated above) abandoned the commitment its
                    # solves were drawn against. The corpus rows survive, so without
                    # this marker the miner would look "lost" forever and
                    # `compose_lane` would refuse the WHOLE lane. A miner's own
                    # re-commit costs that miner its unscored solves, never the lane.
                    self._mark_unscorable(
                        miner_hotkey,
                        "miner re-committed mid-epoch; solves drawn against "
                        f"{previous.model_commitment} were abandoned",
                    )
            self._miners[miner_hotkey] = _MinerState(model_commitment, message)
        self._by_batch[message.batch_id] = miner_hotkey
        self._dispatched.update(t.task_id for t in message.tasks)
        return message

    # -- submit (miner -> validator) --------------------------------------- #
    def rewardable_task(self, task_id: str) -> bool:
        """Whether a solve of this task can earn units under the active policy.

        Synthetic-source tasks are graded and not rewarded unless
        `credit_synthetic_tasks` is set. The wire response has to say so: a miner
        that is told `work_units: 8` for work the epoch will pay 0 for has been
        misled, and the task id grammar admits a `synthvuln:` id in a real holdout
        manifest, so this is reachable without any synthetic source at all.
        """
        return self._credit_synthetic_tasks or not is_synthetic_task(task_id)

    def submit(self, envelope: SubmissionEnvelope) -> SubmissionOutcome:
        """Verify one submission against the batch we dispatched, and corpus it.

        The returned `work_units` is what the epoch will actually pay for this task:
        a solve of a non-rewardable task reports zero here as well as at emission, so
        the wire and the reward agree.
        """
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
        if outcome.work_units > 0 and not self.rewardable_task(envelope.task_id):
            # Make the wire agree with the emission decision. run_epoch excludes this
            # task from the scored submissions, so promising units here would be a
            # promise the epoch does not keep.
            outcome = replace(
                outcome, work_units=Decimal(0),
                reason=f"{outcome.reason}|non_rewardable_source:synthetic",
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
            # A fresh accepted solve makes this miner scoreable again, so any earlier
            # "unscorable" marker (from a re-commit) no longer applies.
            self._clear_unscorable(miner_hotkey)
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

    def handle_dispatch(self, request: Mapping[str, Any], *,
                        authenticated_caller: str | None = None) -> dict[str, Any]:
        """{miner_hotkey, model_commitment} -> DispatchMessage dict (or {error}).

        `authenticated_caller` is supplied by the TRANSPORT (an axon's verified
        dendrite hotkey), never read from the body — the body's `miner_hotkey` is
        untrusted. `dispatch_for` binds the two so a caller can only dispatch for
        itself and an unauthenticated request cannot abandon another miner's solves.
        A production transport MUST pass it; the unauthenticated reference server
        leaves it None, which makes the solve-dropping re-commit path fail closed.
        """
        if not isinstance(request, Mapping):
            return {"error": "dispatch request must be an object"}
        miner = request.get("miner_hotkey")
        commitment = request.get("model_commitment")
        if not isinstance(miner, str) or not miner:
            return {"error": "miner_hotkey is required"}
        if not isinstance(commitment, str) or not commitment:
            return {"error": "model_commitment is required"}
        try:
            return self.dispatch_for(
                miner, commitment, authenticated_caller=authenticated_caller).to_dict()
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

        `issued_at` is PINNED on the first scoring pass for the epoch and reused by
        every later one. The receipt bytes include it, so a retry or a restart that
        passed a fresh timestamp would sign a different receipt for the same epoch
        and "recovered byte-identically" would not be true.
        """
        # Only miners with at least one verified solve are scored — a miner that
        # solved nothing has no rewardable units and no receipt to persist.
        miners = [
            MinerCommit(miner_hotkey=hk, model_commitment=st.model_commitment, pocs=dict(st.pocs))
            for hk, st in self._miners.items() if st.pocs
        ]
        if self._solves is not None:
            issued_at = self._solves.pin_issued_at(self.chain.source_epoch, issued_at)
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
        self._scoring_pass_ran = True
        # Record how this pass ended IN THE SCORES DATABASE, which is what the
        # external mechanism adapter reads. Refusal that lives only on this object
        # is invisible to the adapter, and the adapter is the thing that publishes.
        lost = self.lost_durable_solvers()
        if lost:
            self._scores.mark_epoch(
                self.chain.source_epoch, state=EPOCH_INCOMPLETE,
                detail=(
                    f"{len(lost)} miner(s) with durable solves could not be scored: "
                    f"{', '.join(sorted(lost))}"
                ),
                scored_miners=len(miners),
            )
        else:
            self._scores.mark_epoch(
                self.chain.source_epoch, state=EPOCH_CLOSED,
                detail="scored with every durable solve accounted for",
                scored_miners=len(miners),
            )
        return self._results

    def lost_durable_solvers(self) -> set[str]:
        """Miners with durable evidence of accepted solves this process cannot score.

        The corpus rows and the solve store outlive the process; the in-memory
        scoring state does not. A miner that appears in durable evidence but has
        neither a persisted score nor recoverable in-memory solves has had its
        epoch's work destroyed by the restart, and composing would burn its share.

        Miners recorded as unscorable are NOT lost state: a miner that abandoned the
        commitment it was drawn against, or a loss an operator has acknowledged, is a
        settled outcome. Counting them here is what let one miner wedge the lane's
        composition permanently with two RPCs.
        """
        epoch = self.chain.source_epoch
        durable_solvers = {row["miner_hotkey"] for row in self._corpus.rows(source_epoch=epoch)}
        if self._solves is not None:
            durable_solvers |= set(self._solves.commits(epoch))
        recoverable = {hk for hk, st in self._miners.items() if st.pocs}
        return (
            durable_solvers
            - recoverable
            - set(self._scores.epoch_scores(epoch))
            - set(self._unscorable)
        )

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
                f"run cannot score them ({', '.join(sorted(lost))}); publishing now would "
                "forcibly burn their share. Either resume the epoch with the solve store "
                "that holds their solves, or, if that state is gone, call "
                "acknowledge_unscorable_solves(reason=...) to record the loss and let the "
                "rest of the lane compose."
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

    Refuses unless the epoch is marked `closed` in the same database. Without that
    check this function was the way around the restart guarantee: it reads the score
    table directly, so it could not see `CyberGymService.lost_durable_solvers()` and
    happily composed an empty, 100%-burn lane after the epoch's state was lost,
    which is exactly the outcome the solve store exists to prevent. The cathedral
    mechanism adapter applies the same gate
    (`SELECT state FROM cybergym_epoch_status WHERE epoch=?` must be `closed`)
    before mapping scores to uids.
    """
    score_store.require_closed_epoch(epoch)
    contributions = [
        LaneContribution(row["miner_hotkey"], row["receipt_id"], Decimal(row["earned_units"]))
        for row in score_store.contributions(epoch)
        if Decimal(row["earned_units"]) > 0
    ]
    return Lane(lane_id, allocation, contributions)


def lane_allocation_for(resolved, lane_id: str = CYBERGYM_LANE) -> Decimal:
    """This lane's share from a verified allocation config, or a refusal naming what is.

    The signed `cathedral_lane_allocation_v1` is authoritative on lane *names*, and
    the composing code has to be given the same one. Nothing else checks that they
    agree, and disagreeing is silent in the worst way: both configs verify, the
    vector composes, and every contribution is dropped as "lane not in the
    allocation config" — a 100% burn epoch whose only trace is a `drop_reason` in
    an audit row nobody reads. Every miner earns nothing and the run looks normal.

    The name is easy to get wrong because a CyberGym deployment carries two ids in
    two different namespaces:

        lane id       `cathedral_cybergym`  (`CYBERGYM_LANE`) — names the lane in
                      the signed allocation config, and is what `compose_*_lane`
                      and `integrated_feed.compose_integrated` match on
        mechanism id  `cybergym_v0` — names the MechanismSpec registered with the
                      cathedral publisher (`PUT /mechanisms/{id}`)

    They are unrelated strings, and putting the mechanism id in the `lane` field is
    the mistake this function exists to turn into an error.

    Look the allocation up through here rather than hand-passing a number to
    `compose_scores_lane(allocation=...)`, and the mismatch fails loudly, before an
    epoch is composed.
    """
    allocations = getattr(resolved, "lane_allocations", None)
    if allocations is None:
        raise ProtocolError(
            "expected a ResolvedAllocation from signed_config.resolve_allocation, "
            f"got {type(resolved).__name__}"
        )
    if lane_id not in allocations:
        funded = ", ".join(sorted(allocations)) or "(none)"
        raise ProtocolError(
            f"the signed allocation config does not fund lane {lane_id!r}; it funds: "
            f"{funded}. Composing anyway would drop every contribution to this lane "
            "and publish a 100% burn vector. If this is the CyberGym lane, the "
            f"allocation config's `lane` must be {CYBERGYM_LANE!r} — note that "
            "`cybergym_v0` is the publisher's MechanismSpec id, not a lane id."
        )
    return allocations[lane_id]


__all__ = [
    "CyberGymService", "compose_scores_lane", "compose_results_lane",
    "lane_allocation_for", "CYBERGYM_LANE",
]
