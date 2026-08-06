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
import json
from dataclasses import dataclass, field, replace
from datetime import datetime
from decimal import Decimal
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill.attestation import (
    AttestationError,
    AttestationPolicy,
    attestation_policy_digest,
)
from cathedral_distill.cybergym_attest import (
    PROFILE_PERSISTENT_ENCLAVE,
    CathedralReceiptPolicy,
    cathedral_receipt_policy_digest,
)
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
    observed_eligibility_allows_dispatch,
    run_epoch,
)
from cathedral_distill.cybergym_fresh import is_fresh_task
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
    the same scoring input (`run_epoch` re-draws the common batch from the
    chain-anchored nonce, while the commitment plus the PoC bytes identify each
    miner's submissions). The *dispatch*
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
        cathedral_receipt_policy: CathedralReceiptPolicy | None = None,
        attestation_now: datetime | None = None,
        attestation_required: bool = True,
        gate_policy: EmissionGatePolicy | None = None,
        gates_required: bool = True,
        credit_synthetic_tasks: bool = False,
        acknowledge_synthetic_is_gameable: bool = False,
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
            # A CathedralReceiptPolicy IS attestation enforcement (a real Cathedral
            # TDX receipt is required; the posture reads `enforced=True`), so only warn
            # when NEITHER policy is configured — otherwise the "never in production"
            # warning fires on exactly the receipt-enforced production path.
            if cathedral_receipt_policy is None:
                import warnings
                warnings.warn(
                    "CyberGymService running WITHOUT Intel-TDX attestation enforcement "
                    "(attestation_required=False, no cathedral_receipt_policy): every "
                    "solved PoC is credited with no attestation. Dev/test only — never "
                    "in production.",
                    stacklevel=2,
                )
        # Fail closed on synthetic credit. A synthetic task's answer is a pure,
        # deterministic function of the batch nonce, and the nonce is derivable from
        # public chain state after the block finalizes: `generate_bug(nonce, i)`
        # returns the exploit bytes directly, and `render_source` prints the magic
        # guard and buffer size in plaintext even at level 0. Crediting synthetic
        # solves therefore pays real emission for values a miner computes with no
        # model at all. It is permissible ONLY on the hardware-free dev path, where
        # nothing is at stake; an attested (production) service that also credits
        # synthetic tasks would pay for public-computable answers, so it is refused.
        if credit_synthetic_tasks and attestation_required and not acknowledge_synthetic_is_gameable:
            raise ProtocolError(
                "credit_synthetic_tasks=True is refused in an attested "
                "(production) service: a synthetic task's answer is computable from "
                "public chain state, so crediting it pays emission for no capability. "
                "Synthetic tasks are a dev oracle — run them with "
                "attestation_required=False, or leave credit_synthetic_tasks=False "
                "to grade them without paying. A test that scores synthetic tasks "
                "ON PURPOSE (e.g. to isolate the attestation gate) must set "
                "acknowledge_synthetic_is_gameable=True to say so explicitly; the "
                "launch configuration must never set it."
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
        if (
            gates_required
            and gate_policy is not None
            and gate_policy.require_observed_eligibility
            and gate_policy.eligibility_snapshot is None
        ):
            raise ProtocolError(
                "CyberGym reward dispatch requires a frozen externally observed "
                "eligibility snapshot; a miner-supplied registration timestamp or "
                "an unfrozen registry cannot select a paid commitment."
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
        # The #61 path: a submission may instead attest with a real Cathedral receipt
        # (attest.v1 / persistent enclave), whose Intel DCAP root cannot live in an
        # AttestationPolicy's Ed25519 trusted_roots. None keeps the current behaviour.
        self._cathedral_receipt_policy = cathedral_receipt_policy
        self._attestation_now = attestation_now
        self._gate_policy = gate_policy
        self._gates_required = gates_required
        # Synthetic tasks are graded but not rewarded by default: their artifact
        # renders the answer (see cybergym_synthetic.is_synthetic_task). True is an
        # explicit unsafe-for-rewards override. Fresh tasks are also graded, but
        # always unpaid: their current reversible artifact lets a miner derive the
        # reference PoC mechanically (see cybergym_fresh.is_fresh_task).
        self._credit_synthetic_tasks = credit_synthetic_tasks
        self._miners: dict[str, _MinerState] = {}
        self._by_batch: dict[str, str] = {}  # batch_id -> miner_hotkey
        self._dispatched: set[str] = set()   # task_ids actually served this epoch
        self._results: list[MinerResult] = []
        self._scored_miners: set[str] = set()  # miners this process actually scored
        self._scoring_pass_ran = False         # whether score_epoch ran in this process
        # miner_hotkey -> why its durable solves cannot be scored this epoch
        self._unscorable: dict[str, str] = {}
        self._pin_attestation_posture()
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
            # A generated source must commit its private generator configuration
            # without disclosing it.  A changed fresh seed would otherwise make a
            # restarted verifier score different task bytes under the same epoch.
            "task_source": self._task_source_manifest(),
            "gates_required": bool(self._gates_required),
            "gate_policy": emission_gate_policy_manifest(self._gate_policy),
        }

    def _task_source_manifest(self) -> Mapping[str, object] | None:
        provider = getattr(self.holdout.pool, "epoch_manifest", None)
        if provider is None:
            return None
        manifest = provider()
        if not isinstance(manifest, Mapping):
            raise ProtocolError("task source epoch_manifest must return an object")
        return dict(manifest)

    def _pin_attestation_posture(self) -> None:
        """Record, in the score database, whether this epoch enforces Intel-TDX.

        The epoch manifest already pins every input that decides what an epoch
        draws and what it signs, but it lives in the SOLVE store and it is not what
        travels: the exporter is handed a score-database path and turns its rows
        into the wire report a validator composes weights from. Nothing in that
        report says whether the solves behind it were attested, so an unattested
        development epoch and an attested production epoch are indistinguishable by
        the time they reach an intake. Stamping the posture beside the scores is
        what lets the exporter refuse (see
        `cybergym_score_report.build_score_report`).

        Posture is read off the POLICY, not the `attestation_required` flag: the
        flag only records that an operator was asked to acknowledge the opt-out,
        while the policy is the thing that actually decides whether a solve must
        carry a verified quote to be credited.

        And the policy's CONTENT is stamped, not merely its presence. A restart that
        keeps a policy configured but replaces its `trusted_roots` — the Intel DCAP
        root out, a key the miner holds in — admits every receipt the epoch's opening
        policy refused, while `enforced` still reads True and the export goes out
        with no flag and no warning. Binding
        `attestation.attestation_policy_digest` makes that restart refuse on exactly
        the terms a dropped policy already does.
        """
        # Two policies can each require attestation on the reward path: the
        # report_data-bound cc token (AttestationPolicy) and the real Cathedral
        # receipt (CathedralReceiptPolicy, the #61 path). EITHER makes the epoch
        # enforced, and BOTH decide verdicts, so both must be bound into the posture
        # or a resume that swaps one — e.g. the receipt policy's approved-solver pin —
        # reopens the swapped-policy bypass the posture guard exists to close.
        try:
            att_digest = attestation_policy_digest(self._attestation_policy)
            rcpt_digest = cathedral_receipt_policy_digest(self._cathedral_receipt_policy)
        except AttestationError as exc:
            raise ProtocolError(
                "refusing to open the epoch: an Intel-TDX attestation policy cannot "
                f"be pinned to the score database ({exc}). A policy the posture record "
                "cannot bind is one a restart could change unseen."
            ) from exc
        enforced = (
            self._attestation_policy is not None
            or self._cathedral_receipt_policy is not None
        )
        # No receipt policy -> the digest is byte-identical to the attestation-only
        # value the prior build wrote, so an epoch opened before this change resumes
        # cleanly. With one, the digest binds both, so swapping either is refused.
        if self._cathedral_receipt_policy is None:
            digest = att_digest
        else:
            digest = "sha256:" + hashlib.sha256(
                (att_digest + "|" + rcpt_digest).encode("ascii")
            ).hexdigest()
        try:
            self._scores.record_attestation_posture(
                self.chain.source_epoch,
                enforced=enforced,
                detail=(
                    f"Intel-TDX attestation enforced (attestation={att_digest or 'none'}, "
                    f"receipt={rcpt_digest or 'none'})"
                    if enforced
                    else "no Intel-TDX attestation policy: solves are credited unattested"
                ),
                policy_digest=digest,
            )
        except CyberGymScoreError as exc:
            raise ProtocolError(str(exc)) from exc

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

        Byte-identical recovery: `run_epoch` re-draws the common batch from the
        chain-anchored nonce, so each miner's commitment plus accepted PoC bytes
        are the complete input, GIVEN the same epoch anchor, which
        `_pin_epoch_manifest` enforces.
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
        if not observed_eligibility_allows_dispatch(
            self._gate_policy,
            miner_hotkey=miner_hotkey,
            model_commitment=model_commitment,
            source_epoch=self.chain.source_epoch,
        ):
            raise ProtocolError(
                "dispatch is not eligible in the frozen observed registration "
                "snapshot for this source epoch"
            )
        previous = self._miners.get(miner_hotkey)
        # A commitment change is refused before dispatch, so an unauthorized call
        # has no side effects and accepted solves are never abandoned.
        if previous is not None and previous.model_commitment != model_commitment:
            # The commitment is PINNED for the epoch on first dispatch, and the
            # refusal is unconditional -- not conditioned on accepted solves, and
            # not waived for a caller authenticated as the miner.
            #
            # The common frontier prevents task-selection grinding, but the model
            # commitment is still part of the TDX-bound submission identity and the
            # frozen eligibility snapshot permits exactly one commitment. A change
            # would invalidate durable solves and create conflicting evidence.
            raise ProtocolError(
                f"model_commitment for {miner_hotkey!r} is pinned for source_epoch "
                f"{self.chain.source_epoch} to {previous.model_commitment}; a "
                f"different commitment ({model_commitment}) conflicts with the "
                "frozen eligibility evidence, so it is refused for the rest of the epoch")
        artifact_digest_provider = getattr(self.holdout.pool, "artifact_digest", None)
        if not callable(artifact_digest_provider):
            artifact_digest_provider = None
        message = dispatch(
            self.holdout.pool, self.chain,
            miner_hotkey=miner_hotkey, model_commitment=model_commitment,
            cutoff=self._cutoff, as_of=self._as_of, batch_size=self._batch_size,
            context_provider=self.holdout.context_provider,
            artifact_digest_provider=artifact_digest_provider,
        )
        # A repeat dispatch must not silently erase accepted solves. Same committed
        # model -> same nonce -> same batch, so the solves already accepted this
        # epoch still belong to it and are kept. A different commitment is refused,
        # so accepted solves are never discarded by re-dispatch.
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
        `credit_synthetic_tasks` is set. Fresh-source tasks remain unpaid even
        with that development-only override: their current artifact contains all
        values necessary to derive the reference PoC mechanically. The wire
        response has to say so: a miner that is told `work_units: 8` for work the
        epoch will pay 0 for has been misled. The task-id grammar admits both
        source prefixes in a real holdout manifest, so this is reachable without
        constructing either source locally.
        """
        return (
            not is_fresh_task(task_id)
            and (self._credit_synthetic_tasks or not is_synthetic_task(task_id))
            and self._source_rewardable_task(task_id)
        )

    def _source_rewardable_task(self, task_id: str) -> bool:
        """Honor a task source's own fail-closed reward-admission decision."""
        policy = getattr(self.holdout.pool, "rewardable_task", None)
        if not callable(policy):
            return True
        try:
            return bool(policy(task_id))
        except Exception:  # noqa: BLE001 - source policy failures must not pay
            return False

    def _non_rewardable_source(self, task_id: str) -> str | None:
        """Return the source label that forces a solved task to zero units."""
        if is_fresh_task(task_id):
            return "fresh"
        if is_synthetic_task(task_id):
            return "synthetic"
        if not self._source_rewardable_task(task_id):
            reason = getattr(self.holdout.pool, "non_rewardable_reason", None)
            if callable(reason):
                try:
                    detail = reason(task_id)
                except Exception:  # noqa: BLE001 - preserve fail-closed policy
                    detail = None
                if isinstance(detail, str) and detail:
                    return detail
            return "source"
        return None

    def _authorize_caller_for_batch(self, *, authenticated_caller: str | None,
                                    batch_id: str, task_id: str,
                                    claimed_miner_hotkey: str | None = None) -> None:
        """Bind an authenticated transport caller to one sealed batch and task.

        Legacy loopback development has no transport identity, so ``None`` keeps
        the existing batch ownership checks.  Once a transport proves a caller,
        however, it must not be able to use another miner's batch or submit under
        another hotkey.  This executes before Docker verification: authorization
        failures consume no verifier capacity.
        """
        if authenticated_caller is None:
            return
        if claimed_miner_hotkey is not None and claimed_miner_hotkey != authenticated_caller:
            raise ProtocolError("authenticated caller does not match submission miner_hotkey")
        state = self._miners.get(authenticated_caller)
        if state is None or state.dispatch is None or state.dispatch.batch_id != batch_id:
            raise ProtocolError("authenticated caller has no active sealed batch")
        if state.dispatch.task(task_id) is None:
            raise ProtocolError("task is not in the authenticated caller's batch")

    def submit(self, envelope: SubmissionEnvelope, *,
               authenticated_caller: str | None = None) -> SubmissionOutcome:
        """Verify one submission against the batch we dispatched, and corpus it.

        The returned `work_units` is what the epoch will actually pay for this task:
        a solve of a non-rewardable task reports zero here as well as at emission, so
        the wire and the reward agree.
        """
        self._authorize_caller_for_batch(
            authenticated_caller=authenticated_caller,
            batch_id=envelope.batch_id,
            task_id=envelope.task_id,
            claimed_miner_hotkey=envelope.miner_hotkey,
        )
        miner_hotkey = authenticated_caller or self._by_batch.get(envelope.batch_id)
        if miner_hotkey is None:
            raise ProtocolError("submission references an unknown or expired batch")
        if envelope.miner_hotkey != miner_hotkey:
            raise ProtocolError("submission hotkey does not own this batch")
        state = self._miners[miner_hotkey]
        outcome = process_submission(
            envelope, state.dispatch, self._backend,
            trace_policy=self._trace_policy, weights=self._weights,
            attestation_policy=self._attestation_policy,
            cathedral_receipt_policy=self._cathedral_receipt_policy,
            now=self._attestation_now,
        )
        source = self._non_rewardable_source(envelope.task_id)
        if outcome.work_units > 0 and not self.rewardable_task(envelope.task_id):
            # Make the wire agree with the emission decision. run_epoch excludes this
            # task from the scored submissions, so promising units here would be a
            # promise the epoch does not keep.
            outcome = replace(
                outcome, work_units=Decimal(0),
                reason=f"{outcome.reason}|non_rewardable_source:{source}",
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
            # Capture the attested receipt for the epoch's spot-check sample. The
            # exporter later puts one representative (from a SCORED miner) in the wire
            # report so the validator can independently DCAP-verify a genuine receipt
            # bound to this epoch. Best-effort report metadata — never fail a solve.
            if outcome.attested and envelope.attestation and self._scores is not None:
                try:
                    token = json.loads(base64.b64decode(envelope.attestation, validate=True))
                    if (isinstance(token, dict)
                            and token.get("profile") == PROFILE_PERSISTENT_ENCLAVE
                            and isinstance(token.get("receipt"), dict)
                            and isinstance(token.get("result_b64"), str)):
                        self._scores.record_attestation_sample(
                            self.chain.source_epoch, miner_hotkey,
                            token["receipt"], token["result_b64"],
                        )
                except Exception:  # noqa: BLE001 - sample is best-effort metadata
                    pass
        return outcome

    # -- artifact (validator -> miner): the vulnerable program to analyse --- #
    def _artifact_digest_for(self, task_id: str) -> str | None:
        """Return a source-pinned miner-artifact digest, if this source uses one."""
        provider = getattr(self.holdout.pool, "artifact_digest", None)
        if not callable(provider):
            return None
        digest = provider(task_id)
        if digest is not None and (not isinstance(digest, str) or not digest):
            raise ProtocolError("task source returned an invalid artifact digest")
        return digest

    def artifact_for(self, task_id: str, *, batch_id: str | None = None,
                     authenticated_caller: str | None = None) -> str | bytes:
        """Return the vulnerable program a miner must analyse for a dispatched task.

        This is the 'binary'/'repo' a CyberGym miner needs — over the wire a miner
        has only metadata otherwise, so a blind (level-0) task is unsolvable without
        it. Guarded to tasks THIS service actually dispatched: the holdout is
        secret, so the service must never generate-and-reveal a program for a task
        it did not draw (that would turn the artifact route into a holdout oracle).
        For a synthetic task the artifact is the generated source. A private repro
        task instead returns its separately pinned challenge bytes, and only after
        the caller is authenticated for the sealed batch; verifier images and
        reference PoCs never cross this route.
        """
        artifact_digest = self._artifact_digest_for(task_id)
        if artifact_digest is not None and authenticated_caller is None:
            raise ProtocolError("private challenge artifact requires an authenticated caller")
        if authenticated_caller is not None:
            if not batch_id:
                raise ProtocolError("authenticated artifact request requires batch_id")
            self._authorize_caller_for_batch(
                authenticated_caller=authenticated_caller,
                batch_id=batch_id,
                task_id=task_id,
            )
        elif task_id not in self._dispatched:
            raise ProtocolError("no such dispatched task")
        provider = getattr(self.holdout.pool, "artifact", None)
        program = provider(task_id) if provider is not None else None
        if program is None:
            # Preserve the legacy public-corpus contract: those sources have no
            # private-artifact commitment and miners may resolve their documented
            # binary by digest elsewhere. A private repro source exposes an
            # ``artifact_digest`` policy even when its stores are incomplete, and
            # must never be represented as an out-of-band downloadable image.
            if not callable(getattr(self.holdout.pool, "artifact_digest", None)):
                raise ProtocolError("artifact must be fetched out of band by binary digest")
            raise ProtocolError(
                "no validator-delivered artifact is available for this task"
            )
        if not isinstance(program, (str, bytes)):
            raise ProtocolError("task source returned an invalid artifact")
        return program

    # -- transport-agnostic handlers --------------------------------------- #
    def handle_artifact(self, request: Mapping[str, Any], *,
                        authenticated_caller: str | None = None) -> dict[str, Any]:
        """Return one task artifact, or ``{error}``.

        An authenticated caller must supply its sealed ``batch_id``. The optional
        field preserves the loopback development contract, which has no caller
        identity to bind.
        """
        if not isinstance(request, Mapping):
            return {"error": "artifact request must be an object"}
        task_id = request.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            return {"error": "task_id is required"}
        batch_id = request.get("batch_id")
        if batch_id is not None and (not isinstance(batch_id, str) or not batch_id):
            return {"error": "batch_id must be a non-empty string when provided"}
        try:
            artifact = self.artifact_for(
                task_id, batch_id=batch_id, authenticated_caller=authenticated_caller
            )
            if isinstance(artifact, bytes):
                digest = self._artifact_digest_for(task_id)
                actual = "sha256:" + hashlib.sha256(artifact).hexdigest()
                if digest is None or actual != digest:
                    raise ProtocolError("validator challenge artifact digest mismatch")
                return {
                    "task_id": task_id,
                    "artifact_base64": base64.b64encode(artifact).decode("ascii"),
                    "artifact_digest": digest,
                    "encoding": "base64",
                }
            return {"task_id": task_id, "program": artifact}
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

    def handle_submit(self, body: bytes | str, *,
                      authenticated_caller: str | None = None) -> dict[str, Any]:
        """A POSTed SubmissionEnvelope -> a verdict dict (never raises)."""
        try:
            envelope = SubmissionEnvelope.from_json(body)
            outcome = self.submit(envelope, authenticated_caller=authenticated_caller)
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

        Reuses the canonical `run_epoch` scorer (it re-draws the common batch
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
    score_store: CyberGymScoreStore,
    epoch: int,
    allocation: Decimal,
    lane_id: str = CYBERGYM_LANE,
) -> Lane:
    """Compose a lane straight from `run_epoch` results, refusing gated-out ones.

    The durable route is `compose_scores_lane` (the store is the record of what was
    paid). This exists because callers do compose the returned results directly, and
    when they do, a non-creditable `MinerResult` must be refused rather than
    silently contributing: a failed gate means the miner earns nothing, through
    every route.

    `score_store` and `epoch` are required because results alone cannot show
    whether the epoch actually closed. Taking only `results`, this function
    composed epochs the store marks `incomplete` (which `compose_scores_lane` and
    `CyberGymService.compose_lane` both refuse), and after lost state
    (`score_epoch` returns `[]`) it composed a silent, empty, 100%-burn lane: the
    exact outcome the epoch-status marker exists to prevent. A lost or unscored
    epoch is never marked `closed` (`score_epoch` marks it `incomplete` when
    `lost_durable_solvers` is non-empty), so the one closed-epoch gate covers the
    lost-solve refusal on this route too.
    """
    score_store.require_closed_epoch(epoch)
    contributions = []
    for result in results:
        # The closed-epoch marker vouches only for the epoch it names: results
        # scored under a different epoch must not ride in on this epoch's clean
        # close.
        receipt_epoch = result.receipt.get("source_epoch")
        if receipt_epoch is None or int(str(receipt_epoch)) != int(epoch):
            raise ProtocolError(
                f"refusing to compose the CyberGym lane for epoch {int(epoch)}: "
                f"the result for miner {result.miner_hotkey} was scored under "
                f"epoch {receipt_epoch!r}"
            )
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
