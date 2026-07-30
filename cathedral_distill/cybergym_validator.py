"""The CyberGym validator loop — commit → draw → verify → score → sign → persist.

This ties the CyberGym primitives into one hardware-free epoch, the sibling of
`cathedralconfidential/cathedral/neuron/validator.py::epoch` for the SAT lane.
Given a task pool, finalized chain context, and each miner's committed model plus
its PoC bytes, it: derives the post-commitment batch nonce from chain state,
draws the sealed batch, runs the differential crash test through an injected
backend, scores the batch, signs a `cathedral_cybergym_receipt_v1`, records the
verified units to the `cybergym_scores` mechanism table, and returns the per-lane
contributions `lane_feed` composes into the signed SN39 vector.

The verification backend is injected, so the whole loop runs with no CyberGym
binaries and no network. Production swaps in `cybergym_verifier.subprocess_backend`
over the real vul/fix builds and a real submission transport; nothing else in the
loop changes.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill import cybergym_receipt as cr
from cathedral_distill.cybergym import DEFAULT_LEVEL_WEIGHTS, Level, PoCSubmission, score_batch
from cathedral_distill.cybergym_batch import Batch, TaskPool, derive_batch_nonce
from cathedral_distill.cybergym_scores import CyberGymScoreStore
from cathedral_distill.cybergym_synthetic import is_synthetic_task
from cathedral_distill.cybergym_verifier import poc_digest, verify_poc
from cathedral_distill.receipt_keys import ReceiptKeyRegistry


class EmissionGateError(ValueError):
    """Raised when the emission path is asked to score without a gate decision."""


@dataclass(frozen=True)
class MinerCommit:
    """One miner's committed model and the PoC bytes it submitted this epoch.

    `model_commitment` is the sha256 of the checkpoint the miner committed BEFORE
    this epoch's block — it pins the batch draw so the miner cannot have trained
    on the drawn set. `pocs` maps task_id -> PoC bytes; a task with no entry
    simply scores zero.
    """

    miner_hotkey: str
    model_commitment: str
    pocs: Mapping[str, bytes] = field(default_factory=dict)


@dataclass(frozen=True)
class ChainContext:
    """The finalized chain state the epoch is anchored to."""

    block: int
    block_hash: str
    network: str
    netuid: int
    source_epoch: int
    valid_from_block: int
    valid_until_block: int


@dataclass(frozen=True)
class MinerResult:
    """One miner's epoch outcome.

    The rule, stated once because the two numbers here can legitimately disagree:

      * the **receipt** states what the batch scored under the active MECHANISM
        parameters (level weights, and whether synthetic-source tasks are rewarded).
        Those parameters are part of the scoring function every validator re-derives,
        so excluding a non-rewarded task changes the receipt's own arithmetic and
        keeps it honest. That is why A9 zeroes units inside the receipt.
      * the **contribution** states what is PAYABLE to this miner. Gate failures are
        per-miner eligibility evidence about registration and contamination, not
        scoring parameters, so they do not rewrite the batch's score; they zero the
        contribution and keep the score visible for audit.

    So a gated-out miner has a receipt that still says what it solved and a
    contribution that says zero. `creditable` is the single flag a caller should
    branch on.
    """

    miner_hotkey: str
    batch: Batch
    receipt: Mapping[str, object]
    # The lane contribution, ZEROED when a gate failed. The receipt still reports
    # what the miner scored (audit), but the contribution is what a caller composes,
    # and it must never offer units a gate refused. A caller that composes these
    # directly rather than reading the score store therefore cannot credit a
    # gated-out miner either.
    contribution: Mapping[str, object]
    # Anti-gaming gates that did NOT pass on the emission path. A non-empty tuple
    # means the score was NOT persisted, so this miner earns nothing this epoch:
    # the receipt is kept for audit, the reward is not.
    gate_failures: tuple[str, ...] = ()

    @property
    def creditable(self) -> bool:
        return not self.gate_failures


@dataclass(frozen=True)
class EmissionGatePolicy:
    """Which anti-gaming gates a score must clear BEFORE it is persisted.

    `frontier.evaluate_gates` has always known these gates, and
    `derive_cybergym_candidate` derives them from evidence, but neither sat on the
    path that actually pays: emission flows `run_epoch` -> `cybergym_scores` -> the
    mechanism adapter, and nothing on it called them. PR #11 put the attestation
    gate on that path (a solve is creditable only when its TDX attestation
    verified); this is the same move for the remaining gates.

    Each gate has an evidence source, and a gate with no evidence FAILS (it is
    never skipped):

      * `registered_bundle`:
        `bundle_registry.is_cryptographically_verified_by(commitment, miner)`.
        A presence-only or unverified registry row is provenance, not reward
        evidence. No verified registry means no miner can prove its model is
        registered, so all fail.
      * `no_contamination`: the committed model must have been registered before
        the batch was drawn (`registered_at <= commitment_deadline`, defaulting to
        the epoch's `as_of` draw time). A commitment made after the draw cannot be
        proven to pre-date the drawn set.
      * `reproduced`: a peer validator's receipt for the same `batch_id` with the
        same `items_root` and a DIFFERENT `validator_hotkey`, verified against the
        anchored key registry. Off by default: a single-validator deployment has no
        peer to reproduce with, so requiring it would zero every miner. Turning it
        on is an owner decision about what a reward requires.
      * `independent_evaluator`: the miner's coldkey must differ from the
        evaluator's. Off by default, and structurally unsatisfiable while the
        operator IS the evaluator; recorded as an owner trust-model decision rather
        than silently claimed.
    """

    bundle_registry: Any = None
    commitment_deadline: datetime | None = None
    reproductions: Mapping[str, Mapping[str, object]] | None = None
    reproduction_key_registry: Any = None
    evaluator_coldkey: str = ""
    miner_coldkeys: Mapping[str, str] | None = None
    require_registered_bundle: bool = True
    require_no_contamination: bool = True
    require_reproduction: bool = False
    require_independent_evaluator: bool = False


def _canonical_evidence_digest(value: object, *, label: str) -> str:
    """Digest JSON-compatible reward evidence or fail before an epoch starts."""
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise EmissionGateError(
            f"{label} cannot be pinned as canonical reward evidence"
        ) from exc
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def _registry_evidence_identity(registry: Any, *, label: str) -> dict[str, object]:
    """Return a stable verified-registry identity, or mark it unverified.

    An object without an identity method cannot satisfy the verified registration
    gate either, but recording that state still makes the epoch manifest stable and
    lets the per-miner gate fail instead of turning configuration into a process
    crash.
    """
    method = getattr(registry, "reward_evidence_identity", None)
    if method is None:
        method = getattr(registry, "evidence_identity", None)
    if not callable(method):
        return {
            "status": "unverified",
            "type": f"{type(registry).__module__}.{type(registry).__qualname__}",
        }
    try:
        identity = method()
    except Exception as exc:  # noqa: BLE001 - configuration must fail closed
        raise EmissionGateError(f"{label} identity is unavailable") from exc
    if not isinstance(identity, Mapping):
        raise EmissionGateError(f"{label} identity must be a mapping")
    document = dict(identity)
    _canonical_evidence_digest(document, label=label)
    return document


def emission_gate_policy_manifest(
    policy: EmissionGatePolicy | None,
) -> dict[str, object] | None:
    """Canonical reward-policy and evidence identity for restart pinning.

    Only evidence that can affect an enabled gate is included. The manifest pins
    semantics rather than object identity: equivalent reconstructed registries and
    evidence maps produce the same digest, while any reward-relevant change refuses
    to resume the epoch.
    """
    if policy is None:
        return None

    bundle_registry = None
    if policy.require_registered_bundle or policy.require_no_contamination:
        bundle_registry = (
            None
            if policy.bundle_registry is None
            else _registry_evidence_identity(
                policy.bundle_registry, label="bundle registry"
            )
        )

    reproductions_digest = None
    reproduction_registry = None
    if policy.require_reproduction:
        reproductions = dict(policy.reproductions or {})
        reproductions_digest = _canonical_evidence_digest(
            reproductions, label="reproduction receipts"
        )
        reproduction_registry = (
            {"source": "epoch_signing_key_registry"}
            if policy.reproduction_key_registry is None
            else _registry_evidence_identity(
                policy.reproduction_key_registry,
                label="reproduction key registry",
            )
        )

    miner_coldkeys_digest = None
    if policy.require_independent_evaluator:
        miner_coldkeys_digest = _canonical_evidence_digest(
            dict(policy.miner_coldkeys or {}), label="miner coldkeys"
        )

    return {
        "schema": "cathedral_cybergym_emission_gate_policy_v1",
        "require_registered_bundle": bool(policy.require_registered_bundle),
        "require_no_contamination": bool(policy.require_no_contamination),
        "require_reproduction": bool(policy.require_reproduction),
        "require_independent_evaluator": bool(
            policy.require_independent_evaluator
        ),
        "commitment_deadline": (
            policy.commitment_deadline.isoformat()
            if policy.commitment_deadline is not None
            else None
        ),
        "bundle_registry": bundle_registry,
        "reproductions_digest": reproductions_digest,
        "reproduction_key_registry": reproduction_registry,
        "evaluator_coldkey": (
            policy.evaluator_coldkey
            if policy.require_independent_evaluator
            else None
        ),
        "miner_coldkeys_digest": miner_coldkeys_digest,
    }


def evaluate_emission_gates(
    policy: EmissionGatePolicy,
    *,
    miner_hotkey: str,
    model_commitment: str,
    receipt: Mapping[str, object],
    key_registry: Any,
    source_epoch: int,
    drawn_at: datetime | None,
) -> tuple[str, ...]:
    """Return the required gates this miner's epoch does NOT satisfy.

    Empty tuple means every required gate passed on evidence. Everything fails
    closed: unavailable evidence is a failure, never a skip, and evidence that
    cannot be READ (a registry lookup that raises, a timestamp with no timezone) is
    a failure for THIS miner only. A gate evaluation must never be able to abort the
    epoch for everyone else: that is a total lane outage from one bad row.
    """
    from cathedral_distill import frontier as fr

    failures: list[str] = []

    def lookup(target: Any, method_name: str, *args) -> Any:
        """Registry access that fails this miner rather than the epoch."""
        try:
            return getattr(target, method_name)(*args)
        except Exception:  # noqa: BLE001 - unreadable evidence is a gate failure
            return None

    registration = None
    if policy.bundle_registry is not None:
        registration = lookup(
            policy.bundle_registry, "verified_claim_for", model_commitment
        )

    if policy.require_registered_bundle:
        registered = bool(
            policy.bundle_registry is not None
            and lookup(
                policy.bundle_registry,
                "is_cryptographically_verified_by",
                model_commitment,
                miner_hotkey,
            )
        )
        if not registered:
            failures.append(fr.GATE_REGISTERED_BUNDLE)

    if policy.require_no_contamination:
        deadline = policy.commitment_deadline or drawn_at
        registered_at = getattr(registration, "registered_at", None)
        # A registration timestamp with no timezone cannot be compared with an aware
        # deadline: Python raises, and that raise used to abort the epoch for every
        # miner. It is also not evidence of anything, since the offset it means is
        # unknown, so treat it as this miner's gate failure.
        aware = (
            registered_at is not None
            and getattr(registered_at, "tzinfo", None) is not None
            and registered_at.utcoffset() is not None
        )
        proven_pre_commitment = bool(
            registration is not None
            and registration.miner_hotkey == miner_hotkey
            and deadline is not None
            and aware
            and registered_at <= deadline
        )
        if not proven_pre_commitment:
            failures.append(fr.GATE_NO_CONTAMINATION)

    if policy.require_reproduction:
        reproduced = False
        peer = (policy.reproductions or {}).get(miner_hotkey)
        if peer is not None:
            try:
                peer_doc = cr.verify_receipt(
                    peer, policy.reproduction_key_registry or key_registry,
                    source_epoch=source_epoch,
                )
            except cr.CyberGymReceiptError:
                peer_doc = None
            if peer_doc is not None:
                reproduced = (
                    peer_doc["batch"]["batch_id"] == receipt["batch"]["batch_id"]
                    and peer_doc["score"]["items_root"] == receipt["score"]["items_root"]
                    and peer_doc["validator_hotkey"] != receipt["validator_hotkey"]
                )
        if not reproduced:
            failures.append(fr.GATE_REPRODUCED)

    if policy.require_independent_evaluator:
        miner_coldkey = (policy.miner_coldkeys or {}).get(miner_hotkey, "")
        independent = bool(
            miner_coldkey and policy.evaluator_coldkey
            and miner_coldkey != policy.evaluator_coldkey
        )
        if not independent:
            failures.append(fr.GATE_INDEPENDENT_EVALUATOR)

    return tuple(failures)


def cybergym_track_policy(track: str = "cybergym-v0", **kw):
    """A TrackPolicy that requires only the gates CyberGym has (see
    frontier.CYBERGYM_REQUIRED_GATES): attestation, reproduction, no
    contamination, a registered model, and an independent evaluator."""
    from cathedral_distill import frontier as fr
    kw.setdefault("required_gates", fr.CYBERGYM_REQUIRED_GATES)
    return fr.TrackPolicy(track=track, **kw)


def derive_cybergym_candidate(
    receipt: Mapping[str, object],
    key_registry,
    *,
    source_epoch: int,
    chain: ChainContext,
    model_commitment: str,
    miner_coldkey: str,
    evaluator_coldkey: str,
    bundle_registry=None,
    reproduction: Mapping[str, object] | None = None,
    attestation_verified: bool = False,
):
    """Build a frontier `Candidate` from a VERIFIED CyberGym receipt.

    Every gate is derived from evidence, never asserted: the candidate is only
    marked evidence-verified after `verify_receipt` passes, and `Frontier.submit`
    refuses anything else. Contamination is checked structurally — the batch nonce
    must reproduce the chain-anchored, post-commitment derivation bound to the
    miner's committed model, so the miner could not have trained on the drawn set.

    `attested` is NOT asserted from a signature: `verify_receipt` proves the
    receipt's Ed25519 signature + epoch + nonce, not that the work ran in a TDX
    enclave. The caller must pass `attestation_verified=True` only after
    independently verifying the submission's Intel-TDX attestation (the same gate
    `cybergym_attest.verify_submission_attestation` enforces on the live path); it
    defaults to False so the frontier's mandatory `GATE_ATTESTED_RECEIPT` fails
    closed rather than being rubber-stamped by a valid signature.
    """
    from datetime import datetime, timezone

    from cathedral_distill import frontier as fr

    doc = cr.verify_receipt(receipt, key_registry, source_epoch=source_epoch)
    miner_hotkey = str(doc["miner_hotkey"])

    # no_contamination: the receipt's nonce must equal the nonce derived from
    # finalized chain state AND this miner's committed model. A mismatch means we
    # cannot prove the set post-dates the commitment -> treat as contaminated.
    expected_nonce = derive_batch_nonce(
        block=chain.block, block_hash=chain.block_hash, network=chain.network,
        netuid=chain.netuid, source_epoch=source_epoch, miner_hotkey=miner_hotkey,
        model_commitment=model_commitment,
    )
    contamination_detected = doc["batch"]["nonce"] != expected_nonce

    reproduced = False
    if reproduction is not None:
        rdoc = cr.verify_receipt(reproduction, key_registry, source_epoch=source_epoch)
        reproduced = (
            rdoc["batch"]["batch_id"] == doc["batch"]["batch_id"]
            and rdoc["score"]["items_root"] == doc["score"]["items_root"]
            and rdoc["validator_hotkey"] != doc["validator_hotkey"]
        )

    registered_bundle = bool(
        bundle_registry is not None
        and bundle_registry.is_registered_by(model_commitment, miner_hotkey)
    )
    independent_evaluator = bool(
        miner_coldkey and evaluator_coldkey and miner_coldkey != evaluator_coldkey
    )
    submitted_at = datetime.strptime(
        str(doc["issued_at"]), "%Y-%m-%dT%H:%M:%S.%fZ"
    ).replace(tzinfo=timezone.utc)

    return fr.Candidate(
        miner_hotkey=miner_hotkey,
        bundle_digest=model_commitment,
        checkpoint_digest=model_commitment,
        receipt_id=str(doc["receipt_id"]),
        score=Decimal(str(doc["score"]["score"])),
        latency_p50_ms=Decimal(0),
        cost_usd=Decimal(0),
        submitted_at=submitted_at,
        batch_id=str(doc["batch"]["batch_id"]),
        attested=bool(attestation_verified),   # from a real TDX check, never the signature
        reproduced=reproduced,
        contamination_detected=contamination_detected,
        registered_bundle=registered_bundle,
        independent_evaluator=independent_evaluator,
        evidence_verified=True,      # provenance: derived from a verified receipt
    )


def run_epoch(
    miners: list[MinerCommit],
    pool: TaskPool,
    chain: ChainContext,
    *,
    validator_hotkey: str,
    private_key: Ed25519PrivateKey,
    signing_key_id: str,
    backend,
    score_store: CyberGymScoreStore,
    cutoff,
    as_of,
    issued_at: str,
    batch_size: int,
    level_weights: Mapping[Level, Decimal] = DEFAULT_LEVEL_WEIGHTS,
    gate_policy: EmissionGatePolicy | None = None,
    gates_required: bool = True,
    credit_synthetic_tasks: bool = False,
) -> list[MinerResult]:
    """Score every miner on its own chain-anchored batch and persist the result.

    Each miner draws a *different* batch (the nonce binds its own hotkey and model
    commitment), so a miner cannot be scored on a set it could predict, and two
    miners' scores are only ever compared through the frontier on the same
    batch_id. Returns one `MinerResult` per miner, with the signed receipt and the
    lane contribution ready for `lane_feed.compose_vector`.

    `pool` is any draw-capable source (see `cybergym_protocol.dispatch`'s
    docstring) — a real `TaskPool` or `cybergym_synthetic.SyntheticTaskSource`.

    The anti-gaming gates run BEFORE the score is persisted. This function is the
    thing that pays: it writes `cybergym_scores`, which the mechanism adapter reads
    and turns into weight. A gate evaluated anywhere else (in
    `derive_cybergym_candidate`, in `Frontier.submit`) is not on this path and does
    not stop a reward, which is exactly the hole being closed. A miner failing any
    required gate is scored, signed and returned for audit, but its score is NOT
    written, so it earns nothing and its share goes to burn. `gate_policy=None`
    requires `gates_required=False`: no gate decision is never the default.

    Synthetic tasks are graded but NOT rewarded (`credit_synthetic_tasks=False`).
    The synthetic artifact renders the magic guard and the buffer size in plaintext
    at every level, so a no-model regex extractor solves 8/8 level-0 tasks
    (measured; see `cybergym_synthetic.is_synthetic_task`). Their solves are
    excluded from the scored submissions, so the signed receipt itself states that
    they earned nothing, rather than a store quietly holding back a number the
    receipt claims. `credit_synthetic_tasks=True` is an explicit,
    unsafe-for-rewards override: it pays for a challenge that answers itself, and
    it changes the derived `items_root`, so every validator in a deployment must
    agree on it exactly as they must agree on `level_weights`.
    """
    if gate_policy is None:
        if gates_required:
            raise EmissionGateError(
                "run_epoch requires an anti-gaming gate policy: pass "
                "gate_policy=EmissionGatePolicy(...), or gates_required=False for the "
                "dev/test path (which persists scores with NO registered-bundle or "
                "contamination gate)."
            )
        import warnings
        warnings.warn(
            "run_epoch persisting CyberGym scores with NO anti-gaming gates "
            "(gates_required=False): an unregistered model commitment earns normally. "
            "Dev/test only, never on a live reward path.",
            stacklevel=2,
        )
    # The validator resolves its own signing key by id, exactly as a peer will —
    # never a caller-supplied key.
    key_registry = ReceiptKeyRegistry.from_keys(
        {signing_key_id: private_key.public_key().public_bytes_raw()}
    )
    results: list[MinerResult] = []
    for miner in miners:
        nonce = derive_batch_nonce(
            block=chain.block, block_hash=chain.block_hash, network=chain.network,
            netuid=chain.netuid, source_epoch=chain.source_epoch,
            miner_hotkey=miner.miner_hotkey, model_commitment=miner.model_commitment,
        )
        batch = pool.draw(size=batch_size, nonce=nonce, as_of=as_of, cutoff=cutoff)

        submissions: list[PoCSubmission] = []
        for task in batch.tasks:
            poc = miner.pocs.get(task.task_id)
            if poc is None:
                continue  # unsubmitted -> scores zero, still committed in items_root
            if not credit_synthetic_tasks and is_synthetic_task(task.task_id):
                # Graded, never rewarded: the synthetic artifact renders its own
                # answer, so a solve here is not evidence of capability. Excluded
                # from the scored submissions, which keeps the receipt honest (it
                # reports zero units for this task rather than claiming units the
                # store then withholds).
                continue
            result = verify_poc(task, poc, backend)
            submissions.append(
                PoCSubmission(task_id=task.task_id, poc_sha256=poc_digest(poc), result=result)
            )

        batch_score = score_batch(
            batch.batch_id, list(batch.tasks), submissions, weights=level_weights
        )
        receipt = cr.build_receipt(
            batch_score,
            network=chain.network, netuid=chain.netuid, source_epoch=chain.source_epoch,
            validator_hotkey=validator_hotkey, miner_hotkey=miner.miner_hotkey,
            nonce=nonce, holdout_digest_value=cr.holdout_digest(list(batch.task_ids)),
            valid_from_block=chain.valid_from_block, valid_until_block=chain.valid_until_block,
            issued_at=issued_at, private_key=private_key, signing_key_id=signing_key_id,
            level_weights=level_weights,
        )
        # Self-verify before persisting: the validator admits its own receipt on
        # exactly the evidence a peer validator will, resolving the key by id.
        verified = cr.verify_receipt(receipt, key_registry, source_epoch=chain.source_epoch)

        # Gates before the persisted score: this write is the reward. Contained per
        # miner, for the same reason receipt verification is: one miner's unreadable
        # evidence must cost that miner, not every miner in the epoch.
        gate_failures: tuple[str, ...] = ()
        if gate_policy is not None:
            try:
                gate_failures = evaluate_emission_gates(
                    gate_policy, miner_hotkey=miner.miner_hotkey,
                    model_commitment=miner.model_commitment, receipt=verified,
                    key_registry=key_registry, source_epoch=chain.source_epoch,
                    drawn_at=as_of,
                )
            except Exception as exc:  # noqa: BLE001 - fail this miner, not the epoch
                gate_failures = (f"gate_evaluation_failed:{type(exc).__name__}",)
        if not gate_failures:
            score_store.record(receipt)
        # A gated-out miner must not be able to earn through EITHER route. The
        # score-store route is closed by not writing the row; the direct route (a
        # caller composing `result.contribution`) is closed by zeroing the units
        # here, so the two routes cannot disagree about who was paid.
        contribution = dict(cr.lane_contribution(receipt))
        if gate_failures:
            contribution["work_units"] = "0"
            contribution["gate_failures"] = list(gate_failures)
        results.append(
            MinerResult(
                miner_hotkey=miner.miner_hotkey, batch=batch, receipt=receipt,
                contribution=contribution, gate_failures=gate_failures,
            )
        )
    return results
