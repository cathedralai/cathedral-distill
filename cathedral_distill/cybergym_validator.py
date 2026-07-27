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

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill import cybergym_receipt as cr
from cathedral_distill.cybergym import DEFAULT_LEVEL_WEIGHTS, Level, PoCSubmission, score_batch
from cathedral_distill.cybergym_batch import Batch, TaskPool, derive_batch_nonce, draw_batch
from cathedral_distill.cybergym_scores import CyberGymScoreStore
from cathedral_distill.cybergym_verifier import poc_digest, verify_poc
from cathedral_distill.receipt_keys import ReceiptKeyRegistry


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
    miner_hotkey: str
    batch: Batch
    receipt: Mapping[str, object]
    contribution: Mapping[str, object]


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
):
    """Build a frontier `Candidate` from a VERIFIED CyberGym receipt.

    Every gate is derived from evidence, never asserted: the candidate is only
    marked evidence-verified after `verify_receipt` passes, and `Frontier.submit`
    refuses anything else. Contamination is checked structurally — the batch nonce
    must reproduce the chain-anchored, post-commitment derivation bound to the
    miner's committed model, so the miner could not have trained on the drawn set.
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
        attested=True,               # reached only because verify_receipt passed
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
) -> list[MinerResult]:
    """Score every miner on its own chain-anchored batch and persist the result.

    Each miner draws a *different* batch (the nonce binds its own hotkey and model
    commitment), so a miner cannot be scored on a set it could predict, and two
    miners' scores are only ever compared through the frontier on the same
    batch_id. Returns one `MinerResult` per miner, with the signed receipt and the
    lane contribution ready for `lane_feed.compose_vector`.
    """
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
        batch = draw_batch(pool, size=batch_size, nonce=nonce, as_of=as_of, cutoff=cutoff)

        submissions: list[PoCSubmission] = []
        for task in batch.tasks:
            poc = miner.pocs.get(task.task_id)
            if poc is None:
                continue  # unsubmitted -> scores zero, still committed in items_root
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
        cr.verify_receipt(receipt, key_registry, source_epoch=chain.source_epoch)
        score_store.record(receipt)
        results.append(
            MinerResult(
                miner_hotkey=miner.miner_hotkey, batch=batch, receipt=receipt,
                contribution=cr.lane_contribution(receipt),
            )
        )
    return results
