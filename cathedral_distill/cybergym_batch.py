"""Sealed batch construction for the CyberGym lane — commit, then challenge.

The anti-gaming rule from the design: a miner commits its model *before* it learns
which vulnerabilities it will be scored on. Otherwise it trains on the batch and
the score stops measuring capability. This module draws that batch.

Two properties do the work:

**Recency splits public from private.** OSS-Fuzz discloses vulnerabilities
continuously. Old ones are public — miners may train on them freely, so they are
development data. A batch is drawn only from the *private holdout*: vulnerabilities
disclosed after a cutoff the miner's committed model predates. A retired task
(older than the retention window) moves to the public pool, which is how the
"recency-rotated" set stays fresh without ever exposing the active batch.

**The draw is deterministic from a post-commit nonce.** The selection uses a nonce
the validator issues *after* the model commitment — a later block hash, exactly as
`challenge.py` derives spot-check indices. So the miner cannot know the batch when
it commits, every validator draws the same batch from the same nonce, and the
`batch_id` is the commitment that flows into `score_batch` and the frontier's
paired comparison. Two miners are comparable only on the same `batch_id`.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Sequence

import json
import re

from cathedral_distill.cybergym import Level, Task

BATCH_DOMAIN = b"cathedral-cybergym-batch-draw-v1\x00"
NONCE_DOMAIN = b"cathedral-cybergym-batch-nonce-v1\x00"

MAX_BATCH = 4096
_BLOCK_HASH_RE = re.compile(r"\A(0x)?[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")


class BatchError(ValueError):
    """Raised when a batch cannot be drawn."""


def derive_batch_nonce(
    *,
    block: int,
    block_hash: str,
    network: str,
    netuid: int,
    source_epoch: int,
    miner_hotkey: str,
    model_commitment: str,
) -> str:
    """Derive the batch-draw nonce from finalized chain state, after commitment.

    A random validator-chosen nonce is not a public freshness proof: nothing
    ties it to the epoch or to the model being scored. Instead the nonce is
    DERIVED, under a domain separator, from independently verifiable inputs — the
    finalized block and its hash, the audience, the epoch, the miner, and the
    digest of the model the miner committed *before* this block existed:

        nonce = sha256( DOMAIN || canonical{block, block_hash, network, netuid,
                                             source_epoch, miner_hotkey,
                                             model_commitment} )

    The block hash is observable by anyone; the model_commitment pins the draw to
    the exact checkpoint the miner is being scored on, so a miner cannot have
    trained on the set (the block postdates its commitment) and every validator
    draws the identical batch. `draw_batch` consumes the result.
    """
    if isinstance(block, bool) or not isinstance(block, int) or block < 0:
        raise BatchError("block height is invalid")
    if not isinstance(block_hash, str) or _BLOCK_HASH_RE.match(block_hash.strip().lower()) is None:
        raise BatchError("block_hash must be a 32-byte hex value")
    if not network or not isinstance(network, str):
        raise BatchError("network is invalid")
    if isinstance(netuid, bool) or not isinstance(netuid, int) or netuid < 0:
        raise BatchError("netuid is invalid")
    if isinstance(source_epoch, bool) or not isinstance(source_epoch, int) or source_epoch < 0:
        raise BatchError("source_epoch is invalid")
    if not miner_hotkey or not isinstance(miner_hotkey, str):
        raise BatchError("miner_hotkey is invalid")
    if not isinstance(model_commitment, str) or _DIGEST_RE.match(model_commitment) is None:
        raise BatchError("model_commitment must be a sha256: digest")
    material = json.dumps(
        {
            "block": int(block),
            "block_hash": block_hash.strip().lower().removeprefix("0x"),
            "miner_hotkey": miner_hotkey,
            "model_commitment": model_commitment,
            "netuid": int(netuid),
            "network": network,
            "source_epoch": int(source_epoch),
        },
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    return "cgnonce-sha256:" + hashlib.sha256(NONCE_DOMAIN + material).hexdigest()


@dataclass(frozen=True)
class PooledTask:
    """A task in the pool, tagged with when its vulnerability was disclosed.

    `admitted` records whether the task passed corpus admission
    (`corpus_admission.admit`): it discriminates, it is solvable, and its answer
    is not publicly readable. It is decided ONCE, at ingest, where running the
    differential in Docker is acceptable — never in the draw, which must stay
    deterministic and side-effect-free. A scored batch draws only from admitted
    tasks; an un-admitted task is the shape that paid for garbage (`arvo:3938`)
    or shipped its own answer in a public image. Defaults True so a pool built
    from an already-vetted manifest needs no change, but the ingest path should
    set it explicitly from the gate.
    """

    task_id: str
    level: Level
    binary_digest: str
    disclosed_at: datetime
    admitted: bool = True

    def to_task(self) -> Task:
        return Task(task_id=self.task_id, level=self.level,
                    binary_digest=self.binary_digest)


@dataclass(frozen=True)
class Batch:
    """A drawn, sealed batch: the tasks plus the commitment that identifies it."""

    batch_id: str
    nonce: str
    tasks: tuple[Task, ...]

    @property
    def task_ids(self) -> tuple[str, ...]:
        return tuple(t.task_id for t in self.tasks)


class TaskPool:
    """The full task supply, split into public (trainable) and private (holdout).

    `cutoff` is the disclosure boundary: tasks disclosed strictly after it are
    private (never trained on), tasks on/before it are public. `retention` moves a
    task from private to public once it has aged past the window — the mechanism
    that keeps the holdout rotating and grows the public training corpus.
    """

    def __init__(self, tasks: Sequence[PooledTask]) -> None:
        if not tasks:
            raise BatchError("task pool is empty")
        seen = set()
        for t in tasks:
            # Reuse Task's own validation of ids/digests.
            t.to_task()
            if t.task_id in seen:
                raise BatchError(f"duplicate task in pool: {t.task_id}")
            seen.add(t.task_id)
        self._tasks = tuple(tasks)

    def private_holdout(self, *, as_of: datetime, cutoff: datetime) -> list[PooledTask]:
        """Tasks eligible for a sealed batch: disclosed after `cutoff`, not retired.

        `as_of` is the epoch time; a task disclosed after `cutoff` but still within
        the retention window (i.e. `cutoff < disclosed_at <= as_of`) is private.
        """
        if cutoff > as_of:
            raise BatchError("cutoff cannot be after the epoch time")
        # `admitted` AND the disclosure window, because they close different holes.
        # Disclosure proves the miner could not have TRAINED on the task; admission
        # proves the task can actually pay -- that it discriminates, is solvable, and
        # its answer is not readable straight out of a public image. A task can be
        # fresh (post-cutoff) and still be `arvo:3938`, so both gates apply to a
        # SCORED draw. The public/canary source deliberately does not filter on
        # admission: those tasks are never scored.
        return sorted(
            (t for t in self._tasks
             if t.admitted and cutoff < t.disclosed_at <= as_of),
            key=lambda t: t.task_id,
        )

    def public(self, *, cutoff: datetime) -> list[PooledTask]:
        """Retired/old tasks — freely trainable development data."""
        return sorted(
            (t for t in self._tasks if t.disclosed_at <= cutoff),
            key=lambda t: t.task_id,
        )

    def draw(self, *, size: int, nonce: str, as_of: datetime, cutoff: datetime) -> "Batch":
        """The uniform draw interface `dispatch`/`run_epoch` call. Delegates to
        the free `draw_batch` function — same behavior, just callable
        polymorphically alongside any other draw-capable source (e.g.
        `cybergym_synthetic.SyntheticTaskSource`) without either caller needing
        to know which kind of source it has."""
        return draw_batch(self, size=size, nonce=nonce, as_of=as_of, cutoff=cutoff)

    def draw_public(self, *, size: int, nonce: str, cutoff: datetime) -> "Batch":
        """Draw from the PUBLIC (retired, freely-trainable) set — the same
        deterministic nonce-ranked selection as `draw`, but over tasks whose
        answers are already public. This is the source a liveness canary draws
        from: solving these proves a miner is alive and configured without
        touching the reward-eligible private holdout (see
        `cybergym_mix.PublicCanarySource`)."""
        if size <= 0 or size > MAX_BATCH:
            raise BatchError("batch size out of range")
        if not nonce:
            raise BatchError("a batch draw requires a nonce")
        eligible = self.public(cutoff=cutoff)
        if len(eligible) < size:
            raise BatchError(
                f"only {len(eligible)} public tasks available; need {size}."
            )
        return _select_ranked(eligible, size, nonce)


def _batch_id(nonce: str, task_ids: Sequence[str]) -> str:
    """Commitment over the drawn set. Order-independent (ids are sorted)."""
    body = (nonce + "\x00" + "\x00".join(sorted(task_ids))).encode("utf-8")
    return "sha256:" + hashlib.sha256(BATCH_DOMAIN + body).hexdigest()


# Public alias: other draw-capable sources (e.g. the synthetic generator) reuse
# the same commitment scheme so a batch_id means the same thing regardless of
# which source produced the tasks.
batch_id_for = _batch_id


def draw_batch(
    pool: TaskPool,
    *,
    size: int,
    nonce: str,
    as_of: datetime,
    cutoff: datetime,
) -> Batch:
    """Draw a sealed batch of `size` private tasks, deterministically from `nonce`.

    The nonce must be issued *after* the miner's model commitment (a later block
    hash), so the miner cannot have trained on the drawn set. Given the same pool
    and nonce, every validator draws the identical batch.
    """
    if size <= 0 or size > MAX_BATCH:
        raise BatchError("batch size out of range")
    if not nonce:
        raise BatchError("a batch draw requires a post-commit nonce")

    eligible = pool.private_holdout(as_of=as_of, cutoff=cutoff)
    if len(eligible) < size:
        # Distinguish "no admitted tasks" from "not enough tasks": a holdout that is
        # non-empty but wholly un-admitted is the exact state that would otherwise
        # score nothing while looking merely quiet. Say so, rather than reporting an
        # exhausted holdout when the real problem is that every task was refused at
        # admission (degenerate, or its answer is public).
        admitted = sum(1 for t in pool._tasks if t.admitted)
        detail = (
            "no task in the pool passed corpus admission — every candidate either "
            "does not discriminate or ships its answer in a public image; a scored "
            "batch cannot be drawn until an admitted (private, un-leakable) task is "
            "ingested"
            if admitted == 0 else
            f"only {len(eligible)} admitted private tasks available; need {size}. "
            "The holdout is exhausted — ingest fresh disclosures (whose images are "
            "not publicly pullable) before drawing."
        )
        raise BatchError(detail)
    return _select_ranked(eligible, size, nonce)


def _select_ranked(eligible: Sequence[PooledTask], size: int, nonce: str) -> Batch:
    """Deterministic selection: rank each eligible task by a nonce-keyed hash and
    take the lowest `size`. Uniform, reproducible, and unpredictable before the
    nonce is known — the one selection scheme both the private and the public
    (canary) draws share, so a `batch_id` means the same thing either way."""
    if len(eligible) < size:  # pragma: no cover - callers check with tailored messages
        raise BatchError(f"only {len(eligible)} tasks available; need {size}")

    def rank(task: PooledTask) -> bytes:
        return hashlib.sha256(
            BATCH_DOMAIN + nonce.encode() + b"\x00" + task.task_id.encode()
        ).digest()

    chosen = sorted(eligible, key=rank)[:size]
    tasks = tuple(sorted((t.to_task() for t in chosen), key=lambda t: t.task_id))
    return Batch(
        batch_id=_batch_id(nonce, [t.task_id for t in tasks]),
        nonce=nonce,
        tasks=tasks,
    )


def verify_batch_commitment(batch: Batch) -> bool:
    """Re-derive the batch_id from the nonce and task ids. Any validator can check."""
    return batch.batch_id == _batch_id(batch.nonce, batch.task_ids)
