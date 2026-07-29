"""The CyberGym miner↔validator protocol — dispatch, submit, verify, corpus.

This is the delivery system that turns the CyberGym kernel into a working track:

    validator DISPATCHES a sealed batch → miner SOLVES + records a trajectory →
    miner SUBMITS {PoC, trace} → validator VERIFIES (differential crash) and
    GATES the trace → verified+trainable rows land in the CORPUS, verbatim.

The submission format IS the dataset format: a `TraceSubmission` that clears both
gates is a corpus row with no transformation — which is what makes the flywheel
tight (verified solutions compound straight into training data).

Everything here is pure and transport-agnostic: `dispatch` and `process_submission`
are functions over injected chain state and an injected crash backend, and the
messages are plain JSON-serialisable dataclasses. A real deployment is a thin HTTP
(or Bittensor axon) shim that (1) serves `DispatchMessage.to_dict()` and (2) feeds
a POSTed `SubmissionEnvelope` into `process_submission`. The ~130 GB CyberGym
binaries plug in behind the same backend the hardware-free tests inject.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Callable, Mapping, Sequence

from cathedral_distill.cybergym import (
    DEFAULT_LEVEL_WEIGHTS,
    Level,
    PoCSubmission,
    Task,
    derived_work_units,
)
from cathedral_distill.cybergym_batch import Batch, TaskPool, derive_batch_nonce
from cathedral_distill.cybergym_verifier import poc_digest, verify_poc
from cathedral_distill.trace_submission import (
    TraceQualityPolicy,
    TraceStep,
    TraceSubmission,
    submission_bonus,
)

DISPATCH_SCHEMA = "cathedral_cybergym_dispatch_v1"
ENVELOPE_SCHEMA = "cathedral_cybergym_submission_envelope_v1"
MAX_POC_BYTES = 1024 * 1024

# What each difficulty level reveals to the miner. Lower level = less help = more
# skill = higher weight. level0 is blind discovery: the vulnerable build only.
LEVEL_CONTEXT_FIELDS: Mapping[int, tuple[str, ...]] = {
    0: (),
    1: ("description",),
    2: ("description", "sanitizer_trace"),
    3: ("description", "sanitizer_trace", "patch"),
}


class ProtocolError(ValueError):
    """Raised on a malformed dispatch or submission. Fails closed."""


# --------------------------------------------------------------------------- #
# 1. Dispatch — validator → miner
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class DispatchedTask:
    task_id: str
    level: int
    binary_digest: str
    context: Mapping[str, str]  # only the level-appropriate fields, revealed

    def to_dict(self) -> dict[str, Any]:
        return {"task_id": self.task_id, "level": self.level,
                "binary_digest": self.binary_digest, "context": dict(self.context)}


@dataclass(frozen=True)
class DispatchMessage:
    """The sealed batch a validator serves one miner for one epoch."""

    network: str
    netuid: int
    source_epoch: int
    batch_id: str
    nonce: str
    miner_hotkey: str
    valid_from_block: int
    valid_until_block: int
    tasks: tuple[DispatchedTask, ...]

    def task(self, task_id: str) -> DispatchedTask | None:
        for t in self.tasks:
            if t.task_id == task_id:
                return t
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": DISPATCH_SCHEMA,
            "network": self.network, "netuid": self.netuid,
            "source_epoch": self.source_epoch,
            "batch_id": self.batch_id, "nonce": self.nonce,
            "miner_hotkey": self.miner_hotkey,
            "valid_from_block": self.valid_from_block,
            "valid_until_block": self.valid_until_block,
            "tasks": [t.to_dict() for t in self.tasks],
        }


def dispatch(
    pool: TaskPool,
    chain: Any,
    *,
    miner_hotkey: str,
    model_commitment: str,
    cutoff,
    as_of,
    batch_size: int,
    context_provider: Callable[[str], Mapping[str, str]] | None = None,
) -> DispatchMessage:
    """Draw this miner's sealed batch and serve only its level-appropriate context.

    `chain` supplies finalized state (block, block_hash, network, netuid,
    source_epoch, valid_from_block, valid_until_block). The nonce binds the miner's
    committed model, so the miner cannot have trained on the drawn set and every
    validator dispatches the identical batch. `context_provider(task_id)` returns
    the full task context; only the fields `LEVEL_CONTEXT_FIELDS[level]` allows are
    revealed — a level-0 miner gets nothing but the vulnerable build.

    `pool` is any draw-capable source exposing `.draw(size=, nonce=, as_of=,
    cutoff=) -> Batch` — a real `TaskPool` (disclosure-timed corpus) or
    `cybergym_synthetic.SyntheticTaskSource` (nonce-generated, unlimited,
    never in any public dataset) both satisfy it identically.
    """
    nonce = derive_batch_nonce(
        block=chain.block, block_hash=chain.block_hash, network=chain.network,
        netuid=chain.netuid, source_epoch=chain.source_epoch,
        miner_hotkey=miner_hotkey, model_commitment=model_commitment,
    )
    batch = pool.draw(size=batch_size, nonce=nonce, as_of=as_of, cutoff=cutoff)
    tasks: list[DispatchedTask] = []
    for task in batch.tasks:
        allowed = LEVEL_CONTEXT_FIELDS.get(int(task.level), ())
        full = dict(context_provider(task.task_id)) if context_provider else {}
        revealed = {k: str(full[k]) for k in allowed if k in full}
        tasks.append(DispatchedTask(task_id=task.task_id, level=int(task.level),
                                    binary_digest=task.binary_digest, context=revealed))
    return DispatchMessage(
        network=chain.network, netuid=chain.netuid, source_epoch=chain.source_epoch,
        batch_id=batch.batch_id, nonce=nonce, miner_hotkey=miner_hotkey,
        valid_from_block=chain.valid_from_block, valid_until_block=chain.valid_until_block,
        tasks=tuple(tasks),
    )


# --------------------------------------------------------------------------- #
# 2. Submission — miner → validator
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class SubmissionEnvelope:
    """One miner's answer to one task: the PoC bytes and its trajectory."""

    batch_id: str
    task_id: str
    miner_hotkey: str
    poc_base64: str
    trace: Mapping[str, Any]  # a cathedral_trace_submission_v1 document

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": ENVELOPE_SCHEMA, "batch_id": self.batch_id,
            "task_id": self.task_id, "miner_hotkey": self.miner_hotkey,
            "poc_base64": self.poc_base64, "trace": dict(self.trace),
        }

    @classmethod
    def from_json(cls, raw: bytes | str) -> "SubmissionEnvelope":
        try:
            doc = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise ProtocolError("submission is not valid JSON") from exc
        if not isinstance(doc, Mapping) or doc.get("schema") != ENVELOPE_SCHEMA:
            raise ProtocolError("submission envelope schema is unsupported")
        for key in ("batch_id", "task_id", "miner_hotkey", "poc_base64", "trace"):
            if key not in doc:
                raise ProtocolError(f"submission envelope is missing {key}")
        if not isinstance(doc["trace"], Mapping):
            raise ProtocolError("submission trace must be an object")
        return cls(batch_id=str(doc["batch_id"]), task_id=str(doc["task_id"]),
                   miner_hotkey=str(doc["miner_hotkey"]), poc_base64=str(doc["poc_base64"]),
                   trace=doc["trace"])


def _trace_from_dict(doc: Mapping[str, Any]) -> TraceSubmission:
    try:
        steps = tuple(
            TraceStep(step=int(s["step"]), thought=str(s["thought"]),
                      action=str(s["action"]), output=str(s.get("output", "")))
            for s in doc["steps"]
        )
        return TraceSubmission(
            task_id=str(doc["task_id"]), poc_sha256=str(doc["poc_sha256"]),
            model_id=str(doc["model_id"]), steps=steps, licence=str(doc["licence"]),
            model_seal=doc.get("model_seal"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtocolError(f"trace submission is malformed: {exc}") from exc


# --------------------------------------------------------------------------- #
# 3. Verify + gate + score — the validator's intake pipeline
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class SubmissionOutcome:
    """The validator's verdict on one submission."""

    task_id: str
    miner_hotkey: str
    source_epoch: int
    level: int
    solved: bool
    trainable: bool
    reason: str
    work_units: Decimal            # level-weighted, validator-derived (0 if unsolved)
    bonus: float                   # trace + seal bonus, gated on quality
    poc_sha256: str
    trace_id: str | None
    submission: TraceSubmission | None = field(default=None, repr=False)


def process_submission(
    envelope: SubmissionEnvelope,
    dispatch_msg: DispatchMessage,
    backend,
    *,
    trace_policy: TraceQualityPolicy = TraceQualityPolicy(),
    weights: Mapping[Level, Decimal] = DEFAULT_LEVEL_WEIGHTS,
) -> SubmissionOutcome:
    """Verify one submission against the batch it answers, and score it.

    Fails closed: an off-batch task, a PoC whose digest disagrees with the trace,
    or a malformed trace is rejected. A well-formed submission is run through the
    differential crash test; only a genuine solve earns level-weighted units, and
    only a solve whose trace clears the structural floor (and carries a model seal)
    is `trainable` — eligible for the corpus and the trace bonus.
    """
    if envelope.batch_id != dispatch_msg.batch_id:
        raise ProtocolError("submission batch_id does not match the dispatched batch")
    dt = dispatch_msg.task(envelope.task_id)
    if dt is None:
        raise ProtocolError("submission is for a task not in this batch")

    try:
        poc_bytes = base64.b64decode(envelope.poc_base64, validate=True)
    except (ValueError, TypeError) as exc:
        raise ProtocolError("PoC is not valid base64") from exc
    if not poc_bytes or len(poc_bytes) > MAX_POC_BYTES:
        raise ProtocolError("PoC is empty or exceeds the size limit")

    digest = poc_digest(poc_bytes)
    submission = _trace_from_dict(envelope.trace)
    # Bind the trace to the exact PoC and the challenged task.
    if submission.task_id != envelope.task_id:
        raise ProtocolError("trace task_id disagrees with the submission")
    if submission.poc_sha256 != digest:
        raise ProtocolError("trace poc_sha256 does not match the submitted PoC bytes")

    task = Task(task_id=dt.task_id, level=Level(dt.level), binary_digest=dt.binary_digest)
    result = verify_poc(task, poc_bytes, backend)
    poc_sub = PoCSubmission(task_id=task.task_id, poc_sha256=digest, result=result)

    solved = result.solved
    work_units = derived_work_units(task, poc_sub if solved else None, weights)
    trainable = bool(solved and submission.is_trainable(trace_policy))
    bonus = submission_bonus(submission, trace_policy) if solved else 0.0

    if not solved:
        reason = "not_solved:" + result.outcome
    elif not trainable:
        reason = "solved_trace_below_floor:" + submission.quality(trace_policy).reason
    else:
        reason = "solved_trainable"

    return SubmissionOutcome(
        task_id=task.task_id, miner_hotkey=envelope.miner_hotkey,
        source_epoch=dispatch_msg.source_epoch, level=dt.level, solved=solved,
        trainable=trainable, reason=reason, work_units=work_units, bonus=bonus,
        poc_sha256=digest, trace_id=submission.trace_id() if solved else None,
        submission=submission if solved else None,
    )


# --------------------------------------------------------------------------- #
# 4. Corpus — verified + trainable rows land in the dataset format
# --------------------------------------------------------------------------- #

class CyberGymCorpusStore:
    """The verified-solution corpus. Rows are the trajectory verbatim — the exact
    training format — so a solved+trainable submission compounds into the corpus
    with no transformation. Only verified, trainable, licenced, sealed rows land."""

    def __init__(self, db_path: str) -> None:
        import sqlite3
        self._sqlite = sqlite3
        # check_same_thread=False so the store is usable from a server thread that
        # did not open it; requests are serialised by the single-threaded shim, so
        # there is no concurrent-write hazard.
        self._connection = sqlite3.connect(db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS cybergym_corpus ("
            "  trace_id TEXT PRIMARY KEY,"
            "  task_id TEXT NOT NULL, level INTEGER NOT NULL, source_epoch INTEGER NOT NULL,"
            "  miner_hotkey TEXT NOT NULL, model_id TEXT NOT NULL,"
            "  poc_sha256 TEXT NOT NULL, licence TEXT NOT NULL, model_seal TEXT NOT NULL,"
            "  work_units TEXT NOT NULL, steps_json TEXT NOT NULL)"
        )
        self._connection.commit()

    def record(self, outcome: SubmissionOutcome) -> bool:
        """Persist a verified+trainable row. Returns True if it was added (or was
        already present), False if the outcome is not corpus-eligible."""
        if not outcome.trainable or outcome.submission is None or outcome.trace_id is None:
            return False
        s = outcome.submission
        steps_json = json.dumps([st.as_dict() for st in s.steps], separators=(",", ":"))
        try:
            with self._connection:
                self._connection.execute(
                    "INSERT OR IGNORE INTO cybergym_corpus"
                    "(trace_id, task_id, level, source_epoch, miner_hotkey, model_id,"
                    " poc_sha256, licence, model_seal, work_units, steps_json)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (outcome.trace_id, outcome.task_id, outcome.level, outcome.source_epoch,
                     outcome.miner_hotkey, s.model_id, outcome.poc_sha256, s.licence,
                     str(s.model_seal), str(outcome.work_units), steps_json),
                )
        except self._sqlite.DatabaseError as exc:
            raise ProtocolError("failed to record corpus row") from exc
        return True

    def rows(self, *, source_epoch: int | None = None) -> list[dict[str, Any]]:
        if source_epoch is None:
            cur = self._connection.execute("SELECT * FROM cybergym_corpus ORDER BY trace_id")
        else:
            cur = self._connection.execute(
                "SELECT * FROM cybergym_corpus WHERE source_epoch=? ORDER BY trace_id",
                (source_epoch,))
        out = []
        for r in cur:
            row = dict(r)
            row["steps"] = json.loads(row.pop("steps_json"))  # rehydrate the trajectory
            out.append(row)
        return out

    def size(self) -> int:
        return self._connection.execute("SELECT COUNT(*) FROM cybergym_corpus").fetchone()[0]

    def close(self) -> None:
        self._connection.close()
