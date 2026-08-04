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
from datetime import datetime
from decimal import Decimal
from typing import Any, Callable, Mapping

from cathedral_distill.attestation import AttestationPolicy
from cathedral_distill.cybergym import (
    DEFAULT_LEVEL_WEIGHTS,
    Level,
    PoCSubmission,
    Task,
    derived_work_units,
)
from cathedral_distill.cybergym_attest import (
    CyberGymAttestError,
    verify_submission_attestation,
)
from cathedral_distill.cybergym_batch import TaskPool, derive_batch_nonce
from cathedral_distill.cybergym_verifier import poc_digest, verify_poc
from cathedral_distill.trace_submission import (
    TraceQualityPolicy,
    TraceStep,
    TraceSubmission,
    submission_bonus,
)

DISPATCH_SCHEMA = "cathedral_cybergym_dispatch_v2"
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
        return {
            "task_id": self.task_id,
            "level": self.level,
            "binary_digest": self.binary_digest,
            "context": dict(self.context),
        }


@dataclass(frozen=True)
class DispatchMessage:
    """The sealed batch a validator serves one miner for one epoch."""

    network: str
    netuid: int
    source_epoch: int
    batch_id: str
    nonce: str
    miner_hotkey: str
    model_commitment: str
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
            "network": self.network,
            "netuid": self.netuid,
            "source_epoch": self.source_epoch,
            "batch_id": self.batch_id,
            "nonce": self.nonce,
            "miner_hotkey": self.miner_hotkey,
            "model_commitment": self.model_commitment,
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
        block=chain.block,
        block_hash=chain.block_hash,
        network=chain.network,
        netuid=chain.netuid,
        source_epoch=chain.source_epoch,
        miner_hotkey=miner_hotkey,
        model_commitment=model_commitment,
    )
    batch = pool.draw(size=batch_size, nonce=nonce, as_of=as_of, cutoff=cutoff)
    tasks: list[DispatchedTask] = []
    for task in batch.tasks:
        allowed = LEVEL_CONTEXT_FIELDS.get(int(task.level), ())
        full = dict(context_provider(task.task_id)) if context_provider else {}
        revealed = {k: str(full[k]) for k in allowed if k in full}
        tasks.append(
            DispatchedTask(
                task_id=task.task_id,
                level=int(task.level),
                binary_digest=task.binary_digest,
                context=revealed,
            )
    )
    return DispatchMessage(
        network=chain.network,
        netuid=chain.netuid,
        source_epoch=chain.source_epoch,
        batch_id=batch.batch_id,
        nonce=nonce,
        miner_hotkey=miner_hotkey,
        model_commitment=model_commitment,
        valid_from_block=chain.valid_from_block,
        valid_until_block=chain.valid_until_block,
        tasks=tuple(tasks),
    )


# --------------------------------------------------------------------------- #
# 2. Submission — miner → validator
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SubmissionEnvelope:
    """One miner's answer to one task: the PoC bytes, its trajectory, and the
    Intel-TDX attestation proving it was produced inside a measured enclave.

    `attestation` is a base64-encoded `cathedral_cc_attestation_v1` token whose
    report_data binds this exact submission (see `cybergym_attest`). It is optional
    on the wire — a miner may omit it — but when the validator runs with a TDX
    attestation policy configured, a submission without a valid one earns nothing.
    """

    batch_id: str
    task_id: str
    miner_hotkey: str
    poc_base64: str
    trace: Mapping[str, Any]  # a cathedral_trace_submission_v1 document
    attestation: str | None = None  # base64 cathedral_cc_attestation_v1 token

    def to_dict(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "schema": ENVELOPE_SCHEMA,
            "batch_id": self.batch_id,
            "task_id": self.task_id,
            "miner_hotkey": self.miner_hotkey,
            "poc_base64": self.poc_base64,
            "trace": dict(self.trace),
        }
        if self.attestation is not None:
            doc["attestation"] = self.attestation
        return doc

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
        attestation = doc.get("attestation")
        if attestation is not None and not isinstance(attestation, str):
            raise ProtocolError("submission attestation must be a base64 string")
        return cls(
            batch_id=str(doc["batch_id"]),
            task_id=str(doc["task_id"]),
            miner_hotkey=str(doc["miner_hotkey"]),
            poc_base64=str(doc["poc_base64"]),
            trace=doc["trace"],
            attestation=attestation,
        )


def _trace_from_dict(doc: Mapping[str, Any]) -> TraceSubmission:
    try:
        steps = tuple(
            TraceStep(
                step=int(s["step"]),
                thought=str(s["thought"]),
                action=str(s["action"]),
                output=str(s.get("output", "")),
            )
            for s in doc["steps"]
        )
        return TraceSubmission(
            task_id=str(doc["task_id"]),
            poc_sha256=str(doc["poc_sha256"]),
            model_id=str(doc["model_id"]),
            steps=steps,
            licence=str(doc["licence"]),
            model_seal=doc.get("model_seal"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtocolError(f"trace submission is malformed: {exc}") from exc


# --------------------------------------------------------------------------- #
# 3. Verify + gate + score — the validator's intake pipeline
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SubmissionOutcome:
    """The validator's verdict on one submission.

    `solved` is the raw differential-crash result (the PoC crashes the vulnerable
    build, not the patched one). `attested` is whether the required Intel-TDX
    attestation verified and bound to this submission. A solve earns work units
    only when it is *creditable* = solved AND attested; an unattested solve is a
    genuine crash that proves capability but earns nothing (its PoC never enters
    the reward pool, and it never lands in the corpus).
    """

    task_id: str
    miner_hotkey: str
    source_epoch: int
    level: int
    solved: bool
    trainable: bool
    reason: str
    work_units: Decimal  # level-weighted, validator-derived (0 unless creditable)
    bonus: float  # trace + seal bonus, gated on quality
    poc_sha256: str
    trace_id: str | None
    submission: TraceSubmission | None = field(default=None, repr=False)
    attested: bool = (
        True  # Intel-TDX attestation verified + bound (vacuously true if no policy)
    )

    @property
    def creditable(self) -> bool:
        """A solve that both crashed AND carries a verified TDX attestation."""
        return self.solved and self.attested


def process_submission(
    envelope: SubmissionEnvelope,
    dispatch_msg: DispatchMessage,
    backend,
    *,
    trace_policy: TraceQualityPolicy = TraceQualityPolicy(),
    weights: Mapping[Level, Decimal] = DEFAULT_LEVEL_WEIGHTS,
    attestation_policy: AttestationPolicy | None = None,
    now: datetime | None = None,
) -> SubmissionOutcome:
    """Verify one submission against the batch it answers, and score it.

    Fails closed: an off-batch task, a PoC whose digest disagrees with the trace,
    or a malformed trace is rejected. A well-formed submission is run through the
    differential crash test to set `solved`.

    Intel-TDX attestation gate: when `attestation_policy` is provided (production),
    the submission must carry a valid TDX attestation bound to (batch, task, PoC,
    miner) — see `cybergym_attest`; a solve is *creditable* (earns level-weighted
    units, is corpus-eligible) only when it is both solved AND attested. When no
    policy is given (the hardware-free dev/test path), attestation is not required
    and `attested` is vacuously true, preserving the prior behaviour exactly. A
    missing or invalid attestation is never a hard protocol error — the submission
    is simply not credited (`attested=False`), so one bad attestation cannot break
    an epoch's intake.
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

    # Intel-TDX attestation is checked before the differential container run.
    # Invalid evidence is not merely uncreditable: executing it first lets an
    # authenticated client monopolize verifier capacity with throwaway PoCs.
    attested = True
    attest_reason = ""
    if attestation_policy is not None:
        if not envelope.attestation:
            attested, attest_reason = False, "missing_tdx_attestation"
        else:
            try:
                token = base64.b64decode(envelope.attestation, validate=True)
                verify_submission_attestation(
                    token,
                    batch_id=envelope.batch_id,
                    task_id=envelope.task_id,
                    poc_sha256=digest,
                    trace_id=submission.trace_id(),
                    miner_hotkey=envelope.miner_hotkey,
                    model_commitment=dispatch_msg.model_commitment,
                    policy=attestation_policy,
                    now=now,
                )
            except (ValueError, TypeError, CyberGymAttestError) as exc:
                attested, attest_reason = False, f"tdx_attestation_invalid:{exc}"
    if not attested:
        return SubmissionOutcome(
            task_id=dt.task_id,
            miner_hotkey=envelope.miner_hotkey,
            source_epoch=dispatch_msg.source_epoch,
            level=dt.level,
            solved=False,
            trainable=False,
            reason="unattested:" + attest_reason,
            work_units=Decimal(0),
            bonus=0.0,
            poc_sha256=digest,
            trace_id=None,
            submission=None,
            attested=False,
        )

    task = Task(
        task_id=dt.task_id, level=Level(dt.level), binary_digest=dt.binary_digest
    )
    result = verify_poc(task, poc_bytes, backend)
    poc_sub = PoCSubmission(task_id=task.task_id, poc_sha256=digest, result=result)
    solved = result.solved

    creditable = solved and attested
    work_units = derived_work_units(task, poc_sub if creditable else None, weights)
    trainable = bool(creditable and submission.is_trainable(trace_policy))
    bonus = submission_bonus(submission, trace_policy) if creditable else 0.0

    if not solved:
        reason = "not_solved:" + result.outcome
    elif not trainable:
        reason = "solved_trace_below_floor:" + submission.quality(trace_policy).reason
    else:
        reason = "solved_trainable"

    return SubmissionOutcome(
        task_id=task.task_id,
        miner_hotkey=envelope.miner_hotkey,
        source_epoch=dispatch_msg.source_epoch,
        level=dt.level,
        solved=solved,
        trainable=trainable,
        reason=reason,
        work_units=work_units,
        bonus=bonus,
        poc_sha256=digest,
        trace_id=submission.trace_id() if creditable else None,
        submission=submission if creditable else None,
        attested=attested,
    )


# --------------------------------------------------------------------------- #
# 4. Corpus — verified + trainable rows land in the dataset format
# --------------------------------------------------------------------------- #


class CyberGymCorpusStore:
    """Verified, canonical training examples plus bounded duplicate evidence.

    A corpus row is one solved ``(source_epoch, task_id, poc_sha256)``.  Trace
    text and model seals make a trace content-addressed, but they must not let a
    repeated solution inflate the training corpus or durable-progress counters.
    Variants therefore increment an audit counter and retain only bounded
    metadata; they never become additional training rows.
    """

    MAX_DUPLICATE_AUDIT_VARIANTS = 3

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
            "  trace_id TEXT NOT NULL,"
            "  task_id TEXT NOT NULL, level INTEGER NOT NULL, source_epoch INTEGER NOT NULL,"
            "  miner_hotkey TEXT NOT NULL, model_id TEXT NOT NULL,"
            "  poc_sha256 TEXT NOT NULL, licence TEXT NOT NULL, model_seal TEXT NOT NULL,"
            "  work_units TEXT NOT NULL, steps_json TEXT NOT NULL,"
            "  PRIMARY KEY (source_epoch, task_id, poc_sha256))"
        )
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS cybergym_corpus_dedup_audit ("
            "  source_epoch INTEGER NOT NULL, task_id TEXT NOT NULL, poc_sha256 TEXT NOT NULL,"
            "  excluded_duplicates INTEGER NOT NULL, recorded_variants INTEGER NOT NULL,"
            "  PRIMARY KEY (source_epoch, task_id, poc_sha256))"
        )
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS cybergym_corpus_duplicate_variants ("
            "  source_epoch INTEGER NOT NULL, task_id TEXT NOT NULL, poc_sha256 TEXT NOT NULL,"
            "  trace_id TEXT NOT NULL, miner_hotkey TEXT NOT NULL, model_id TEXT NOT NULL,"
            "  model_seal TEXT NOT NULL,"
            "  PRIMARY KEY (source_epoch, task_id, poc_sha256, trace_id))"
        )
        self._migrate_canonical_solve_identity()
        self._connection.commit()

    def record(self, outcome: SubmissionOutcome) -> bool:
        """Persist a verified+trainable canonical solve.

        Returns ``True`` when the outcome is corpus-eligible, including a
        duplicate that was excluded from the training corpus and recorded in the
        bounded audit trail. Returns ``False`` for an ineligible outcome.
        """
        if not outcome.trainable or outcome.submission is None or outcome.trace_id is None:
            return False
        s = outcome.submission
        steps_json = json.dumps([st.as_dict() for st in s.steps], separators=(",", ":"))
        try:
            with self._connection:
                inserted = self._connection.execute(
                    "INSERT OR IGNORE INTO cybergym_corpus"
                    "(trace_id, task_id, level, source_epoch, miner_hotkey, model_id,"
                    " poc_sha256, licence, model_seal, work_units, steps_json)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (outcome.trace_id, outcome.task_id, outcome.level, outcome.source_epoch,
                     outcome.miner_hotkey, s.model_id, outcome.poc_sha256, s.licence,
                     str(s.model_seal), str(outcome.work_units), steps_json),
                ).rowcount
                if not inserted:
                    self._record_duplicate(
                        source_epoch=outcome.source_epoch, task_id=outcome.task_id,
                        poc_sha256=outcome.poc_sha256, trace_id=outcome.trace_id,
                        miner_hotkey=outcome.miner_hotkey, model_id=s.model_id,
                        model_seal=str(s.model_seal),
                    )
        except self._sqlite.DatabaseError as exc:
            raise ProtocolError("failed to record corpus row") from exc
        return True

    def _migrate_canonical_solve_identity(self) -> None:
        """Rebuild legacy trace-identity databases under the canonical key.

        Older databases used ``trace_id`` as their only identity.  Retain the
        lexicographically first historical trace as the canonical training row and
        move later variants to the bounded audit tables. The rebuild also lets the
        same trace occur in separate source epochs, which the old global trace
        primary key incorrectly rejected. The migration is transactional, so an
        interrupted startup leaves the old database unchanged.
        """
        try:
            with self._connection:
                columns = self._connection.execute("PRAGMA table_info(cybergym_corpus)").fetchall()
                primary_key = [
                    row["name"] for row in sorted(columns, key=lambda row: int(row["pk"]))
                    if row["pk"]
                ]
                if primary_key == ["source_epoch", "task_id", "poc_sha256"]:
                    return
                if primary_key != ["trace_id"]:
                    raise ProtocolError("unsupported cybergym corpus schema")
                self._connection.execute(
                    "CREATE TABLE cybergym_corpus_canonical ("
                    "  trace_id TEXT NOT NULL,"
                    "  task_id TEXT NOT NULL, level INTEGER NOT NULL, source_epoch INTEGER NOT NULL,"
                    "  miner_hotkey TEXT NOT NULL, model_id TEXT NOT NULL,"
                    "  poc_sha256 TEXT NOT NULL, licence TEXT NOT NULL, model_seal TEXT NOT NULL,"
                    "  work_units TEXT NOT NULL, steps_json TEXT NOT NULL,"
                    "  PRIMARY KEY (source_epoch, task_id, poc_sha256))"
                )
                rows = self._connection.execute(
                    "SELECT * FROM cybergym_corpus "
                    "ORDER BY source_epoch, task_id, poc_sha256, trace_id"
                ).fetchall()
                for row in rows:
                    inserted = self._connection.execute(
                        "INSERT OR IGNORE INTO cybergym_corpus_canonical "
                        "SELECT trace_id, task_id, level, source_epoch, miner_hotkey, model_id, "
                        "poc_sha256, licence, model_seal, work_units, steps_json "
                        "FROM cybergym_corpus WHERE trace_id=?",
                        (row["trace_id"],),
                    ).rowcount
                    if not inserted:
                        self._record_duplicate(
                            source_epoch=int(row["source_epoch"]), task_id=str(row["task_id"]),
                            poc_sha256=str(row["poc_sha256"]), trace_id=str(row["trace_id"]),
                            miner_hotkey=str(row["miner_hotkey"]), model_id=str(row["model_id"]),
                            model_seal=str(row["model_seal"]),
                        )
                self._connection.execute("DROP TABLE cybergym_corpus")
                self._connection.execute(
                    "ALTER TABLE cybergym_corpus_canonical RENAME TO cybergym_corpus"
                )
        except self._sqlite.DatabaseError as exc:
            raise ProtocolError("failed to migrate canonical corpus identity") from exc

    def _record_duplicate(
        self, *, source_epoch: int, task_id: str, poc_sha256: str, trace_id: str,
        miner_hotkey: str, model_id: str, model_seal: str,
    ) -> None:
        """Count an excluded duplicate and retain at most a few trace identities."""
        self._connection.execute(
            "INSERT INTO cybergym_corpus_dedup_audit"
            "(source_epoch, task_id, poc_sha256, excluded_duplicates, recorded_variants)"
            " VALUES (?,?,?,?,0)"
            " ON CONFLICT(source_epoch, task_id, poc_sha256) DO UPDATE SET"
            " excluded_duplicates=excluded_duplicates+1",
            (int(source_epoch), str(task_id), str(poc_sha256), 1),
        )
        audit = self._connection.execute(
            "SELECT recorded_variants FROM cybergym_corpus_dedup_audit "
            "WHERE source_epoch=? AND task_id=? AND poc_sha256=?",
            (int(source_epoch), str(task_id), str(poc_sha256)),
        ).fetchone()
        if audit is None or int(audit["recorded_variants"]) >= self.MAX_DUPLICATE_AUDIT_VARIANTS:
            return
        added = self._connection.execute(
            "INSERT OR IGNORE INTO cybergym_corpus_duplicate_variants"
            "(source_epoch, task_id, poc_sha256, trace_id, miner_hotkey, model_id, model_seal)"
            " VALUES (?,?,?,?,?,?,?)",
            (int(source_epoch), str(task_id), str(poc_sha256), str(trace_id),
             str(miner_hotkey), str(model_id), str(model_seal)),
        ).rowcount
        if added:
            self._connection.execute(
                "UPDATE cybergym_corpus_dedup_audit SET recorded_variants=recorded_variants+1 "
                "WHERE source_epoch=? AND task_id=? AND poc_sha256=?",
                (int(source_epoch), str(task_id), str(poc_sha256)),
            )

    def rows(self, *, source_epoch: int | None = None) -> list[dict[str, Any]]:
        if source_epoch is None:
            cur = self._connection.execute(
                "SELECT * FROM cybergym_corpus ORDER BY trace_id"
            )
        else:
            cur = self._connection.execute(
                "SELECT * FROM cybergym_corpus WHERE source_epoch=? ORDER BY trace_id",
                (source_epoch,),
            )
        out = []
        for r in cur:
            row = dict(r)
            row["steps"] = json.loads(row.pop("steps_json"))  # rehydrate the trajectory
            out.append(row)
        return out

    def size(self) -> int:
        return self._connection.execute(
            "SELECT COUNT(*) FROM cybergym_corpus"
        ).fetchone()[0]

    def audit(self, *, source_epoch: int | None = None) -> dict[str, int]:
        """Return canonical corpus and excluded-duplicate counts for status/export."""
        where = "" if source_epoch is None else " WHERE source_epoch=?"
        params = () if source_epoch is None else (int(source_epoch),)
        canonical = self._connection.execute(
            "SELECT COUNT(*) FROM cybergym_corpus" + where, params
        ).fetchone()[0]
        duplicates = self._connection.execute(
            "SELECT COALESCE(SUM(excluded_duplicates), 0) FROM cybergym_corpus_dedup_audit" + where,
            params,
        ).fetchone()[0]
        variants = self._connection.execute(
            "SELECT COALESCE(SUM(recorded_variants), 0) FROM cybergym_corpus_dedup_audit" + where,
            params,
        ).fetchone()[0]
        return {
            "canonical_solves": int(canonical),
            "excluded_duplicates": int(duplicates),
            "recorded_duplicate_variants": int(variants),
        }

    def close(self) -> None:
        self._connection.close()
