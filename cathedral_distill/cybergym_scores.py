"""Durable per-(miner, epoch) CyberGym scores — the writer for the mechanism feed.

The CyberGym mechanism adapter in `cathedralai/cathedral`
(`scaffold/publisher/mechanism_cybergym_adapter.py`) reads verified per-miner
scores from a `cybergym_scores` table and maps them to uids. Nothing wrote that
table; this is the writer. It records the level-weighted work units from a
verified `cathedral_cybergym_receipt_v1`, keyed by (miner_hotkey, epoch), so the
adapter's `SELECT miner_hotkey, score FROM cybergym_scores WHERE epoch=?` returns
exactly the verified frontier this validator scored. The adapter also requires
`cybergym_epoch_status.state = 'closed'` for that epoch before publishing —
the same gate as `require_closed_epoch` / `compose_scores_lane` here.

The `score` column is the level-weighted **earned units** (the adapter's
"level-weighted sum of verified PoC solves"), stored as REAL to match the
adapter's schema; earned units are small exact-in-float64 sums of the pinned
weights. A `receipt_id` column is carried for audit — the adapter ignores extra
columns. Writes are transactional and idempotent for the same receipt; a
different score for the same (miner, epoch) is refused rather than silently
overwritten, so a re-score cannot quietly change a published frontier.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from decimal import Decimal
from typing import Mapping

from cathedral_distill.cybergym_receipt import validate_structure


class CyberGymScoreError(RuntimeError):
    """Raised when a score cannot be recorded durably."""


# Epoch lifecycle, persisted in the SAME database the mechanism adapter reads.
# A composer that cannot see this marker cannot tell "nobody solved anything" from
# "this validator lost the epoch's state", and those two produce the same empty,
# 100%-burn vector.
EPOCH_OPEN = "open"              # no scoring pass has completed for this epoch
EPOCH_CLOSED = "closed"          # scored, complete, safe to compose and publish
EPOCH_INCOMPLETE = "incomplete"  # scored but state was lost: composing under-credits


def _require_durable_path(db_path: str, *, what: str) -> str:
    """Refuse a database path that cannot survive a restart.

    An in-memory store forgets everything on restart, which is precisely the
    failure this store exists to prevent, and it fails OPEN: the epoch looks like
    an epoch nobody solved.
    """
    if not isinstance(db_path, str) or not db_path.strip():
        raise CyberGymScoreError(f"{what} requires a durable database path")
    if db_path == ":memory:" or "mode=memory" in db_path:
        raise CyberGymScoreError(
            f"an in-memory {what} is not durable: a restart loses the epoch's state, "
            "which is the failure it exists to prevent; pass a file path"
        )
    return db_path


class CyberGymScoreStore:
    """SQLite-backed writer for the `cybergym_scores` mechanism table."""

    def __init__(self, db_path: str, *, durability_required: bool = True) -> None:
        # The same refusal the solve store makes, and for a sharper reason: this
        # table's whole purpose is to be read as a FILE by the external mechanism
        # adapter, from another process. An in-memory score store could be marked
        # EPOCH_CLOSED and composed in-process while the adapter saw an empty
        # database and published 100% burn. The opt-out is named in full so a
        # test can say what it is giving up and production cannot do it by
        # accident (mirrors the service's solve_durability_required).
        if durability_required:
            db_path = _require_durable_path(db_path, what="CyberGymScoreStore")
        self._db_path = db_path
        # check_same_thread=False so a server thread can persist scores; the
        # single-threaded service serialises access (no concurrent writers).
        self._connection = sqlite3.connect(db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS cybergym_scores ("
            "  miner_hotkey TEXT NOT NULL,"
            "  epoch INTEGER NOT NULL,"
            "  score REAL NOT NULL,"
            "  earned_units TEXT NOT NULL,"
            "  receipt_id TEXT NOT NULL,"
            "  PRIMARY KEY (miner_hotkey, epoch))"
        )
        # The completeness marker lives beside the scores, on purpose: the external
        # mechanism adapter reads this database directly, so it must be able to see
        # whether the epoch it is about to publish actually closed. Its query is
        # `SELECT state FROM cybergym_epoch_status WHERE epoch=?`, and anything other
        # than 'closed' (including a missing row) means do not publish.
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS cybergym_epoch_status ("
            "  epoch INTEGER PRIMARY KEY,"
            "  state TEXT NOT NULL,"
            "  detail TEXT NOT NULL,"
            "  scored_miners INTEGER NOT NULL,"
            "  marked_at TEXT NOT NULL)"
        )
        self._connection.commit()

    # -- epoch lifecycle --------------------------------------------------- #
    def mark_epoch(
        self,
        epoch: int,
        *,
        state: str,
        detail: str = "",
        scored_miners: int = 0,
        at: str | None = None,
    ) -> None:
        """Record how an epoch's scoring pass ended. Fails closed on a bad state."""
        if state not in (EPOCH_OPEN, EPOCH_CLOSED, EPOCH_INCOMPLETE):
            raise CyberGymScoreError(f"unknown epoch state {state!r}")
        from datetime import datetime, timezone

        stamp = at or datetime.now(timezone.utc).isoformat()
        try:
            with self._connection:
                existing = self._connection.execute(
                    "SELECT state, marked_at FROM cybergym_epoch_status WHERE epoch=?",
                    (int(epoch),),
                ).fetchone()
                # A completed epoch is a frozen producer artifact. Re-running the
                # same scoring pass may refresh its explanatory detail, but it must
                # not mint a new freshness timestamp for the same epoch: Cathedral's
                # intake correctly treats two different same-epoch reports as
                # equivocation. Preserve the first close time across closed->closed
                # retries, and refuse to reopen a closed epoch. Incomplete->closed
                # remains the valid recovery transition before first publication.
                if existing is not None and str(existing["state"]) == EPOCH_CLOSED:
                    if state != EPOCH_CLOSED:
                        raise CyberGymScoreError(
                            f"refusing to change closed cybergym epoch {int(epoch)} "
                            f"back to {state!r}: an exportable epoch is immutable"
                        )
                    stamp = str(existing["marked_at"])
                self._connection.execute(
                    "INSERT INTO cybergym_epoch_status"
                    "(epoch, state, detail, scored_miners, marked_at) VALUES (?,?,?,?,?)"
                    " ON CONFLICT(epoch) DO UPDATE SET state=excluded.state,"
                    "  detail=excluded.detail, scored_miners=excluded.scored_miners,"
                    "  marked_at=excluded.marked_at",
                    (int(epoch), state, str(detail), int(scored_miners), stamp),
                )
        except sqlite3.DatabaseError as exc:
            raise CyberGymScoreError("failed to record the epoch state") from exc

    def epoch_state(self, epoch: int) -> tuple[str, str]:
        """`(state, detail)` for an epoch. An unmarked epoch is `open`."""
        row = self._connection.execute(
            "SELECT state, detail FROM cybergym_epoch_status WHERE epoch=?", (int(epoch),)
        ).fetchone()
        if row is None:
            return EPOCH_OPEN, "no scoring pass has been recorded for this epoch"
        return str(row["state"]), str(row["detail"])

    def epoch_status(self, epoch: int) -> dict[str, object]:
        """The durable close record used to timestamp an exported score report.

        ``generated_at`` must come from producer state, not from the moment an
        operator happens to retry publication. Returning the persisted marker lets
        the report exporter reuse the first close time byte-for-byte. An unmarked
        epoch is represented as open rather than synthesized as complete.
        """
        row = self._connection.execute(
            "SELECT state, detail, scored_miners, marked_at "
            "FROM cybergym_epoch_status WHERE epoch=?",
            (int(epoch),),
        ).fetchone()
        if row is None:
            return {
                "state": EPOCH_OPEN,
                "detail": "no scoring pass has been recorded for this epoch",
                "scored_miners": 0,
                "marked_at": None,
            }
        return {
            "state": str(row["state"]),
            "detail": str(row["detail"]),
            "scored_miners": int(row["scored_miners"]),
            "marked_at": str(row["marked_at"]),
        }

    def require_closed_epoch(self, epoch: int) -> None:
        """Raise unless this epoch closed cleanly. The gate every composer needs."""
        state, detail = self.epoch_state(epoch)
        if state != EPOCH_CLOSED:
            raise CyberGymScoreError(
                f"refusing to compose CyberGym epoch {int(epoch)}: its state is "
                f"{state!r} ({detail}). Composing now would publish a vector that "
                "cannot be distinguished from an epoch nobody solved."
            )

    def record(self, receipt: Mapping[str, object]) -> None:
        """Persist the verified earned units for one (miner, epoch).

        The receipt must already be structurally valid (call `verify_receipt`
        first for signature/replay). This re-derives the durable fields from the
        receipt rather than trusting caller-passed numbers.
        """
        doc = validate_structure(receipt)  # fail closed on a malformed receipt
        miner = str(doc["miner_hotkey"])
        epoch = int(doc["source_epoch"])
        receipt_id = str(doc["receipt_id"])
        earned_text = str(doc["score"]["work_units"])
        earned = Decimal(earned_text)
        score_real = float(earned)

        try:
            with self._connection:  # one transaction; rolls back on any raise
                existing = self._connection.execute(
                    "SELECT earned_units, receipt_id FROM cybergym_scores "
                    "WHERE miner_hotkey=? AND epoch=?",
                    (miner, epoch),
                ).fetchone()
                state = self._connection.execute(
                    "SELECT state FROM cybergym_epoch_status WHERE epoch=?",
                    (epoch,),
                ).fetchone()
                if existing is not None:
                    if existing["receipt_id"] == receipt_id:
                        return  # idempotent: same receipt already recorded
                    if state is not None and str(state["state"]) == EPOCH_CLOSED:
                        raise CyberGymScoreError(
                            f"refusing a replacement cybergym score for closed epoch "
                            f"{epoch}: a complete epoch is immutable once it can be "
                            "exported"
                        )
                    if Decimal(existing["earned_units"]) != earned:
                        raise CyberGymScoreError(
                            f"conflicting cybergym score for {miner} epoch {epoch}: "
                            "refusing to overwrite a published frontier"
                        )
                    # Same units, different receipt id (e.g. re-issued): keep first.
                    return
                if state is not None and str(state["state"]) == EPOCH_CLOSED:
                    raise CyberGymScoreError(
                        f"refusing a new cybergym score for closed epoch {epoch}: "
                        "a complete epoch is immutable once it can be exported"
                    )
                self._connection.execute(
                    "INSERT INTO cybergym_scores"
                    "(miner_hotkey, epoch, score, earned_units, receipt_id) "
                    "VALUES (?,?,?,?,?)",
                    (miner, epoch, score_real, earned_text, receipt_id),
                )
        except sqlite3.DatabaseError as exc:
            raise CyberGymScoreError("failed to record cybergym score") from exc

    def score_for(self, miner_hotkey: str, epoch: int) -> Decimal | None:
        row = self._connection.execute(
            "SELECT earned_units FROM cybergym_scores WHERE miner_hotkey=? AND epoch=?",
            (miner_hotkey, epoch),
        ).fetchone()
        return Decimal(row["earned_units"]) if row is not None else None

    def epoch_scores(self, epoch: int) -> dict[str, Decimal]:
        """Exactly what the adapter reads: verified per-miner scores for an epoch."""
        return {
            row["miner_hotkey"]: Decimal(row["earned_units"])
            for row in self._connection.execute(
                "SELECT miner_hotkey, earned_units FROM cybergym_scores WHERE epoch=?",
                (epoch,),
            )
        }

    def contributions(self, epoch: int) -> list[dict[str, object]]:
        """Verified rows for an epoch, carrying the receipt_id — the in-repo
        `compose_vector` bridge needs `(miner_hotkey, receipt_id, earned_units)`
        to build lane contributions auditable back to receipts."""
        return [
            {"miner_hotkey": row["miner_hotkey"], "receipt_id": row["receipt_id"],
             "earned_units": row["earned_units"]}
            for row in self._connection.execute(
                "SELECT miner_hotkey, receipt_id, earned_units FROM cybergym_scores "
                "WHERE epoch=? ORDER BY miner_hotkey",
                (epoch,),
            )
        ]

    def close(self) -> None:
        self._connection.close()


class CyberGymSolveStore:
    """Durable per-(epoch, miner, task) accepted solves: the crash-recovery store.

    `CyberGymScoreStore` persists the epoch's OUTCOME, but only at epoch close.
    Between the first accepted submission and `score_epoch` the epoch's entire
    state lived in `CyberGymService._miners`, in memory. A restart in that window
    (the whole scoring window, hours on a live subnet) lost every miner's accepted
    PoCs while the corpus rows survived on disk, and the lane then composed empty
    and published a forced-burn vector: every miner paid for the validator's
    restart, silently.

    This is the missing durable half. It stores exactly what `run_epoch` needs to
    re-derive the same scores: the miner's committed model and its accepted PoC
    bytes, keyed by (epoch, miner_hotkey, task_id), because `run_epoch` re-draws
    each batch from the chain-anchored nonce rather than from any dispatch state.
    Recovery is therefore byte-identical scoring, not an approximation.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = _require_durable_path(db_path, what="CyberGymSolveStore")
        self._connection = sqlite3.connect(db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS cybergym_solves ("
            "  epoch INTEGER NOT NULL,"
            "  miner_hotkey TEXT NOT NULL,"
            "  task_id TEXT NOT NULL,"
            "  model_commitment TEXT NOT NULL,"
            "  poc BLOB NOT NULL,"
            "  PRIMARY KEY (epoch, miner_hotkey, task_id))"
        )
        # Verification runs an adversarial PoC through the differential backend.
        # Keep the bounded attempt budget beside durable solves so a process
        # restart cannot reset a miner's expensive-execution allowance.
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS cybergym_submission_attempts ("
            "  epoch INTEGER NOT NULL,"
            "  miner_hotkey TEXT NOT NULL,"
            "  task_id TEXT NOT NULL,"
            "  attempts INTEGER NOT NULL CHECK (attempts >= 0),"
            "  PRIMARY KEY (epoch, miner_hotkey, task_id))"
        )
        # Solves that exist in durable evidence (a corpus row) but can no longer be
        # scored, with the reason. Two sources: a miner that abandoned the commitment
        # they were drawn against (its own act, its own loss), and an operator
        # acknowledging state this validator genuinely cannot reconstruct. Recording
        # it is what stops the "durable or refuse" guard from becoming a permanent,
        # miner-triggerable outage of the whole lane.
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS cybergym_unscorable ("
            "  epoch INTEGER NOT NULL,"
            "  miner_hotkey TEXT NOT NULL,"
            "  reason TEXT NOT NULL,"
            "  marked_at TEXT NOT NULL,"
            "  PRIMARY KEY (epoch, miner_hotkey))"
        )
        # The epoch's scoring inputs, so a restart cannot silently score the same
        # epoch under a different anchor. Recovering the PoCs is not enough for
        # byte-identical scoring: the batch nonce is derived from the finalized
        # block and block hash, so a restart that supplied a different block drew a
        # different batch and produced a different receipt for the same epoch.
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS cybergym_epoch_manifest ("
            "  epoch INTEGER PRIMARY KEY,"
            "  manifest_json TEXT NOT NULL,"
            "  manifest_digest TEXT NOT NULL,"
            "  issued_at TEXT)"
        )
        self._connection.commit()

    # -- the epoch's scoring inputs ---------------------------------------- #
    @staticmethod
    def canonical_manifest(manifest: Mapping[str, object]) -> tuple[str, str]:
        """`(canonical_json, digest)` for an epoch manifest. Sorted, ASCII, no floats."""
        text = json.dumps(dict(manifest), sort_keys=True, ensure_ascii=True,
                          separators=(",", ":"), allow_nan=False)
        return text, "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()

    def record_manifest(self, epoch: int, manifest: Mapping[str, object]) -> str:
        """Pin this epoch's scoring inputs, or fail if they disagree with the pin.

        First write wins and every later run must match it exactly. The error names
        the fields that differ, because "your restart is scoring epoch N under
        block 512 but the epoch was drawn at block 500" is the operator's actual
        problem.
        """
        text, digest = self.canonical_manifest(manifest)
        existing = self.manifest_for(epoch)
        if existing is not None:
            if existing["digest"] == digest:
                return digest
            differing = sorted(
                key for key in set(existing["manifest"]) | set(manifest)
                if existing["manifest"].get(key) != dict(manifest).get(key)
            )
            raise CyberGymScoreError(
                f"epoch {int(epoch)} was already pinned to different scoring inputs; "
                f"refusing to score it again. Differing: {', '.join(differing)}"
            )
        try:
            with self._connection:
                self._connection.execute(
                    "INSERT INTO cybergym_epoch_manifest"
                    "(epoch, manifest_json, manifest_digest, issued_at) VALUES (?,?,?,NULL)",
                    (int(epoch), text, digest),
                )
        except sqlite3.DatabaseError as exc:
            raise CyberGymScoreError("failed to record the epoch manifest") from exc
        return digest

    def manifest_for(self, epoch: int) -> dict[str, object] | None:
        row = self._connection.execute(
            "SELECT manifest_json, manifest_digest, issued_at FROM cybergym_epoch_manifest "
            "WHERE epoch=?",
            (int(epoch),),
        ).fetchone()
        if row is None:
            return None
        return {
            "manifest": json.loads(row["manifest_json"]),
            "digest": str(row["manifest_digest"]),
            "issued_at": row["issued_at"],
        }

    def pin_issued_at(self, epoch: int, issued_at: str) -> str:
        """Pin the epoch's issue timestamp on first use and return the pinned one.

        The receipt bytes include `issued_at`, so a retry or a restart that passed a
        fresh timestamp would produce a different receipt for the same epoch and
        "recovered byte-identically" would be false. The first value wins and every
        later pass reuses it.
        """
        row = self._connection.execute(
            "SELECT issued_at FROM cybergym_epoch_manifest WHERE epoch=?", (int(epoch),)
        ).fetchone()
        if row is None:
            raise CyberGymScoreError(
                f"epoch {int(epoch)} has no pinned manifest; record_manifest first"
            )
        if row["issued_at"]:
            return str(row["issued_at"])
        try:
            with self._connection:
                self._connection.execute(
                    "UPDATE cybergym_epoch_manifest SET issued_at=? WHERE epoch=?",
                    (str(issued_at), int(epoch)),
                )
        except sqlite3.DatabaseError as exc:
            raise CyberGymScoreError("failed to pin the epoch issue timestamp") from exc
        return str(issued_at)

    def record(
        self, *, epoch: int, miner_hotkey: str, model_commitment: str, task_id: str, poc: bytes
    ) -> None:
        """Persist one accepted solve. Re-submitting the same task replaces it."""
        if not isinstance(poc, (bytes, bytearray)) or not poc:
            raise CyberGymScoreError("a solve must carry non-empty PoC bytes")
        try:
            with self._connection:
                self._connection.execute(
                    "INSERT INTO cybergym_solves"
                    "(epoch, miner_hotkey, task_id, model_commitment, poc) VALUES (?,?,?,?,?)"
                    " ON CONFLICT(epoch, miner_hotkey, task_id) DO UPDATE SET"
                    "  model_commitment=excluded.model_commitment, poc=excluded.poc",
                    (int(epoch), str(miner_hotkey), str(task_id), str(model_commitment),
                     bytes(poc)),
                )
        except sqlite3.DatabaseError as exc:
            raise CyberGymScoreError("failed to record cybergym solve") from exc

    def reserve_submission_attempt(
        self,
        *,
        epoch: int,
        miner_hotkey: str,
        task_id: str,
        max_attempts: int,
    ) -> int | None:
        """Atomically consume one expensive verification attempt.

        Returns its one-based count, or ``None`` if the durable task budget is
        already exhausted. The reservation deliberately happens before the
        untrusted PoC reaches the differential backend; a crashing process can
        spend an attempt, but cannot reset or exceed the bound.
        """
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
            raise CyberGymScoreError("max_attempts must be a positive integer")
        try:
            with self._connection:
                row = self._connection.execute(
                    "SELECT attempts FROM cybergym_submission_attempts "
                    "WHERE epoch=? AND miner_hotkey=? AND task_id=?",
                    (int(epoch), str(miner_hotkey), str(task_id)),
                ).fetchone()
                current = int(row["attempts"]) if row is not None else 0
                if current >= max_attempts:
                    return None
                next_attempt = current + 1
                self._connection.execute(
                    "INSERT INTO cybergym_submission_attempts"
                    "(epoch, miner_hotkey, task_id, attempts) VALUES (?,?,?,?)"
                    " ON CONFLICT(epoch, miner_hotkey, task_id) DO UPDATE SET"
                    " attempts=excluded.attempts",
                    (int(epoch), str(miner_hotkey), str(task_id), next_attempt),
                )
        except sqlite3.DatabaseError as exc:
            raise CyberGymScoreError("failed to reserve cybergym submission attempt") from exc
        return next_attempt

    def submission_attempts(self, *, epoch: int, miner_hotkey: str, task_id: str) -> int:
        """Return the durable attempt count for observability and tests."""
        row = self._connection.execute(
            "SELECT attempts FROM cybergym_submission_attempts "
            "WHERE epoch=? AND miner_hotkey=? AND task_id=?",
            (int(epoch), str(miner_hotkey), str(task_id)),
        ).fetchone()
        return int(row["attempts"]) if row is not None else 0

    def forget_miner(self, *, epoch: int, miner_hotkey: str) -> None:
        """Drop a miner's solves for an epoch (it re-committed a different model)."""
        try:
            with self._connection:
                self._connection.execute(
                    "DELETE FROM cybergym_solves WHERE epoch=? AND miner_hotkey=?",
                    (int(epoch), str(miner_hotkey)),
                )
        except sqlite3.DatabaseError as exc:
            raise CyberGymScoreError("failed to clear cybergym solves") from exc

    def record_unscorable(self, *, epoch: int, miner_hotkey: str, reason: str) -> None:
        """Record that this miner's durable solves for this epoch cannot be scored.

        Deletes nothing: the corpus rows and any surviving solve rows stay exactly
        where they are, so an operator can still inspect what happened. This only
        records that they are not scoreable, which is what keeps one miner's
        abandoned commitment from blocking the whole lane's composition forever.
        """
        from datetime import datetime, timezone

        try:
            with self._connection:
                self._connection.execute(
                    "INSERT INTO cybergym_unscorable"
                    "(epoch, miner_hotkey, reason, marked_at) VALUES (?,?,?,?)"
                    " ON CONFLICT(epoch, miner_hotkey) DO UPDATE SET"
                    "  reason=excluded.reason, marked_at=excluded.marked_at",
                    (int(epoch), str(miner_hotkey), str(reason),
                     datetime.now(timezone.utc).isoformat()),
                )
        except sqlite3.DatabaseError as exc:
            raise CyberGymScoreError("failed to record an unscorable solve set") from exc

    def clear_unscorable(self, *, epoch: int, miner_hotkey: str) -> None:
        """Drop the marker, for a miner that has become scoreable again."""
        try:
            with self._connection:
                self._connection.execute(
                    "DELETE FROM cybergym_unscorable WHERE epoch=? AND miner_hotkey=?",
                    (int(epoch), str(miner_hotkey)),
                )
        except sqlite3.DatabaseError as exc:
            raise CyberGymScoreError("failed to clear an unscorable solve set") from exc

    def unscorable(self, epoch: int) -> dict[str, str]:
        """`{miner_hotkey: reason}` for this epoch."""
        return {
            row["miner_hotkey"]: str(row["reason"])
            for row in self._connection.execute(
                "SELECT miner_hotkey, reason FROM cybergym_unscorable WHERE epoch=?",
                (int(epoch),),
            )
        }

    def commits(self, epoch: int) -> dict[str, tuple[str, dict[str, bytes]]]:
        """`{miner_hotkey: (model_commitment, {task_id: poc})}` for one epoch."""
        out: dict[str, tuple[str, dict[str, bytes]]] = {}
        for row in self._connection.execute(
            "SELECT miner_hotkey, task_id, model_commitment, poc FROM cybergym_solves "
            "WHERE epoch=? ORDER BY miner_hotkey, task_id",
            (int(epoch),),
        ):
            commitment, pocs = out.setdefault(row["miner_hotkey"], (row["model_commitment"], {}))
            pocs[row["task_id"]] = bytes(row["poc"])
        return out

    def size(self) -> int:
        return self._connection.execute("SELECT COUNT(*) FROM cybergym_solves").fetchone()[0]

    def close(self) -> None:
        self._connection.close()


__all__ = ["CyberGymScoreError", "CyberGymScoreStore", "CyberGymSolveStore"]
