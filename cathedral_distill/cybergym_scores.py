"""Durable per-(miner, epoch) CyberGym scores — the writer for the mechanism feed.

The CyberGym mechanism adapter in `cathedralai/cathedral`
(`scaffold/publisher/mechanism_cybergym_adapter.py`) reads verified per-miner
scores from a `cybergym_scores` table and maps them to uids. Nothing wrote that
table; this is the writer. It records the level-weighted work units from a
verified `cathedral_cybergym_receipt_v1`, keyed by (miner_hotkey, epoch), so the
adapter's `SELECT miner_hotkey, score FROM cybergym_scores WHERE epoch=?` returns
exactly the verified frontier this validator scored.

The `score` column is the level-weighted **earned units** (the adapter's
"level-weighted sum of verified PoC solves"), stored as REAL to match the
adapter's schema; earned units are small exact-in-float64 sums of the pinned
weights. A `receipt_id` column is carried for audit — the adapter ignores extra
columns. Writes are transactional and idempotent for the same receipt; a
different score for the same (miner, epoch) is refused rather than silently
overwritten, so a re-score cannot quietly change a published frontier.
"""
from __future__ import annotations

import sqlite3
from decimal import Decimal
from typing import Mapping

from cathedral_distill.cybergym_receipt import validate_structure


class CyberGymScoreError(RuntimeError):
    """Raised when a score cannot be recorded durably."""


class CyberGymScoreStore:
    """SQLite-backed writer for the `cybergym_scores` mechanism table."""

    def __init__(self, db_path: str) -> None:
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
        self._connection.commit()

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
                if existing is not None:
                    if existing["receipt_id"] == receipt_id:
                        return  # idempotent: same receipt already recorded
                    if Decimal(existing["earned_units"]) != earned:
                        raise CyberGymScoreError(
                            f"conflicting cybergym score for {miner} epoch {epoch}: "
                            "refusing to overwrite a published frontier"
                        )
                    # Same units, different receipt id (e.g. re-issued): keep first.
                    return
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
