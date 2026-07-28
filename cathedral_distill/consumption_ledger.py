"""Atomic once-only consumption of replay tokens (nonces / eval-ids / receipt ids).

Replay protection by epoch/window/freshness stops a receipt from being *valid*
outside its epoch, but nothing stops a still-valid receipt from being submitted
twice within its window and credited twice. This ledger closes that: a token is
consumed exactly once, atomically, and a second consume fails closed.

`receipt_id` is the natural universal token — it is derived from the canonical
receipt body, which includes the chain-anchored nonce and the epoch, so a
different nonce or epoch yields a different `receipt_id`. Consuming `receipt_id`
once therefore consumes the nonce once, across every receipt family.

The store is a tiny SQLite table with the token as PRIMARY KEY, so the once-only
guarantee is the database's atomic uniqueness constraint, not application logic.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime


class ReplayError(RuntimeError):
    """Raised when a token has already been consumed. Fails closed."""


class ConsumptionLedger:
    """Durable once-only ledger for replay tokens."""

    def __init__(self, db_path: str = ":memory:") -> None:
        # check_same_thread=False so a server thread can consume; the caller
        # serialises access (a validator credits one receipt at a time).
        self._connection = sqlite3.connect(db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS consumed_tokens ("
            "  token TEXT PRIMARY KEY,"
            "  kind TEXT NOT NULL,"
            "  source_epoch INTEGER,"
            "  consumed_at TEXT NOT NULL)"
        )
        self._connection.commit()

    def consume(
        self,
        token: str,
        *,
        kind: str = "receipt_id",
        source_epoch: int | None = None,
        at: datetime | None = None,
    ) -> None:
        """Consume `token` exactly once. Raises `ReplayError` if already consumed.

        The insert is the atomic once-only gate: a duplicate token hits the
        PRIMARY KEY constraint and is rejected in the same transaction.
        """
        if not isinstance(token, str) or not token:
            raise ReplayError("consumption token must be a non-empty string")
        stamp = (at or datetime.now()).isoformat()
        try:
            with self._connection:  # one transaction; rolls back on any raise
                self._connection.execute(
                    "INSERT INTO consumed_tokens(token, kind, source_epoch, consumed_at) "
                    "VALUES (?,?,?,?)",
                    (token, kind, source_epoch, stamp),
                )
        except sqlite3.IntegrityError as exc:
            raise ReplayError(f"token already consumed: {token}") from exc

    def is_consumed(self, token: str) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM consumed_tokens WHERE token=?", (token,)
        ).fetchone()
        return row is not None

    def size(self) -> int:
        return self._connection.execute("SELECT COUNT(*) FROM consumed_tokens").fetchone()[0]

    def close(self) -> None:
        self._connection.close()


__all__ = ["ConsumptionLedger", "ReplayError"]
