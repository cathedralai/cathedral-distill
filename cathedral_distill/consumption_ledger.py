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

Two properties this ledger has to have, and how they are obtained:

  * **Atomic under concurrency.** Every `consume` runs on its own connection
    inside an explicit `BEGIN IMMEDIATE` transaction, so the write lock is taken
    *before* the insert and concurrent consumers of the same token serialise: one
    wins, every other one hits the PRIMARY KEY constraint and fails closed. (One
    shared connection in Python's default deferred-transaction mode does NOT give
    this: `with connection` on a connection shared by N threads interleaves N
    logical transactions into one implicit transaction, so many threads observe
    "success" for a single inserted row. Measured pre-fix: 24 threads off a
    barrier, 5 to 13 successes, one row.) `busy_timeout` makes a lock-contending
    consumer wait instead of erroring out.
  * **Durable.** There is deliberately no default path: an in-memory ledger
    forgets every consumed token on restart, which fails OPEN (a receipt credited
    before the restart is creditable again), and with per-call connections
    `:memory:` is not even shared between calls. No path means refuse.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime

DEFAULT_BUSY_TIMEOUT_MS = 5_000


class ReplayError(RuntimeError):
    """Raised when a token has already been consumed. Fails closed."""


class _NoReplayLedger:
    """The explicit "run without replay protection" marker.

    The admission and composition entries take a *required* ledger argument, so
    running without replay protection has to be typed out rather than obtained by
    forgetting a keyword. `NO_REPLAY_LEDGER` is that opt-out: greppable in a
    production configuration, and impossible to pass by accident.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "NO_REPLAY_LEDGER"


NO_REPLAY_LEDGER = _NoReplayLedger()


class ConsumptionLedger:
    """Durable once-only ledger for replay tokens. Safe for concurrent callers."""

    def __init__(
        self,
        db_path: str | None = None,
        *,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    ) -> None:
        if not isinstance(db_path, str) or not db_path.strip():
            raise ReplayError(
                "ConsumptionLedger requires a durable database path (no default): a "
                "non-durable ledger forgets consumed tokens on restart, which fails OPEN"
            )
        if db_path == ":memory:" or "mode=memory" in db_path:
            raise ReplayError(
                "an in-memory ConsumptionLedger is not durable and is not shared between "
                "connections; pass a file path"
            )
        self._db_path = db_path
        self._busy_timeout_ms = max(0, int(busy_timeout_ms))
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS consumed_tokens ("
                "  token TEXT PRIMARY KEY,"
                "  kind TEXT NOT NULL,"
                "  source_epoch INTEGER,"
                "  consumed_at TEXT NOT NULL)"
            )
            connection.execute("COMMIT")
        except sqlite3.DatabaseError as exc:
            raise ReplayError(f"consumption ledger could not be opened: {exc}") from exc
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        """A fresh connection in autocommit mode, so transactions are explicit.

        One connection per call (rather than one shared connection with
        `check_same_thread=False`) is what makes concurrent consumption correct:
        each caller gets its own transaction instead of sharing one.
        """
        connection = sqlite3.connect(
            self._db_path, isolation_level=None, timeout=self._busy_timeout_ms / 1000
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
        return connection

    def consume(
        self,
        token: str,
        *,
        kind: str = "receipt_id",
        source_epoch: int | None = None,
        at: datetime | None = None,
    ) -> None:
        """Consume `token` exactly once. Raises `ReplayError` if already consumed.

        The insert inside `BEGIN IMMEDIATE` is the atomic once-only gate: a
        duplicate token hits the PRIMARY KEY constraint and is rejected. Any other
        database failure (lock timeout, disk full) also raises `ReplayError`, so a
        ledger that cannot record a consumption never credits the receipt.
        """
        if not isinstance(token, str) or not token:
            raise ReplayError("consumption token must be a non-empty string")
        stamp = (at or datetime.now()).isoformat()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")  # take the write lock first
            try:
                connection.execute(
                    "INSERT INTO consumed_tokens(token, kind, source_epoch, consumed_at) "
                    "VALUES (?,?,?,?)",
                    (token, kind, source_epoch, stamp),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise ReplayError(f"token already consumed: {token}") from exc
            connection.execute("COMMIT")
        except sqlite3.DatabaseError as exc:
            # Fail closed: an unrecordable consumption must not become a credit.
            raise ReplayError(
                f"consumption ledger unavailable, refusing to credit {token}: {exc}"
            ) from exc
        finally:
            connection.close()

    def is_consumed(self, token: str) -> bool:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT 1 FROM consumed_tokens WHERE token=?", (token,)
            ).fetchone()
        finally:
            connection.close()
        return row is not None

    def size(self) -> int:
        connection = self._connect()
        try:
            return connection.execute("SELECT COUNT(*) FROM consumed_tokens").fetchone()[0]
        finally:
            connection.close()

    def close(self) -> None:
        """No-op: connections are per-call and always closed. Kept for callers."""
        return None


__all__ = ["ConsumptionLedger", "ReplayError", "NO_REPLAY_LEDGER"]
