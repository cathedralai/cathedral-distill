"""Live, public status for one running CyberGym validator.

A dashboard needs a read surface, and it must be a *different* surface from the
lane's wire protocol: the dispatch/artifact/submit routes are authenticated,
stateful and mutating, while this is an anonymous read that a static page polls.
So it is one GET, one curated payload, and nothing here writes.

**Curated on purpose.** `CyberGymService.epoch_manifest()` is the full record of
everything that decides what an epoch draws and signs, which is exactly why most
of it must not be published while the epoch is open: `batch_size`, `cutoff`,
`as_of`, the level weights and the gate policy tell a miner how to time and shape
a submission for maximum credit. What is published instead is the manifest's
`digest`, so anyone holding the manifest can check this validator is running the
one they think it is, without the endpoint handing out the draw parameters.

What IS published is either already on chain, already in a signed receipt, or
needed to verify one:

* the epoch, its state, and the authorized block window a receipt is bound to;
* the validator hotkey, `signing_key_id` and public-key digest, because a receipt
  whose signer cannot be resolved cannot be verified by anyone;
* participation counts and the scored leaderboard, which become on-chain weights;
* the aggregated training-corpus size — the subnet's actual product, per README's
  "the data is the product" — since `CyberGymCorpusStore` only accepts rows that
  already passed verification, trainability, and licensing.

Every section fails soft. A dashboard that goes blank because one SQLite read was
locked mid-verify is worse than one reporting a stale section, so a section that
cannot be read reports `{"available": false, "detail": ...}` and the rest of the
payload still serves.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable

from cathedral_distill.cybergym_receipt import RECEIPT_SCHEMA
from cathedral_distill.cybergym_scores import CyberGymSolveStore
from cathedral_distill.cybergym_service import CYBERGYM_LANE

SCHEMA = "cathedral.distill.status.v1"

# The manifest keys this endpoint is allowed to publish. Anything not listed is
# withheld, so a field added to the manifest later is private until someone
# decides otherwise rather than being disclosed by default.
_PUBLIC_MANIFEST_KEYS = (
    "source_epoch",
    "network",
    "netuid",
    "valid_from_block",
    "valid_until_block",
    "validator_hotkey",
    "signing_key_id",
    "signing_public_key_digest",
)

DEFAULT_LEADERBOARD_LIMIT = 25


def _now_iso(now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _unavailable(exc: Exception) -> dict[str, Any]:
    return {"available": False, "detail": f"{type(exc).__name__}: {exc}"}


def _epoch_block(service: Any) -> dict[str, Any]:
    """The epoch's public identity, plus the digest of its full manifest."""
    try:
        manifest = service.epoch_manifest()
    except Exception as exc:  # noqa: BLE001 - a status read never raises
        return _unavailable(exc)
    block = {key: manifest.get(key) for key in _PUBLIC_MANIFEST_KEYS}
    block["available"] = True
    block["manifest_schema"] = manifest.get("schema")
    try:
        _, digest = CyberGymSolveStore.canonical_manifest(manifest)
    except Exception:  # noqa: BLE001 - the digest is a nicety, not the payload
        digest = None
    block["manifest_digest"] = digest
    return block


def _state_block(scores: Any, epoch: int) -> dict[str, Any]:
    try:
        state, detail = scores.epoch_state(epoch)
    except Exception as exc:  # noqa: BLE001
        return _unavailable(exc)
    return {"available": True, "state": state, "detail": detail}


def _leaderboard(scores: Any, epoch: int, limit: int) -> dict[str, Any]:
    """Scored earned units for the epoch, highest first then hotkey.

    Empty is a normal answer, not an error: an epoch with no completed scoring
    pass has no scores yet, which is what `epoch.state == "open"` says. Reporting
    it as unavailable would make a healthy open epoch look broken.
    """
    try:
        raw = scores.epoch_scores(epoch)
    except Exception as exc:  # noqa: BLE001
        return _unavailable(exc)
    rows = sorted(
        ((str(hotkey), Decimal(str(units))) for hotkey, units in raw.items()),
        key=lambda row: (-row[1], row[0]),
    )
    total = sum((units for _hotkey, units in rows), Decimal(0))
    return {
        "available": True,
        "scored_miners": len(rows),
        "total_earned_units": str(total),
        "truncated": len(rows) > limit,
        "top": [
            {"rank": index, "miner_hotkey": hotkey, "earned_units": str(units)}
            for index, (hotkey, units) in enumerate(rows[:limit], start=1)
        ],
    }


def _corpus_block(corpus: Any, epoch: int) -> dict[str, Any]:
    """The aggregated training corpus this validator has produced.

    `CyberGymCorpusStore.record` only accepts verified, trainable, licensed rows
    (see its docstring), so `size()` is not a proxy for the corpus — it IS the
    corpus: the README's "the data is the product" claim, made checkable. Reported
    across all epochs (the product accumulates) and for this epoch (the rate).
    """
    try:
        total = corpus.size()
        this_epoch = len(corpus.rows(source_epoch=epoch))
    except Exception as exc:  # noqa: BLE001 - a status read never raises
        return _unavailable(exc)
    return {"available": True, "total_rows": total, "this_epoch_rows": this_epoch}


def _participation(service: Any, scores: Any, solves: Any, epoch: int) -> dict[str, Any]:
    """Who is in this epoch and what stage they are at.

    This is the section that moves while an epoch is open, and the only one a
    dashboard can show before a scoring pass has run.
    """
    block: dict[str, Any] = {"available": True}
    for name, read in (
        ("scored", lambda: len(scores.epoch_scores(epoch))),
        ("pending", lambda: len(service.pending_solvers())),
        ("committed", lambda: len(solves.commits(epoch)) if solves is not None else None),
        ("unscorable", lambda: len(solves.unscorable(epoch)) if solves is not None else None),
        ("durable_solves", lambda: solves.size() if solves is not None else None),
    ):
        try:
            block[name] = read()
        except Exception as exc:  # noqa: BLE001 - one unreadable counter is not fatal
            block[name] = None
            block.setdefault("errors", {})[name] = f"{type(exc).__name__}: {exc}"
    return block


def build_status(
    service: Any,
    *,
    leaderboard_limit: int = DEFAULT_LEADERBOARD_LIMIT,
    key_registry: Any = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """One JSON-ready snapshot of what this validator can currently attest to.

    Read-only and side-effect free: it calls no handler that mutates a store, and
    it never raises. A caller can serve the result straight to an anonymous
    client.

    `key_registry` is the `ServedKeyRegistry` behind `GET /v1/keys`, if this host
    serves one. Reporting it here closes the loop: `epoch.signing_key_id` says which
    key signed, and `key_registry` says whether the registry that resolves it is
    verified and still fresh. Those two disagreeing is the difference between
    receipts that verify and receipts that do not.
    """
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": _now_iso(now),
        "lane": {"lane_id": CYBERGYM_LANE, "receipt_schema": RECEIPT_SCHEMA},
    }
    if key_registry is not None:
        try:
            payload["key_registry"] = key_registry.status()
        except Exception as exc:  # noqa: BLE001 - a status read never raises
            payload["key_registry"] = _unavailable(exc)
    epoch_block = _epoch_block(service)
    payload["epoch"] = epoch_block

    scores = getattr(service, "_scores", None)
    solves = getattr(service, "_solves", None)
    corpus = getattr(service, "_corpus", None)
    epoch = epoch_block.get("source_epoch")
    if epoch is None or scores is None:
        detail = (
            "the epoch manifest could not be read"
            if epoch is None
            else "this service has no score store"
        )
        for key in ("state", "participation", "leaderboard", "corpus"):
            payload[key] = {"available": False, "detail": detail}
        return payload

    payload["state"] = _state_block(scores, epoch)
    payload["participation"] = _participation(service, scores, solves, epoch)
    payload["leaderboard"] = _leaderboard(scores, epoch, leaderboard_limit)
    payload["corpus"] = (
        _corpus_block(corpus, epoch) if corpus is not None
        else {"available": False, "detail": "this service has no corpus store"}
    )
    return payload


class StatusCache:
    """A TTL cache in front of a status builder.

    Two reasons this is not just `build_status` per request.

    The reads touch the same SQLite connections the submit path writes, and those
    connections are shared across threads (`check_same_thread=False`) on the
    understanding that the service serialises access. So on a threaded server the
    builder has to take the service lock, which means an uncached status read can
    queue behind a slow verify. One build shared for `ttl_secs` bounds that to once
    per window however many viewers are polling.

    It also keeps an anonymous, unauthenticated route from being an amplifier: the
    work a caller can provoke is capped by the TTL, not by their request rate.

    The builder is injected rather than a service being passed in, so the caller
    decides whether the build needs a lock — see `cybergym_http.make_threaded_server`.

    A build that raises is not cached: the next request retries rather than serving
    the failure for the rest of the window.
    """

    def __init__(
        self,
        builder: Callable[[], dict[str, Any]],
        *,
        ttl_secs: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._builder = builder
        self._ttl = max(0.0, float(ttl_secs))
        self._clock = clock
        self._lock = threading.Lock()
        self._payload: dict[str, Any] | None = None
        self._built_at: float | None = None

    @classmethod
    def for_service(
        cls,
        service: Any,
        *,
        ttl_secs: float = 5.0,
        leaderboard_limit: int = DEFAULT_LEADERBOARD_LIMIT,
        key_registry: Any = None,
        lock: Any = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> "StatusCache":
        """Cache over one service, optionally serialised behind `lock`."""

        def build() -> dict[str, Any]:
            if lock is None:
                return build_status(
                    service,
                    leaderboard_limit=leaderboard_limit,
                    key_registry=key_registry,
                )
            with lock:
                return build_status(
                    service,
                    leaderboard_limit=leaderboard_limit,
                    key_registry=key_registry,
                )

        return cls(build, ttl_secs=ttl_secs, clock=clock)

    def get(self) -> dict[str, Any]:
        with self._lock:
            now = self._clock()
            fresh = (
                self._payload is not None
                and self._built_at is not None
                and (now - self._built_at) < self._ttl
            )
            if not fresh:
                payload = self._builder()
                payload["cache"] = {"ttl_secs": self._ttl}
                self._payload = payload
                self._built_at = now
            served = dict(self._payload or {})
            age = 0.0 if self._built_at is None else max(0.0, now - self._built_at)
        served["cache"] = {**served.get("cache", {}), "age_secs": round(age, 3)}
        return served


__all__ = ["SCHEMA", "DEFAULT_LEADERBOARD_LIMIT", "build_status", "StatusCache"]
