"""Serve the root-signed key registry, so a live receipt's signer can be resolved.

A receipt carries a `signing_key_id`; the registry is what turns that into a public
key. Until validators can fetch one, **no live receipt has a resolvable signer** —
the receipt verifies against nothing, which is the launch gap this closes.

The registry is safe to serve from anywhere, because the trust is in the root
signature and the anchored `root.pub`, not in the transport. What this module adds
over `python -m http.server` is that it refuses to hand out a registry that its own
fetchers would reject:

**Verified before served, on every load.** Serving an unverifiable registry moves
the failure from one diagnosable place (here, at startup, naming the reason) to
every consumer at once, where it surfaces as receipts mysteriously failing to
verify. `trusted_roots` is therefore required, not optional: a relay that cannot
check what it relays cannot tell a rotation from a mistake.

**Staleness is the trap.** `verify_key_registry` enforces
`generated_at + max_age_seconds` (default 24h) *independently* of the registry's own
`valid_until`. A registry signed with a year-long window is still refused by every
default-configured fetcher the next day. So a served registry has to be re-signed on
that cadence, and this module reports the deadline (`fresh_until`) and flips to
`stale` when it passes, rather than serving bytes nobody will accept.

**Rotation without a restart.** The file is re-read when its mtime or size changes,
and the new bytes are verified before they replace the old. A rotation that does not
verify leaves the previous good registry in place and reports the failure.

Bytes are served **verbatim**. `registry_digest` hashes the raw bytes, so
re-serialising the JSON would change the digest even where the signature still
verified, and every published digest would stop matching.
"""

from __future__ import annotations

import os
import threading
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping

from cathedral_distill.receipt_keys import (
    DEFAULT_MAX_AGE_SECONDS,
    MAX_REGISTRY_BYTES,
    ReceiptKeyError,
    registry_digest,
    verify_key_registry,
)

# Serving states, in the order an operator cares about.
SERVED = "served"            # verified, fresh, safe to hand out
STALE = "stale"              # verified, but past generated_at + max_age: re-sign it
UNVERIFIED = "unverified"    # present and does not verify, or absent/unreadable


class ServedRegistryError(RuntimeError):
    """The configured key registry cannot be served. Fails closed."""


class ServedKeyRegistry:
    """A verified, mtime-watched view of one signed key-registry file."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        trusted_roots: Mapping[str, bytes],
        *,
        max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
        clock: Any = None,
    ) -> None:
        if not trusted_roots:
            raise ServedRegistryError(
                "serving a key registry requires the trusted root(s) that anchor it: "
                "an unverified relay cannot tell a rotation from a mistake, and every "
                "fetcher would reject the file anyway"
            )
        self._path = os.fspath(path)
        self._roots = dict(trusted_roots)
        self._max_age = int(max_age_seconds)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._body: bytes | None = None
        self._digest: str | None = None
        self._generated_at: datetime | None = None
        self._stamp: tuple[int, int] | None = None
        self._detail: str = "not loaded"

    # -- loading ----------------------------------------------------------- #
    def _read(self) -> tuple[bytes, tuple[int, int]]:
        try:
            stat = os.stat(self._path)
        except OSError as exc:
            raise ServedRegistryError(
                f"key registry {self._path!r} cannot be read: {exc}"
            ) from exc
        if stat.st_size > MAX_REGISTRY_BYTES:
            raise ServedRegistryError(
                f"key registry {self._path!r} is {stat.st_size} bytes, over the "
                f"{MAX_REGISTRY_BYTES}-byte limit every verifier enforces"
            )
        try:
            with open(self._path, "rb") as handle:
                body = handle.read()
        except OSError as exc:
            raise ServedRegistryError(
                f"key registry {self._path!r} cannot be read: {exc}"
            ) from exc
        return body, (stat.st_mtime_ns, stat.st_size)

    def _load_locked(self) -> None:
        """Re-read and verify if the file changed. Keeps the last good copy on failure."""
        try:
            body, stamp = self._read()
        except ServedRegistryError as exc:
            self._detail = str(exc)
            if self._body is None:
                raise
            return
        if stamp == self._stamp and self._body is not None:
            return
        try:
            # Verify with a staleness bound that cannot fail here, so a stale
            # registry is reported as `stale` rather than indistinguishable from a
            # forged one. Freshness is judged separately, from generated_at.
            verify_key_registry(body, self._roots, now=self._clock(),
                                max_age_seconds=10 ** 12)
        except ReceiptKeyError as exc:
            self._detail = (
                f"key registry {self._path!r} does not verify against the anchored "
                f"root(s): {exc}"
            )
            if self._body is None:
                raise ServedRegistryError(self._detail) from exc
            return  # keep serving the previous good copy
        document_generated = _generated_at(body)
        self._body, self._stamp = body, stamp
        self._digest = registry_digest(body)
        self._generated_at = document_generated
        self._detail = "verified against the anchored root"

    def refresh(self) -> None:
        with self._lock:
            self._load_locked()

    # -- serving ----------------------------------------------------------- #
    def fresh_until(self) -> datetime | None:
        if self._generated_at is None:
            return None
        return self._generated_at + timedelta(seconds=self._max_age)

    def _state_locked(self) -> str:
        if self._body is None:
            return UNVERIFIED
        deadline = self.fresh_until()
        if deadline is not None and self._clock() >= deadline:
            return STALE
        return SERVED

    def state(self) -> str:
        """The current serving state, loading first if nothing is loaded yet.

        Lazily loads rather than reporting `unverified` for a perfectly good file
        nobody has asked for yet: `state()` is the natural first call, and it must
        not answer differently depending on whether `body()` happened to run before
        it. Never raises — a load failure IS the state.
        """
        with self._lock:
            try:
                self._load_locked()
            except ServedRegistryError:
                pass
            return self._state_locked()

    def body(self) -> bytes:
        """The exact bytes to serve, or a refusal saying why there are none.

        A `stale` registry is refused rather than served: every default-configured
        fetcher applies the same `generated_at + max_age` bound, so handing it over
        only relocates the failure. The refusal names the deadline it passed.
        """
        with self._lock:
            self._load_locked()
            state = self._state_locked()
            if state == SERVED and self._body is not None:
                return self._body
            if state == STALE:
                raise ServedRegistryError(
                    f"key registry {self._digest} was generated at "
                    f"{_iso(self._generated_at)} and is stale as of "
                    f"{_iso(self.fresh_until())} (max_age_seconds={self._max_age}); "
                    "every default-configured verifier now refuses it. Re-sign and "
                    "re-serve it: `valid_until` being far off does not extend this"
                )
            raise ServedRegistryError(self._detail)

    def status(self) -> dict[str, Any]:
        """A JSON-ready summary for a status surface. Never raises."""
        with self._lock:
            try:
                self._load_locked()
            except ServedRegistryError:
                pass
            state = self._state_locked()
            return {
                "state": state,
                "available": state == SERVED,
                "digest": self._digest,
                "generated_at": _iso(self._generated_at),
                "fresh_until": _iso(self.fresh_until()),
                "max_age_seconds": self._max_age,
                "detail": self._detail,
            }

    def etag(self) -> str | None:
        return f'"{self._digest}"' if self._digest else None


def _generated_at(body: bytes) -> datetime | None:
    """`generated_at` from already-verified bytes; the verifier proved it parses."""
    import json

    try:
        raw = json.loads(body.decode("utf-8"))["generated_at"]
        return datetime.strptime(str(raw), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except Exception:  # noqa: BLE001 - a summary field, never the gate
        return None


def _iso(moment: datetime | None) -> str | None:
    return None if moment is None else moment.strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "SERVED",
    "STALE",
    "UNVERIFIED",
    "ServedRegistryError",
    "ServedKeyRegistry",
]
