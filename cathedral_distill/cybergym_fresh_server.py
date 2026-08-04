"""Run the fresh sealed CyberGym verifier in loopback-only E2E mode.

This entrypoint exists to exercise the *fresh* task path without changing the
legacy real-corpus reference server.  It deliberately refuses public binds and
requires an explicit development opt-in because it does not configure the
production TDX identity adapter or emission gate policy.  It is therefore a
safe staging target for miner → verifier → durable-score testing, never a
reward-bearing deployment.

Required environment:

``CYBERGYM_E2E_ALLOW_UNATTESTED=1``
    Explicit acknowledgement that this loopback E2E process is not a live reward
    verifier.
``CYBERGYM_FRESH_SEED``
    At least 32 random bytes as hex.  The seed stays validator-side; its digest is
    pinned in the durable epoch manifest.
``CYBERGYM_SIGNING_SEED``
    32-byte Ed25519 seed as 64 hex characters.
``CYBERGYM_CORPUS_DB``, ``CYBERGYM_SCORE_DB``, ``CYBERGYM_SOLVE_DB``
    Persistent SQLite paths for the E2E lifecycle.
``CYBERGYM_E2E_AS_OF``
    A timezone-aware, stable ISO-8601 epoch timestamp.  It is pinned in the
    durable manifest, so it must be reused for a restart and for the separate
    close command.

The process binds only ``127.0.0.1`` / ``::1`` and is meant to be reached over
an SSH tunnel.  A production replacement must supply a real transport identity
adapter, Intel-TDX policy, and emission gates before it can bind elsewhere.
"""
from __future__ import annotations

import os
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill.cybergym_fresh import FreshTaskError, fresh_holdout
from cathedral_distill.cybergym_http import make_threaded_server
from cathedral_distill.cybergym_protocol import CyberGymCorpusStore
from cathedral_distill.cybergym_scores import CyberGymScoreStore, CyberGymSolveStore
from cathedral_distill.cybergym_service import CYBERGYM_LANE, CyberGymService
from cathedral_distill.cybergym_validator import ChainContext

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def _hex_seed(name: str, *, minimum_bytes: int = 32, exact_bytes: int | None = None) -> bytes:
    text = _required(name)
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        raise SystemExit(f"{name} must be hexadecimal") from None
    if exact_bytes is not None and len(raw) != exact_bytes:
        raise SystemExit(f"{name} must contain exactly {exact_bytes} bytes")
    if len(raw) < minimum_bytes:
        raise SystemExit(f"{name} must contain at least {minimum_bytes} bytes")
    return raw


def _e2e_enabled() -> None:
    if os.environ.get("CYBERGYM_E2E_ALLOW_UNATTESTED", "") != "1":
        raise SystemExit(
            "CYBERGYM_E2E_ALLOW_UNATTESTED=1 is required: this loopback server "
            "does not configure production TDX and emission gates"
        )


def _as_of_from_environment() -> datetime:
    """Read a restart-stable E2E draw timestamp from the protected environment."""
    raw = _required("CYBERGYM_E2E_AS_OF")
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise SystemExit(
            "CYBERGYM_E2E_AS_OF must be a timezone-aware ISO-8601 timestamp"
        ) from None
    if value.tzinfo is None:
        raise SystemExit("CYBERGYM_E2E_AS_OF must include a timezone")
    return value.astimezone(UTC)


def build_service(
    *,
    fresh_seed: bytes,
    private_key: Ed25519PrivateKey,
    corpus_db: str,
    score_db: str,
    solve_db: str,
    validator_hotkey: str,
    as_of: datetime,
) -> CyberGymService:
    """Construct the durable fresh E2E verifier; importable for integration tests."""
    holdout, backend = fresh_holdout(fresh_seed)
    chain = ChainContext(
        block=100,
        block_hash="0x" + "cd" * 32,
        network="finney",
        netuid=39,
        source_epoch=21,
        valid_from_block=100,
        valid_until_block=460,
    )
    return CyberGymService(
        holdout,
        chain,
        backend=backend,
        corpus_store=CyberGymCorpusStore(corpus_db),
        score_store=CyberGymScoreStore(score_db),
        solve_store=CyberGymSolveStore(solve_db),
        validator_hotkey=validator_hotkey,
        private_key=private_key,
        signing_key_id="cybergym-fresh-e2e-1",
        batch_size=1,
        cutoff=None,
        as_of=as_of,
        # The explicit environment acknowledgement in ``main`` confines this to
        # loopback E2E.  Production keeps these defaults and must pass both real
        # policies, so this helper cannot accidentally be wired as an authority.
        attestation_required=False,
        gates_required=False,
    )


def build_service_from_environment() -> CyberGymService:
    """Build the fresh E2E service from its protected, restart-stable config.

    The loopback server and the one-shot epoch closer call this same function so
    they cannot accidentally reconstruct the durable epoch with different inputs.
    """
    _e2e_enabled()
    try:
        fresh_seed = _hex_seed("CYBERGYM_FRESH_SEED")
    except FreshTaskError as exc:  # defensive: constructor also validates later
        raise SystemExit(f"CYBERGYM_FRESH_SEED is invalid: {exc}") from None
    signing_seed = _hex_seed("CYBERGYM_SIGNING_SEED", exact_bytes=32)
    return build_service(
        fresh_seed=fresh_seed,
        private_key=Ed25519PrivateKey.from_private_bytes(signing_seed),
        corpus_db=_required("CYBERGYM_CORPUS_DB"),
        score_db=_required("CYBERGYM_SCORE_DB"),
        solve_db=_required("CYBERGYM_SOLVE_DB"),
        validator_hotkey=os.environ.get("CYBERGYM_VALIDATOR_HOTKEY", "cathedral-fresh-e2e"),
        as_of=_as_of_from_environment(),
    )


def main() -> None:
    host = os.environ.get("CYBERGYM_HOST", "127.0.0.1").strip()
    if host not in _LOOPBACK_HOSTS:
        raise SystemExit("fresh E2E verifier may bind only a loopback host")
    service = build_service_from_environment()
    port = int(os.environ.get("PORT", "8667"))
    server = make_threaded_server(
        service,
        host=host,
        port=port,
        healthz={
            "status": "ok",
            "task_source": "fresh-sealed",
            "lane": CYBERGYM_LANE,
        },
    )
    print(
        f"CyberGym fresh E2E verifier serving loopback tasks on {host}:{port} "
        "(unattested development mode)",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
