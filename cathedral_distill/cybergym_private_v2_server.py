"""Serve an authenticated, loopback-only private-v2 CyberGym E2E verifier.

This deployment entrypoint is intentionally narrower than a production axon. It
uses one configured miner identity plus a bearer secret so an operator can run
the complete private-artifact path through an SSH tunnel before wiring the
network's real hotkey-authentication transport. It refuses a public bind,
requires durable corpus/solve/score stores, and requires an explicit opt-in to
the unattested and gate-free E2E configuration.

It is suitable for a live infrastructure E2E, never for a reward authority.
Production must supply a transport identity adapter, Intel-TDX policy, and the
normal emission gate policy instead of this entrypoint.
"""

from __future__ import annotations

import hmac
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill.corpus_admission import require_admitted_private_manifest
from cathedral_distill.cybergym_attest import CathedralReceiptPolicy
from cathedral_distill.cybergym_holdout import Holdout
from cathedral_distill.cybergym_http import make_threaded_server
from cathedral_distill.cybergym_private_artifacts import (
    PrivateChallengeArtifactStore,
    PrivateReferencePoCStore,
)
from cathedral_distill.cybergym_protocol import CyberGymCorpusStore
from cathedral_distill.cybergym_repro import ReproTaskSource, available_tasks
from cathedral_distill.cybergym_repro_manifest import (
    PrivateReproManifest,
    ReproManifestError,
    load_private_repro_manifest_file,
)
from cathedral_distill.cybergym_scores import CyberGymScoreStore, CyberGymSolveStore
from cathedral_distill.cybergym_service import CYBERGYM_LANE, CyberGymService
from cathedral_distill.cybergym_validator import ChainContext

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_E2E_OPT_IN_ENV = "CYBERGYM_E2E_ALLOW_UNATTESTED"
_MINER_ENV = "CYBERGYM_E2E_MINER_HOTKEY"
_TOKEN_FILE_ENV = "CYBERGYM_E2E_BEARER_TOKEN_FILE"
# Set to the approved solver's `workload_sha256` to ENFORCE the Cathedral-receipt
# path (a real Intel-TDX receipt bound to that workload is required to credit).
# Unset (default) keeps the loopback dev/test posture that credits unattested solves.
_APPROVED_WORKLOAD_ENV = "CYBERGYM_APPROVED_WORKLOAD_SHA256"
_BATCH_SIZE_ENV = "CYBERGYM_BATCH_SIZE"


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def _receipt_policy_from_environment() -> CathedralReceiptPolicy | None:
    """Build the receipt-enforcement policy from the approved-workload env, or None.

    OFF by default: with `CYBERGYM_APPROVED_WORKLOAD_SHA256` unset the verifier keeps
    its current unattested loopback posture. When set, the value is the approved
    solver's `workload_sha256` a live Cathedral `attest.v1` receipt must pin — so a
    workload that merely echoes a looked-up answer can never credit. Fails closed on a
    malformed digest rather than silently running unenforced.
    """
    raw = os.environ.get(_APPROVED_WORKLOAD_ENV, "").strip().lower()
    if not raw:
        return None
    if len(raw) != 64 or any(c not in "0123456789abcdef" for c in raw):
        raise SystemExit(
            f"{_APPROVED_WORKLOAD_ENV} must be a 64-hex sha256 (the approved solver's "
            f"workload_sha256); got {raw!r}"
        )
    return CathedralReceiptPolicy(expected_workload_sha256=raw)


def _batch_size_from_environment() -> int:
    """How many tasks the common frontier draws per miner per epoch (default 1).

    A launch corpus serves several problems an epoch; the loopback E2E default of
    one keeps existing single-task rigs unchanged. `draw` requires the manifest to
    hold at least this many eligible tasks, so an over-large value fails closed at
    dispatch rather than silently serving fewer. Rejects a non-positive or
    non-integer value rather than defaulting past a typo.
    """
    raw = os.environ.get(_BATCH_SIZE_ENV, "").strip()
    if not raw:
        return 1
    try:
        value = int(raw)
    except ValueError:
        raise SystemExit(
            f"{_BATCH_SIZE_ENV} must be a positive integer; got {raw!r}"
        ) from None
    if value < 1:
        raise SystemExit(f"{_BATCH_SIZE_ENV} must be >= 1; got {value}")
    return value


def _private_manifest_from_environment() -> PrivateReproManifest:
    try:
        manifest = load_private_repro_manifest_file(
            _required("CYBERGYM_CORPUS_MANIFEST")
        )
    except ReproManifestError as exc:
        raise SystemExit(f"CYBERGYM_CORPUS_MANIFEST is invalid: {exc}") from None
    if not manifest.reward_ready:
        raise SystemExit(
            "private-v2 E2E verifier requires a v2 manifest with digest-pinned "
            "miner artifacts and validator-held reference PoCs"
        )
    return manifest


def _signing_key_from_environment() -> Ed25519PrivateKey:
    text = _required("CYBERGYM_SIGNING_SEED")
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        raise SystemExit(
            "CYBERGYM_SIGNING_SEED must be 64 hexadecimal characters"
        ) from None
    if len(raw) != 32:
        raise SystemExit("CYBERGYM_SIGNING_SEED must contain exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _private_file(name: str) -> bytes:
    path = Path(_required(name))
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise SystemExit(f"{name} must not be group- or world-readable")
        value = path.read_bytes().strip()
    except OSError as exc:
        raise SystemExit(f"{name} cannot be read: {exc}") from None
    if not value:
        raise SystemExit(f"{name} is empty")
    return value


def authenticated_miner_from_environment() -> Callable[
    [Mapping[str, str], bytes], str | None
]:
    """Return the loopback E2E identity adapter.

    The bearer secret is intentionally deployment-local and the returned hotkey is
    configured, rather than trusted from a request body. ``CyberGymService`` then
    binds every dispatch, artifact read, and submit to that exact sealed batch.
    """
    miner = _required(_MINER_ENV)
    token = _private_file(_TOKEN_FILE_ENV).decode("utf-8")
    expected = f"Bearer {token}"

    def authenticate(headers: Mapping[str, str], _body: bytes) -> str | None:
        actual = headers.get("Authorization", "")
        return miner if hmac.compare_digest(actual, expected) else None

    return authenticate


def _as_of_from_environment() -> datetime:
    """Read a restart-stable E2E draw timestamp from the protected environment.

    The server and the separate ``...-close`` command each build their own
    service, so ``as_of`` must not come from the wall clock: it is pinned into the
    durable epoch manifest on the first run, and a second process computing a fresh
    ``datetime.now()`` would fail the manifest-resume check on ``as_of`` alone and
    make the exported report impossible to reproduce byte-for-byte. This mirrors
    ``cybergym_fresh_server._as_of_from_environment`` so both E2E entrypoints are
    restartable and closable across processes.
    """
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
    manifest: PrivateReproManifest,
    *,
    private_key: Ed25519PrivateKey,
    challenge_artifacts: PrivateChallengeArtifactStore,
    reference_pocs: PrivateReferencePoCStore,
    corpus_db: str,
    score_db: str,
    solve_db: str,
    validator_hotkey: str,
    as_of: datetime,
    cathedral_receipt_policy: CathedralReceiptPolicy | None = None,
    batch_size: int = 1,
) -> CyberGymService:
    """Build the durable private-v2 verifier used by the server and close command.

    When ``cathedral_receipt_policy`` is set the receipt path is ENFORCED (posture
    reads ``enforced=True``; only a real Cathedral TDX receipt bound to the approved
    workload credits). None keeps the loopback dev/test posture.
    """
    if not manifest.reward_ready:
        raise ReproManifestError("private-v2 verifier requires a reward-ready manifest")
    chain = ChainContext(
        block=100,
        block_hash="0x" + "cd" * 32,
        network="finney",
        netuid=39,
        source_epoch=21,
        valid_from_block=100,
        valid_until_block=460,
    )
    if manifest.source_epoch != chain.source_epoch:
        raise ReproManifestError(
            f"manifest source_epoch {manifest.source_epoch} does not match "
            f"the E2E chain epoch {chain.source_epoch}"
        )
    source = ReproTaskSource(
        manifest,
        challenge_artifacts=challenge_artifacts,
        reference_pocs=reference_pocs,
    )
    return CyberGymService(
        Holdout(pool=source, _context={}),
        chain,
        backend=source.backend,
        corpus_store=CyberGymCorpusStore(corpus_db),
        score_store=CyberGymScoreStore(score_db),
        solve_store=CyberGymSolveStore(solve_db),
        validator_hotkey=validator_hotkey,
        private_key=private_key,
        signing_key_id="cybergym-private-v2-e2e-1",
        batch_size=batch_size,
        cutoff=None,
        as_of=as_of,
        # `attestation_required=False` because this path has no full TDX
        # AttestationPolicy; enforcement, when on, comes from the receipt policy (a
        # CathedralReceiptPolicy makes the posture `enforced=True` and requires a real
        # receipt in process_submission). The env opt-in confines the *unenforced*
        # posture (both None) to the loopback E2E deployment.
        attestation_required=False,
        cathedral_receipt_policy=cathedral_receipt_policy,
        gates_required=False,
    )


def build_service_from_environment() -> CyberGymService:
    """Load an admitted private-v2 verifier from protected deployment inputs."""
    if os.environ.get(_E2E_OPT_IN_ENV) != "1":
        raise SystemExit(
            f"{_E2E_OPT_IN_ENV}=1 is required: this verifier has no TDX or "
            "emission-gate policy"
        )
    manifest = _private_manifest_from_environment()
    artifacts = PrivateChallengeArtifactStore.from_directory(
        manifest, _required("CYBERGYM_CHALLENGE_ARTIFACT_DIR")
    )
    references = PrivateReferencePoCStore.from_directory(
        manifest, _required("CYBERGYM_REFERENCE_POC_DIR")
    )
    available = available_tasks(manifest)
    if set(available) != {task.task_id for task in manifest.tasks}:
        raise SystemExit(
            "every digest-pinned manifest image must be available locally before "
            "the private-v2 verifier serves a task"
        )
    try:
        require_admitted_private_manifest(manifest, reference_pocs=references)
    except ReproManifestError as exc:
        raise SystemExit(f"CYBERGYM_CORPUS_MANIFEST is not scoreable: {exc}") from None
    return build_service(
        manifest,
        private_key=_signing_key_from_environment(),
        challenge_artifacts=artifacts,
        reference_pocs=references,
        corpus_db=_required("CYBERGYM_CORPUS_DB"),
        score_db=_required("CYBERGYM_SCORE_DB"),
        solve_db=_required("CYBERGYM_SOLVE_DB"),
        validator_hotkey=os.environ.get(
            "CYBERGYM_VALIDATOR_HOTKEY", "cathedral-private-v2-e2e"
        ),
        as_of=_as_of_from_environment(),
        cathedral_receipt_policy=_receipt_policy_from_environment(),
        batch_size=_batch_size_from_environment(),
    )


def main() -> None:
    host = os.environ.get("CYBERGYM_HOST", "127.0.0.1").strip()
    if host not in _LOOPBACK_HOSTS:
        raise SystemExit("private-v2 E2E verifier may bind only a loopback host")
    port = int(os.environ.get("PORT", "8668"))
    service = build_service_from_environment()
    server = make_threaded_server(
        service,
        host=host,
        port=port,
        authenticator=authenticated_miner_from_environment(),
        require_authentication=True,
        healthz={
            "status": "ok",
            "task_source": "private-v2",
            "lane": CYBERGYM_LANE,
        },
    )
    print(f"CyberGym private-v2 E2E verifier serving on {host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":  # pragma: no cover
    main()
