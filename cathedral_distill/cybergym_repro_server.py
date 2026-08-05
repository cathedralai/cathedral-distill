"""Run the legacy CyberGym real-corpus dry-run server.

The reference dry-run deployment: `ReproTaskSource` (draw real challenges) + the real
`docker_reproduce_backend` (verify PoCs against the genuine vul/fix builds) behind
the production `make_threaded_server`. This is the exact spine proven live on
`cathedral-challenge-holder`, promoted out of an ops script into the package so it
is version-controlled and configured from the environment rather than edited in place.
It has no caller-identity verifier, so it deliberately refuses v2 private manifests;
those require an authenticated transport adapter around ``CyberGymService``.

Config (all via env):
  PORT                    listen port                       (default 8666)
  CYBERGYM_HOST           bind address                      (default 127.0.0.1; this
                                                             reference entrypoint has
                                                             no public auth mechanism)
  CYBERGYM_SIGNING_SEED   ed25519 seed, 64 hex chars        (default: ephemeral — receipts
                                                             won't verify across restarts)
  CYBERGYM_VALIDATOR_HOTKEY  validator hotkey ss58          (default cathedral-repro-validator)
  CYBERGYM_CORPUS_DB      corpus sqlite path                (default: a fresh per-boot temp file)
  CYBERGYM_SCORE_DB       score sqlite path                 (default: a fresh per-boot temp file)
  CYBERGYM_CORPUS_MANIFEST  private per-epoch digest-pinned task manifest (required)

Every task in the private manifest must have both exact image digests available
locally. A tag-only list or a partial image set refuses startup.

Run:  PORT=8666 CYBERGYM_CORPUS_DB=/srv/cgd/corpus.sqlite \
      CYBERGYM_CORPUS_MANIFEST=/srv/cgd/private-repro-manifest.json \
      python -m cathedral_distill.cybergym_repro_server
"""
from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill.corpus_admission import require_admitted_private_manifest
from cathedral_distill.cybergym_holdout import Holdout
from cathedral_distill.cybergym_http import make_threaded_server
from cathedral_distill.cybergym_protocol import CyberGymCorpusStore
from cathedral_distill.cybergym_private_artifacts import (
    PrivateChallengeArtifactStore,
    PrivateReferencePoCStore,
)
from cathedral_distill.cybergym_repro import ReproTaskSource, available_tasks
from cathedral_distill.cybergym_repro_manifest import (
    PrivateReproManifest,
    ReproManifestError,
    load_private_repro_manifest_file,
)
from cathedral_distill.cybergym_scores import CyberGymScoreStore
from cathedral_distill.cybergym_service import CYBERGYM_LANE, CyberGymService
from cathedral_distill.cybergym_validator import ChainContext


def _signing_key() -> tuple[Ed25519PrivateKey, bool]:
    seed = os.environ.get("CYBERGYM_SIGNING_SEED", "").strip()
    if not seed:
        return Ed25519PrivateKey.generate(), True  # ephemeral: fine for a dry run, not production
    # A mistyped seed used to die with a raw cryptography traceback ("Expected 32
    # bytes") that never named the env var; refuse with the variable and the fix.
    try:
        raw = bytes.fromhex(seed)
    except ValueError:
        raise SystemExit(
            "CYBERGYM_SIGNING_SEED must be 64 hex characters (a 32-byte ed25519 "
            f"seed); got {len(seed)} characters that are not valid hex"
        ) from None
    if len(raw) != 32:
        raise SystemExit(
            "CYBERGYM_SIGNING_SEED must be 64 hex characters (a 32-byte ed25519 "
            f"seed); got {len(seed)} hex characters"
        )
    return Ed25519PrivateKey.from_private_bytes(raw), False


def _manifest_from_environment() -> PrivateReproManifest:
    path = os.environ.get("CYBERGYM_CORPUS_MANIFEST", "").strip()
    if not path:
        raise SystemExit(
            "CYBERGYM_CORPUS_MANIFEST is required: a tag-only task list cannot "
            "start the real CyberGym reproduction server"
        )
    try:
        return load_private_repro_manifest_file(path)
    except ReproManifestError as exc:
        raise SystemExit(f"CYBERGYM_CORPUS_MANIFEST is invalid: {exc}") from None


def build_service(
    manifest: PrivateReproManifest,
    *,
    private_key: Ed25519PrivateKey,
    challenge_artifacts: PrivateChallengeArtifactStore | None = None,
    reference_pocs: PrivateReferencePoCStore | None = None,
    corpus_db: str | None = None,
    score_db: str | None = None,
    validator_hotkey: str = "cathedral-repro-validator",
) -> CyberGymService:
    """Wire a `CyberGymService` over the real source + Docker backend. Importable so
    the wiring is testable with an injected backend and per-run temp stores."""
    if corpus_db is None or score_db is None:
        # Fresh per-boot files rather than ":memory:": the score store refuses an
        # in-memory path outright (it exists to be read as a file by the external
        # mechanism adapter), and the shipped reference server has to keep booting
        # with zero configuration. A dry run intentionally starts clean each boot;
        # a real deployment sets CYBERGYM_CORPUS_DB / CYBERGYM_SCORE_DB.
        run_dir = tempfile.mkdtemp(prefix="cybergym-repro-")
        corpus_db = corpus_db or os.path.join(run_dir, "corpus.sqlite")
        score_db = score_db or os.path.join(run_dir, "scores.sqlite")
    src = ReproTaskSource(
        manifest,
        challenge_artifacts=challenge_artifacts,
        reference_pocs=reference_pocs,
    )
    # Placeholder chain window; a live validator reads this from the subtensor and
    # only needs it to compose weights, not to run the dispatch/verify/score loop.
    chain = ChainContext(block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
                         source_epoch=21, valid_from_block=100, valid_until_block=460)
    if manifest.source_epoch != chain.source_epoch:
        raise ReproManifestError(
            f"manifest source_epoch {manifest.source_epoch} does not match chain epoch {chain.source_epoch}"
        )
    return CyberGymService(
        Holdout(pool=src, _context={}), chain, backend=src.backend,
        corpus_store=CyberGymCorpusStore(corpus_db), score_store=CyberGymScoreStore(score_db),
        validator_hotkey=validator_hotkey, private_key=private_key, signing_key_id="cybergym-1",
        batch_size=1, cutoff=None, as_of=datetime.now(UTC), attestation_required=False,
        # This reference server is a dry-run harness (ephemeral signing key, per-boot
        # temp stores by default), so it explicitly opts out of the durable-solve-store
        # and anti-gaming-gate requirements the constructor otherwise enforces
        # fail-closed: without these it raises and the server cannot start at all. A
        # real validator MUST instead pass a durable solve_store and a real
        # EmissionGatePolicy.
        solve_durability_required=False, gates_required=False)


def main() -> None:
    port = int(os.environ.get("PORT", "8666"))
    host = os.environ.get("CYBERGYM_HOST", "127.0.0.1")
    key, ephemeral = _signing_key()
    manifest = _manifest_from_environment()
    if manifest.reward_ready:
        raise SystemExit(
            "v2 private manifests require an authenticated transport adapter; "
            "this reference server has no caller-identity verifier and must not "
            "serve private challenge artifacts"
        )
    ids = available_tasks(manifest)
    if set(ids) != set(task.task_id for task in manifest.tasks):
        raise SystemExit(
            "every digest-pinned manifest task must have both images available locally; "
            "refusing to serve a partial or unverifiable corpus"
        )
    try:
        require_admitted_private_manifest(manifest)
    except ReproManifestError as exc:
        raise SystemExit(f"CYBERGYM_CORPUS_MANIFEST is not scoreable: {exc}") from None
    svc = build_service(
        manifest, private_key=key,
        # An unset or empty variable falls through to build_service's per-boot temp
        # files; ":memory:" is no longer a bootable score-store path (the store
        # refuses it, because the external adapter reads the database as a file).
        corpus_db=os.environ.get("CYBERGYM_CORPUS_DB") or None,
        score_db=os.environ.get("CYBERGYM_SCORE_DB") or None,
        validator_hotkey=os.environ.get("CYBERGYM_VALIDATOR_HOTKEY", "cathedral-repro-validator"))
    server = make_threaded_server(svc, host=host, port=port,
                                  healthz={"status": "ok", "tasks": ids,
                                           "lane": CYBERGYM_LANE})
    if ephemeral:
        print("WARNING: no CYBERGYM_SIGNING_SEED set — using an ephemeral key; "
              "receipts will not verify across restarts.", flush=True)
    print(f"CyberGym validator serving real tasks {ids} on {host}:{port} "
          f"(threaded, GET /healthz)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
