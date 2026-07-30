"""Run a CyberGym validator over the real corpus, on real hardware.

The reference deployment: `ReproTaskSource` (draw real challenges) + the real
`docker_reproduce_backend` (verify PoCs against the genuine vul/fix builds) behind
the production `make_threaded_server`. This is the exact spine proven live on
`cathedral-challenge-holder`, promoted out of an ops script into the package so it
is version-controlled and configured from the environment rather than edited in place.

Config (all via env):
  PORT                    listen port                       (default 8666)
  CYBERGYM_HOST           bind address                      (default 0.0.0.0)
  CYBERGYM_SIGNING_SEED   ed25519 seed, 64 hex chars        (default: ephemeral — receipts
                                                             won't verify across restarts)
  CYBERGYM_VALIDATOR_HOTKEY  validator hotkey ss58          (default cathedral-repro-validator)
  CYBERGYM_CORPUS_DB      corpus sqlite path                (default :memory:)
  CYBERGYM_SCORE_DB       score sqlite path                 (default :memory:)
  CYBERGYM_TASKS          comma-separated task ids to serve (default: the pulled subset)

Only tasks whose vul+fix images are actually pulled are dispatched, so a miner
never draws a challenge the verifier can't run.

Run:  PORT=8666 CYBERGYM_CORPUS_DB=/srv/cgd/corpus.sqlite \
      python -m cathedral_distill.cybergym_repro_server
"""
from __future__ import annotations

import os
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill.cybergym_holdout import Holdout
from cathedral_distill.cybergym_http import make_threaded_server
from cathedral_distill.cybergym_protocol import CyberGymCorpusStore
from cathedral_distill.cybergym_repro import REPRO_SUBSET, ReproTaskSource, available_tasks
from cathedral_distill.cybergym_scores import CyberGymScoreStore
from cathedral_distill.cybergym_service import CyberGymService
from cathedral_distill.cybergym_validator import ChainContext


def _signing_key() -> tuple[Ed25519PrivateKey, bool]:
    seed = os.environ.get("CYBERGYM_SIGNING_SEED", "").strip()
    if seed:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)), False
    return Ed25519PrivateKey.generate(), True  # ephemeral: fine for a dry run, not production


def resolve_tasks() -> list[str]:
    """The task ids to serve: an explicit CYBERGYM_TASKS list, else the subset whose
    images are pulled, else the full subset (so the server still boots for a dry run)."""
    explicit = os.environ.get("CYBERGYM_TASKS", "").strip()
    ids = [t.strip() for t in explicit.split(",") if t.strip()] if explicit else list(REPRO_SUBSET)
    return available_tasks(ids) or ids


def build_service(ids, *, private_key: Ed25519PrivateKey, corpus_db: str = ":memory:",
                  score_db: str = ":memory:",
                  validator_hotkey: str = "cathedral-repro-validator") -> CyberGymService:
    """Wire a `CyberGymService` over the real source + Docker backend. Importable so
    the wiring is testable with an injected backend and in-memory stores."""
    src = ReproTaskSource(ids)
    # Placeholder chain window; a live validator reads this from the subtensor and
    # only needs it to compose weights, not to run the dispatch/verify/score loop.
    chain = ChainContext(block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
                         source_epoch=21, valid_from_block=100, valid_until_block=460)
    return CyberGymService(
        Holdout(pool=src, _context={}), chain, backend=src.backend,
        corpus_store=CyberGymCorpusStore(corpus_db), score_store=CyberGymScoreStore(score_db),
        validator_hotkey=validator_hotkey, private_key=private_key, signing_key_id="cybergym-1",
        batch_size=1, cutoff=None, as_of=datetime.now(UTC), attestation_required=False)


def main() -> None:
    port = int(os.environ.get("PORT", "8666"))
    host = os.environ.get("CYBERGYM_HOST", "0.0.0.0")
    key, ephemeral = _signing_key()
    ids = resolve_tasks()
    svc = build_service(
        ids, private_key=key,
        corpus_db=os.environ.get("CYBERGYM_CORPUS_DB", ":memory:"),
        score_db=os.environ.get("CYBERGYM_SCORE_DB", ":memory:"),
        validator_hotkey=os.environ.get("CYBERGYM_VALIDATOR_HOTKEY", "cathedral-repro-validator"))
    server = make_threaded_server(svc, host=host, port=port,
                                  healthz={"status": "ok", "tasks": ids, "lane": "cybergym_v0"})
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
