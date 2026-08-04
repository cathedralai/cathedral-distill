"""Fresh sealed challenges are dispatchable and rewardable without static ARVO.

The legacy ``SyntheticTaskSource`` remains a deliberately unpaid oracle.  These
tests cover the separate fresh source used by the verifier path: it derives new
task bytes after a finalized epoch nonce, keeps a reference PoC validator-side,
and delivers an artifact that does not print the answer in plaintext.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime
from decimal import Decimal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from cathedral_distill.cybergym_protocol import CyberGymCorpusStore, ProtocolError, SubmissionEnvelope
from cathedral_distill.cybergym_scores import CyberGymScoreStore, CyberGymSolveStore
from cathedral_distill.cybergym_service import CyberGymService
from cathedral_distill.cybergym_fresh import (
    CRASH_EXIT,
    FreshTaskSource,
    execute,
    fresh_holdout,
    is_fresh_task,
)
from cathedral_distill.cybergym_fresh_server import build_service as build_fresh_e2e_service
from cathedral_distill.cybergym_fresh_close import main as close_fresh_e2e
from cathedral_distill.cybergym_validator import ChainContext
from cathedral_distill.cybergym_verifier import poc_digest

SEED = bytes(range(32))
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
MODEL = "sha256:" + hashlib.sha256(b"fresh-model").hexdigest()
NOW = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
CUTOFF = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)


def _chain(epoch: int = 21) -> ChainContext:
    return ChainContext(
        block=100 + epoch,
        block_hash="0x" + f"{epoch:064x}",
        network="finney",
        netuid=39,
        source_epoch=epoch,
        valid_from_block=100 + epoch,
        valid_until_block=460 + epoch,
    )


def _trace(task_id: str, poc: bytes) -> dict:
    detail = (
        "I traced the decoded guard and the derived capacity through the parser, "
        "then constructed an input whose length crosses the vulnerable copy boundary "
        "while checking that the patched length guard rejects the same input."
    )
    return {
        "task_id": task_id,
        "poc_sha256": poc_digest(poc),
        "model_id": "cathedral/fresh-e2e",
        "licence": "cathedral-corpus-v1",
        "model_seal": "sha256:" + hashlib.sha256(b"fresh-seal").hexdigest(),
        "steps": [
            {"step": 1, "action": "read_file", "thought": detail},
            {"step": 2, "action": "reason", "thought": detail},
            {"step": 3, "action": "write_poc", "thought": detail},
            {"step": 4, "action": "verify", "thought": detail},
            {"step": 5, "action": "submit", "thought": detail},
        ],
    }


def _service(tmp_path, *, epoch: int = 21):
    holdout, backend = fresh_holdout(SEED, levels=(0,))
    service = CyberGymService(
        holdout,
        _chain(epoch),
        backend=backend,
        corpus_store=CyberGymCorpusStore(str(tmp_path / "corpus.sqlite")),
        score_store=CyberGymScoreStore(str(tmp_path / "scores.sqlite")),
        solve_store=CyberGymSolveStore(str(tmp_path / "solves.sqlite")),
        validator_hotkey="5FreshValidator",
        private_key=KEY,
        signing_key_id="fresh-1",
        batch_size=2,
        cutoff=CUTOFF,
        as_of=NOW,
        attestation_required=False,
        gates_required=False,
    )
    return service, holdout.pool


def test_fresh_source_is_distinct_per_epoch_and_stable_on_redispatch():
    first = FreshTaskSource(SEED, levels=(0, 1))
    repeat = FreshTaskSource(SEED, levels=(0, 1))
    a = first.draw(size=3, nonce="cgnonce-sha256:" + "a" * 64)
    b = repeat.draw(size=3, nonce="cgnonce-sha256:" + "a" * 64)
    later = first.draw(size=3, nonce="cgnonce-sha256:" + "b" * 64)

    assert a == b
    assert a.batch_id != later.batch_id
    assert a.task_ids != later.task_ids
    assert a.evidence_digest and a.evidence_digest.startswith("sha256:")
    assert all(is_fresh_task(task.task_id) for task in a.tasks)


def test_fresh_artifact_does_not_print_the_reference_trigger():
    source = FreshTaskSource(SEED, levels=(0,))
    batch = source.draw(size=1, nonce="cgnonce-sha256:" + "c" * 64)
    task_id = batch.tasks[0].task_id
    challenge = source._challenges[task_id]  # verifier-held reference material
    artifact = source.artifact(task_id)

    assert artifact is not None
    assert challenge.magic not in artifact.encode()
    assert challenge.reference_poc not in artifact.encode()
    # The old mechanical two-regex oracle cannot recover either required value.
    assert re.findall(r"\\x([0-9a-f]{2})", artifact) == []
    assert re.search(r"char buf\[(\d+)\]", artifact) is None
    assert execute(challenge, challenge.reference_poc, patched=False) == CRASH_EXIT
    assert execute(challenge, challenge.reference_poc, patched=True) != CRASH_EXIT


def test_service_dispatches_fresh_artifact_and_scores_its_admitted_reference(tmp_path):
    service, source = _service(tmp_path)
    dispatch = service.dispatch_for("5FreshMiner", MODEL, authenticated_caller="5FreshMiner")
    task = dispatch.tasks[0]
    challenge = source._challenges[task.task_id]  # held by the verifier in production

    delivered = service.handle_artifact(
        {"task_id": task.task_id, "batch_id": dispatch.batch_id},
        authenticated_caller="5FreshMiner",
    )
    assert delivered["task_id"] == task.task_id
    assert challenge.magic not in delivered["program"].encode()

    outcome = service.submit(
        SubmissionEnvelope(
            batch_id=dispatch.batch_id,
            task_id=task.task_id,
            miner_hotkey="5FreshMiner",
            poc_base64=base64.b64encode(challenge.reference_poc).decode(),
            trace=_trace(task.task_id, challenge.reference_poc),
        ),
        authenticated_caller="5FreshMiner",
    )
    assert outcome.solved and outcome.creditable
    assert outcome.work_units == Decimal("8")

    results = service.score_epoch(issued_at="2026-08-04T12:00:00.000000Z")
    assert len(results) == 1
    assert service._scores.epoch_scores(21)["5FreshMiner"] == Decimal("8")


def test_seed_commitment_is_public_but_seed_is_not():
    source = FreshTaskSource(SEED)
    manifest = source.epoch_manifest()

    assert manifest["schema"] == "cathedral_cybergym_fresh_source_v1"
    assert manifest["seed_commitment"].startswith("sha256:")
    assert SEED.hex() not in str(manifest)


def test_loopback_e2e_server_uses_the_fresh_source_and_durable_state(tmp_path):
    service = build_fresh_e2e_service(
        fresh_seed=SEED,
        private_key=KEY,
        corpus_db=str(tmp_path / "corpus.sqlite"),
        score_db=str(tmp_path / "scores.sqlite"),
        solve_db=str(tmp_path / "solves.sqlite"),
        validator_hotkey="5FreshE2E",
        as_of=NOW,
    )

    source_manifest = service.epoch_manifest()["task_source"]
    assert source_manifest["schema"] == "cathedral_cybergym_fresh_source_v1"
    assert source_manifest["seed_commitment"].startswith("sha256:")
    assert service._solves.manifest_for(21)["manifest"] == service.epoch_manifest()


def test_restart_with_a_different_fresh_seed_is_refused(tmp_path):
    paths = {
        "corpus_db": str(tmp_path / "corpus.sqlite"),
        "score_db": str(tmp_path / "scores.sqlite"),
        "solve_db": str(tmp_path / "solves.sqlite"),
    }
    build_fresh_e2e_service(
        fresh_seed=SEED,
        private_key=KEY,
        validator_hotkey="5FreshE2E",
        as_of=NOW,
        **paths,
    )
    with pytest.raises(ProtocolError, match="task_source"):
        build_fresh_e2e_service(
            fresh_seed=b"x" * 32,
            private_key=KEY,
            validator_hotkey="5FreshE2E",
            as_of=NOW,
            **paths,
        )


def test_restart_with_a_different_fresh_as_of_is_refused(tmp_path):
    paths = {
        "corpus_db": str(tmp_path / "corpus.sqlite"),
        "score_db": str(tmp_path / "scores.sqlite"),
        "solve_db": str(tmp_path / "solves.sqlite"),
    }
    build_fresh_e2e_service(
        fresh_seed=SEED,
        private_key=KEY,
        validator_hotkey="5FreshE2E",
        as_of=NOW,
        **paths,
    )
    with pytest.raises(ProtocolError, match="as_of"):
        build_fresh_e2e_service(
            fresh_seed=SEED,
            private_key=KEY,
            validator_hotkey="5FreshE2E",
            as_of=NOW.replace(minute=NOW.minute + 1),
            **paths,
        )


def test_fresh_close_command_restores_solves_and_closes_epoch(tmp_path, monkeypatch, capsys):
    paths = {
        "corpus_db": str(tmp_path / "corpus.sqlite"),
        "score_db": str(tmp_path / "scores.sqlite"),
        "solve_db": str(tmp_path / "solves.sqlite"),
    }
    service = build_fresh_e2e_service(
        fresh_seed=SEED,
        private_key=KEY,
        validator_hotkey="5FreshE2E",
        as_of=NOW,
        **paths,
    )
    dispatch = service.dispatch_for("5FreshMiner", MODEL, authenticated_caller="5FreshMiner")
    task = dispatch.tasks[0]
    challenge = service.holdout.pool._challenges[task.task_id]
    service.submit(
        SubmissionEnvelope(
            batch_id=dispatch.batch_id,
            task_id=task.task_id,
            miner_hotkey="5FreshMiner",
            poc_base64=base64.b64encode(challenge.reference_poc).decode(),
            trace=_trace(task.task_id, challenge.reference_poc),
        ),
        authenticated_caller="5FreshMiner",
    )
    monkeypatch.setenv("CYBERGYM_E2E_ALLOW_UNATTESTED", "1")
    monkeypatch.setenv("CYBERGYM_FRESH_SEED", SEED.hex())
    monkeypatch.setenv("CYBERGYM_SIGNING_SEED", bytes(range(32, 64)).hex())
    monkeypatch.setenv("CYBERGYM_E2E_AS_OF", NOW.isoformat())
    monkeypatch.setenv("CYBERGYM_VALIDATOR_HOTKEY", "5FreshE2E")
    for name, path in paths.items():
        monkeypatch.setenv("CYBERGYM_" + name.upper(), path)

    assert close_fresh_e2e(["--issued-at", "2026-08-04T12:00:00.000000Z"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "closed"
    assert payload["scores"] == {"5FreshMiner": "8"}
