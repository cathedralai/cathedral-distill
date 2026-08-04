"""Immutable task manifests are the only reward-bearing real-corpus source."""
from __future__ import annotations

import hashlib
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.cybergym_protocol import ProtocolError, dispatch  # noqa: E402
from cathedral_distill.cybergym_repro import (  # noqa: E402
    ReproError,
    ReproTaskSource,
    docker_reproduce_backend,
    execution_profile_digest,
)
from cathedral_distill.cybergym_scores import CyberGymScoreStore  # noqa: E402
from cathedral_distill.cybergym_task_manifest import (  # noqa: E402
    ImmutableTaskManifest,
    TaskManifestError,
)
from cathedral_distill.cybergym_validator import ChainContext, MinerCommit, run_epoch  # noqa: E402


NOW = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
CUTOFF = NOW - timedelta(days=2)
EPOCH = 99
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _ref(label: str) -> str:
    return f"registry.example/cybergym/{label}@sha256:{hashlib.sha256(label.encode()).hexdigest()}"


def _document(*, vulnerable: str | None = None, fixed: str | None = None, private_until=None):
    return {
        "schema": "cathedral_cybergym_task_manifest_v1",
        "source_epoch": EPOCH,
        "created_at": (NOW - timedelta(days=1)).isoformat(),
        "commitment_cutoff": CUTOFF.isoformat(),
        "private_until": (private_until or NOW + timedelta(days=3)).isoformat(),
        "tasks": [{
            "task_id": "arvo:368",
            "level": 2,
            "disclosed_at": (NOW - timedelta(hours=12)).isoformat(),
            "vulnerable_image": vulnerable or _ref("arvo-368-vul"),
            "fixed_image": fixed or _ref("arvo-368-fix"),
            "context": {"description": "heap-use-after-free"},
        }],
    }


def _manifest(**kwargs) -> ImmutableTaskManifest:
    return ImmutableTaskManifest.from_document(_document(**kwargs))


def _chain() -> ChainContext:
    return ChainContext(
        block=1000,
        block_hash="0x" + "ab" * 32,
        network="finney",
        netuid=39,
        source_epoch=EPOCH,
        valid_from_block=1000,
        valid_until_block=1100,
    )


def test_manifest_rejects_mutable_tag_only_images():
    with pytest.raises(TaskManifestError, match="immutable repo@sha256"):
        _manifest(vulnerable="registry.example/cybergym/arvo-368-vul:latest")


def test_same_logical_image_name_with_different_bytes_changes_manifest_and_pair_digest():
    first = _manifest(vulnerable=_ref("arvo-368-vul-a"))
    second = _manifest(vulnerable=_ref("arvo-368-vul-b"))
    assert first.digest != second.digest
    assert first.tasks[0].binary_digest != second.tasks[0].binary_digest


def test_manifest_source_dispatches_exact_image_references_and_digest():
    manifest = _manifest()
    source = ReproTaskSource(manifest)
    message = dispatch(
        source, _chain(), miner_hotkey="5Miner",
        model_commitment="sha256:" + "cd" * 32,
        cutoff=CUTOFF, as_of=NOW, batch_size=1,
        context_provider=source.context_provider,
    )
    document = message.to_dict()
    assert document["task_manifest_digest"] == manifest.digest
    assert document["execution_profile_digest"] == execution_profile_digest()
    assert document["tasks"][0]["image_references"] == {
        "vulnerable": manifest.tasks[0].vulnerable_image,
        "fixed": manifest.tasks[0].fixed_image,
    }

    wrong_epoch = ChainContext(
        block=1000, block_hash="0x" + "ab" * 32, network="finney", netuid=39,
        source_epoch=EPOCH + 1, valid_from_block=1000, valid_until_block=1100,
    )
    with pytest.raises(ProtocolError, match="manifest source_epoch"):
        dispatch(
            source, wrong_epoch, miner_hotkey="5Miner",
            model_commitment="sha256:" + "cd" * 32,
            cutoff=CUTOFF, as_of=NOW, batch_size=1,
        )


def test_expired_or_cutoff_mismatched_manifest_cannot_draw_a_reward_task():
    source = ReproTaskSource(_manifest(private_until=NOW))
    with pytest.raises(ReproError, match="no longer private"):
        source.draw(size=1, nonce="cgnonce-sha256:" + "11" * 32,
                    cutoff=CUTOFF, as_of=NOW)

    source = ReproTaskSource(_manifest())
    with pytest.raises(ReproError, match="cutoff does not match"):
        source.draw(size=1, nonce="cgnonce-sha256:" + "11" * 32,
                    cutoff=CUTOFF - timedelta(seconds=1), as_of=NOW)


def test_backend_refuses_a_tag_even_if_a_caller_bypasses_manifest_loading():
    with pytest.raises(ReproError, match="immutable repo@sha256"):
        docker_reproduce_backend("arvo:368", b"poc", "vul", image_ref="n132/arvo:368-vul")


def test_signed_receipt_binds_the_immutable_manifest_digest(tmp_path):
    manifest = _manifest()
    source = ReproTaskSource(manifest)
    results = run_epoch(
        [MinerCommit(
            miner_hotkey="5Miner",
            model_commitment="sha256:" + "cd" * 32,
            pocs={"arvo:368": b"proof"},
        )],
        source,
        _chain(),
        validator_hotkey="5Validator",
        private_key=KEY,
        signing_key_id="cybergym-1",
        backend=lambda _task, _poc, mode: 1 if mode == "vul" else 0,
        score_store=CyberGymScoreStore(str(tmp_path / "scores.sqlite")),
        cutoff=CUTOFF,
        as_of=NOW,
        issued_at="2026-08-04T12:00:00.000000Z",
        batch_size=1,
        gates_required=False,
    )
    assert results[0].receipt["batch"]["holdout_digest"] == manifest.digest
    assert (
        results[0].receipt["batch"]["execution_profile_digest"]
        == execution_profile_digest()
    )
