"""Reward eligibility is observed, frozen, identity-collapsed, and shared-batch."""
from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from cathedral_distill.bundle_registry import (
    BundleRegistration,
    BundleRegistry,
    ed25519_registration_verifier,
)
from cathedral_distill.cybergym import Level
from cathedral_distill.cybergym_batch import PooledTask, TaskPool, derive_epoch_batch_nonce
from cathedral_distill.cybergym_eligibility import (
    EligibilityError,
    EligibilitySnapshot,
    RegistrationObservation,
    ed25519_observation_verifier,
    freeze_eligibility_snapshot,
)
from cathedral_distill.cybergym_scores import CyberGymScoreStore
from cathedral_distill.cybergym_holdout import Holdout
from cathedral_distill.cybergym_protocol import CyberGymCorpusStore, ProtocolError
from cathedral_distill.cybergym_service import CyberGymService
from cathedral_distill.cybergym_validator import (
    ChainContext,
    EmissionGatePolicy,
    MinerCommit,
    run_epoch,
)


NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
CLOSE = NOW - timedelta(hours=1)
CHAIN = ChainContext(
    block=100,
    block_hash="0x" + "ab" * 32,
    network="finney",
    netuid=39,
    source_epoch=21,
    valid_from_block=100,
    valid_until_block=460,
)
REGISTRY_VERSION = "registry-v1"
MINER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
OBSERVER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))
RECEIPT_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(3, 35)))


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _registration(hotkey: str, digest: str, key: Ed25519PrivateKey, *, registered_at=CLOSE):
    unsigned = BundleRegistration(
        miner_hotkey=hotkey,
        track="cybergym-v0",
        bundle_digest=digest,
        version="v1",
        registered_at=registered_at,
    )
    return BundleRegistration(
        miner_hotkey=hotkey,
        track="cybergym-v0",
        bundle_digest=digest,
        version="v1",
        registered_at=registered_at,
        signature=base64.b64encode(key.sign(unsigned.signing_payload())).decode(),
    )


def _registry(*registrations):
    keys = {
        "5Alice": MINER_KEY.public_key().public_bytes_raw(),
        "5Bob": OTHER_KEY.public_key().public_bytes_raw(),
    }
    registry = BundleRegistry()
    verifier = ed25519_registration_verifier(keys)
    for registration in registrations:
        registry.register(registration, signature_verifier=verifier)
    return registry


def _observation(
    *,
    hotkey: str,
    digest: str,
    paid_identity: str,
    observed_at=CLOSE - timedelta(minutes=1),
    observed_block=99,
    sequence=1,
):
    unsigned = RegistrationObservation(
        source_epoch=CHAIN.source_epoch,
        miner_hotkey=hotkey,
        bundle_digest=digest,
        paid_identity=paid_identity,
        observed_at=observed_at,
        observed_block=observed_block,
        registry_version=REGISTRY_VERSION,
        sequence=sequence,
        observer_key_id="observer-1",
        signature="pending",
    )
    return RegistrationObservation(
        source_epoch=unsigned.source_epoch,
        miner_hotkey=unsigned.miner_hotkey,
        bundle_digest=unsigned.bundle_digest,
        paid_identity=unsigned.paid_identity,
        observed_at=unsigned.observed_at,
        observed_block=unsigned.observed_block,
        registry_version=unsigned.registry_version,
        sequence=unsigned.sequence,
        observer_key_id=unsigned.observer_key_id,
        signature=base64.b64encode(OBSERVER_KEY.sign(unsigned.signing_payload())).decode(),
    )


def _snapshot(registry, *observations):
    return freeze_eligibility_snapshot(
        registry=registry,
        observations=observations,
        observation_verifier=ed25519_observation_verifier(
            {"observer-1": OBSERVER_KEY.public_key().public_bytes_raw()}
        ),
        source_epoch=CHAIN.source_epoch,
        registration_close=CLOSE,
        anchor_block=CHAIN.block,
        registry_version=REGISTRY_VERSION,
    )


def _pool():
    return TaskPool(
        [
            PooledTask(
                task_id="arvo:1",
                level=Level(0),
                binary_digest=_digest("bin-1"),
                disclosed_at=NOW,
            ),
            PooledTask(
                task_id="arvo:2",
                level=Level(2),
                binary_digest=_digest("bin-2"),
                disclosed_at=NOW,
            ),
        ]
    )


def _backend(task_id, _poc, mode):
    return 1 if task_id == "arvo:1" and mode == "vul" else 0


def test_backdated_miner_registration_and_post_close_observation_are_ineligible():
    commitment = _digest("alice")
    registry = _registry(_registration("5Alice", commitment, MINER_KEY, registered_at=CLOSE - timedelta(days=9)))
    snapshot = _snapshot(
        registry,
        _observation(
            hotkey="5Alice",
            digest=commitment,
            paid_identity="coldkey:alice",
            observed_at=CLOSE + timedelta(seconds=1),
        ),
    )
    assert snapshot.entries == ()
    assert not snapshot.is_eligible("5Alice", commitment, source_epoch=CHAIN.source_epoch)


def test_snapshot_replay_is_stable_and_a_changed_registration_set_changes_digest():
    alice = _digest("alice")
    bob = _digest("bob")
    registry = _registry(
        _registration("5Alice", alice, MINER_KEY),
        _registration("5Bob", bob, OTHER_KEY),
    )
    alice_observation = _observation(hotkey="5Alice", digest=alice, paid_identity="coldkey:alice")
    bob_observation = _observation(
        hotkey="5Bob", digest=bob, paid_identity="coldkey:bob", sequence=2
    )
    first = _snapshot(registry, alice_observation)
    replay = _snapshot(registry, alice_observation)
    restored = EligibilitySnapshot.from_dict(first.as_dict())
    changed = _snapshot(registry, alice_observation, bob_observation)
    assert replay.digest == first.digest == restored.digest
    assert replay.entries == restored.entries
    assert changed.digest != first.digest


def test_snapshot_deserialization_refuses_malformed_entry_or_rejection_lists():
    commitment = _digest("alice")
    registry = _registry(_registration("5Alice", commitment, MINER_KEY))
    snapshot = _snapshot(
        registry,
        _observation(hotkey="5Alice", digest=commitment, paid_identity="coldkey:alice"),
    )
    malformed_list = snapshot.as_dict()
    malformed_list["rejected_hotkeys"] = "5Alice"
    with pytest.raises(EligibilityError, match="snapshot schema is invalid"):
        EligibilitySnapshot.from_dict(malformed_list)

    malformed_entry = snapshot.as_dict()
    malformed_entry["entries"][0]["observed_block"] = True
    with pytest.raises(EligibilityError, match="snapshot fields are malformed"):
        EligibilitySnapshot.from_dict(malformed_entry)


def test_duplicate_paid_identity_cannot_claim_multiple_hotkeys_or_commitments():
    alice = _digest("alice")
    bob = _digest("bob")
    registry = _registry(
        _registration("5Alice", alice, MINER_KEY),
        _registration("5Bob", bob, OTHER_KEY),
    )
    snapshot = _snapshot(
        registry,
        _observation(hotkey="5Alice", digest=alice, paid_identity="platform:tdx-123"),
        _observation(hotkey="5Bob", digest=bob, paid_identity="platform:tdx-123", sequence=2),
    )
    assert snapshot.entries == ()
    assert snapshot.rejected_paid_identities == ("platform:tdx-123",)


def test_dispatch_refuses_post_close_or_alternate_commitment(tmp_path):
    commitment = _digest("alice")
    alternate = _digest("alice-alternate")
    registry = _registry(_registration("5Alice", commitment, MINER_KEY))
    snapshot = _snapshot(
        registry,
        _observation(hotkey="5Alice", digest=commitment, paid_identity="coldkey:alice"),
    )
    service = CyberGymService(
        Holdout(pool=_pool(), _context={}),
        CHAIN,
        backend=_backend,
        corpus_store=CyberGymCorpusStore(":memory:"),
        score_store=CyberGymScoreStore(":memory:", durability_required=False),
        solve_store=None,
        solve_durability_required=False,
        validator_hotkey="5Validator",
        private_key=RECEIPT_KEY,
        signing_key_id="validator-1",
        batch_size=2,
        cutoff=CLOSE,
        as_of=NOW,
        attestation_required=False,
        gate_policy=EmissionGatePolicy(bundle_registry=registry, eligibility_snapshot=snapshot),
    )
    with pytest.raises(ProtocolError, match="frozen observed registration"):
        service.dispatch_for("5Alice", alternate)
    assert service.dispatch_for("5Alice", commitment).batch_id


def test_shared_batch_and_signed_snapshot_evidence_leave_no_hotkey_lottery(tmp_path):
    alice = _digest("alice")
    bob = _digest("bob")
    registry = _registry(
        _registration("5Alice", alice, MINER_KEY),
        _registration("5Bob", bob, OTHER_KEY),
    )
    snapshot = _snapshot(
        registry,
        _observation(hotkey="5Alice", digest=alice, paid_identity="coldkey:alice"),
        _observation(hotkey="5Bob", digest=bob, paid_identity="coldkey:bob", sequence=2),
    )
    policy = EmissionGatePolicy(bundle_registry=registry, eligibility_snapshot=snapshot)
    results = run_epoch(
        [
            MinerCommit("5Alice", alice, {"arvo:1": b"alice"}),
            MinerCommit("5Bob", bob, {"arvo:1": b"bob"}),
        ],
        _pool(),
        CHAIN,
        validator_hotkey="5Validator",
        private_key=RECEIPT_KEY,
        signing_key_id="validator-1",
        backend=_backend,
        score_store=CyberGymScoreStore(str(tmp_path / "scores.sqlite")),
        cutoff=CLOSE,
        as_of=NOW,
        issued_at="2026-08-01T12:00:00.000000Z",
        batch_size=2,
        gate_policy=policy,
    )
    assert results[0].batch.batch_id == results[1].batch.batch_id
    assert results[0].batch.nonce == derive_epoch_batch_nonce(
        block=CHAIN.block,
        block_hash=CHAIN.block_hash,
        network=CHAIN.network,
        netuid=CHAIN.netuid,
        source_epoch=CHAIN.source_epoch,
    )
    assert all(result.creditable for result in results)
    assert all(
        result.receipt["schema"] == "cathedral_cybergym_receipt_v2"
        and result.receipt["batch"]["eligibility_snapshot_digest"] == snapshot.digest
        for result in results
    )
