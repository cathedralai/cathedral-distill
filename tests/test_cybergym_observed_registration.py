"""Reward eligibility must use observed registrations, never miner timestamps.

These are the direct regressions for the two pre-anchor selection vulnerabilities:
backdating a miner claim and choosing among many commitments after seeing the batch
anchor.  The usual gate/service suites prove the result reaches the payment path;
this module proves the evidence object itself cannot be forged or reinterpreted.
"""
from __future__ import annotations

import base64
import hashlib
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.bundle_registry import (  # noqa: E402
    BundleRegistration,
    BundleRegistry,
    RegistrationError,
    RegistrationObservation,
    ed25519_registration_verifier,
    load_registry,
)
from cathedral_distill.cybergym_holdout import load_holdout  # noqa: E402
from cathedral_distill.cybergym_protocol import (  # noqa: E402
    CyberGymCorpusStore,
    ProtocolError,
)
from cathedral_distill.cybergym_scores import CyberGymScoreStore  # noqa: E402
from cathedral_distill.cybergym_service import CyberGymService  # noqa: E402
from cathedral_distill.cybergym_validator import (  # noqa: E402
    ChainContext,
    EmissionGatePolicy,
)


EPOCH = 41
CLOSE = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
ANCHOR_BLOCK = 900
MINER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OBSERVER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
OBSERVER = "registry-observer-1"


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def _registration(
    *,
    hotkey: str = "5Alice",
    digest: str | None = None,
    claimed_at: datetime = CLOSE - timedelta(days=10),
    observed_at: datetime = CLOSE - timedelta(days=1),
    observed_block: int = ANCHOR_BLOCK - 1,
    sequence: int = 1,
    paid_identity: str | None = "coldkey:alice",
    paid_identity_kind: str | None = "coldkey",
) -> BundleRegistration:
    observation = RegistrationObservation(
        source_epoch=EPOCH,
        observed_at=observed_at,
        observed_block=observed_block,
        observer_key_id=OBSERVER,
        sequence=sequence,
        signature="pending",
        paid_identity=paid_identity,
        paid_identity_kind=paid_identity_kind,
    )
    unsigned = BundleRegistration(
        miner_hotkey=hotkey,
        track="cybergym-v0",
        bundle_digest=digest or _digest("checkpoint"),
        version="v1",
        registered_at=claimed_at,
        observation=observation,
    )
    signed = BundleRegistration(
        miner_hotkey=unsigned.miner_hotkey,
        track=unsigned.track,
        bundle_digest=unsigned.bundle_digest,
        version=unsigned.version,
        registered_at=unsigned.registered_at,
        signature=base64.b64encode(MINER_KEY.sign(unsigned.signing_payload())).decode(),
        observation=observation,
    )
    observed = RegistrationObservation(
        source_epoch=EPOCH,
        observed_at=observed_at,
        observed_block=observed_block,
        observer_key_id=OBSERVER,
        sequence=sequence,
        signature=base64.b64encode(
            OBSERVER_KEY.sign(signed.observation_payload())
        ).decode(),
        paid_identity=paid_identity,
        paid_identity_kind=paid_identity_kind,
    )
    return BundleRegistration(
        miner_hotkey=signed.miner_hotkey,
        track=signed.track,
        bundle_digest=signed.bundle_digest,
        version=signed.version,
        registered_at=signed.registered_at,
        signature=signed.signature,
        observation=observed,
    )


def _registry(*registrations: BundleRegistration) -> BundleRegistry:
    registry = BundleRegistry()
    miner_verifier = ed25519_registration_verifier(
        {registration.miner_hotkey: MINER_KEY.public_key().public_bytes_raw()
         for registration in registrations}
    )
    observer_verifier = ed25519_registration_verifier(
        {OBSERVER: OBSERVER_KEY.public_key().public_bytes_raw()}
    )
    for registration in registrations:
        registry.register(
            registration,
            signature_verifier=miner_verifier,
            observation_verifier=observer_verifier,
        )
    return registry


def test_a_backdated_miner_claim_cannot_make_a_late_observation_eligible():
    registration = _registration(
        claimed_at=datetime(2020, 1, 1, tzinfo=UTC),
        observed_at=CLOSE + timedelta(seconds=1),
    )
    snapshot = _registry(registration).freeze_eligibility_snapshot(
        source_epoch=EPOCH, registration_close=CLOSE, anchor_block=ANCHOR_BLOCK
    )
    assert snapshot.entries == ()
    assert {item["reason"] for item in snapshot.rejected_identities} == {
        "observed_after_close"
    }


def test_an_observer_signature_cannot_be_reused_with_a_backdated_receipt():
    honest = _registration(observed_at=CLOSE + timedelta(hours=1))
    late = honest.observation
    assert late is not None
    forged = BundleRegistration(
        miner_hotkey=honest.miner_hotkey,
        track=honest.track,
        bundle_digest=honest.bundle_digest,
        version=honest.version,
        registered_at=honest.registered_at,
        signature=honest.signature,
        observation=RegistrationObservation(
            source_epoch=late.source_epoch,
            observed_at=CLOSE - timedelta(days=1),
            observed_block=late.observed_block,
            observer_key_id=late.observer_key_id,
            sequence=late.sequence,
            signature=late.signature,
            registry_version=late.registry_version,
            paid_identity=late.paid_identity,
            paid_identity_kind=late.paid_identity_kind,
        ),
    )
    with pytest.raises(RegistrationError, match="observation signature does not verify"):
        _registry(forged)


def test_observation_at_or_after_the_anchor_never_receives_a_batch():
    registration = _registration(observed_block=ANCHOR_BLOCK)
    snapshot = _registry(registration).freeze_eligibility_snapshot(
        source_epoch=EPOCH, registration_close=CLOSE, anchor_block=ANCHOR_BLOCK
    )
    assert snapshot.entries == ()
    assert snapshot.rejected_identities == (
        {"paid_identity": "5Alice", "reason": "observed_at_or_after_anchor"},
    )


def test_multiple_pre_registered_commitments_fail_closed_for_one_paid_identity():
    first = _registration(digest=_digest("first"), sequence=1)
    second = _registration(digest=_digest("second"), sequence=2)
    snapshot = _registry(first, second).freeze_eligibility_snapshot(
        source_epoch=EPOCH, registration_close=CLOSE, anchor_block=ANCHOR_BLOCK,
        paid_identities={"5Alice": "coldkey:alice"},
    )
    assert snapshot.entries == ()
    assert snapshot.rejected_identities == (
        {"paid_identity": "coldkey:alice", "reason": "multiple_commitments"},
    )
    assert not snapshot.permits(
        miner_hotkey="5Alice", model_commitment=first.bundle_digest,
        paid_identity="coldkey:alice",
    )
    assert not snapshot.permits(
        miner_hotkey="5Alice", model_commitment=second.bundle_digest,
        paid_identity="coldkey:alice",
    )


def test_duplicate_observed_platform_identity_cannot_multiply_hotkeys():
    """The signed platform binding, not a local map, is the paid identity."""
    first = _registration(
        hotkey="5Alice",
        digest=_digest("alice"),
        sequence=1,
        paid_identity="tdx:platform-42",
        paid_identity_kind="tdx_platform",
    )
    second = _registration(
        hotkey="5Bob",
        digest=_digest("bob"),
        sequence=2,
        paid_identity="tdx:platform-42",
        paid_identity_kind="tdx_platform",
    )
    snapshot = _registry(first, second).freeze_eligibility_snapshot(
        source_epoch=EPOCH,
        registration_close=CLOSE,
        anchor_block=ANCHOR_BLOCK,
        require_paid_identity=True,
    )
    assert snapshot.entries == ()
    assert snapshot.rejected_identities == (
        {"paid_identity": "tdx:platform-42", "reason": "multiple_commitments"},
    )


def test_local_identity_map_cannot_override_the_signed_observation():
    registration = _registration()
    snapshot = _registry(registration).freeze_eligibility_snapshot(
        source_epoch=EPOCH,
        registration_close=CLOSE,
        anchor_block=ANCHOR_BLOCK,
        paid_identities={"5Alice": "coldkey:someone-else"},
        require_paid_identity=True,
    )
    assert snapshot.entries == ()
    assert snapshot.rejected_identities == (
        {"paid_identity": "coldkey:alice", "reason": "paid_identity_binding_mismatch"},
    )


def test_service_refuses_dispatch_for_a_conflicted_paid_identity(tmp_path):
    first = _registration(digest=_digest("first"), sequence=1)
    second = _registration(digest=_digest("second"), sequence=2)
    registry = _registry(first, second)
    with pytest.warns(UserWarning):
        service = CyberGymService(
            load_holdout([{
                "task_id": "arvo:1", "level": 0, "binary_digest": _digest("binary"),
                "disclosed_at": "2026-08-01T00:00:00Z",
            }]),
            ChainContext(
                block=ANCHOR_BLOCK,
                block_hash="0x" + "ab" * 32,
                network="finney",
                netuid=39,
                source_epoch=EPOCH,
                valid_from_block=ANCHOR_BLOCK,
                valid_until_block=ANCHOR_BLOCK + 100,
            ),
            backend=lambda *_args: 0,
            corpus_store=CyberGymCorpusStore(str(tmp_path / "corpus.sqlite")),
            score_store=CyberGymScoreStore(str(tmp_path / "scores.sqlite")),
            solve_durability_required=False,
            validator_hotkey="5Validator",
            private_key=MINER_KEY,
            signing_key_id="cybergym-1",
            batch_size=1,
            cutoff=CLOSE,
            as_of=CLOSE + timedelta(days=1),
            attestation_required=False,
            gate_policy=EmissionGatePolicy(
                bundle_registry=registry,
                paid_identities={"5Alice": "coldkey:alice"},
            ),
        )
    with pytest.raises(ProtocolError, match="frozen observed eligibility"):
        service.dispatch_for("5Alice", first.bundle_digest)


def test_snapshot_replay_is_stable_and_a_changed_registry_refuses_it():
    initial = _registry(_registration())
    snapshot = initial.freeze_eligibility_snapshot(
        source_epoch=EPOCH, registration_close=CLOSE, anchor_block=ANCHOR_BLOCK
    )
    replayed = load_registry(
        initial.as_public_index(),
        signature_verifier=ed25519_registration_verifier(
            {"5Alice": MINER_KEY.public_key().public_bytes_raw()}
        ),
        observation_verifier=ed25519_registration_verifier(
            {OBSERVER: OBSERVER_KEY.public_key().public_bytes_raw()}
        ),
    )
    replay_snapshot = replayed.freeze_eligibility_snapshot(
        source_epoch=EPOCH, registration_close=CLOSE, anchor_block=ANCHOR_BLOCK
    )
    assert replay_snapshot.as_dict() == snapshot.as_dict()
    assert replayed.verify_eligibility_snapshot(snapshot)

    replayed.register(
        _registration(hotkey="5Bob", digest=_digest("bob"), sequence=2),
        signature_verifier=ed25519_registration_verifier(
            {"5Bob": MINER_KEY.public_key().public_bytes_raw()}
        ),
        observation_verifier=ed25519_registration_verifier(
            {OBSERVER: OBSERVER_KEY.public_key().public_bytes_raw()}
        ),
    )
    assert not replayed.verify_eligibility_snapshot(snapshot)


def test_replay_uses_observer_sequence_not_a_miner_claimed_timestamp():
    shared = _digest("contested")
    first_observed = _registration(
        hotkey="5Bob",
        digest=shared,
        claimed_at=CLOSE + timedelta(days=10),
        sequence=1,
    )
    backdated_claim = _registration(
        hotkey="5Alice",
        digest=shared,
        claimed_at=datetime(2020, 1, 1, tzinfo=UTC),
        sequence=2,
    )
    replayed = load_registry(
        # Deliberately reversed: an attacker must not win by shipping a claimed
        # timestamp from years before the observer actually saw its registration.
        [backdated_claim.as_dict(), first_observed.as_dict()],
        signature_verifier=ed25519_registration_verifier({
            "5Alice": MINER_KEY.public_key().public_bytes_raw(),
            "5Bob": MINER_KEY.public_key().public_bytes_raw(),
        }),
        observation_verifier=ed25519_registration_verifier(
            {OBSERVER: OBSERVER_KEY.public_key().public_bytes_raw()}
        ),
    )
    assert replayed.claim_for(shared).miner_hotkey == "5Bob"
