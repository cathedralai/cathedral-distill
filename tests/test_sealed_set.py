"""Tests for eval-set sealing.

The properties that matter: a miner holding the ciphertext learns nothing, a
sealed blob cannot be relabelled as a different set, and shard rotation is
deterministic so a validator can reproduce which items were live.
"""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import sealed_set as ss  # noqa: E402


def _items(count: int = 8):
    return [
        ss.EvalItem(
            item_id=f"fe-{index:03d}",
            prompt=f"Build a component that does thing {index}.",
            checks={"kind": "vitest", "canary": index == 3},
        )
        for index in range(count)
    ]


@pytest.fixture
def enclave():
    private = X25519PrivateKey.generate()
    return private, private.public_key().public_bytes_raw()


def test_seal_open_round_trip(enclave):
    private, public = enclave
    items = _items()
    sealed = ss.seal("frontend_v0", items, public)
    opened = ss.open_sealed(sealed, private)
    assert [i.item_id for i in opened] == sorted(i.item_id for i in items)
    assert opened[0].prompt == items[0].prompt


def test_ciphertext_leaks_no_prompt_text(enclave):
    _, public = enclave
    items = _items()
    sealed = ss.seal("frontend_v0", items, public)
    assert b"Build a component" not in sealed.ciphertext
    # The public manifest is safe to publish alongside the ciphertext.
    manifest = sealed.manifest()
    assert "prompt" not in str(manifest)
    assert manifest["item_count"] == len(items)


def test_sealed_and_plaintext_digests_differ(enclave):
    _, public = enclave
    sealed = ss.seal("frontend_v0", _items(), public)
    # The receipt schema rejects a receipt where these are equal.
    assert sealed.sealed_digest != sealed.plaintext_digest


def test_wrong_enclave_cannot_open(enclave):
    _, public = enclave
    sealed = ss.seal("frontend_v0", _items(), public)
    attacker = X25519PrivateKey.generate()
    with pytest.raises(ss.SealedSetError, match="not the one the set was sealed to"):
        ss.open_sealed(sealed, attacker)


def test_application_key_digest_is_recorded_and_published(enclave):
    _, public = enclave
    sealed = ss.seal("frontend_v0", _items(), public)
    assert sealed.application_key_sha256 == ss.application_key_sha256(public)
    # docs/KEY_RELEASE.md requires this digest be checkable by a verifier.
    assert sealed.manifest()["application_key_sha256"] == sealed.application_key_sha256


def test_attestation_binding_is_enforced_when_supplied(enclave):
    private, public = enclave
    sealed = ss.seal("frontend_v0", _items(), public)
    ok = ss.open_sealed(
        sealed, private,
        attested_application_key_sha256=sealed.application_key_sha256)
    assert len(ok) == 8
    # A quote that committed to a different application key must not open it,
    # even though this enclave holds the correct private key.
    other = ss.application_key_sha256(X25519PrivateKey.generate().public_key().public_bytes_raw())
    with pytest.raises(ss.SealedSetError, match="attestation does not bind"):
        ss.open_sealed(sealed, private, attested_application_key_sha256=other)


def test_relabelling_a_set_fails_authentication(enclave):
    private, public = enclave
    sealed = ss.seal("frontend_v0", _items(), public)
    # Claim the easy set's ciphertext is actually the hard set.
    forged = dataclasses.replace(sealed, evalset_id="frontend_hard_v0")
    with pytest.raises(ss.SealedSetError, match="authenticated decryption"):
        ss.open_sealed(forged, private)


def test_tampered_ciphertext_is_rejected(enclave):
    private, public = enclave
    sealed = ss.seal("frontend_v0", _items(), public)
    flipped = bytearray(sealed.ciphertext)
    flipped[0] ^= 0x01
    with pytest.raises(ss.SealedSetError, match="authenticated decryption"):
        ss.open_sealed(dataclasses.replace(sealed, ciphertext=bytes(flipped)), private)


def test_digest_is_independent_of_authoring_order():
    items = _items()
    a = ss.canonical_set("frontend_v0", items)
    b = ss.canonical_set("frontend_v0", list(reversed(items)))
    assert a == b


def test_duplicate_item_ids_are_rejected():
    item = _items(1)[0]
    with pytest.raises(ss.SealedSetError, match="duplicate"):
        ss.canonical_set("frontend_v0", [item, item])


def test_empty_set_is_rejected():
    with pytest.raises(ss.SealedSetError, match="at least one item"):
        ss.canonical_set("frontend_v0", [])


def test_shard_rotation_is_deterministic_and_moves():
    items = _items(64)
    first = {i.item_id for i in ss.rotate_holdout(items, epoch=1, shards=4, active=2)}
    again = {i.item_id for i in ss.rotate_holdout(items, epoch=1, shards=4, active=2)}
    later = {i.item_id for i in ss.rotate_holdout(items, epoch=2, shards=4, active=2)}
    assert first == again, "a validator must be able to reproduce the selection"
    assert first != later, "the live holdout must move between epochs"


def test_shard_rotation_rejects_bad_config():
    with pytest.raises(ss.SealedSetError, match="invalid shard"):
        ss.rotate_holdout(_items(), epoch=0, shards=2, active=5)


def test_canaries_are_discoverable_by_the_validator():
    assert ss.contamination_canaries(_items()) == ["fe-003"]
