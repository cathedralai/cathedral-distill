"""Sealing for evaluation sets.

The threat is simple and fatal if unhandled: a miner who can read the eval set
trains on it, and the score stops measuring capability. Hashing the set does not
help — a digest pins which set was used but does nothing to keep it secret.

So the set travels as ciphertext. The data key is wrapped to an enclave X25519
key and released only against an accepted attestation grant, which is exactly
what `cathedral.key_release` already brokers. This module is deliberately thin:
it produces the ciphertext and the digests the receipt commits to, and hands the
wrapped key to that existing machinery rather than inventing a second custody
path.

Note on what sealing does and does not buy. Sealing stops a miner from reading
the set. It does not stop a miner from *learning* the set across many runs by
observing per-item pass/fail, which is why the receipt reports only an aggregate
score and a Merkle root, and why `rotate_holdout` exists: shards retire on a
schedule so leakage through repeated scoring stays bounded.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cathedral_distill.eval_receipt import canonical_json, sha256_digest

SET_SCHEMA = "cathedral_evalset_v1"
SEALED_SCHEMA = "cathedral_sealed_evalset_v1"

# Domain separation, matching the convention used across cathedral_thin.
WRAP_INFO = b"cathedral-evalset-key-wrap-v1\x00"
AAD_DOMAIN = b"cathedral-evalset-aad-v1\x00"

NONCE_BYTES = 12
KEY_BYTES = 32


class SealedSetError(ValueError):
    """Raised when an eval set cannot be sealed or opened."""


@dataclass(frozen=True)
class EvalItem:
    """One graded task.

    `item_id` is public and appears in the Merkle tree. `prompt` and `checks`
    are secret: they are the part a miner must never see.
    """

    item_id: str
    prompt: str
    checks: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "prompt": self.prompt,
            "checks": dict(self.checks),
        }


@dataclass(frozen=True)
class SealedSet:
    """Ciphertext plus the digests a receipt commits to."""

    evalset_id: str
    ciphertext: bytes
    nonce: bytes
    wrapped_key: Mapping[str, Any]
    plaintext_digest: str
    sealed_digest: str
    item_count: int
    application_key_sha256: str

    def manifest(self) -> dict[str, Any]:
        """Public manifest. Safe to publish: contains no item content."""
        return {
            "schema": SEALED_SCHEMA,
            "evalset_id": self.evalset_id,
            "sealed_digest": self.sealed_digest,
            "plaintext_digest": self.plaintext_digest,
            "item_count": self.item_count,
            "application_key_sha256": self.application_key_sha256,
            "wrapped_key": dict(self.wrapped_key),
        }


def canonical_set(evalset_id: str, items: Sequence[EvalItem]) -> bytes:
    """Serialise a set to the one byte form its digest refers to."""
    if not items:
        raise SealedSetError("an eval set must contain at least one item")
    seen = set()
    for item in items:
        if not item.item_id:
            raise SealedSetError("item_id must be non-empty")
        if item.item_id in seen:
            raise SealedSetError(f"duplicate item_id: {item.item_id}")
        seen.add(item.item_id)
    body = {
        "schema": SET_SCHEMA,
        "evalset_id": evalset_id,
        # Sorted so the digest does not depend on authoring order.
        "items": [item.as_dict() for item in sorted(items, key=lambda i: i.item_id)],
    }
    return canonical_json(body)


def _aad(evalset_id: str, plaintext_digest: str) -> bytes:
    """Bind the ciphertext to the identity of the set it encrypts.

    Without this, a sealed blob could be relabelled as a different evalset_id
    and a miner's score for an easy set could be presented as a score on a hard
    one.
    """
    return AAD_DOMAIN + canonical_json(
        {"evalset_id": evalset_id, "plaintext_digest": plaintext_digest}
    )


def _wrap_key(data_key: bytes, enclave_public: bytes) -> dict[str, Any]:
    """Wrap the data key to an enclave X25519 public key (HPKE-style)."""
    if len(enclave_public) != 32:
        raise SealedSetError("enclave public key must be 32 bytes")
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(enclave_public))
    kek = HKDF(
        algorithm=hashes.SHA256(), length=KEY_BYTES, salt=None, info=WRAP_INFO
    ).derive(shared)
    nonce = os.urandom(NONCE_BYTES)
    blob = AESGCM(kek).encrypt(nonce, data_key, WRAP_INFO)
    from base64 import b64encode

    return {
        "algorithm": "x25519-hkdf-sha256-aes256gcm",
        "ephemeral_public_base64": b64encode(
            ephemeral.public_key().public_bytes_raw()
        ).decode(),
        "nonce_base64": b64encode(nonce).decode(),
        "ciphertext_base64": b64encode(blob).decode(),
    }


def _unwrap_key(wrapped: Mapping[str, Any], enclave_private: X25519PrivateKey) -> bytes:
    from base64 import b64decode

    if wrapped.get("algorithm") != "x25519-hkdf-sha256-aes256gcm":
        raise SealedSetError("unsupported key wrap algorithm")
    try:
        ephemeral_public = b64decode(wrapped["ephemeral_public_base64"])
        nonce = b64decode(wrapped["nonce_base64"])
        blob = b64decode(wrapped["ciphertext_base64"])
    except Exception as exc:
        raise SealedSetError("malformed wrapped key") from exc
    shared = enclave_private.exchange(X25519PublicKey.from_public_bytes(ephemeral_public))
    kek = HKDF(
        algorithm=hashes.SHA256(), length=KEY_BYTES, salt=None, info=WRAP_INFO
    ).derive(shared)
    try:
        return AESGCM(kek).decrypt(nonce, blob, WRAP_INFO)
    except Exception as exc:
        raise SealedSetError("wrapped key did not open for this enclave") from exc


def seal(
    evalset_id: str,
    items: Sequence[EvalItem],
    enclave_public: bytes,
    *,
    data_key: bytes | None = None,
) -> SealedSet:
    """Encrypt a set and wrap its data key to an enclave."""
    plaintext = canonical_set(evalset_id, items)
    plaintext_digest = sha256_digest(plaintext)
    key = data_key or secrets.token_bytes(KEY_BYTES)
    if len(key) != KEY_BYTES:
        raise SealedSetError("data key must be 32 bytes")
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(
        nonce, plaintext, _aad(evalset_id, plaintext_digest)
    )
    return SealedSet(
        evalset_id=evalset_id,
        ciphertext=ciphertext,
        nonce=nonce,
        wrapped_key=_wrap_key(key, enclave_public),
        plaintext_digest=plaintext_digest,
        sealed_digest=sha256_digest(nonce + ciphertext),
        item_count=len(items),
        application_key_sha256=application_key_sha256(enclave_public),
    )


def application_key_sha256(enclave_public: bytes) -> str:
    """Digest of the enclave application key, per `docs/KEY_RELEASE.md`.

    Cathedral's key-release contract requires this digest to be bound into the
    worker's fresh attestation. Holding the private key is therefore not enough
    to open a set: the enclave must have been *attested with* that exact key.
    Recording it here is what lets a verifier check the two agree.
    """
    if len(enclave_public) != 32:
        raise SealedSetError("enclave public key must be 32 bytes")
    return sha256_digest(enclave_public)


def open_sealed(
    sealed: SealedSet,
    enclave_private: X25519PrivateKey,
    *,
    attested_application_key_sha256: str | None = None,
) -> list[EvalItem]:
    """Open a sealed set inside the enclave. Fails closed on any mismatch.

    `attested_application_key_sha256` is the digest the worker's TDX quote
    actually committed to. Passing it enforces the KEY_RELEASE binding; omitting
    it opens the set on key possession alone, which is only acceptable in the
    hardware-free path where no attestation exists to check against.
    """
    derived = application_key_sha256(
        enclave_private.public_key().public_bytes_raw()
    )
    if derived != sealed.application_key_sha256:
        raise SealedSetError(
            "this enclave key is not the one the set was sealed to"
        )
    if (
        attested_application_key_sha256 is not None
        and attested_application_key_sha256 != sealed.application_key_sha256
    ):
        raise SealedSetError(
            "attestation does not bind the application key this set was sealed to"
        )
    key = _unwrap_key(sealed.wrapped_key, enclave_private)
    try:
        plaintext = AESGCM(key).decrypt(
            sealed.nonce,
            sealed.ciphertext,
            _aad(sealed.evalset_id, sealed.plaintext_digest),
        )
    except Exception as exc:
        raise SealedSetError("sealed set failed authenticated decryption") from exc
    if sha256_digest(plaintext) != sealed.plaintext_digest:
        raise SealedSetError("opened set does not match its committed digest")
    body = json.loads(plaintext)
    if body.get("schema") != SET_SCHEMA or body.get("evalset_id") != sealed.evalset_id:
        raise SealedSetError("opened set has the wrong identity")
    return [
        EvalItem(
            item_id=entry["item_id"], prompt=entry["prompt"], checks=entry["checks"]
        )
        for entry in body["items"]
    ]


def rotate_holdout(
    items: Sequence[EvalItem], *, epoch: int, shards: int, active: int
) -> list[EvalItem]:
    """Select the shards live at a given epoch.

    Repeated scoring against a fixed set leaks it one bit at a time. Rotating
    which shards are live bounds how much any single miner can learn, and makes
    a contaminated score decay instead of persisting.

    Assignment is deterministic from item_id, so the same item always lands in
    the same shard and a validator can reproduce the selection.
    """
    if shards <= 0 or active <= 0 or active > shards:
        raise SealedSetError("invalid shard configuration")
    chosen = {(epoch + offset) % shards for offset in range(active)}
    selected = [
        item
        for item in items
        if int.from_bytes(
            hashlib.sha256(item.item_id.encode()).digest()[:4], "big"
        )
        % shards
        in chosen
    ]
    if not selected:
        raise SealedSetError("shard rotation selected no items")
    return selected


def contamination_canaries(items: Iterable[EvalItem]) -> list[str]:
    """Item ids marked as canaries.

    A canary is an item whose correct answer is not derivable from public data —
    it is only obtainable by having seen the sealed set. A miner scoring well on
    canaries has read the test, and that is a contamination signal no amount of
    attestation would otherwise surface.
    """
    return sorted(
        item.item_id for item in items if bool(item.checks.get("canary", False))
    )
