"""A signed registry that resolves a receipt's `signing_key_id` to an anchored key.

A receipt verifier must never trust a caller-supplied public key: an attacker
would sign with its own key and hand you the matching public key, and the
signature would "verify". The compute receipt resolves `signing_key_id` through a
signed policy/key registry; this is the Distill/CyberGym equivalent — the same
trust shape as `cathedralconfidential`'s coldkey allowlist: canonical JSON, an
Ed25519 signature over the unsigned document by a *trusted root* key, a validity
window, a publication-age ceiling, per-key status and validity, and bounded
encoding. The verifier looks up the receipt's `signing_key_id` here and uses the
key the registry anchors — nothing the claimant supplies.

`verify_key_registry` is the production path (a signed artifact + trusted roots).
`ReceiptKeyRegistry.from_keys` builds an unsigned registry for the hardware-free
path only, where there is no signed registry to anchor against; it still forces
resolution by `key_id`, so a receipt can never carry its own verifying key.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral_distill.distill_receipt import canonical_bytes  # shared canonical rule

REGISTRY_SCHEMA = "cathedral_receipt_key_registry_v1"
MAX_REGISTRY_BYTES = 1024 * 1024
MAX_KEYS = 4096
DEFAULT_MAX_AGE_SECONDS = 86_400

_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TIME_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_TOP_KEYS = frozenset(
    {"schema", "release", "generated_at", "valid_from", "valid_until",
     "registry_key_id", "keys", "signature"}
)
_KEY_KEYS = frozenset({"key_id", "public_key_base64", "valid_from", "valid_until", "status"})
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})


class ReceiptKeyError(ValueError):
    """A key registry or a key resolution failed. Fails closed."""


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise ReceiptKeyError(f"{name} must be canonical UTC time")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


@dataclass(frozen=True)
class ReceiptKey:
    key_id: str
    public_key: bytes
    valid_from: datetime
    valid_until: datetime
    status: str

    def usable_at(self, at: datetime) -> bool:
        return self.status == "active" and self.valid_from <= at < self.valid_until


class ReceiptKeyRegistry:
    """Resolves a `signing_key_id` to the anchored `Ed25519PublicKey`."""

    def __init__(self, keys: Mapping[str, ReceiptKey]) -> None:
        self._keys = dict(keys)

    def resolve(self, key_id: object, *, at: datetime) -> Ed25519PublicKey:
        if not isinstance(key_id, str) or _ID_RE.fullmatch(key_id) is None:
            raise ReceiptKeyError("receipt signing_key_id is invalid")
        key = self._keys.get(key_id)
        if key is None:
            raise ReceiptKeyError(f"signing key {key_id!r} is not in the registry")
        if not key.usable_at(at):
            raise ReceiptKeyError(f"signing key {key_id!r} is retired, revoked, or out of window")
        return Ed25519PublicKey.from_public_bytes(key.public_key)

    def evidence_identity(self) -> dict[str, object]:
        """Stable semantic identity for restart-pinned reward evidence.

        Reproduction admission depends on key bytes, status and validity windows.
        Those exact inputs are canonicalized here so changing a key registry while
        an epoch is in flight cannot silently change which peer receipt verifies.
        """
        rows = [
            {
                "key_id": key.key_id,
                "public_key_base64": base64.b64encode(key.public_key).decode("ascii"),
                "valid_from": key.valid_from.isoformat(),
                "valid_until": key.valid_until.isoformat(),
                "status": key.status,
            }
            for key in sorted(self._keys.values(), key=lambda item: item.key_id)
        ]
        body = {
            "schema": "cathedral_receipt_key_registry_identity_v1",
            "keys": rows,
        }
        return {
            "schema": body["schema"],
            "digest": "sha256:" + hashlib.sha256(canonical_bytes(body)).hexdigest(),
            "keys": len(rows),
        }

    @classmethod
    def from_keys(
        cls,
        keys: Mapping[str, bytes],
        *,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
    ) -> "ReceiptKeyRegistry":
        """Unsigned registry for the hardware-free path. Every key is active over
        a wide window; production uses `verify_key_registry` instead."""
        vf = valid_from or datetime(2000, 1, 1, tzinfo=UTC)
        vu = valid_until or datetime(2100, 1, 1, tzinfo=UTC)
        resolved: dict[str, ReceiptKey] = {}
        for key_id, public in keys.items():
            if not isinstance(public, bytes) or len(public) != 32:
                raise ReceiptKeyError("public key must be 32 bytes")
            resolved[key_id] = ReceiptKey(key_id, public, vf, vu, "active")
        return cls(resolved)


def verify_key_registry(
    data: bytes,
    trusted_roots: Mapping[str, bytes],
    *,
    now: datetime | None = None,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> ReceiptKeyRegistry:
    """Verify a signed key-registry artifact and return the resolver.

    Fails closed on any schema, signature, window, or staleness failure. The
    signature is checked against `trusted_roots[registry_key_id]` — the operator
    root that anchors the whole registry — so no key in it is self-asserted.
    """
    import json

    if not isinstance(data, bytes) or not data or len(data) > MAX_REGISTRY_BYTES:
        raise ReceiptKeyError("key registry is empty or oversized")
    try:
        document = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReceiptKeyError("key registry is not UTF-8 JSON") from exc
    if not isinstance(document, dict) or frozenset(document) != _TOP_KEYS:
        raise ReceiptKeyError("key registry has missing or unknown fields")
    if document["schema"] != REGISTRY_SCHEMA:
        raise ReceiptKeyError("key registry schema is unsupported")

    root_id = document["registry_key_id"]
    if not isinstance(root_id, str) or _ID_RE.fullmatch(root_id) is None:
        raise ReceiptKeyError("registry_key_id is invalid")
    root = trusted_roots.get(root_id)
    if not isinstance(root, bytes) or len(root) != 32:
        raise ReceiptKeyError("registry root key is not trusted")

    signature = document["signature"]
    if not isinstance(signature, dict) or frozenset(signature) != _SIGNATURE_KEYS:
        raise ReceiptKeyError("registry signature object is invalid")
    if signature["algorithm"] != "ed25519":
        raise ReceiptKeyError("registry signature algorithm is unsupported")
    try:
        signature_bytes = base64.b64decode(signature["value_base64"], validate=True)
    except (TypeError, binascii.Error, ValueError) as exc:
        raise ReceiptKeyError("registry signature is not canonical base64") from exc
    if len(signature_bytes) != 64:
        raise ReceiptKeyError("registry signature must be 64 bytes")
    unsigned = {k: v for k, v in document.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(root).verify(signature_bytes, canonical_bytes(unsigned))
    except (InvalidSignature, ValueError) as exc:
        raise ReceiptKeyError("registry signature verification failed") from exc

    generated = _timestamp(document["generated_at"], "generated_at")
    valid_from = _timestamp(document["valid_from"], "valid_from")
    valid_until = _timestamp(document["valid_until"], "valid_until")
    if not valid_from < valid_until:
        raise ReceiptKeyError("registry validity window is invalid")
    check = now or datetime.now(UTC)
    if check.tzinfo is None or check.utcoffset() != timedelta(0):
        raise ReceiptKeyError("verification time must be UTC")
    if not valid_from <= check < valid_until:
        raise ReceiptKeyError("key registry is outside its validity window")
    if (isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int)
            or max_age_seconds <= 0):
        raise ReceiptKeyError("max_age_seconds must be positive")
    if check - generated > timedelta(seconds=max_age_seconds):
        raise ReceiptKeyError("key registry is too stale")

    keys_raw = document["keys"]
    if not isinstance(keys_raw, list) or len(keys_raw) > MAX_KEYS:
        raise ReceiptKeyError("registry keys must be a bounded list")
    keys: dict[str, ReceiptKey] = {}
    for entry in keys_raw:
        if not isinstance(entry, dict) or frozenset(entry) != _KEY_KEYS:
            raise ReceiptKeyError("registry key entry has missing or unknown fields")
        key_id = entry["key_id"]
        if not isinstance(key_id, str) or _ID_RE.fullmatch(key_id) is None:
            raise ReceiptKeyError("registry key_id is invalid")
        if key_id in keys:
            raise ReceiptKeyError(f"duplicate key_id {key_id!r}")
        try:
            public = base64.b64decode(entry["public_key_base64"], validate=True)
        except (TypeError, binascii.Error, ValueError) as exc:
            raise ReceiptKeyError("registry public key is not canonical base64") from exc
        if len(public) != 32:
            raise ReceiptKeyError("registry public key must be 32 bytes")
        if entry["status"] not in ("active", "retired", "revoked"):
            raise ReceiptKeyError("registry key status is invalid")
        keys[key_id] = ReceiptKey(
            key_id=key_id, public_key=public,
            valid_from=_timestamp(entry["valid_from"], "key valid_from"),
            valid_until=_timestamp(entry["valid_until"], "key valid_until"),
            status=entry["status"],
        )
    return ReceiptKeyRegistry(keys)


def sign_key_registry(unsigned_document: Mapping[str, object], root_private_seed: bytes) -> dict:
    """Attach an Ed25519 signature to an unsigned key-registry document."""
    if "signature" in unsigned_document:
        raise ReceiptKeyError("unsigned registry must not carry a signature")
    if not isinstance(root_private_seed, bytes) or len(root_private_seed) != 32:
        raise ReceiptKeyError("root private seed must be 32 bytes")
    document = dict(unsigned_document)
    signature = Ed25519PrivateKey.from_private_bytes(root_private_seed).sign(
        canonical_bytes(document)
    )
    document["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return document


def registry_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


__all__ = [
    "ReceiptKeyError", "ReceiptKey", "ReceiptKeyRegistry",
    "verify_key_registry", "sign_key_registry", "registry_digest", "REGISTRY_SCHEMA",
]
