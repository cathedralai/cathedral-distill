"""The signed receipt key registry (#3.3): a verifier resolves signing_key_id to
an anchored key, and never trusts a caller-supplied key."""
from __future__ import annotations

import base64
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import receipt_keys as rk  # noqa: E402

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
ROOT_SEED = bytes(range(64, 96))
ROOT = Ed25519PrivateKey.from_private_bytes(ROOT_SEED)
ROOT_PUB = ROOT.public_key().public_bytes_raw()
SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
SIGNER_PUB = SIGNER.public_key().public_bytes_raw()
TRUSTED = {"root-1": ROOT_PUB}


def _fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _unsigned(**over):
    doc = {
        "schema": rk.REGISTRY_SCHEMA,
        "release": 1,
        "generated_at": _fmt(NOW - timedelta(minutes=5)),
        "valid_from": _fmt(NOW - timedelta(days=1)),
        "valid_until": _fmt(NOW + timedelta(days=1)),
        "registry_key_id": "root-1",
        "keys": [{
            "key_id": "distill-1",
            "public_key_base64": base64.b64encode(SIGNER_PUB).decode(),
            "valid_from": _fmt(NOW - timedelta(days=1)),
            "valid_until": _fmt(NOW + timedelta(days=1)),
            "status": "active",
        }],
    }
    doc.update(over)
    return doc


def _signed(**over) -> bytes:
    return json.dumps(rk.sign_key_registry(_unsigned(**over), ROOT_SEED)).encode()


def test_signed_registry_resolves_the_anchored_key():
    reg = rk.verify_key_registry(_signed(), TRUSTED, now=NOW)
    pub = reg.resolve("distill-1", at=NOW)
    # the resolved key verifies a signature made by SIGNER
    sig = SIGNER.sign(b"payload")
    pub.verify(sig, b"payload")  # no raise


def test_untrusted_root_is_rejected():
    with pytest.raises(rk.ReceiptKeyError, match="root key is not trusted"):
        rk.verify_key_registry(_signed(), {"other": ROOT_PUB}, now=NOW)


def test_tampered_document_fails_signature():
    data = _signed()
    doc = json.loads(data)
    doc["keys"][0]["public_key_base64"] = base64.b64encode(bytes(range(1, 33))).decode()
    with pytest.raises(rk.ReceiptKeyError, match="signature verification failed"):
        rk.verify_key_registry(json.dumps(doc).encode(), TRUSTED, now=NOW)


def test_stale_registry_is_rejected():
    old = _signed(generated_at=_fmt(NOW - timedelta(days=3)))
    with pytest.raises(rk.ReceiptKeyError, match="too stale"):
        rk.verify_key_registry(old, TRUSTED, now=NOW)


def test_outside_validity_window_is_rejected():
    future = _signed(valid_from=_fmt(NOW + timedelta(hours=1)),
                     valid_until=_fmt(NOW + timedelta(days=1)),
                     generated_at=_fmt(NOW))
    with pytest.raises(rk.ReceiptKeyError, match="validity window"):
        rk.verify_key_registry(future, TRUSTED, now=NOW)


def test_unknown_key_id_does_not_resolve():
    reg = rk.verify_key_registry(_signed(), TRUSTED, now=NOW)
    with pytest.raises(rk.ReceiptKeyError, match="not in the registry"):
        reg.resolve("distill-999", at=NOW)


def test_revoked_key_does_not_resolve():
    doc = _unsigned()
    doc["keys"][0]["status"] = "revoked"
    with pytest.raises(rk.ReceiptKeyError, match="retired, revoked, or out of window"):
        rk.verify_key_registry(json.dumps(rk.sign_key_registry(doc, ROOT_SEED)).encode(),
                               TRUSTED, now=NOW).resolve("distill-1", at=NOW)


def test_key_used_before_its_window_does_not_resolve():
    reg = rk.verify_key_registry(_signed(), TRUSTED, now=NOW)
    with pytest.raises(rk.ReceiptKeyError, match="out of window"):
        reg.resolve("distill-1", at=NOW - timedelta(days=2))


def test_from_keys_still_forces_resolution_by_id():
    # the hardware-free path: no caller-supplied key, still resolved by key_id
    reg = rk.ReceiptKeyRegistry.from_keys({"distill-1": SIGNER_PUB})
    assert reg.resolve("distill-1", at=NOW).public_bytes_raw() == SIGNER_PUB
    with pytest.raises(rk.ReceiptKeyError, match="not in the registry"):
        reg.resolve("nope", at=NOW)
