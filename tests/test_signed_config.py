"""Remote-controlled burn + mechanism-allocation config (issue cathedral-validator#1).

Proves a validator can change the burn fraction and the Compute-vs-Distill split
without a redeploy, but only from a Cathedral-signed, versioned config, verified
for signer authority, network/subnet target, freshness, rollback protection, and
burn destination before it is applied.
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import signed_config as sc  # noqa: E402
from cathedral_distill.receipt_keys import ReceiptKeyRegistry  # noqa: E402

_SEED = bytes(range(1, 33))
KEY = Ed25519PrivateKey.from_private_bytes(_SEED)
KEYREG = ReceiptKeyRegistry.from_keys({"cathedral-config-1": KEY.public_key().public_bytes_raw()})
NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)


def _envelope(schema: str, *, version: int = 1) -> dict:
    return {
        "schema": schema,
        "config_version": version,
        "network": "finney",
        "netuid": 39,
        "generated_at": "2026-07-25T11:30:00Z",
        "valid_from": "2026-07-25T00:00:00Z",
        "valid_until": "2026-08-01T00:00:00Z",
        "signing_key_id": "cathedral-config-1",
    }


def _burn_bytes(*, version=1, fraction="0.10", burn_hotkey="5Burn", key=KEY, signing_key_id=None):
    doc = _envelope(sc.BURN_CONFIG_SCHEMA, version=version)
    if signing_key_id is not None:
        doc["signing_key_id"] = signing_key_id
    doc["burn"] = {"fraction": fraction, "burn_hotkey": burn_hotkey}
    signed = sc.sign_config(doc, key.private_bytes_raw())
    return json.dumps(signed).encode()


def _alloc_bytes(*, version=1, allocations=None, key=KEY):
    doc = _envelope(sc.ALLOCATION_CONFIG_SCHEMA, version=version)
    doc["allocations"] = allocations or [
        {"lane": "cathedral_confidential_tdx", "allocation": "0.45", "enabled": True},
        {"lane": "cathedral_distill", "allocation": "0.45", "enabled": True},
    ]
    signed = sc.sign_config(doc, key.private_bytes_raw())
    return json.dumps(signed).encode()


def _verify_burn(data, **kw):
    return sc.verify_burn_config(data, KEYREG, network="finney", netuid=39, now=NOW, **kw)


def _verify_alloc(data, **kw):
    return sc.verify_allocation_config(data, KEYREG, network="finney", netuid=39, now=NOW, **kw)


# --------------------------------------------------------------------------- #
# Happy path + resolve
# --------------------------------------------------------------------------- #

def test_signed_burn_and_allocation_resolve_into_composer_inputs():
    burn = _verify_burn(_burn_bytes())
    alloc = _verify_alloc(_alloc_bytes())
    assert burn.fraction == Decimal("0.10") and burn.burn_hotkey == "5Burn"
    assert alloc.allocations["cathedral_distill"] == (Decimal("0.45"), True)

    resolved = sc.resolve_allocation(burn, alloc)
    assert resolved.burn_fraction == Decimal("0.10")
    assert resolved.burn_hotkey == "5Burn"
    assert resolved.lane_allocations == {
        "cathedral_confidential_tdx": Decimal("0.45"),
        "cathedral_distill": Decimal("0.45"),
    }
    assert resolved.config_versions == (1, 1)


def test_disabled_lane_share_folds_into_burn_completeness():
    # GPU lane present but disabled: its share must be accounted to burn, so the
    # completeness invariant is enabled-allocations + burn == 1.
    burn = _verify_burn(_burn_bytes(fraction="0.20"))
    alloc = _verify_alloc(_alloc_bytes(allocations=[
        {"lane": "cathedral_confidential_tdx", "allocation": "0.45", "enabled": True},
        {"lane": "cathedral_confidential_gpu", "allocation": "0.35", "enabled": False},
        {"lane": "cathedral_distill", "allocation": "0.35", "enabled": True},
    ]))
    resolved = sc.resolve_allocation(burn, alloc)
    assert set(resolved.lane_allocations) == {"cathedral_confidential_tdx", "cathedral_distill"}
    assert resolved.burn_fraction == Decimal("0.20")  # 0.45 + 0.35 + 0.20 == 1


def test_adding_a_lane_is_config_driven():
    # A third enabled lane is just a new allocation entry — no code change.
    burn = _verify_burn(_burn_bytes(fraction="0.10"))
    alloc = _verify_alloc(_alloc_bytes(allocations=[
        {"lane": "cathedral_confidential_tdx", "allocation": "0.40", "enabled": True},
        {"lane": "cathedral_confidential_gpu", "allocation": "0.20", "enabled": True},
        {"lane": "cathedral_distill", "allocation": "0.30", "enabled": True},
    ]))
    resolved = sc.resolve_allocation(burn, alloc)
    assert len(resolved.lane_allocations) == 3


# --------------------------------------------------------------------------- #
# Reject paths — one per verified property
# --------------------------------------------------------------------------- #

def test_unknown_signing_key_id_is_refused():
    # an id the anchored registry does not carry -> cannot be resolved
    with pytest.raises(sc.SignedConfigError, match="signing key could not be resolved"):
        _verify_burn(_burn_bytes(signing_key_id="cathedral-config-unknown"))


def test_wrong_key_breaks_signature():
    # id resolves to the anchored key, but the doc was signed by a different key
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    with pytest.raises(sc.SignedConfigError, match="signature verification failed"):
        _verify_burn(_burn_bytes(key=other))


def test_tampered_body_breaks_signature():
    doc = json.loads(_burn_bytes().decode())
    doc["burn"]["fraction"] = "0.90"  # flip the fraction after signing
    with pytest.raises(sc.SignedConfigError, match="signature verification failed"):
        _verify_burn(json.dumps(doc).encode())


def test_wrong_network_is_refused():
    with pytest.raises(sc.SignedConfigError, match="network does not match"):
        sc.verify_burn_config(_burn_bytes(), KEYREG, network="test", netuid=39, now=NOW)


def test_wrong_netuid_is_refused():
    with pytest.raises(sc.SignedConfigError, match="netuid does not match"):
        sc.verify_burn_config(_burn_bytes(), KEYREG, network="finney", netuid=1, now=NOW)


def test_rollback_to_older_version_is_refused():
    # a config older than the applied fence is a rollback attack
    with pytest.raises(sc.SignedConfigError, match="rollback"):
        _verify_burn(_burn_bytes(version=3), min_version=5)


def test_same_or_newer_version_is_accepted():
    assert _verify_burn(_burn_bytes(version=5), min_version=5).config_version == 5
    assert _verify_burn(_burn_bytes(version=6), min_version=5).config_version == 6


def test_stale_config_is_refused():
    late = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)  # >24h after generated_at
    with pytest.raises(sc.SignedConfigError, match="too stale"):
        sc.verify_burn_config(_burn_bytes(), KEYREG, network="finney", netuid=39, now=late)


def test_outside_validity_window_is_refused():
    early = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)  # before valid_from
    with pytest.raises(sc.SignedConfigError, match="validity window"):
        sc.verify_burn_config(_burn_bytes(), KEYREG, network="finney", netuid=39, now=early)


def test_pinned_burn_destination_mismatch_is_refused():
    with pytest.raises(sc.SignedConfigError, match="burn destination"):
        _verify_burn(_burn_bytes(burn_hotkey="5Attacker"), expected_burn_hotkey="5Burn")


def test_incoherent_allocation_pair_is_refused():
    burn = _verify_burn(_burn_bytes(fraction="0.10"))
    alloc = _verify_alloc(_alloc_bytes(allocations=[
        {"lane": "cathedral_confidential_tdx", "allocation": "0.45", "enabled": True},
    ]))  # 0.45 + 0.10 != 1
    with pytest.raises(sc.SignedConfigError, match="sum to exactly 1"):
        sc.resolve_allocation(burn, alloc)


def test_unknown_field_fails_closed():
    doc = _envelope(sc.BURN_CONFIG_SCHEMA)
    doc["burn"] = {"fraction": "0.10", "burn_hotkey": "5Burn"}
    doc["surprise"] = 1
    signed = sc.sign_config(doc, KEY.private_bytes_raw())
    with pytest.raises(sc.SignedConfigError, match="unknown fields"):
        _verify_burn(json.dumps(signed).encode())


def test_float_in_config_is_refused():
    # canonical bytes reject floats — a signer cannot smuggle a float fraction
    doc = _envelope(sc.BURN_CONFIG_SCHEMA)
    doc["burn"] = {"fraction": 0.10, "burn_hotkey": "5Burn"}  # float, not decimal string
    with pytest.raises(Exception):
        sc.sign_config(doc, KEY.private_bytes_raw())
