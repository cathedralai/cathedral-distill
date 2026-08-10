"""v3 CyberGym receipt: the canonical-environment block (reproduce timeout, resource
limits, network policy, verifier image digest) is pinned into the SIGNED body so a
peer re-deriving the score can confirm the exact conditions — bound by the signature,
validated fail-closed, and with v1/v2 left byte-for-byte unchanged.
"""
from __future__ import annotations

import hashlib
import sys
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym_receipt as cr  # noqa: E402
from cathedral_distill.cybergym import BatchScore  # noqa: E402
from cathedral_distill.receipt_keys import ReceiptKeyRegistry  # noqa: E402

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
KEYREG = ReceiptKeyRegistry.from_keys({"cg-test-1": KEY.public_key().public_bytes_raw()})
NOW = "2026-08-10T12:00:00.000000Z"
EPOCH = 11


def _digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _score() -> BatchScore:
    # earned = per_level_solved[2] * DEFAULT weight[2] (2) = 2*2 = 4; score = 4/8.
    return BatchScore(
        batch_id=_digest("batch"), graded_tasks=4, solved_tasks=2,
        earned_units=Decimal("4"), max_units=Decimal("8"), score=Decimal("0.5"),
        items_root=_digest("items"), per_level_solved={0: 0, 1: 0, 2: 2, 3: 0},
    )


GOOD_ENV = {
    "reproduce_timeout_s": "120", "cpu_seconds": "60", "memory_bytes": "unlimited",
    "network_policy": "none", "verifier_digest": _digest("verifier"),
}


def _build(*, env=None, eligibility=_digest("elig")):
    return cr.build_receipt(
        _score(), network="finney", netuid=39, source_epoch=EPOCH,
        validator_hotkey="5Val", miner_hotkey="5Miner", nonce="nonce-1",
        holdout_digest_value=_digest("holdout"), eligibility_snapshot_digest=eligibility,
        valid_from_block=100, valid_until_block=460, issued_at=NOW,
        private_key=KEY, signing_key_id="cg-test-1", env=env,
    )


# --------------------------------------------------------------------------- #
# Happy path + binding
# --------------------------------------------------------------------------- #

def test_v3_roundtrip():
    r = _build(env=GOOD_ENV)
    assert r["schema"] == cr.RECEIPT_SCHEMA_V3
    assert r["env"] == GOOD_ENV
    cr.validate_structure(r)
    cr.verify_receipt(r, KEYREG, source_epoch=EPOCH)  # signature covers env


def test_env_is_signature_bound():
    r = _build(env=GOOD_ENV)
    r["env"]["reproduce_timeout_s"] = "999"  # tamper, do not re-sign
    with pytest.raises(cr.CyberGymReceiptError):
        cr.verify_receipt(r, KEYREG, source_epoch=EPOCH)


def test_memory_bytes_decimal_also_accepted():
    env = {**GOOD_ENV, "memory_bytes": "2147483648"}
    r = _build(env=env)
    cr.verify_receipt(r, KEYREG, source_epoch=EPOCH)


# --------------------------------------------------------------------------- #
# Backward compatibility — v1/v2 untouched
# --------------------------------------------------------------------------- #

def test_v2_unchanged_no_env_key():
    r = _build(env=None)  # eligibility set, no env
    assert r["schema"] == cr.RECEIPT_SCHEMA_V2
    assert "env" not in r
    cr.verify_receipt(r, KEYREG, source_epoch=EPOCH)


def test_v1_unchanged():
    r = _build(env=None, eligibility=None)
    assert r["schema"] == cr.RECEIPT_SCHEMA_V1
    assert "env" not in r
    cr.verify_receipt(r, KEYREG, source_epoch=EPOCH)


def test_env_on_a_v1_or_v2_receipt_is_rejected():
    # A non-v3 receipt carrying an `env` key is an unknown-key error (strict set).
    r = _build(env=None)
    r["env"] = GOOD_ENV
    with pytest.raises(cr.CyberGymReceiptError):
        cr.validate_structure(r)


def test_v3_without_env_key_is_rejected():
    r = _build(env=GOOD_ENV)
    del r["env"]
    with pytest.raises(cr.CyberGymReceiptError):
        cr.validate_structure(r)


# --------------------------------------------------------------------------- #
# Fail-closed env validation
# --------------------------------------------------------------------------- #

def test_env_requires_eligibility():
    with pytest.raises(cr.CyberGymReceiptError):
        _build(env=GOOD_ENV, eligibility=None)


@pytest.mark.parametrize("field,bad", [
    ("reproduce_timeout_s", "soon"),
    ("cpu_seconds", "-1"),
    ("memory_bytes", "lots"),
    ("network_policy", "allow_all"),
    ("verifier_digest", "deadbeef"),
])
def test_env_bad_field_rejected(field, bad):
    r = _build(env=GOOD_ENV)
    r["env"][field] = bad
    with pytest.raises(cr.CyberGymReceiptError):
        cr.validate_structure(r)


@pytest.mark.parametrize("mutate", [
    lambda e: e.pop("network_policy"),
    lambda e: e.update({"extra": "x"}),
])
def test_env_key_set_is_exact(mutate):
    r = _build(env=GOOD_ENV)
    mutate(r["env"])
    with pytest.raises(cr.CyberGymReceiptError):
        cr.validate_structure(r)
