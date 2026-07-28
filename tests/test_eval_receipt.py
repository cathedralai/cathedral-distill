"""Tests for cathedral_ml_eval_receipt_v1.

These target the properties a miner would attack, not the happy path: claiming
a score that its own item counts do not support, submitting an unencrypted
"sealed" set, replaying another run's quote, and grading a subset of the set.
"""
from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import eval_receipt as er  # noqa: E402


def _digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _receipt(**overrides):
    leaves = [
        er.item_leaf(index, f"item-{index}", _digest(f"out-{index}"), index < 7)
        for index in range(10)
    ]
    document = {
        "schema": er.SCHEMA,
        "network": "finney",
        "netuid": 39,
        "source_epoch": 4211,
        "eval_id": _digest("eval"),
        "validator_hotkey": "5Validator",
        "miner_hotkey": "5Miner",
        "nonce_base64": "3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "issued_at": "2026-07-25T09:00:00Z",
        "completed_at": "2026-07-25T09:04:00Z",
        "valid_from_block": 6_000_000,
        "valid_until_block": 6_000_360,
        "model": {
            "model_id": "cathedral/student-frontend-4b",
            "weights_digest": _digest("weights"),
            "tokenizer_digest": _digest("tokenizer"),
        },
        "runtime": {
            "image_digest": _digest("image"),
            "runner_digest": _digest("runner"),
            "decode_digest": _digest("decode"),
        },
        "evalset": {
            "evalset_id": "frontend_v0",
            "sealed_digest": _digest("sealed"),
            "plaintext_digest": _digest("plain"),
            "item_count": 10,
            "key_grant_id": "grant-0001",
        },
        "grader": {
            "grader_id": "frontend_build_test_v0",
            "grader_digest": _digest("grader"),
            "harness_digest": _digest("harness"),
        },
        "score": {
            "graded_items": 10,
            "passed_items": 7,
            "score": "0.7",
            "items_root": er.items_root(leaves),
            "input_tokens": 4096,
            "output_tokens": 8192,
            "latency_p50_ms": "812.5",
            "latency_p95_ms": "1904.25",
            "work_units": "10",
        },
        "eval_authorization": None,
        "attestation": {
            "kind": "none",
            "evidence_digest": "",
            "evidence_uri": "",
            "policy_digest": "",
            "report_data_hex": "",
        },
    }
    for key, value in overrides.items():
        document[key] = value
    document["receipt_id"] = er.receipt_id_for(document)
    document["signature"] = {"algorithm": "sr25519", "value_base64": "AA=="}
    return document


def test_valid_receipt_round_trips():
    receipt = _receipt()
    assert er.validate_receipt(receipt)["netuid"] == 39


def test_unattested_receipt_is_valid_but_earns_nothing():
    # The honest mode: structurally sound, provably worth zero — even if the
    # verifier reports a passing quote, a "none" attestation earns nothing.
    receipt = _receipt()
    assert er.validate_receipt(receipt)
    assert er.creditable_as_verified_work(receipt, attestation_verified=True) is False


def test_score_must_match_item_counts():
    receipt = _receipt()
    receipt["score"]["score"] = "0.95"
    receipt["receipt_id"] = er.receipt_id_for(receipt)
    with pytest.raises(er.EvalReceiptError, match="does not match"):
        er.validate_receipt(receipt)


def test_passed_cannot_exceed_graded():
    receipt = _receipt()
    receipt["score"]["passed_items"] = 11
    receipt["receipt_id"] = er.receipt_id_for(receipt)
    with pytest.raises(er.EvalReceiptError, match="exceeds"):
        er.validate_receipt(receipt)


def test_partial_run_is_rejected():
    # Grading only the easy half of the set is not a score.
    receipt = _receipt()
    receipt["score"]["graded_items"] = 5
    receipt["score"]["passed_items"] = 5
    receipt["score"]["score"] = "1"
    receipt["receipt_id"] = er.receipt_id_for(receipt)
    with pytest.raises(er.EvalReceiptError, match="item_count"):
        er.validate_receipt(receipt)


def test_unencrypted_set_is_rejected():
    receipt = _receipt()
    receipt["evalset"]["sealed_digest"] = receipt["evalset"]["plaintext_digest"]
    receipt["receipt_id"] = er.receipt_id_for(receipt)
    with pytest.raises(er.EvalReceiptError, match="not encrypted"):
        er.validate_receipt(receipt)


def test_unknown_field_is_rejected():
    receipt = _receipt()
    receipt["extra"] = 1
    with pytest.raises(er.EvalReceiptError, match="unknown keys"):
        er.validate_receipt(receipt)


def test_receipt_id_detects_tampering():
    receipt = _receipt()
    receipt["score"]["latency_p50_ms"] = "1.0"
    with pytest.raises(er.EvalReceiptError, match="receipt_id"):
        er.validate_receipt(receipt)


def test_attested_receipt_binds_report_data():
    base = _receipt()
    document = {k: v for k, v in base.items() if k not in {"receipt_id", "signature"}}
    document["attestation"] = {
        "kind": "tdx",
        "evidence_digest": _digest("quote"),
        "evidence_uri": "https://miner.example/quote.bin",
        "policy_digest": _digest("policy"),
        "report_data_hex": "",
    }
    document["attestation"]["report_data_hex"] = er.expected_report_data(document).hex()
    document["receipt_id"] = er.receipt_id_for(document)
    document["signature"] = {"algorithm": "sr25519", "value_base64": "AA=="}
    assert er.validate_receipt(document)
    # A tdx receipt is creditable ONLY when the raw quote actually verified;
    # the kind alone (a claim) is not enough.
    assert er.creditable_as_verified_work(document, attestation_verified=True) is True
    assert er.creditable_as_verified_work(document, attestation_verified=False) is False


def test_quote_cannot_be_replayed_onto_another_run():
    base = _receipt()
    document = {k: v for k, v in base.items() if k not in {"receipt_id", "signature"}}
    document["attestation"] = {
        "kind": "tdx",
        "evidence_digest": _digest("quote"),
        "evidence_uri": "https://miner.example/quote.bin",
        "policy_digest": _digest("policy"),
        "report_data_hex": "",
    }
    document["attestation"]["report_data_hex"] = er.expected_report_data(document).hex()

    # Same quote, different checkpoint: the execution half no longer matches.
    stolen = copy.deepcopy(document)
    stolen["model"]["weights_digest"] = _digest("other-weights")
    stolen["receipt_id"] = er.receipt_id_for(stolen)
    stolen["signature"] = {"algorithm": "sr25519", "value_base64": "AA=="}
    with pytest.raises(er.EvalReceiptError, match="report_data"):
        er.validate_receipt(stolen)


def test_items_root_is_order_sensitive_and_stable():
    a = [er.item_leaf(0, "a", _digest("1"), True),
         er.item_leaf(1, "b", _digest("2"), False)]
    assert er.items_root(a) == er.items_root(list(a))
    assert er.items_root(a) != er.items_root(list(reversed(a)))


def test_items_root_distinguishes_pass_from_fail():
    passed = [er.item_leaf(0, "a", _digest("1"), True)]
    failed = [er.item_leaf(0, "a", _digest("1"), False)]
    assert er.items_root(passed) != er.items_root(failed)


def test_leaf_binds_position():
    # The same content at two positions hashes to two different leaves.
    assert er.item_leaf(0, "a", _digest("1"), True) != er.item_leaf(1, "a", _digest("1"), True)


def test_odd_leaf_promotion_avoids_duplicate_ambiguity():
    # A three-leaf tree must not collide with the four-leaf tree formed by
    # duplicating the last leaf.
    leaves = [er.item_leaf(n, f"i{n}", _digest(str(n)), True) for n in range(3)]
    assert er.items_root(leaves) != er.items_root(leaves + [leaves[-1]])


def test_canonical_decimal_normalises():
    assert er.canonical_decimal("0.700") == "0.7"
    assert er.canonical_decimal(Decimal_from("1.000")) == "1"
    assert er.canonical_decimal(0) == "0"


def Decimal_from(text: str):
    from decimal import Decimal

    return Decimal(text)


# --------------------------------------------------------------------------- #
# The evaluator authorization — signed grant, bound and verified (issue #1, #15)
# --------------------------------------------------------------------------- #
from datetime import UTC, datetime  # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from cathedral_distill.receipt_keys import ReceiptKeyRegistry  # noqa: E402

_AUTH_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(9, 41)))
_AUTH_REG = ReceiptKeyRegistry.from_keys({"eval-authority-1": _AUTH_KEY.public_key().public_bytes_raw()})
_AT = datetime(2026, 7, 25, 9, 0, tzinfo=UTC)


def _authorized(auth_key=_AUTH_KEY, auth_over=None):
    base = _receipt()
    auth = er.build_authorization(dict(base, **(auth_over or {})), auth_key,
                                  signing_key_id="eval-authority-1")
    return _receipt(eval_authorization=auth)


def test_authorization_round_trips_and_binds():
    receipt = _authorized()
    auth = er.verify_authorization(receipt, _AUTH_REG, current_block=6_000_100, at=_AT)
    assert auth["miner_hotkey"] == "5Miner"


def test_present_authorization_is_structurally_validated():
    receipt = _receipt(eval_authorization={"schema": "wrong", "eval_id": "x"})
    with pytest.raises(er.EvalReceiptError):
        er.validate_receipt(receipt)


def test_missing_authorization_is_refused_on_reward_path():
    with pytest.raises(er.EvalReceiptError, match="required"):
        er.verify_authorization(_receipt(), _AUTH_REG, current_block=6_000_100, at=_AT)


def test_authorization_for_another_miner_is_refused():
    receipt = _authorized(auth_over={"miner_hotkey": "5Other"})
    with pytest.raises(er.EvalReceiptError, match="does not match"):
        er.verify_authorization(receipt, _AUTH_REG, current_block=6_000_100, at=_AT)


def test_forged_authorization_signature_is_refused():
    rogue = Ed25519PrivateKey.from_private_bytes(bytes(range(50, 82)))
    receipt = _authorized(auth_key=rogue)
    with pytest.raises(er.EvalReceiptError, match="signature does not verify"):
        er.verify_authorization(receipt, _AUTH_REG, current_block=6_000_100, at=_AT)


def test_authorization_block_window_is_enforced():
    receipt = _authorized()
    with pytest.raises(er.EvalReceiptError, match="block window"):
        er.verify_authorization(receipt, _AUTH_REG, current_block=7_000_000, at=_AT)
