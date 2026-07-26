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
        er.item_leaf(f"item-{index}", _digest(f"out-{index}"), index < 7)
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
    # The honest mode: structurally sound, provably worth zero.
    receipt = _receipt()
    assert er.validate_receipt(receipt)
    assert er.creditable_as_verified_work(receipt) is False


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
    assert er.creditable_as_verified_work(document) is True


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
    a = [er.item_leaf("a", _digest("1"), True), er.item_leaf("b", _digest("2"), False)]
    assert er.items_root(a) == er.items_root(list(a))
    assert er.items_root(a) != er.items_root(list(reversed(a)))


def test_items_root_distinguishes_pass_from_fail():
    passed = [er.item_leaf("a", _digest("1"), True)]
    failed = [er.item_leaf("a", _digest("1"), False)]
    assert er.items_root(passed) != er.items_root(failed)


def test_odd_leaf_promotion_avoids_duplicate_ambiguity():
    # A three-leaf tree must not collide with the four-leaf tree formed by
    # duplicating the last leaf.
    leaves = [er.item_leaf(f"i{n}", _digest(str(n)), True) for n in range(3)]
    assert er.items_root(leaves) != er.items_root(leaves + [leaves[-1]])


def test_canonical_decimal_normalises():
    assert er.canonical_decimal("0.700") == "0.7"
    assert er.canonical_decimal(Decimal_from("1.000")) == "1"
    assert er.canonical_decimal(0) == "0"


def Decimal_from(text: str):
    from decimal import Decimal

    return Decimal(text)
