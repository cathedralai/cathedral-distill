"""Tests for the Polaris attestation binding.

These check the binding actually binds: a quote from one run must not validate
a different score, a different checkpoint, or a non-allowlisted eval image.
"""
from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import eval_receipt as er  # noqa: E402
from cathedral_distill import polaris_attest as pa  # noqa: E402

NONCE = "a3f1" * 16
PUBKEY = "bG9jYWwtdGVzdC1wdWJsaWMta2V5LWJhc2U2NA=="
IMAGE = "sha256:" + "1c" * 32


def _digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _pre_attestation():
    leaves = [
        er.item_leaf(f"item-{n}", _digest(f"out-{n}"), n < 7) for n in range(10)
    ]
    return {
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
            "image_digest": IMAGE,
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
        "attestation": dict(pa._BLANK_ATTESTATION),
    }


def _attested(document=None):
    document = document or _pre_attestation()
    report_data = pa.expected_polaris_report_data(
        document, nonce=NONCE, e2e_pubkey_b64=PUBKEY, image_digest=IMAGE
    )
    signed = pa.attach_polaris_attestation(
        document,
        report_data=report_data,
        evidence_digest=_digest("quote"),
        evidence_uri="https://polaris.example/quote.bin",
        policy_digest=_digest("policy"),
    )
    signed["receipt_id"] = er.receipt_id_for(signed)
    signed["signature"] = {"algorithm": "sr25519", "value_base64": "AA=="}
    return signed, report_data


def _verify(receipt, report_data, **kwargs):
    params = dict(
        nonce=NONCE,
        e2e_pubkey_b64=PUBKEY,
        image_digest=IMAGE,
        report_data=report_data,
        intel_verified=True,
        allowed_image_digests={IMAGE},
    )
    params.update(kwargs)
    return pa.verify_polaris_receipt(receipt, **params)


def test_honest_run_verifies():
    receipt, report_data = _attested()
    assert _verify(receipt, report_data)["score"]["score"] == "0.7"


def test_attested_receipt_is_creditable():
    receipt, _ = _attested()
    assert er.creditable_as_verified_work(receipt) is True


def test_stdout_is_stable_and_excludes_attestation():
    document = _pre_attestation()
    first = pa.polaris_stdout(document)
    assert first == pa.polaris_stdout(copy.deepcopy(document))
    # No trailing newline: the binding hashes these bytes exactly.
    assert not first.endswith(b"\n")
    # The blanked attestation must not leak a report_data into its own preimage.
    assert b'"report_data_hex":""' in first


def test_score_change_breaks_execution_binding():
    receipt, report_data = _attested()
    tampered = copy.deepcopy(receipt)
    tampered["score"]["passed_items"] = 10
    tampered["score"]["score"] = "1"
    tampered["receipt_id"] = er.receipt_id_for(tampered)
    with pytest.raises(pa.PolarisBindingError, match="execution binding"):
        _verify(tampered, report_data)


def test_checkpoint_swap_breaks_execution_binding():
    receipt, report_data = _attested()
    tampered = copy.deepcopy(receipt)
    tampered["model"]["weights_digest"] = _digest("other-weights")
    tampered["receipt_id"] = er.receipt_id_for(tampered)
    with pytest.raises(pa.PolarisBindingError, match="execution binding"):
        _verify(tampered, report_data)


def test_wrong_nonce_breaks_identity_binding():
    receipt, report_data = _attested()
    with pytest.raises(pa.PolarisBindingError, match="identity binding"):
        _verify(receipt, report_data, nonce="ffff" * 16)


def test_non_allowlisted_eval_image_is_rejected():
    # A genuine TDX quote of a lenient grader is still worthless.
    receipt, report_data = _attested()
    with pytest.raises(pa.PolarisBindingError, match="not allowlisted"):
        _verify(receipt, report_data, allowed_image_digests={_digest("other-image")})


def test_unverified_intel_chain_is_rejected():
    receipt, report_data = _attested()
    with pytest.raises(pa.PolarisBindingError, match="Intel"):
        _verify(receipt, report_data, intel_verified=False)


def test_truncated_report_data_is_rejected():
    receipt, report_data = _attested()
    with pytest.raises(pa.PolarisBindingError, match="64 bytes"):
        _verify(receipt, report_data[:32])


def test_polaris_kind_is_not_self_binding():
    # Structural validation must not imply the quote was checked.
    assert pa.POLARIS_KIND not in er.SELF_BINDING_ATTESTATION_KINDS
    assert pa.POLARIS_KIND in er.ATTESTATION_KINDS


def test_binding_matches_polaris_client_recipe():
    """Recompute the recipe independently, as scaffold/polaris.py implements it."""
    document = _pre_attestation()
    stdout = pa.polaris_stdout(document)
    low = hashlib.sha256((NONCE + PUBKEY).encode()).digest()
    high = hashlib.sha256(
        (IMAGE + hashlib.sha256(stdout).hexdigest()).encode()
    ).digest()
    assert pa.expected_polaris_report_data(
        document, nonce=NONCE, e2e_pubkey_b64=PUBKEY, image_digest=IMAGE
    ) == low + high
