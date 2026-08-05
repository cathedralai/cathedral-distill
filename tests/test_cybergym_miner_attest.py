"""The miner-side attestation helper → the validator gate, without hardware.

`offline_token` builds exactly the `cathedral_cc_attestation_v1` document Cathedral
would return for a submission-bound quote. These tests prove that a token the miner
produces for a real submission binding is accepted by the SAME
`verify_submission_attestation` the validator runs, and refused for any other
submission — so the only thing the live path adds is Cathedral's hardware quote and
signature (cathedral-compute#108).
"""
from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill.attestation import AttestationPolicy
from cathedral_distill.cybergym_attest import (
    CyberGymAttestError,
    submission_report_data,
    verify_submission_attestation,
)
from cathedral_distill.cybergym_miner_attest import (
    MinerAttestClient,
    attestation_field,
    bind,
    offline_token,
)

MEASURE = "tdx-mrtd:" + "ab" * 24
ROOT_SEED = bytes(range(32))
ROOT_ID = "intel-dcap-root-1"
ROOT_PUB = Ed25519PrivateKey.from_private_bytes(ROOT_SEED).public_key().public_bytes_raw()
NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
ISSUED = "2026-07-29T12:00:00Z"
POLICY = AttestationPolicy(
    trusted_roots={ROOT_ID: ROOT_PUB}, allowed_measurements=frozenset({MEASURE})
)
SUB = dict(
    batch_id="b1", task_id="arvo:368", poc_sha256="sha256:" + "ab" * 32,
    trace_id="sha256:" + "cd" * 32, miner_hotkey="5Miner",
    model_commitment="sha256:" + "ef" * 32,
)


def _token(**over):
    rd = bind(**{**SUB, **{k: over.pop(k) for k in list(over) if k in SUB}})
    return rd, offline_token(report_data=rd, measurement=MEASURE, root_seed=ROOT_SEED,
                             signing_key_id=ROOT_ID, issued_at=ISSUED, **over)


def test_a_bound_offline_token_is_accepted_by_the_validator_gate():
    rd, token = _token()
    doc = verify_submission_attestation(token, policy=POLICY, now=NOW, **SUB)  # raises on fail
    assert doc["tee"] == "intel_tdx"
    assert doc["report_data"] == rd


def test_a_token_bound_to_another_submission_is_refused():
    _, token = _token()
    with pytest.raises(CyberGymAttestError):
        verify_submission_attestation(
            token, policy=POLICY, now=NOW, **{**SUB, "task_id": "arvo:999"})
    with pytest.raises(CyberGymAttestError):
        verify_submission_attestation(
            token, policy=POLICY, now=NOW, **{**SUB, "miner_hotkey": "5Other"})


def test_an_untrusted_signer_is_refused():
    rd = bind(**SUB)
    token = offline_token(report_data=rd, measurement=MEASURE, root_seed=bytes(range(1, 33)),
                          signing_key_id=ROOT_ID, issued_at=ISSUED)
    with pytest.raises(CyberGymAttestError):
        verify_submission_attestation(token, policy=POLICY, now=NOW, **SUB)


def test_bind_matches_submission_report_data_and_binds_the_artifact():
    assert bind(**SUB) == submission_report_data(**SUB)
    # a private (sealed-batch) task additionally binds the dispatched artifact digest
    with_art = bind(**SUB, artifact_digest="sha256:" + "11" * 32)
    assert with_art != bind(**SUB)
    token = offline_token(report_data=with_art, measurement=MEASURE, root_seed=ROOT_SEED,
                          signing_key_id=ROOT_ID, issued_at=ISSUED)
    doc = verify_submission_attestation(
        token, policy=POLICY, now=NOW, artifact_digest="sha256:" + "11" * 32, **SUB)
    assert doc["report_data"] == with_art


def test_attestation_field_is_the_base64_the_envelope_carries():
    token = b"the-token-bytes"
    assert base64.b64decode(attestation_field(token)) == token


def test_the_client_response_seam_parses_a_token_and_refuses_junk():
    assert MinerAttestClient._token_from_response(
        {"attestation": base64.b64encode(b"tok").decode()}) == b"tok"
    assert MinerAttestClient._token_from_response({"token": {"schema": "x"}}) == b'{"schema": "x"}'
    with pytest.raises(ValueError):
        MinerAttestClient._token_from_response({"unexpected": 1})
