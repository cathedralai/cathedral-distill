"""The attested-teacher datapath — proof the pinned teacher actually ran.

Proves the SEC-5 discipline: the transcript root is bound into the attestation's
report_data, so a validator trusts the (prompt, completion, logprobs) leaves only
because a genuine, measurement-pinned enclave running the pinned teacher produced
them — tamper the root, the completions, the enclave, the teacher pin, or the
freshness and verification fails closed; a single leaf opens with a cheap Merkle
proof, no re-running the teacher.
"""
from __future__ import annotations

import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import attestation as att  # noqa: E402
from cathedral_distill import attested_transcript as ax  # noqa: E402
from cathedral_distill.eval_receipt import sha256_digest  # noqa: E402
from cathedral_distill.teacher_registry import (  # noqa: E402
    PURPOSE_DISTILLATION,
    TeacherRecord,
    TeacherRegistry,
)

# Verifier-held trust anchors (test stand-ins for NRAS/DCAP roots).
ROOT_SEED = bytes(range(32, 64))
ROOT_PUB = Ed25519PrivateKey.from_private_bytes(ROOT_SEED).public_key().public_bytes_raw()
MEAS = "sev-snp-measurement-sha384:" + "cd" * 48
GPU_MEAS = "gpu-vbios-sha256:" + "ab" * 32

NOW = datetime(2026, 7, 28, 12, 15, tzinfo=UTC)
AT = datetime(2026, 7, 28, tzinfo=UTC)
ISSUED = "2026-07-28T12:10:00Z"

LIC = sha256_digest(b"modified-mit-kimi")
TEACHER_ID = "moonshot/kimi/k3"
TEACHER_PIN = {"teacher_id": TEACHER_ID, "licence_digest": LIC, "endpoint_id": "yunwu.ai/v1"}
DECODE_PIN = {"temperature": "0", "top_p": "1", "max_tokens": 8192, "seed": 39}


def _policy(**over):
    base = dict(trusted_roots={"nras-1": ROOT_PUB},
                allowed_measurements=frozenset({MEAS}),
                allowed_gpu_measurements=frozenset({GPU_MEAS}))
    base.update(over)
    return att.AttestationPolicy(**base)


def _registry(*, commercial=True, licence=LIC):
    reg = TeacherRegistry()
    reg.add(TeacherRecord(
        teacher_id=TEACHER_ID, licence_digest=licence, licence_uri="https://kimi/licence",
        reviewed_at=datetime(2026, 7, 1, tzinfo=UTC), review_expires_at=datetime(2027, 1, 1, tzinfo=UTC),
        reviewer="jared", permitted_purposes=frozenset({PURPOSE_DISTILLATION}),
        commercial_use=commercial, competing_model_training=True))
    return reg


def _leaves(n=3):
    return [
        ax.TranscriptLeaf(
            index=i, item_id=f"prompt-{i}",
            prompt_digest=sha256_digest(f"prompt-{i}".encode()),
            completion_digest=sha256_digest(f"completion-{i}".encode()),
            logprobs_digest=sha256_digest(f"logprobs-{i}".encode()),
        )
        for i in range(n)
    ]


def _token(report_data, *, measurement=MEAS, gpu=GPU_MEAS, key_id="nras-1",
           seed=ROOT_SEED, issued=ISSUED):
    body = {"schema": att.ATTESTATION_SCHEMA, "tee": "amd_sev_snp", "measurement": measurement,
            "gpu_measurement": gpu, "report_data": report_data,
            "issued_at": issued, "signing_key_id": key_id}
    return att.sign_attestation(body, seed)


def _bundle_and_token(leaves=None, *, teacher_pin=TEACHER_PIN, decode_pin=DECODE_PIN):
    leaves = leaves or _leaves()
    rd = ax.report_data_for(leaves, teacher_pin=teacher_pin, decode_pin=decode_pin)
    token = _token(rd)
    bundle = ax.build_attested_transcript(leaves, teacher_pin=teacher_pin,
                                          decode_pin=decode_pin, token=token)
    return leaves, bundle, token


def _verify(bundle, token, **over):
    kw = dict(policy=_policy(), teacher_registry=_registry(), now=NOW, at=AT)
    kw.update(over)
    return ax.verify_attested_transcript(bundle, token, **kw)


# --------------------------------------------------------------------------- #
# Happy path + cheap per-leaf opening
# --------------------------------------------------------------------------- #

def test_genuine_bundle_verifies_and_every_leaf_opens():
    leaves, bundle, token = _bundle_and_token()
    verified = _verify(bundle, token)
    assert verified.teacher_id == TEACHER_ID
    assert verified.measurement == MEAS
    assert verified.leaf_count == 3
    # a validator opens any leaf with a Merkle proof — no re-running the teacher
    for i in range(len(leaves)):
        leaf, proof = ax.open_leaf(leaves, i)
        assert ax.verify_leaf(verified, leaf, proof) is True


def test_two_validators_derive_the_same_commitment():
    leaves = _leaves()
    a = ax.report_data_for(leaves, teacher_pin=TEACHER_PIN, decode_pin=DECODE_PIN)
    b = ax.report_data_for(list(_leaves()), teacher_pin=dict(TEACHER_PIN), decode_pin=dict(DECODE_PIN))
    assert a == b and len(a) == 64  # deterministic, bare-hex report_data


# --------------------------------------------------------------------------- #
# SEC-5: the root/completions are bound into the attestation
# --------------------------------------------------------------------------- #

def test_tampered_root_breaks_the_attestation_binding():
    _, bundle, token = _bundle_and_token()
    other_root = sha256_digest(b"a different transcript")
    forged = replace(bundle, transcript_root=other_root)  # keep the real token
    with pytest.raises(ax.AttestedTranscriptError, match="attestation did not verify"):
        _verify(forged, token)


def test_swapped_completion_fails_leaf_verification():
    leaves, bundle, token = _bundle_and_token()
    verified = _verify(bundle, token)
    leaf, proof = ax.open_leaf(leaves, 1)
    doctored = replace(leaf, completion_digest=sha256_digest(b"a cheaper model wrote this"))
    assert ax.verify_leaf(verified, doctored, proof) is False


def test_leaf_cannot_be_replayed_at_another_position():
    leaves, bundle, token = _bundle_and_token()
    verified = _verify(bundle, token)
    _, proof0 = ax.open_leaf(leaves, 0)
    assert ax.verify_leaf(verified, leaves[1], proof0) is False  # leaf 1 vs proof for 0


# --------------------------------------------------------------------------- #
# SEC-TDX-1 / SEC-1-3 / freshness inherited from verify_attestation
# --------------------------------------------------------------------------- #

def test_unpinned_enclave_measurement_is_refused():
    leaves = _leaves()
    rd = ax.report_data_for(leaves, teacher_pin=TEACHER_PIN, decode_pin=DECODE_PIN)
    token = _token(rd, measurement="sev-snp-measurement-sha384:" + "ff" * 48)
    bundle = ax.build_attested_transcript(leaves, teacher_pin=TEACHER_PIN,
                                          decode_pin=DECODE_PIN, token=token)
    with pytest.raises(ax.AttestedTranscriptError, match="attestation did not verify"):
        _verify(bundle, token)


def test_stale_attestation_is_refused():
    _, bundle, token = _bundle_and_token()
    late = datetime(2026, 7, 30, tzinfo=UTC)  # >24h after issued
    with pytest.raises(ax.AttestedTranscriptError, match="attestation did not verify"):
        _verify(bundle, token, now=late)


def test_token_that_does_not_hash_to_the_committed_digest_is_refused():
    _, bundle, _ = _bundle_and_token()
    _, _, other_token = _bundle_and_token(_leaves(2))
    with pytest.raises(ax.AttestedTranscriptError, match="do not hash to the committed"):
        _verify(bundle, other_token)


# --------------------------------------------------------------------------- #
# Teacher-pin enforcement
# --------------------------------------------------------------------------- #

def test_non_commercial_teacher_is_refused_on_the_reward_path():
    _, bundle, token = _bundle_and_token()
    with pytest.raises(ax.AttestedTranscriptError, match="not permitted"):
        _verify(bundle, token, teacher_registry=_registry(commercial=False))


def test_teacher_absent_from_registry_is_refused():
    _, bundle, token = _bundle_and_token()
    with pytest.raises(ax.AttestedTranscriptError, match="not in the registry"):
        _verify(bundle, token, teacher_registry=TeacherRegistry())


def test_licence_drift_after_attestation_is_refused():
    # The enclave attested under licence L (matching the registry then); the registry
    # later re-reviews to L'. The bundle+token still bind L, so the attestation
    # passes, but the licence-digest cross-check catches the drift.
    _, bundle, token = _bundle_and_token()
    drifted = _registry(licence=sha256_digest(b"kimi-licence-v2"))
    with pytest.raises(ax.AttestedTranscriptError, match="licence digest does not match"):
        _verify(bundle, token, teacher_registry=drifted)


# --------------------------------------------------------------------------- #
# Commitment hygiene
# --------------------------------------------------------------------------- #

def test_float_decode_param_is_rejected():
    with pytest.raises(ax.AttestedTranscriptError, match="floats"):
        ax.decode_pin_digest({"temperature": 0.0, "top_p": "1"})


def test_outcome_digest_binds_a_validate_by_execution_result():
    # a CyberGym leaf commits the differential result the enclave observed; absent -> sentinel
    d = ax.outcome_digest({"task_id": "synthvuln:ab:0", "vul_exit_code": 1, "fix_exit_code": 0})
    assert d.startswith("sha256:") and d != ax.ABSENT_DIGEST
    assert ax.outcome_digest({}) == ax.ABSENT_DIGEST
