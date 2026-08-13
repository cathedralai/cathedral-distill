"""The agent-in-enclave profile: same solve/miner/nonce binding as persistent_enclave PLUS a verified
restricted-egress firewall, so the agent could reach only the approved model hosts and had no
out-of-band channel to a looked-up answer. This is the runtime enforcement of the provider allowlist
(docs/AGENT_ENCLAVE_EGRESS.md in the backend repo). The egress firewall is posture-bound, so a resume
cannot widen it."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill.cybergym_attest import (
    CathedralReceiptPolicy,
    CyberGymAttestError,
    PROFILE_AGENT_ENCLAVE,
    RECEIPT_ATTESTATION_SCHEMA,
    cathedral_receipt_policy_digest,
    cathedral_receipt_policy_manifest,
    verify_submission_receipt,
)
from cathedral_distill.cybergym_cathedral_attest import enclave_commitment_bytes, enclave_result_bytes
from cathedral_distill.cybergym_protocol import _trace_from_dict

HOSTS = frozenset({"api.deepseek.com", "api.openai.com"})
POLICY = CathedralReceiptPolicy(expected_workload_sha256="a" * 64, expected_egress_allowlist=HOSTS)
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
TASK, POC, MINER, NONCE = "arvo:1", b"SOLVE:x", "5Miner", "cgnonce-sha256:" + "ab" * 32
PD = "sha256:" + hashlib.sha256(POC).hexdigest()
_TRACE = {"task_id": TASK, "poc_sha256": PD, "model_id": "m", "licence": "cathedral-corpus-v1",
          "steps": [{"step": 1, "thought": "t", "action": "a"}]}
TR = _trace_from_dict(_TRACE).trace_id()
_SIG = KEY.sign(enclave_commitment_bytes(task_id=TASK, poc_sha256=PD, trace_id=TR,
                                         miner_hotkey=MINER, nonce=NONCE, verdict="pass"))
ENV = enclave_result_bytes(
    enclave_pubkey_b64=base64.b64encode(KEY.public_key().public_bytes_raw()).decode(),
    task_id=TASK, poc_sha256=PD, trace_id=TR, miner_hotkey=MINER, nonce=NONCE,
    verdict="pass", signature_b64=base64.b64encode(_SIG).decode())
GOOD_POLICY = {"hardware_class": "tdx_cpu", "reuse": "forbidden", "egress": "restricted",
               "egress_allowlist": ["api.deepseek.com", "api.openai.com"], "tls_pinning": True}


def _token(task_policy):
    receipt = {"schema": "cathedral_customer_receipt_v1", "receipt_status": "ready", "cpu_tee": "intel_tdx",
               "workload_sha256": "a" * 64, "result_sha256": hashlib.sha256(ENV).hexdigest(),
               "intel_verified": True, "report_data_match": True, "execution_binding_verified": True,
               "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "task_policy": task_policy}
    return {"schema": RECEIPT_ATTESTATION_SCHEMA, "profile": PROFILE_AGENT_ENCLAVE,
            "receipt": receipt, "result_b64": base64.b64encode(ENV).decode()}


def _verify(task_policy, policy=POLICY):
    return verify_submission_receipt(_token(task_policy), task_id=TASK, poc_sha256=PD, trace_id=TR,
                                     miner_hotkey=MINER, nonce=NONCE, policy=policy)


def test_manifest_binds_the_egress_allowlist_into_the_posture_digest():
    m = cathedral_receipt_policy_manifest(POLICY)
    assert m["expected_egress_allowlist"] == ["api.deepseek.com", "api.openai.com"]
    assert m["require_tls_pinning"] is True
    # widening the allowlist (or dropping TLS pinning) changes the digest — a resume cannot do it silently
    wider = CathedralReceiptPolicy(expected_workload_sha256="a" * 64,
                                   expected_egress_allowlist=HOSTS | {"evil.example"})
    assert cathedral_receipt_policy_digest(POLICY) != cathedral_receipt_policy_digest(wider)
    no_tls = CathedralReceiptPolicy(expected_workload_sha256="a" * 64,
                                    expected_egress_allowlist=HOSTS, require_tls_pinning=False)
    assert cathedral_receipt_policy_digest(POLICY) != cathedral_receipt_policy_digest(no_tls)


def test_provider_restricted_egress_is_attested():
    result = _verify(GOOD_POLICY)
    assert result["profile"] == PROFILE_AGENT_ENCLAVE
    assert "attested_intel_tdx_enclave_result_bound" in result["reason"]


def test_broader_or_missing_egress_is_refused():
    for task_policy in (
        {**GOOD_POLICY, "egress": "none"},                       # cannot serve a reasoning agent
        {**GOOD_POLICY, "egress": "any"},                        # unconstrained
        {**GOOD_POLICY, "egress_allowlist": [*GOOD_POLICY["egress_allowlist"], "evil.example"]},  # superset
        {**GOOD_POLICY, "egress_allowlist": ["api.deepseek.com"]},   # subset
        {k: v for k, v in GOOD_POLICY.items() if k != "tls_pinning"},  # no TLS pinning
        {k: v for k, v in GOOD_POLICY.items() if k != "egress_allowlist"},  # no allowlist at all
    ):
        with pytest.raises(CyberGymAttestError):
            _verify(task_policy)


def test_policy_without_an_egress_allowlist_refuses_the_profile():
    """A CathedralReceiptPolicy with no expected_egress_allowlist cannot accept an agent_enclave
    receipt — otherwise the profile would be no stronger than persistent_enclave."""
    weak = CathedralReceiptPolicy(expected_workload_sha256="a" * 64)  # no egress allowlist
    with pytest.raises(CyberGymAttestError):
        _verify(GOOD_POLICY, policy=weak)
