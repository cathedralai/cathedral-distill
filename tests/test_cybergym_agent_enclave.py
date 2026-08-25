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
# agent_enclave requires a trustless receipt_verifier (so Cathedral's signature covers the egress
# task_policy). A stub that accepts any receipt isolates the egress/nonce logic under test from the
# signature check (covered by the real trustless-verifier tests elsewhere).
def _OK_VERIFIER(receipt):  # noqa: ANN001
    return True


POLICY = CathedralReceiptPolicy(expected_workload_sha256="a" * 64, expected_egress_allowlist=HOSTS,
                                receipt_verifier=_OK_VERIFIER)
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
    wider = CathedralReceiptPolicy(expected_workload_sha256="a" * 64, receipt_verifier=_OK_VERIFIER,
                                   expected_egress_allowlist=HOSTS | {"evil.example"})
    assert cathedral_receipt_policy_digest(POLICY) != cathedral_receipt_policy_digest(wider)
    no_tls = CathedralReceiptPolicy(expected_workload_sha256="a" * 64, receipt_verifier=_OK_VERIFIER,
                                    expected_egress_allowlist=HOSTS, require_tls_pinning=False)
    assert cathedral_receipt_policy_digest(POLICY) != cathedral_receipt_policy_digest(no_tls)


def test_provider_restricted_egress_is_attested():
    result = _verify(GOOD_POLICY)
    assert result["profile"] == PROFILE_AGENT_ENCLAVE
    assert "attested_intel_tdx_enclave_result_bound" in result["reason"]


def test_polaris_allow_egress_string_is_treated_as_restricted():
    result = _verify(
        {
            "hardware_class": "tdx_cpu",
            "reuse": "forbidden",
            "egress": "allow:api.deepseek.com,api.openai.com",
            "tls_pinning": True,
        }
    )
    assert result["profile"] == PROFILE_AGENT_ENCLAVE


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


# --- report_data nonce binding: the enclave quote (not the miner's result envelope) binds the
#     dispatch nonce, so a receipt cannot be replayed for another dispatch (wallscaler / compute#108) ---
import hashlib as _h  # noqa: E402

NONCE_POLICY = CathedralReceiptPolicy(expected_workload_sha256="a" * 64,
                                      expected_egress_allowlist=HOSTS, require_report_data_nonce=True,
                                      receipt_verifier=_OK_VERIFIER)
_GOOD_NS = _h.sha256(NONCE.encode("ascii")).hexdigest()


def _token_ns(nonce_sha256=None, report_data_match=True):
    import copy
    tok = copy.deepcopy(_token(GOOD_POLICY))
    tok["receipt"]["report_data_match"] = report_data_match
    if nonce_sha256 is not None:
        tok["receipt"]["nonce_sha256"] = nonce_sha256
    return tok


def _verify_ns(policy=NONCE_POLICY, **kw):
    return verify_submission_receipt(_token_ns(**kw), task_id=TASK, poc_sha256=PD, trace_id=TR,
                                     miner_hotkey=MINER, nonce=NONCE, policy=policy)


def test_report_data_nonce_binding_is_posture_bound():
    m = cathedral_receipt_policy_manifest(NONCE_POLICY)
    assert m["require_report_data_nonce"] is True
    off = CathedralReceiptPolicy(expected_workload_sha256="a" * 64, expected_egress_allowlist=HOSTS,
                                 receipt_verifier=_OK_VERIFIER)
    assert cathedral_receipt_policy_digest(NONCE_POLICY) != cathedral_receipt_policy_digest(off)


def test_receipt_bound_to_the_dispatch_nonce_is_attested():
    assert "attested" in _verify_ns(nonce_sha256=_GOOD_NS)["reason"]


def test_a_receipt_for_a_different_or_missing_nonce_is_refused():
    with pytest.raises(CyberGymAttestError):                      # nonce for another dispatch
        _verify_ns(nonce_sha256=_h.sha256(b"cgnonce-sha256:other").hexdigest())
    with pytest.raises(CyberGymAttestError):                      # no report_data nonce at all
        _verify_ns()
    with pytest.raises(CyberGymAttestError):                      # Cathedral never verified report_data
        _verify_ns(nonce_sha256=_GOOD_NS, report_data_match=False)


def test_nonce_binding_is_off_by_default_backward_compatible():
    off = CathedralReceiptPolicy(expected_workload_sha256="a" * 64, expected_egress_allowlist=HOSTS,
                                 receipt_verifier=_OK_VERIFIER)
    # a receipt with no nonce_sha256 still attests when the policy does not require it
    assert "attested" in _verify_ns(policy=off)["reason"]


# --- hardening from the adversarial-verification pass (workflow wf_d893fba5) ---

def test_agent_enclave_requires_a_trustless_receipt_verifier():
    """Without a receipt_verifier the egress task_policy is unauthenticated plaintext a miner can swap
    (the real receipt is Cathedral-signed), so the profile refuses trusted-issuer mode."""
    no_verifier = CathedralReceiptPolicy(expected_workload_sha256="a" * 64, expected_egress_allowlist=HOSTS)
    with pytest.raises(CyberGymAttestError):
        _verify(GOOD_POLICY, policy=no_verifier)


def test_attest_v1_is_refused_when_the_nonce_binding_is_required():
    """attest.v1 carries no dispatch-nonce binding — refuse the downgrade so a policy requiring the
    nonce cannot be satisfied by the miner/nonce-unbound profile (cross-dispatch replay)."""
    from cathedral_distill.cybergym_attest import PROFILE_ATTEST_V1
    payload = {"schema": RECEIPT_ATTESTATION_SCHEMA, "profile": PROFILE_ATTEST_V1, "receipt": {}}
    with pytest.raises(CyberGymAttestError):
        verify_submission_receipt(payload, task_id=TASK, poc_sha256=PD, trace_id=TR,
                                  miner_hotkey=MINER, nonce=NONCE, policy=NONCE_POLICY)


def test_a_malformed_nonce_sha256_is_a_clean_error_not_a_crash():
    """A non-hex (e.g. non-ASCII) nonce_sha256 must raise CyberGymAttestError, not a TypeError that
    escapes the verifier contract and crashes an intake loop (compare_digest rejects non-ASCII)."""
    for bad in ("é" * 64, "zz" * 32, "abc", ""):     # non-ascii, non-hex, short, empty
        with pytest.raises(CyberGymAttestError):
            _verify_ns(nonce_sha256=bad)
