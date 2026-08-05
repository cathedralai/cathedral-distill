"""The in-enclave solver → validator contract, proven without TDX or Docker.

An injected differential backend stands in for the corpus-baked vul/fix builds.
The tests prove the solver produces exactly the signed result envelope the
validator's `verify_persistent_enclave_attestation` accepts, that the verdict is
*derived* from the differential rather than asserted, and that a result bound to
one task/poc cannot be replayed against another.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill.cybergym_cathedral_attest import (
    verify_persistent_enclave_attestation,
)
from cathedral_distill.cybergym_enclave_solver import VERDICT_FAIL, VERDICT_PASS, solve
from cathedral_distill.cybergym_verifier import poc_digest

TASK = "arvo:10001"
POC = b"CGV2-E2E:MANGO/17\n"
TRACE = "sha256:" + "cd" * 32
WORKLOAD = "649e90742fe3bdb4f523b57429a51d0f29119011ddae5f86070b191a437519fa"
MINER = "5SolverMiner"
NONCE = "cgnonce-sha256:" + "ef" * 32
NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def _solve(**kw):
    kw.setdefault("miner_hotkey", MINER)
    kw.setdefault("nonce", NONCE)
    return solve(**kw)


def _backend(vul_code: int, fix_code: int):
    def backend(task_id: str, poc: bytes, mode: str) -> int:
        return fix_code if mode == "fix" else vul_code

    return backend


def _receipt(envelope: bytes, *, workload: str = WORKLOAD, **overrides):
    receipt = {
        "receipt_id": "worker-1",
        "receipt_status": "ready",
        "schema": "cathedral_customer_receipt_v1",
        "cpu_tee": "intel_tdx",
        "execution_class": "tdx_cpu",
        "issued_at": "2026-08-05T11:59:00Z",
        "workload_sha256": workload,
        "result_sha256": hashlib.sha256(envelope).hexdigest(),
        "intel_verified": True,
        "report_data_match": True,
        "execution_binding_verified": True,
    }
    receipt.update(overrides)
    return receipt


def _verify(envelope, *, task_id=TASK, poc=POC, workload=WORKLOAD,
            miner_hotkey=MINER, nonce=NONCE, **kw):
    kw.setdefault("now", NOW)
    return verify_persistent_enclave_attestation(
        _receipt(envelope, workload=workload),
        task_id=task_id,
        poc_sha256=poc_digest(poc),
        trace_id=TRACE,
        miner_hotkey=miner_hotkey,
        nonce=nonce,
        result_bytes=envelope,
        expected_workload_sha256=workload,
        **kw,
    )


def test_a_solved_differential_round_trips_through_the_validator():
    envelope = _solve(task_id=TASK, poc_bytes=POC, trace_id=TRACE, backend=_backend(134, 0))
    a = _verify(envelope, require_verdict=True)
    assert a.attested and a.result_bound and a.workload_bound and a.signature_bound
    assert a.verdict == VERDICT_PASS


def test_the_verdict_is_derived_from_the_differential_not_asserted():
    # vuln build did not crash -> not solved -> a signed FAIL, still a valid receipt
    weak = _solve(task_id=TASK, poc_bytes=b"not-a-crash", trace_id=TRACE, backend=_backend(0, 0))
    a = _verify(weak, poc=b"not-a-crash", require_verdict=True)
    assert a.attested and a.verdict == VERDICT_FAIL
    # the patched build also crashed -> the differential proves nothing -> FAIL
    both = _solve(task_id=TASK, poc_bytes=POC, trace_id=TRACE, backend=_backend(134, 134))
    a = _verify(both, require_verdict=True)
    assert a.attested and a.verdict == VERDICT_FAIL


def test_a_solve_for_one_task_cannot_be_replayed_against_another():
    envelope = _solve(task_id=TASK, poc_bytes=POC, trace_id=TRACE, backend=_backend(134, 0))
    # the validator checks the receipt against a DIFFERENT task than the solve bound
    a = verify_persistent_enclave_attestation(
        _receipt(envelope),
        task_id="arvo:999",
        poc_sha256=poc_digest(POC),
        trace_id=TRACE,
        miner_hotkey=MINER,
        nonce=NONCE,
        result_bytes=envelope,
        expected_workload_sha256=WORKLOAD,
        now=NOW,
    )
    assert not a.attested and "different task/poc/trace" in a.reason


def test_the_envelope_is_byte_stable_for_a_fixed_key():
    key = Ed25519PrivateKey.generate()
    kw = dict(task_id=TASK, poc_bytes=POC, trace_id=TRACE, backend=_backend(134, 0))
    assert _solve(signing_key=key, **kw) == _solve(signing_key=key, **kw)


def test_a_fresh_key_is_generated_when_none_is_supplied():
    kw = dict(task_id=TASK, poc_bytes=POC, trace_id=TRACE, backend=_backend(134, 0))
    # two runs without a supplied key -> different enclave pubkeys, both accepted
    e1 = _solve(**kw)
    e2 = _solve(**kw)
    assert e1 != e2
    assert _verify(e1).attested and _verify(e2).attested
    k1 = _verify(e1).enclave_key_b64
    k2 = _verify(e2).enclave_key_b64
    assert k1 and k2 and k1 != k2
    # and each pubkey is a real 32-byte Ed25519 key
    assert len(base64.b64decode(k1)) == 32


def test_a_solve_for_one_miner_cannot_be_replayed_by_another():
    # The hole this binding closes (self-review of #104): miner A's genuine result,
    # verified against a DIFFERENT miner's hotkey, fails — the enclave signed over
    # A's hotkey, so B cannot resubmit A's receipt under its own batch and earn.
    envelope = _solve(task_id=TASK, poc_bytes=POC, trace_id=TRACE, backend=_backend(134, 0))
    assert _verify(envelope).attested                       # the rightful miner
    assert not _verify(envelope, miner_hotkey="5OtherMiner").attested
    assert not _verify(envelope, nonce="cgnonce-sha256:" + "00" * 32).attested


def test_the_poc_is_read_from_b64_env_when_no_upload_is_possible(monkeypatch):
    # attest.v1 takes no uploaded files, so the PoC arrives base64 in the bound env.
    from cathedral_distill.cybergym_enclave_solver import _poc_from_environment
    monkeypatch.setenv("CYBERGYM_POC_B64", base64.b64encode(POC).decode())
    assert _poc_from_environment() == POC
