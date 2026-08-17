"""The agent-in-enclave composition, proven without TDX, Docker, or a real model.

A mock completer stands in for the reasoning model and an injected differential backend
for the corpus-baked vul/fix builds. The tests prove that the combined workload
(agent MANUFACTURES the PoC -> the SAME enclave runs+signs the differential) produces
exactly the signed envelope the validator's ``verify_persistent_enclave_attestation``
accepts, and — the load-bearing property — that the envelope verdict is re-derived by
``solve()`` from an INDEPENDENT vul/fix run, so an agent that lies about a crash still
yields a signed FAIL.
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from cathedral_distill.cybergym_agent_enclave_solver import NO_POC_EXIT, solve_with_agent
from cathedral_distill.cybergym_cathedral_attest import verify_persistent_enclave_attestation
from cathedral_distill.cybergym_enclave_solver import VERDICT_FAIL, VERDICT_PASS
from cathedral_distill.cybergym_verifier import poc_digest

TASK = "arvo:10001"
POC = bytes.fromhex("deadbeefcafe")          # the agent "discovers" this crashing input
POC_HEX = "deadbeefcafe"
TRACE = "sha256:" + "cd" * 32
WORKLOAD = "649e90742fe3bdb4f523b57429a51d0f29119011ddae5f86070b191a437519fa"
MINER = "5AgentEnclaveMiner"
NONCE = "cgnonce-sha256:" + "ef" * 32
MODEL = "mock-model-v1"
WORKSPACE = {"vuln.c": "void f(char*s){char b[8];strcpy(b,s);}\n"}
NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def _completer(reply: str):
    """A model that emits ``reply`` every turn (the bare-hex path feeds it to run_poc)."""
    def complete(_messages):
        return reply
    return complete


def _backend(vul_code: int, fix_code: int):
    def backend(task_id: str, poc: bytes, mode: str) -> int:
        return fix_code if mode == "fix" else vul_code
    return backend


def _run(reply, backend, **kw):
    kw.setdefault("task_id", TASK)
    kw.setdefault("trace_id", TRACE)
    kw.setdefault("miner_hotkey", MINER)
    kw.setdefault("nonce", NONCE)
    kw.setdefault("model_id", MODEL)
    kw.setdefault("workspace", WORKSPACE)
    kw.setdefault("max_turns", 3)
    return solve_with_agent(complete=_completer(reply), backend=backend, **kw)


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


def _verify(envelope, *, poc=POC, **kw):
    kw.setdefault("now", NOW)
    return verify_persistent_enclave_attestation(
        _receipt(envelope),
        task_id=TASK,
        poc_sha256=poc_digest(poc),
        trace_id=TRACE,
        miner_hotkey=MINER,
        nonce=NONCE,
        result_bytes=envelope,
        expected_workload_sha256=WORKLOAD,
        **kw,
    )


def test_agent_manufactured_solve_round_trips_through_the_validator():
    # vul crashes on the agent's PoC, patched build is clean -> a genuine solve.
    result, envelope = _run(POC_HEX, _backend(134, 0))
    assert result.solved and result.poc == POC and result.trace is not None
    a = _verify(envelope, require_verdict=True)
    assert a.attested and a.result_bound and a.workload_bound and a.signature_bound
    assert a.verdict == VERDICT_PASS


def test_verdict_is_derived_by_solve_not_by_the_agent():
    # The agent's run_poc only checks the VULNERABLE build, so it "solves" here.
    # But the same input also crashes the PATCHED build -> the differential proves
    # nothing. solve() re-runs both and derives FAIL, overriding the agent's claim.
    result, envelope = _run(POC_HEX, _backend(134, 134))
    assert result.solved and result.poc == POC          # the agent believes it won
    a = _verify(envelope, require_verdict=True)
    assert a.attested and a.verdict == VERDICT_FAIL      # solve() is the authority


def test_no_poc_produced_attests_nothing():
    # A model that never emits a candidate -> no PoC -> no envelope to sign.
    result, envelope = _run("I could not find a crashing input.", _backend(134, 0))
    assert not result.solved and result.poc is None
    assert envelope is None
    assert NO_POC_EXIT != 0


def test_a_manufactured_solve_cannot_be_replayed_by_another_miner():
    _result, envelope = _run(POC_HEX, _backend(134, 0))
    # a different miner replays the SAME envelope -> commitment binds MINER, so it fails
    a = verify_persistent_enclave_attestation(
        _receipt(envelope),
        task_id=TASK,
        poc_sha256=poc_digest(POC),
        trace_id=TRACE,
        miner_hotkey="5SomeoneElse",
        nonce=NONCE,
        result_bytes=envelope,
        expected_workload_sha256=WORKLOAD,
        now=NOW,
    )
    assert not a.attested
