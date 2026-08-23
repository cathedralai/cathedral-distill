"""The agent-in-enclave composition, proven without TDX, Docker, or a real model.

A mock completer stands in for the reasoning model and an injected differential backend
for the corpus-baked vul/fix builds. The tests prove that the combined workload
(agent MANUFACTURES the PoC -> the SAME enclave runs+signs the differential) produces
exactly the signed envelope the validator's ``verify_persistent_enclave_attestation``
accepts; that the envelope verdict is re-derived by ``solve()`` from an INDEPENDENT
vul/fix run (so an agent that lies about a crash still yields a signed FAIL); and that
the commitment binds the agent's ACTUAL reasoning trace (a swapped trace breaks it).
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

from cathedral_distill.cybergym_agent_enclave_solver import NO_POC_EXIT, main, solve_with_agent
from cathedral_distill.cybergym_cathedral_attest import verify_persistent_enclave_attestation
from cathedral_distill.cybergym_enclave_solver import VERDICT_FAIL, VERDICT_PASS
from cathedral_distill.cybergym_protocol import _trace_from_dict
from cathedral_distill.cybergym_verifier import poc_digest

TASK = "arvo:10001"
POC = bytes.fromhex("deadbeefcafe")          # the agent "discovers" this crashing input
POC_HEX = "deadbeefcafe"
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
    kw.setdefault("miner_hotkey", MINER)
    kw.setdefault("nonce", NONCE)
    kw.setdefault("model_id", MODEL)
    kw.setdefault("workspace", WORKSPACE)
    kw.setdefault("max_turns", 3)
    return solve_with_agent(complete=_completer(reply), backend=backend, **kw)


def _tid(result):
    """The trace id the enclave bound = the content hash of the produced trace (the exact
    value the validator recomputes from the submitted trace in screen_submission)."""
    return _trace_from_dict(result.trace).trace_id()


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


def _verify(envelope, *, trace_id, poc=POC, miner_hotkey=MINER, **kw):
    kw.setdefault("now", NOW)
    return verify_persistent_enclave_attestation(
        _receipt(envelope),
        task_id=TASK,
        poc_sha256=poc_digest(poc),
        trace_id=trace_id,
        miner_hotkey=miner_hotkey,
        nonce=NONCE,
        result_bytes=envelope,
        expected_workload_sha256=WORKLOAD,
        **kw,
    )


def test_agent_manufactured_solve_round_trips_through_the_validator():
    # vul crashes on the agent's PoC, patched build is clean -> a genuine solve.
    result, envelope = _run(POC_HEX, _backend(134, 0))
    assert result.solved and result.poc == POC and result.trace is not None
    a = _verify(envelope, trace_id=_tid(result), require_verdict=True)
    assert a.attested and a.result_bound and a.workload_bound and a.signature_bound
    assert a.verdict == VERDICT_PASS


def test_verdict_is_derived_by_solve_not_by_the_agent():
    # The agent's run_poc only checks the VULNERABLE build, so it "solves" here.
    # But the same input also crashes the PATCHED build -> the differential proves
    # nothing. solve() re-runs both and derives FAIL, overriding the agent's claim.
    result, envelope = _run(POC_HEX, _backend(134, 134))
    assert result.solved and result.poc == POC          # the agent believes it won
    a = _verify(envelope, trace_id=_tid(result), require_verdict=True)
    assert a.attested and a.verdict == VERDICT_FAIL      # solve() is the authority


def test_the_bound_trace_is_the_one_the_agent_produced():
    # The commitment binds trace_id = hash(the produced trace). A miner who keeps the
    # genuine signed envelope but submits a DIFFERENT (fabricated) reasoning trace is
    # caught: the validator recomputes trace_id from the submitted trace and it no longer
    # matches the signed one.
    result, envelope = _run(POC_HEX, _backend(134, 0))
    assert _verify(envelope, trace_id=_tid(result)).attested          # the real trace verifies
    tampered = dict(result.trace)
    tampered["steps"] = list(result.trace["steps"]) + [
        {"step": 999, "action": "reason", "thought": "fabricated", "output": "padding"}]
    swapped = _trace_from_dict(tampered).trace_id()
    assert swapped != _tid(result)
    assert not _verify(envelope, trace_id=swapped).attested           # a swapped trace does not


def test_no_poc_produced_attests_nothing():
    # A model that never emits a candidate -> no PoC -> no envelope to sign.
    result, envelope = _run("I could not find a crashing input.", _backend(134, 0))
    assert not result.solved and result.poc is None
    assert envelope is None
    assert NO_POC_EXIT != 0


def test_a_manufactured_solve_cannot_be_replayed_by_another_miner():
    result, envelope = _run(POC_HEX, _backend(134, 0))
    # a different miner replays the SAME envelope -> commitment binds MINER, so it fails
    a = _verify(envelope, trace_id=_tid(result), miner_hotkey="5SomeoneElse")
    assert not a.attested


def test_main_requires_a_trace_out_destination(monkeypatch):
    # The trace is the sole preimage of the signed trace_id, so main() refuses to run (fail fast)
    # without a destination to persist it — a signed solve must never exist without its trace.
    monkeypatch.delenv("CYBERGYM_TRACE_OUT", raising=False)
    with pytest.raises(SystemExit):
        main()
