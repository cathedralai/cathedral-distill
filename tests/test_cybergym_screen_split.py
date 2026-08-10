"""The screen/benchmark split of `process_submission` is behaviour-preserving.

`screen_submission` does the format/binding checks + the Intel-TDX attestation gate and returns
a `ScreenOutcome` — no differential. `benchmark_submission` runs the differential + scoring on a
screened submission. `process_submission` is exactly their composition. This is the seam that
lets the backend screen FIFO in real time and have three distinct validators benchmark the
accepted submissions separately (for the quorum), without changing the fused path's behaviour.
"""
from __future__ import annotations

import base64
import hashlib
import sys
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym as cg  # noqa: E402
from cathedral_distill import cybergym_batch as cb  # noqa: E402
from cathedral_distill import cybergym_protocol as cp  # noqa: E402
from cathedral_distill import cybergym_validator as cv  # noqa: E402
from cathedral_distill.cybergym_verifier import poc_digest  # noqa: E402

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
CUTOFF = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
MODEL = "sha256:" + hashlib.sha256(b"ckpt").hexdigest()
POC = b"exploit-bytes-for-arvo-1"
_SCALAR_FIELDS = ("task_id", "miner_hotkey", "source_epoch", "level", "solved", "trainable",
                  "reason", "work_units", "bonus", "poc_sha256", "trace_id", "attested")


def _dg(seed):
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _pool():
    return cb.TaskPool([cb.PooledTask(task_id="arvo:1", level=cg.Level(0),
                                      binary_digest=_dg("b1"), disclosed_at=NOW, admitted=True)])


def _chain():
    return cv.ChainContext(block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
                           source_epoch=11, valid_from_block=100, valid_until_block=460)


def _backend(solved_ids):
    def run(task_id, poc, mode):
        return 1 if (task_id in solved_ids and mode == "vul") else 0
    return run


def _raising_backend(task_id, poc, mode):
    raise AssertionError("the differential backend must not run for an unattested submission")


def _dispatch():
    return cp.dispatch(_pool(), _chain(), miner_hotkey="5Miner", model_commitment=MODEL,
                       cutoff=CUTOFF, as_of=NOW, batch_size=1)


def _good_trace(task_id, digest):
    long = ("I walk the parser and read the length field then compare it against the destination "
            "buffer size to decide whether an attacker controlled value can exceed the allocation "
            "and corrupt adjacent heap metadata on the vulnerable build only path right here now")
    steps = [
        {"step": 1, "thought": f"open valid.c:1897 and read the header length; {long}", "action": "read_file"},
        {"step": 2, "thought": f"cross-check parse.c:44 and util.c:210 for the bound; {long}", "action": "read_file"},
        {"step": 3, "thought": f"length at valid.c:1900 is trusted so an oversized header overflows; {long}", "action": "reason"},
        {"step": 4, "thought": f"write the PoC with an oversized length header; {long}", "action": "write_poc"},
        {"step": 5, "thought": f"confirm the sanitizer fires on vul not fix at valid.c:1900; {long}", "action": "verify"},
    ]
    return {"task_id": task_id, "poc_sha256": digest, "model_id": "cathedral/agent-v1",
            "steps": steps, "licence": "cathedral-corpus-v1", "model_seal": _dg("seal")}


def _envelope(dispatch_msg, task_id, poc_bytes):
    digest = poc_digest(poc_bytes)
    return cp.SubmissionEnvelope(
        batch_id=dispatch_msg.batch_id, task_id=task_id, miner_hotkey="5Miner",
        poc_base64=base64.b64encode(poc_bytes).decode(), trace=_good_trace(task_id, digest))


def test_process_submission_equals_screen_then_benchmark():
    d = _dispatch()
    env = _envelope(d, "arvo:1", POC)
    backend = _backend({"arvo:1"})
    fused = cp.process_submission(env, d, backend)
    split = cp.benchmark_submission(cp.screen_submission(env, d), backend)
    for field in _SCALAR_FIELDS:
        assert getattr(fused, field) == getattr(split, field), field
    assert fused.solved and fused.trainable and fused.reason == "solved_trainable"
    assert fused.work_units == Decimal("8")


def test_screen_submission_is_attested_on_dev_path_and_carries_payload():
    d = _dispatch()
    s = cp.screen_submission(_envelope(d, "arvo:1", POC), d)
    assert s.attested and s.attest_reason == ""
    assert s.digest == poc_digest(POC) and s.poc_bytes == POC
    assert s.task.task_id == "arvo:1" and s.source_epoch == 11 and s.level == 0


def test_screen_submission_fails_closed_off_batch():
    d = _dispatch()
    bad = replace(_envelope(d, "arvo:1", POC), batch_id="not-the-batch")
    with pytest.raises(cp.ProtocolError):
        cp.screen_submission(bad, d)


def test_benchmark_skips_backend_for_unattested_screen():
    d = _dispatch()
    s = cp.screen_submission(_envelope(d, "arvo:1", POC), d)
    unattested = replace(s, attested=False, attest_reason="missing_tdx_attestation")
    out = cp.benchmark_submission(unattested, _raising_backend)  # backend must not be called
    assert out.solved is False and out.attested is False
    assert out.reason == "rejected_unattested:missing_tdx_attestation"
    assert out.work_units == Decimal(0) and out.submission is None


def test_benchmark_not_solved_when_backend_reports_no_crash():
    d = _dispatch()
    out = cp.benchmark_submission(cp.screen_submission(_envelope(d, "arvo:1", POC), d), _backend(set()))
    assert out.solved is False and out.reason.startswith("not_solved:")
    assert out.work_units == Decimal(0) and out.trace_id is None


def test_screen_gate_actually_rejects_a_missing_attestation_under_a_policy():
    # Exercise the REAL gate wiring (not a hand-built ScreenOutcome): with an attestation policy
    # configured and no attestation on the envelope, screen_submission must set attested=False,
    # and benchmark_submission must then reject it WITHOUT running the differential.
    from cathedral_distill.attestation import AttestationPolicy

    policy = AttestationPolicy(trusted_roots={}, allowed_measurements=frozenset())
    d = _dispatch()
    s = cp.screen_submission(_envelope(d, "arvo:1", POC), d, attestation_policy=policy)
    assert s.attested is False and s.attest_reason == "missing_tdx_attestation"
    out = cp.benchmark_submission(s, _raising_backend)  # backend must not run
    assert out.attested is False and not out.solved
    assert out.reason == "rejected_unattested:missing_tdx_attestation"
