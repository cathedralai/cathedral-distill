"""Stage 1 harness-capability competition: run a committed general harness on a
fresh sealed batch and score it by GENUINE solves, using the same differential
verifier as the reward path. No traces are collected in Stage 1.

Hardware-free: the harness runner and the crash backend are both injected, so no
CyberGym binaries or TDX enclave are needed to exercise the scoring wiring.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym_protocol as cp  # noqa: E402
from cathedral_distill import cybergym_stage1 as s1  # noqa: E402
from cathedral_distill.cybergym_verifier import poc_digest  # noqa: E402


def _dg(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


HARNESS = _dg("harness-v1")


def _dispatch(model_commitment=HARNESS, task_levels=(("arvo:1", 0), ("arvo:2", 2))):
    tasks = tuple(
        cp.DispatchedTask(task_id=tid, level=lvl, binary_digest=_dg(tid), context={})
        for tid, lvl in task_levels
    )
    return cp.DispatchMessage(
        network="finney", netuid=39, source_epoch=11, batch_id="batch-1", nonce="nonce",
        miner_hotkey="5Miner", model_commitment=model_commitment,
        valid_from_block=100, valid_until_block=460, tasks=tasks,
    )


def _submission(digest=HARNESS):
    return s1.HarnessSubmission(miner_hotkey="5Miner", harness_digest=digest, version="v1")


def _runner(produce_for):
    """A fake harness: emits exploit bytes for the listed task_ids, nothing else."""
    def run(submission, task, artifact):
        return b"exploit-" + task.task_id.encode() if task.task_id in produce_for else None
    return run


def _backend(crash_ids):
    """Injected differential: crash the vul build (only) for the listed task_ids."""
    def run(task_id, poc, mode):
        return 1 if (task_id in crash_ids and mode == "vul") else 0
    return run


# --------------------------------------------------------------------------- #
# Submission validation — fails closed
# --------------------------------------------------------------------------- #

def test_submission_rejects_bad_digest():
    with pytest.raises(s1.HarnessError):
        s1.HarnessSubmission(miner_hotkey="5Miner", harness_digest="deadbeef", version="v1")


def test_submission_rejects_empty_hotkey():
    with pytest.raises(s1.HarnessError):
        s1.HarnessSubmission(miner_hotkey="", harness_digest=HARNESS, version="v1")


def test_submission_rejects_bad_version():
    with pytest.raises(s1.HarnessError):
        s1.HarnessSubmission(miner_hotkey="5Miner", harness_digest=HARNESS, version="")
    with pytest.raises(s1.HarnessError):
        s1.HarnessSubmission(miner_hotkey="5Miner", harness_digest=HARNESS, version="x" * 33)


# --------------------------------------------------------------------------- #
# evaluate_harness — genuine solves only
# --------------------------------------------------------------------------- #

def test_scores_only_genuine_solves():
    # Harness emits an exploit for both tasks, but only arvo:1 actually crashes.
    score = s1.evaluate_harness(
        _submission(), _dispatch(),
        runner=_runner({"arvo:1", "arvo:2"}), backend=_backend({"arvo:1"}),
    )
    assert score.dispatched == 2
    assert score.solved == 1
    assert score.solve_rate == pytest.approx(0.5)
    by_id = {r.task_id: r for r in score.results}
    assert by_id["arvo:1"].solved is True
    assert by_id["arvo:1"].exploit_sha256 == poc_digest(b"exploit-arvo:1")
    assert by_id["arvo:2"].solved is False  # produced, but did not crash the vul build


def test_no_output_is_not_a_solve():
    score = s1.evaluate_harness(
        _submission(), _dispatch(),
        runner=_runner({"arvo:1"}), backend=_backend({"arvo:1", "arvo:2"}),
    )
    by_id = {r.task_id: r for r in score.results}
    assert by_id["arvo:1"].solved is True
    assert by_id["arvo:2"].solved is False
    assert by_id["arvo:2"].exploit_sha256 is None
    assert by_id["arvo:2"].reason == "harness_produced_no_exploit"


def test_empty_batch_scores_zero():
    score = s1.evaluate_harness(
        _submission(), _dispatch(task_levels=()),
        runner=_runner(set()), backend=_backend(set()),
    )
    assert score.dispatched == 0
    assert score.solved == 0
    assert score.solve_rate == 0


# --------------------------------------------------------------------------- #
# Commit-then-draw — enforced here, fails closed
# --------------------------------------------------------------------------- #

def test_rejects_dispatch_not_committed_to_harness():
    # The batch was frozen to a DIFFERENT commitment, so the harness could have
    # been tuned to its own graded set. Refuse to score it.
    other = _dispatch(model_commitment=_dg("some-other-model"))
    with pytest.raises(s1.HarnessError):
        s1.evaluate_harness(
            _submission(), other,
            runner=_runner({"arvo:1"}), backend=_backend({"arvo:1"}),
        )


# --------------------------------------------------------------------------- #
# Artifact plumbing — the harness only ever sees the challenge artifact
# --------------------------------------------------------------------------- #

def test_artifact_provider_is_queried_per_task():
    seen: list[str] = []

    def provider(task_id: str) -> bytes:
        seen.append(task_id)
        return b"challenge-" + task_id.encode()

    def run(submission, task, artifact):
        assert artifact == b"challenge-" + task.task_id.encode()
        return b"exploit-" + task.task_id.encode()

    s1.evaluate_harness(
        _submission(), _dispatch(), runner=run, backend=_backend({"arvo:1"}),
        artifact_provider=provider,
    )
    assert seen == ["arvo:1", "arvo:2"]


# --------------------------------------------------------------------------- #
# Ranking — most genuine solves first, deterministic
# --------------------------------------------------------------------------- #

def test_rank_orders_by_solves_then_digest():
    a = s1.HarnessScore("m1", _dg("aaa"), dispatched=3,
                        results=(s1.HarnessResult("t1", True, "sha256:x", "solved"),))
    b = s1.HarnessScore("m2", _dg("bbb"), dispatched=3, results=(
        s1.HarnessResult("t1", True, "sha256:x", "solved"),
        s1.HarnessResult("t2", True, "sha256:y", "solved"),
    ))
    c = s1.HarnessScore("m3", _dg("ccc"), dispatched=3, results=())
    ranked = s1.rank_harnesses([a, b, c])
    assert [s.miner_hotkey for s in ranked] == ["m2", "m1", "m3"]


def test_rank_tie_breaks_on_digest():
    # Equal solve counts → deterministic ascending-digest order (ungrindable by
    # resubmitting under a fresh hotkey).
    d1, d2 = _dg("aaa"), _dg("zzz")
    one = s1.HarnessScore("m1", d1, dispatched=1,
                          results=(s1.HarnessResult("t1", True, "sha256:x", "solved"),))
    two = s1.HarnessScore("m2", d2, dispatched=1,
                          results=(s1.HarnessResult("t1", True, "sha256:x", "solved"),))
    ranked = s1.rank_harnesses([two, one])
    assert [s.harness_digest for s in ranked] == sorted([d1, d2])


# --------------------------------------------------------------------------- #
# Execution log (distill#142): the runner returns exploit AND log; every
# dispatched task is persisted, including the no-exploit / failure cases.
# --------------------------------------------------------------------------- #
import json as _json  # noqa: E402


def _log_for(task_id, reason="produced_output"):
    return s1.build_execution_log(
        task_id=task_id, terminal_reason=reason, duration_ms=5,
        steps=[{"seq": 0, "action": "run_harness", "args": {"argv": ["h", task_id]},
                "result": {"stdout": "out", "stderr": "", "exit_code": 0},
                "files": [{"path": "x", "op": "read", "sha256": _dg(task_id)}]}])


def _run_runner(produce_for, *, with_log=True):
    """A harness that returns a HarnessRun: exploit for listed tasks, a log for ALL of them."""
    def run(submission, task, artifact):
        exploit = b"exploit-" + task.task_id.encode() if task.task_id in produce_for else None
        reason = s1.EXIT_NO_OUTPUT if exploit is None else "produced_output"
        log = _log_for(task.task_id, reason) if with_log else None
        return s1.HarnessRun(exploit=exploit, log=log, duration_ms=5, exit_reason=reason)
    return run


def test_runner_returns_exploit_and_log_ref_is_carried():
    sunk: dict[str, bytes] = {}
    score = s1.evaluate_harness(
        _submission(), _dispatch(), runner=_run_runner({"arvo:1"}),
        backend=_backend({"arvo:1"}), log_sink=lambda tid, blob: sunk.__setitem__(tid, blob))
    solved = {r.task_id: r for r in score.results}
    assert solved["arvo:1"].solved and solved["arvo:1"].exit_reason == s1.EXIT_SOLVED
    # every result carries a content-addressed log ref matching the sunk bytes
    for tid, r in solved.items():
        assert r.log_sha256 == "sha256:" + hashlib.sha256(sunk[tid]).hexdigest()


def test_log_is_persisted_for_EVERY_dispatched_task_including_failures():
    """The whole point: a harness that produced nothing is stored exactly like one that solved."""
    sunk: dict[str, bytes] = {}
    disp = _dispatch(task_levels=(("arvo:1", 0), ("arvo:2", 2), ("arvo:3", 1)))
    score = s1.evaluate_harness(
        _submission(), disp, runner=_run_runner({"arvo:1"}),  # only arvo:1 produces an exploit
        backend=_backend({"arvo:1"}), log_sink=lambda tid, blob: sunk.__setitem__(tid, blob))
    # one log per DISPATCHED task, not per solve
    assert set(sunk) == {"arvo:1", "arvo:2", "arvo:3"} == {r.task_id for r in score.results}
    assert score.solved == 1  # only arvo:1 solved
    # the failures carry a terminal reason and a stored log
    fails = [r for r in score.results if not r.solved]
    assert len(fails) == 2 and all(r.log_sha256 and r.exit_reason == s1.EXIT_NO_OUTPUT for r in fails)


def test_legacy_bytes_runner_still_accepted_no_log():
    """One release of backward compatibility: a bare bytes|None runner works, logs are just absent."""
    calls: list[str] = []
    score = s1.evaluate_harness(
        _submission(), _dispatch(), runner=_runner({"arvo:1"}), backend=_backend({"arvo:1"}),
        log_sink=lambda tid, blob: calls.append(tid))
    assert score.solved == 1
    assert all(r.log_sha256 is None for r in score.results)  # no log from a legacy runner
    assert calls == []  # sink never called when there is no log to persist


def test_execution_log_is_a_record_not_a_narrative():
    blob = _log_for("arvo:900001", s1.EXIT_TIMEOUT)
    doc = _json.loads(blob)
    assert doc["schema"] == s1.EXECUTION_LOG_SCHEMA
    assert doc["task_family"] == "arvo" and doc["terminal_reason"] == s1.EXIT_TIMEOUT
    step = doc["steps"][0]
    assert set(step) == {"seq", "action", "args", "result", "files", "ts_ms"}
    assert set(step["result"]) == {"stdout", "stderr", "exit_code"}
    assert "thought" not in step and "reasoning" not in step  # execution record, not a thought log


def test_local_harness_runner_emits_same_log_shape():
    runner = s1.local_harness_runner("cat")  # echoes the challenge artifact (stdin) to stdout
    dt = cp.DispatchedTask(task_id="arvo:7", level=0, binary_digest=_dg("arvo:7"), context={})
    run = runner(_submission(), dt, b"the-artifact")
    assert isinstance(run, s1.HarnessRun) and run.exploit == b"the-artifact"
    doc = _json.loads(run.log)
    assert doc["schema"] == s1.EXECUTION_LOG_SCHEMA and doc["task_family"] == "arvo"
    assert doc["steps"][0]["action"] == "run_harness"
    assert doc["steps"][0]["files"][0]["sha256"] == "sha256:" + hashlib.sha256(b"the-artifact").hexdigest()


# --------------------------------------------------------------------------- #
# Hardening from the adversarial pass: the "every dispatched task yields a log"
# guarantee must survive a RAISING runner, a modern run that forgot its log,
# and empty-bytes logs; and the log must not be a padding surface.
# --------------------------------------------------------------------------- #

def test_a_raising_runner_yields_a_crash_log_and_the_batch_continues():
    """A runner that RAISES on one task must not abort the batch: that task gets a synthesized
    crash log and every LATER task is still graded and logged."""
    sunk: dict[str, bytes] = {}
    disp = _dispatch(task_levels=(("arvo:1", 0), ("arvo:2", 0), ("arvo:3", 0)))

    def runner(submission, task, artifact):
        if task.task_id == "arvo:2":
            raise RuntimeError("enclave attestation blew up")
        return s1.HarnessRun(exploit=None, log=_log_for(task.task_id, s1.EXIT_NO_OUTPUT),
                             exit_reason=s1.EXIT_NO_OUTPUT)

    score = s1.evaluate_harness(_submission(), disp, runner=runner, backend=_backend(set()),
                                log_sink=lambda tid, blob: sunk.__setitem__(tid, blob))
    assert set(sunk) == {"arvo:1", "arvo:2", "arvo:3"}  # every dispatched task logged, crash included
    crashed = next(r for r in score.results if r.task_id == "arvo:2")
    assert crashed.exit_reason == s1.EXIT_CRASH and crashed.reason.startswith("harness_run_crashed")
    assert _json.loads(sunk["arvo:2"])["terminal_reason"] == s1.EXIT_CRASH


def test_modern_run_with_no_log_synthesizes_a_minimal_one():
    """A NEW-style HarnessRun whose runner forgot the log on a failure path is the highest-value
    row; synthesize a minimal log so it is never a silent drop (legacy bytes|None stays log-free)."""
    sunk: dict[str, bytes] = {}
    disp = _dispatch(task_levels=(("arvo:1", 0),))

    def runner(submission, task, artifact):
        return s1.HarnessRun(exploit=None, log=None, exit_reason=s1.EXIT_TIMEOUT)

    score = s1.evaluate_harness(_submission(), disp, runner=runner, backend=_backend(set()),
                                log_sink=lambda tid, blob: sunk.__setitem__(tid, blob))
    assert "arvo:1" in sunk  # synthesized, not dropped
    doc = _json.loads(sunk["arvo:1"])
    assert doc["schema"] == s1.EXECUTION_LOG_SCHEMA and doc["terminal_reason"] == s1.EXIT_TIMEOUT
    assert score.results[0].log_sha256 == "sha256:" + hashlib.sha256(sunk["arvo:1"]).hexdigest()


def test_empty_log_bytes_are_persisted_not_dropped():
    """Empty bytes are a log, not the absence of one: the sink fires on `is not None`, not truthiness
    (guards against a future regression to `if run.log:` that would silently drop b'')."""
    sunk: dict[str, bytes] = {}
    disp = _dispatch(task_levels=(("arvo:1", 0),))
    runner = lambda sub, task, art: s1.HarnessRun(exploit=None, log=b"", exit_reason=s1.EXIT_NO_OUTPUT)
    s1.evaluate_harness(_submission(), disp, runner=runner, backend=_backend(set()),
                        log_sink=lambda tid, blob: sunk.__setitem__(tid, blob))
    assert sunk == {"arvo:1": b""}


def test_observation_fields_are_size_capped_not_a_padding_surface():
    big = "A" * (200 * 1024)
    blob = s1.build_execution_log(
        task_id="arvo:1", terminal_reason=s1.EXIT_NO_OUTPUT,
        steps=[{"seq": 0, "action": "run", "args": {"pad": big},
                "result": {"stdout": big, "stderr": "", "exit_code": 0}}])
    doc = _json.loads(blob)
    assert len(doc["steps"][0]["result"]["stdout"]) <= 64 * 1024 + 64        # stdout capped
    assert doc["steps"][0]["args"] == {"_truncated_bytes": len(_json.dumps({"pad": big}, separators=(",", ":")))}


def test_build_execution_log_never_raises_on_a_non_json_native_arg():
    """A str-coercible-but-not-JSON-native arg (Decimal/set/bytes) must serialize, not TypeError:
    the size pre-check and the final dump must agree (both go through default=str)."""
    from decimal import Decimal
    blob = s1.build_execution_log(
        task_id="arvo:1", terminal_reason=s1.EXIT_NO_OUTPUT,
        steps=[{"seq": 0, "action": "run", "args": {"budget": Decimal("1.5"), "tags": {"a", "b"}}}])
    doc = _json.loads(blob)  # round-trips cleanly
    assert doc["steps"][0]["args"]["budget"] == "1.5"  # stringified, not exploded


def test_execution_log_carries_the_declared_model_when_supplied():
    """Schema readiness for V1 provenance: the log records WHICH model produced the trajectory
    (the miner's registration-signed model), and defaults to '' so existing callers are unaffected."""
    with_model = _json.loads(s1.build_execution_log(
        task_id="arvo:1", terminal_reason=s1.EXIT_SOLVED, steps=[], model="deepseek-v4-pro"))
    assert with_model["model"] == "deepseek-v4-pro"
    default = _json.loads(s1.build_execution_log(task_id="arvo:1", terminal_reason=s1.EXIT_SOLVED, steps=[]))
    assert default["model"] == ""
