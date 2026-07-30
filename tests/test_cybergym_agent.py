"""The real tool-using CyberGym agent loop (Hermes function-calling).

A scripted model drives the agent through a genuine trajectory — list, read,
try a wrong PoC, refine, crash — and we assert the loop iterates to a solve and
emits a real cathedral_trace_submission_v1 trace that (a) clears the trainable
floor because the steps are real work and (b) verifies through the actual
validator pipeline (process_submission) as solved + trainable.
"""
from __future__ import annotations

import base64
import hashlib

from cathedral_distill.cybergym_agent import (
    build_system_prompt,
    parse_tool_calls,
    run_agent,
)
from cathedral_distill.cybergym_protocol import (
    DispatchedTask,
    DispatchMessage,
    SubmissionEnvelope,
    process_submission,
)
from cathedral_distill.cybergym_synthetic import SyntheticTaskSource, generate_bug

NONCE = "agent01ab"
MINER = "5AgentMiner"


def _fixture():
    source = SyntheticTaskSource()
    batch = source.draw(size=1, nonce=NONCE)
    task = batch.tasks[0]
    bug = generate_bug(NONCE, 0, level=int(task.level))
    return source, task, bug


def _scripted_model(bug):
    """A fake `complete` that plays a realistic solve: list -> read -> wrong PoC
    (bad magic) -> wrong PoC (short) -> correct trigger -> crash."""
    good = bug.trigger.hex()
    bad_magic = ("deadbeef" + bug.trigger[4:].hex())            # right length, wrong magic -> clean
    short = (bug.magic.hex() + "0001" + "41")                    # right magic, tiny length -> clean
    replies = [
        'I begin by listing the workspace to see what I have been handed. '
        '<tool_call>{"name": "list_files", "arguments": {}}</tool_call>',
        'There is a single vulnerable build, vuln.c. I read it to understand the parser before crafting any input, '
        'paying attention to the entry guard and the copy. '
        '<tool_call>{"name": "read_file", "arguments": {"path": "vuln.c"}}</tool_call>',
        'At vuln.c:1 a four-byte magic prefix gates the parser via memcmp, so any input that does not reproduce that '
        'exact magic is rejected before the vulnerable path. At vuln.c:2 a two-byte big-endian length is read straight '
        'from attacker bytes with no clamp, and at vuln.c:4 the memcpy copies that many bytes into a fixed stack buffer. '
        'Let me first confirm the magic gate by sending the right length but a wrong magic, which should exit cleanly. '
        f'<tool_call>{{"name": "run_poc", "arguments": {{"hex": "{bad_magic}"}}}}</tool_call>',
        'As expected that was a clean exit, confirming the magic at vuln.c:1 must match byte-for-byte. Now I reproduce '
        'the magic but with a tiny length to check that a small copy does not overflow the buffer at vuln.c:4. '
        f'<tool_call>{{"name": "run_poc", "arguments": {{"hex": "{short}"}}}}</tool_call>',
        'Clean again, so a small length is safe. The overflow needs a length strictly past the buffer size read at '
        'vuln.c:3, so I now send the correct magic followed by a big-endian length just beyond the buffer and that many '
        'filler bytes, which should overrun the stack buffer at vuln.c:4 on the vulnerable build. '
        f'<tool_call>{{"name": "run_poc", "arguments": {{"hex": "{good}"}}}}</tool_call>',
    ]
    state = {"i": 0}

    def complete(_messages):
        i = state["i"]
        state["i"] = min(i + 1, len(replies) - 1)
        return replies[i]

    return complete


def test_parse_and_prompt_basics():
    assert "read_file" in build_system_prompt() and "run_poc" in build_system_prompt()
    calls = parse_tool_calls('reasoning <tool_call>{"name": "read_file", "arguments": {"path": "vuln.c"}}</tool_call>')
    assert calls == [{"name": "read_file", "arguments": {"path": "vuln.c"}}]
    assert parse_tool_calls("no calls here") == []


def test_agent_iterates_to_a_real_solve_with_a_genuine_trace():
    source, task, bug = _fixture()
    workspace = {"vuln.c": source.artifact(task.task_id)}
    res = run_agent(_scripted_model(bug), task_id=task.task_id, workspace=workspace,
                    backend=source.backend, miner_hotkey=MINER, model_id="test/scripted", max_turns=8)
    assert res.solved and res.poc == bug.trigger
    # the trace is built from the REAL steps: list, read, two failed PoCs, the crash, verify
    actions = [s["action"] for s in res.trace["steps"]]
    assert actions.count("read_file") >= 1 and actions.count("write_poc") >= 2 and actions[-1] == "verify"
    assert len(res.trace["steps"]) >= 5
    # and it was a genuine iterate — at least one clean-exit observation before the crash
    outputs = [s["output"] for s in res.trace["steps"]]
    assert any("clean exit" in o for o in outputs) and any("CRASHED" in o for o in outputs)


def test_agent_trace_verifies_through_the_validator_pipeline():
    source, task, bug = _fixture()
    workspace = {"vuln.c": source.artifact(task.task_id)}
    res = run_agent(_scripted_model(bug), task_id=task.task_id, workspace=workspace,
                    backend=source.backend, miner_hotkey=MINER, model_id="test/scripted", max_turns=8)
    assert res.solved

    dt = DispatchedTask(task_id=task.task_id, level=int(task.level),
                        binary_digest=task.binary_digest, context={})
    msg = DispatchMessage(network="finney", netuid=39, source_epoch=11,
                          batch_id="b", nonce=NONCE, miner_hotkey=MINER,
                          valid_from_block=1, valid_until_block=999, tasks=(dt,))
    env = SubmissionEnvelope(batch_id="b", task_id=task.task_id, miner_hotkey=MINER,
                             poc_base64=base64.b64encode(res.poc).decode(), trace=res.trace)
    out = process_submission(env, msg, source.backend)     # hardware-free path (no attestation policy)
    assert out.solved and out.work_units > 0
    assert out.trainable, out.reason                        # the genuine trajectory clears the floor
    # the trace the validator would corpus is exactly the agent's trajectory
    assert out.submission is not None and out.submission.trace_id() == \
        __import__("cathedral_distill.cybergym_protocol", fromlist=["_trace_from_dict"])._trace_from_dict(res.trace).trace_id()


def test_agent_calls_the_backend_with_the_vul_mode_contract_not_vuln():
    # regression: run_agent must drive the backend with "vul" (the VerifierBackend
    # contract: mode is "vul"|"fix"), never "vuln". The production backends raise
    # VerifierError on an unknown mode, so a typo crashes the agent on its first
    # run_poc — but the synthetic backend treats any non-"fix" string as vul and
    # hides it. A strict backend that mirrors the production contract catches it.
    source, task, bug = _fixture()
    workspace = {"vuln.c": source.artifact(task.task_id)}

    def strict_backend(task_id, poc, mode):
        if mode not in ("vul", "fix"):
            raise RuntimeError(f"unknown mode {mode!r}")   # what subprocess_backend does
        return source.backend(task_id, poc, mode)

    res = run_agent(_scripted_model(bug), task_id=task.task_id, workspace=workspace,
                    backend=strict_backend, miner_hotkey=MINER, model_id="test/strict", max_turns=8)
    assert res.solved and res.poc == bug.trigger


def test_agent_reports_unsolved_when_it_never_crashes():
    source, task, bug = _fixture()
    workspace = {"vuln.c": source.artifact(task.task_id)}
    # a model that only ever reads, never crafts a crashing PoC
    def lazy(_m):
        return 'thinking <tool_call>{"name": "read_file", "arguments": {"path": "vuln.c"}}</tool_call>'
    res = run_agent(lazy, task_id=task.task_id, workspace=workspace, backend=source.backend,
                    miner_hotkey=MINER, model_id="test/lazy", max_turns=4)
    assert not res.solved and res.poc is None and res.trace is None
    assert res.reason.startswith("unsolved")
