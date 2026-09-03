"""The real agent: sanitizer-trace feedback and a fuzz tool.

The baseline agent flew blind — run_poc returned only a crash/clean bit, so on real ARVO bugs
(found originally by industrial fuzzing) it could not steer toward the vulnerable code, and both
a 27B and a strong coding model solved 0/8. A real analyst sees the sanitizer report and can run
a fuzzer. These tests cover both: the report digest that turns a crash into steering signal, and
the fuzz tool that drives real mutation instead of one-shot crafting.
"""
from __future__ import annotations

from cathedral_distill.cybergym_agent import (
    CYBERGYM_TOOLS,
    FuzzResult,
    Observation,
    build_system_prompt,
    run_agent,
    summarize_sanitizer_report,
)

WORKSPACE = {"png.c": "int ReadMNGImage(){ /* ... */ }", "harness.cc": "LLVMFuzzerTestOneInput"}
ASAN = (
    "=================================================================\n"
    "==17==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602 at pc 0x49\n"
    "READ of size 4 at 0x602 thread T0\n"
    "    #0 0x49 in ReadMNGImage coders/png.c:872\n"
    "    #1 0x4a in ReadImage magick/constitute.c:1600\n"
    "    #2 0x4b in LLVMFuzzerTestOneInput fuzzing/coder_fuzzer.cc:41\n"
    + "0x0602: fa fa fa fa " * 500  # the shadow dump that must be dropped
)


class TestTheSanitizerDigestSteers:
    def test_it_extracts_the_finding_and_top_frames(self):
        out = summarize_sanitizer_report(ASAN)
        assert "heap-buffer-overflow" in out
        assert "ReadMNGImage coders/png.c:872" in out
        assert "LLVMFuzzerTestOneInput" in out

    def test_it_drops_the_shadow_dump(self):
        out = summarize_sanitizer_report(ASAN)
        assert "fa fa fa fa" not in out
        assert len(out) <= 1300

    def test_a_clean_run_returns_the_targets_own_output_as_a_signal(self):
        """'invalid chunk length' tells the agent its input was rejected before the bug."""
        out = summarize_sanitizer_report("libpng error: invalid chunk length\n")
        assert "invalid chunk length" in out

    def test_empty_output_is_labelled_not_blank(self):
        assert summarize_sanitizer_report("") == "no output"

    def test_msan_warning_form_is_caught_too(self):
        out = summarize_sanitizer_report("==7==WARNING: MemorySanitizer: use-of-uninitialized-value\n    #0 0x1 in f a.c:2")
        assert "MemorySanitizer: use-of-uninitialized-value" in out


class TestRunPocSurfacesTheReport:
    def test_a_crash_hands_back_the_sanitizer_finding(self):
        crashing = bytes.fromhex("8a4d4e47")
        def complete(_):
            return '<tool_call>{"name":"run_poc","arguments":{"hex":"8a4d4e47"}}</tool_call>'
        def observe(task_id, poc):
            return Observation(crashed=(poc == crashing), report=summarize_sanitizer_report(ASAN))
        res = run_agent(complete, task_id="arvo:10400", workspace=WORKSPACE, backend=lambda *a: 0,
                        miner_hotkey="5m", model_id="m", max_turns=3, max_output_chars=4000,
                        observe=observe)
        assert res.solved is True
        # the crash step records the real finding, so the trajectory and the model both see it
        poc_steps = [s for s in res.steps_raw if s["action"] == "write_poc"]
        assert any("heap-buffer-overflow" in s["output"] for s in poc_steps)

    def test_a_clean_run_surfaces_the_parse_error(self):
        emitted = {}
        def complete(messages):
            for msg in reversed(messages):
                if "clean exit" in msg.get("content", ""):
                    emitted["out"] = msg["content"]; break
            return '<tool_call>{"name":"run_poc","arguments":{"hex":"00"}}</tool_call>'
        def observe(task_id, poc):
            return Observation(crashed=False, report="libpng error: invalid signature")
        run_agent(complete, task_id="arvo:1", workspace=WORKSPACE, backend=lambda *a: 0,
                  miner_hotkey="5m", model_id="m", max_turns=2, max_output_chars=4000, observe=observe)
        assert "invalid signature" in emitted.get("out", "")

    def test_without_observe_it_falls_back_to_the_crash_bit(self):
        """Existing callers pass no observe and keep the old crash/clean behaviour."""
        crashing = bytes.fromhex("ff")
        def complete(_):
            return '<tool_call>{"name":"run_poc","arguments":{"hex":"ff"}}</tool_call>'
        res = run_agent(complete, task_id="arvo:1", workspace=WORKSPACE,
                        backend=lambda tid, poc, mode: 1 if poc == crashing else 0,
                        miner_hotkey="5m", model_id="m", max_turns=2, max_output_chars=4000)
        assert res.solved is True


class TestTheFuzzTool:
    def test_it_is_declared_and_taught(self):
        assert "fuzz" in {t["function"]["name"] for t in CYBERGYM_TOOLS}
        assert "fuzz tool" in build_system_prompt()

    def test_a_fuzzer_crash_is_confirmed_through_the_differential_and_solves(self):
        """A fuzzer artifact cannot be credited without reproducing on the vulnerable build."""
        found = bytes.fromhex("8a4d4e47deadbeef")
        def complete(_):
            return '<tool_call>{"name":"fuzz","arguments":{"seeds":["8a4d4e47"],"dictionary":["MNG"]}}</tool_call>'
        def fuzzer(task_id, seeds, dictionary):
            assert seeds == [bytes.fromhex("8a4d4e47")]
            assert dictionary == [b"MNG"]
            return FuzzResult(crashing_input=found, report="crashed after 12000 runs")
        res = run_agent(complete, task_id="arvo:10400", workspace=WORKSPACE,
                        backend=lambda tid, poc, mode: 1 if poc == found else 0,
                        miner_hotkey="5m", model_id="m", max_turns=2, max_output_chars=4000,
                        fuzzer=fuzzer)
        assert res.solved is True and res.poc == found

    def test_a_fuzzer_crash_that_does_not_reproduce_is_refused(self):
        """Fail closed: a crash the differential does not confirm must not score."""
        found = bytes.fromhex("aa")
        emitted = {}
        def complete(_):
            return '<tool_call>{"name":"fuzz","arguments":{}}</tool_call>'
        def fuzzer(*a):
            return FuzzResult(crashing_input=found, report="found a crash")
        res = run_agent(complete, task_id="arvo:1", workspace=WORKSPACE,
                        backend=lambda *a: 0,  # never reproduces
                        miner_hotkey="5m", model_id="m", max_turns=2, max_output_chars=4000,
                        fuzzer=fuzzer, on_step=lambda s: emitted.setdefault("o", s.get("output","")))
        assert res.solved is False

    def test_no_crash_reports_cleanly_and_keeps_going(self):
        calls = iter(['<tool_call>{"name":"fuzz","arguments":{}}</tool_call>',
                      '<tool_call>{"name":"run_poc","arguments":{"hex":"ff"}}</tool_call>'])
        def fuzzer(*a):
            return FuzzResult(crashing_input=None, report="no crash in 55s / 800000 runs")
        res = run_agent(lambda m: next(calls), task_id="arvo:1", workspace=WORKSPACE,
                        backend=lambda tid, poc, mode: 1 if poc == b"\xff" else 0,
                        miner_hotkey="5m", model_id="m", max_turns=3, max_output_chars=4000,
                        fuzzer=fuzzer)
        assert res.solved is True  # fell through to the run_poc that crashes

    def test_the_tool_is_absent_when_no_fuzzer_is_wired(self):
        emitted = {}
        def complete(messages):
            for msg in reversed(messages):
                if "not available" in msg.get("content", ""):
                    emitted["seen"] = True; break
            return '<tool_call>{"name":"fuzz","arguments":{}}</tool_call>'
        run_agent(complete, task_id="arvo:1", workspace=WORKSPACE, backend=lambda *a: 0,
                  miner_hotkey="5m", model_id="m", max_turns=2, max_output_chars=4000)
        assert emitted.get("seen") is True

    def test_fuzz_counts_as_an_attempt_for_the_exploration_budget(self):
        """A fuzz call is an attempt, so it resets the read budget like run_poc."""
        from cathedral_distill.cybergym_agent import MAX_READS_BEFORE_ATTEMPT
        nudged = {"seen": False}
        seq = (['<tool_call>{"name":"read_file","arguments":{"path":"png.c"}}</tool_call>'] * 4
               + ['<tool_call>{"name":"fuzz","arguments":{}}</tool_call>']
               + ['<tool_call>{"name":"read_file","arguments":{"path":"png.c"}}</tool_call>'] * 3)
        it = iter(seq)
        def complete(messages):
            for msg in reversed(messages):
                if "read enough" in msg.get("content", ""):
                    nudged["seen"] = True; break
            return next(it)
        run_agent(complete, task_id="arvo:1", workspace=WORKSPACE, backend=lambda *a: 0,
                  miner_hotkey="5m", model_id="m", max_turns=len(seq), max_output_chars=4000,
                  fuzzer=lambda *a: FuzzResult(None, "no crash"))
        assert nudged["seen"] is False  # 4 reads, fuzz resets, 3 reads => never past 8
