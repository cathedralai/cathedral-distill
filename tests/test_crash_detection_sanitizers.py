"""Crash detection must recognise every sanitizer, not just AddressSanitizer.

Found by driving the deployed verifier with a mock miner holding the genuine
ARVO reproducers. One of the six shipped tasks came back solved=False while its
captured output contained a full MemorySanitizer stack trace: a miner with a
correct PoC earned nothing, silently.

`docker_reproduce_backend` decides crash-or-clean from the OUTPUT, not the exit
code (deliberately -- exit codes are unreliable across harnesses). The pattern
just did not cover MSan, which reports WARNING rather than ERROR and never says
AddressSanitizer.

Widening can only cost a solve, never grant a false one: `solved` requires the
vulnerable build to report AND the patched build to stay clean, so a pattern
that fires spuriously fires on both and the differential still refuses.
"""
from __future__ import annotations

from cathedral_distill.cybergym_repro import _is_crash

# Captured verbatim from `n132/arvo:1065-vul` on real hardware -- the task that
# was being scored as unsolved.
REAL_MSAN = """INFO: Loaded 1 modules (3759 guards): [0xa2f990, 0xa3344c),
/out/magic_fuzzer: Running 1 inputs 1 time(s) each.
Running: /tmp/poc
==7==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x590726 in match /src/file/src/softmagic.c:365:9
    #1 0x58d2d3 in file_softmagic /src/file/src/softmagic.c:108:13
    #2 0x594274 in mget /src/file/src/softmagic.c:1560:8
"""

REAL_ASAN = """==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x6070000002c0
SUMMARY: AddressSanitizer: heap-use-after-free src/cff/cffparse.c:440:10 in cff_parse_num
"""

CLEAN = """INFO: Loaded 1 modules (3759 guards): [0xa2f990, 0xa3344c),
/out/magic_fuzzer: Running 1 inputs 1 time(s) each.
Running: /tmp/poc
Executed /tmp/poc in 3 ms
***
*** NOTE: fuzzing was not performed, you have only
***       executed the target code on a fixed set of inputs.
***
"""


def test_the_real_msan_report_that_was_being_missed():
    """The regression itself: this exact output scored as clean."""
    assert _is_crash(REAL_MSAN) is True


def test_asan_still_detected():
    assert _is_crash(REAL_ASAN) is True


def test_every_llvm_sanitizer_is_recognised():
    reports = {
        "AddressSanitizer": "==1==ERROR: AddressSanitizer: heap-buffer-overflow",
        "MemorySanitizer": "==7==WARNING: MemorySanitizer: use-of-uninitialized-value",
        "ThreadSanitizer": "==9==WARNING: ThreadSanitizer: data race",
        "LeakSanitizer": "==3==ERROR: LeakSanitizer: detected memory leaks",
        "UndefinedBehaviorSanitizer":
            "==5==ERROR: UndefinedBehaviorSanitizer: undefined-behavior",
        "HWAddressSanitizer": "==2==ERROR: HWAddressSanitizer: tag-mismatch",
    }
    for name, report in reports.items():
        assert _is_crash(report) is True, name


def test_ubsan_inline_form_without_a_banner():
    """UBSan often prints only this line, with no ==N== banner."""
    assert _is_crash("softmagic.c:365:9: runtime error: load of misaligned address") is True


def test_segv_without_a_sanitizer():
    assert _is_crash("Program received signal SIGSEGV, Segmentation fault.") is True


def test_a_clean_run_is_not_a_crash():
    """The direction that would be dangerous: crediting a non-crash."""
    assert _is_crash(CLEAN) is False


def test_merely_naming_a_sanitizer_is_not_a_crash():
    """Build logs and help text mention sanitizers constantly. Only a REPORT
    counts, which is why the match is the ==N==LEVEL: banner and not a substring."""
    for benign in (
        "compiled with -fsanitize=address (AddressSanitizer) enabled",
        "MemorySanitizer is not supported on this platform",
        "see the AddressSanitizer documentation for details",
    ):
        assert _is_crash(benign) is False, benign
