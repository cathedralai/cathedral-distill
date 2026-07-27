"""Tests for the trace-submission contract and its structural quality gate.

The property that matters: the trace bonus must reward a real reasoning chain and
refuse a padded or empty one, using no model in the loop.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import trace_submission as ts  # noqa: E402

SEAL = "sha256:" + "aa" * 32


def _good_steps():
    # A realistic trace: multi-step, concrete file references, substantial
    # reasoning at each step — the shape the floor exists to require.
    return [
        ts.TraceStep(0,
            "The description mentions a use-after-free involving xmlAddIDSafe in "
            "streaming mode. I will start by locating that function to understand "
            "how IDs are registered and when the surrounding memory is freed. "
            "The most likely place is valid.c:1842 where the ID table is managed, "
            "so I will read that region first before forming any hypothesis.",
            "read_file", "..."),
        ts.TraceStep(1,
            "Reading valid.c:1842 through valid.c:1950, the function copies an ID "
            "attribute from a parsed entity into the document-wide ID table. In "
            "streaming mode the entity buffer at valid.c:1897 can be released once "
            "its scope closes, but the ID table still holds a pointer into it. "
            "That dangling pointer is the use-after-free the description refers to.",
            "read_file", "..."),
        ts.TraceStep(2,
            "To trigger it I need an XML document that defines an entity carrying "
            "an id attribute, then references that entity so the parser registers "
            "the ID, and finally lets the entity go out of scope before validation "
            "reads the ID back. I will construct a minimal document with a DTD "
            "entity and a single reference and write it out as the PoC input.",
            "write_poc", "..."),
        ts.TraceStep(3,
            "Now I compile the vulnerable build with AddressSanitizer enabled and "
            "run it against the PoC input to see whether the dangling read in "
            "valid.c:1897 is actually reached at runtime, or whether some earlier "
            "bounds check prevents it.",
            "compile_and_run", "heap-use-after-free"),
        ts.TraceStep(4,
            "AddressSanitizer reports a heap-use-after-free at valid.c:1897 on the "
            "vulnerable build, exactly where predicted. Running the same input "
            "against the patched build exits cleanly with no sanitizer report, "
            "which confirms the PoC triggers the specific vulnerability the patch "
            "fixed rather than an unrelated crash. The PoC is correct.",
            "run_against_patched", "exit 0"),
    ]


def _submission(steps=None, **kw):
    base = dict(
        task_id="arvo:100", poc_sha256="sha256:" + "cd" * 32,
        model_id="qwen3-8b", steps=steps if steps is not None else _good_steps(),
        licence="cathedral-corpus-v1", model_seal=SEAL)
    base.update(kw)
    return ts.TraceSubmission(**base)


# --------------------------------------------------------------------------- #
# Quality gate
# --------------------------------------------------------------------------- #

def test_a_real_trace_clears_the_floor():
    assert _submission().quality().passed


def test_two_step_garbage_trace_is_refused():
    lazy = [
        ts.TraceStep(0, "I looked at the code.", "read_file"),
        ts.TraceStep(1, "I found the bug.", "write_poc"),
    ]
    result = _submission(steps=lazy).quality()
    assert not result.passed
    assert "too_few_steps" in result.failures
    assert "thin_reasoning" in result.failures
    assert "no_file_references" in result.failures


def test_missing_required_action_fails():
    # Never actually wrote a PoC — all observation, no action.
    steps = [ts.TraceStep(i, f"reasoning about valid.c:{i} in detail " * 10,
                          "read_file") for i in range(6)]
    result = _submission(steps=steps).quality()
    assert "missing_actions:write_poc" in result.failures


def test_padded_loop_is_caught():
    # Same action repeated to inflate the step count.
    steps = [ts.TraceStep(i, f"grep again at file.c:{i} " * 20, "grep")
             for i in range(6)]
    steps.append(ts.TraceStep(6, "write it " * 40 + " see file.c:9 and file.c:10",
                              "write_poc"))
    result = _submission(steps=steps).quality()
    assert "repeated_action" in result.failures


def test_thin_reasoning_fails_even_with_enough_steps():
    steps = [ts.TraceStep(i, "ok", "read_file" if i < 3 else "write_poc")
             for i in range(6)]
    assert "thin_reasoning" in _submission(steps=steps).quality().failures


def test_file_references_required():
    steps = [ts.TraceStep(i, "long detailed reasoning without any file citation " * 8,
                          "read_file" if i < 3 else "write_poc") for i in range(6)]
    assert "no_file_references" in _submission(steps=steps).quality().failures


# --------------------------------------------------------------------------- #
# Bonus gating
# --------------------------------------------------------------------------- #

def test_bonus_only_pays_a_floor_clearing_trace():
    good = _submission()
    assert ts.submission_bonus(good) == ts.TRACE_BONUS + ts.SEAL_BONUS

    lazy_steps = [ts.TraceStep(0, "x", "read_file"), ts.TraceStep(1, "y", "write_poc")]
    lazy = _submission(steps=lazy_steps)
    # Fails the floor → no trace bonus, but the seal is still present.
    assert ts.submission_bonus(lazy) == ts.SEAL_BONUS


def test_no_submission_no_bonus():
    assert ts.submission_bonus(None) == 0.0


def test_unsealed_trace_gets_trace_bonus_but_not_seal_bonus():
    assert ts.submission_bonus(_submission(model_seal=None)) == ts.TRACE_BONUS


def test_trainable_requires_floor_and_seal():
    assert _submission().is_trainable()
    assert not _submission(model_seal=None).is_trainable()  # unattributed
    lazy = _submission(steps=[ts.TraceStep(0, "x", "read_file"),
                              ts.TraceStep(1, "y", "write_poc")])
    assert not lazy.is_trainable()  # below floor


# --------------------------------------------------------------------------- #
# Contract integrity
# --------------------------------------------------------------------------- #

def test_missing_licence_is_refused():
    with pytest.raises(ValueError, match="reuse licence"):
        _submission(licence="")


def test_empty_steps_refused():
    with pytest.raises(ValueError, match="steps"):
        _submission(steps=[])


def test_trace_id_is_content_addressed():
    assert _submission().trace_id() == _submission().trace_id()
    assert _submission().trace_id() != _submission(model_id="other").trace_id()
