"""A task must prove it can pay before it is allowed to.

Regression for two defects verified against the live verifier (issue #44):

* `arvo:3938` credited `NOT-A-REAL-CRASH-INPUT` with `work_units=2` and marked it
  `solved_trainable`, because its zero-byte reference reproducer means the
  vulnerable build crashes on anything.
* the reference reproducer for a public ARVO task is readable straight out of the
  image a miner can pull, so a fully-credited solve costs one `docker run`.
"""
from __future__ import annotations

import subprocess
from types import SimpleNamespace

from cathedral_distill.corpus_admission import (
    CONTROL_INPUTS,
    admit,
    answer_is_public,
    reference_poc,
    scoreable,
)


def _completed(stdout: bytes = b"", returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=b"")


def _runner(*, poc: bytes | None, manifest_ok: bool = True):
    """Fake `docker`: serves a baked reproducer and a registry manifest lookup."""

    def run(argv, **kwargs):
        if "manifest" in argv:
            return _completed(returncode=0 if manifest_ok else 1)
        if "cat" in argv:
            if poc is None:
                return _completed(returncode=1)
            return _completed(stdout=poc)
        return _completed()

    return run


def _backend(*, crashes_on):
    """Fake differential: `crashes_on(poc, mode) -> bool`."""

    def backend(task_id, poc, mode, **kwargs):
        return 1 if crashes_on(poc, mode) else 0

    return backend


class TestDiscrimination:
    def test_a_task_whose_vul_build_crashes_on_anything_is_refused(self):
        """This is `arvo:3938`: zero-byte reference, crashes regardless of input."""
        result = admit(
            "arvo:3938",
            _run=_runner(poc=b""),
            _backend=_backend(crashes_on=lambda poc, mode: mode != "fix"),
        )
        assert result.discriminates is False
        assert result.scoreable is False
        assert any("control inputs" in r for r in result.reasons)

    def test_a_well_formed_task_is_admitted(self):
        real = b"\xff\xfe crash me"
        result = admit(
            "arvo:10400",
            _run=_runner(poc=real, manifest_ok=False),  # not publicly pullable
            _backend=_backend(crashes_on=lambda poc, mode: poc == real and mode != "fix"),
        )
        assert result.discriminates is True
        assert result.solvable is True
        assert result.scoreable is True
        assert result.reasons == ()

    def test_every_control_input_is_tried(self):
        seen = []

        def backend(task_id, poc, mode, **kwargs):
            if mode == "vul":
                seen.append(poc)
            return 0

        admit("arvo:1", _run=_runner(poc=None), _backend=backend)
        for control in CONTROL_INPUTS:
            assert control in seen


class TestSolvability:
    def test_a_task_with_no_reference_reproducer_is_refused(self):
        """Absence is not evidence of a real vulnerability, so it is not assumed."""
        result = admit(
            "arvo:9",
            _run=_runner(poc=None),
            _backend=_backend(crashes_on=lambda poc, mode: False),
        )
        assert result.solvable is False
        assert result.scoreable is False
        assert any("no reference reproducer" in r for r in result.reasons)

    def test_a_reference_that_also_crashes_the_patched_build_is_refused(self):
        """A generic crash is not the vulnerability the patch fixed."""
        real = b"boom"
        result = admit(
            "arvo:11",
            _run=_runner(poc=real, manifest_ok=False),
            _backend=_backend(crashes_on=lambda poc, mode: poc == real),  # crashes BOTH
        )
        assert result.solvable is False
        assert any("also crashes the patched build" in r for r in result.reasons)


class TestPublicAnswer:
    def test_a_publicly_pullable_image_carrying_the_answer_is_not_scoreable(self):
        real = b"\x01\x02 crash"
        result = admit(
            "arvo:10400",
            _run=_runner(poc=real, manifest_ok=True),  # anyone can pull it
            _backend=_backend(crashes_on=lambda poc, mode: poc == real and mode != "fix"),
        )
        assert result.solvable is True          # it IS a real vulnerability
        assert result.discriminates is True     # and it DOES discriminate
        assert result.answer_is_public is True  # but the answer is free
        assert result.scoreable is False
        assert any("read the answer without solving" in r for r in result.reasons)

    def test_an_unpullable_image_leaks_nothing(self):
        result = answer_is_public("arvo:1", _run=_runner(poc=b"x", manifest_ok=False))
        assert result is False

    def test_a_pullable_image_with_no_baked_reproducer_leaks_nothing(self):
        result = answer_is_public("arvo:1", _run=_runner(poc=None, manifest_ok=True))
        assert result is False


class TestReferenceExtraction:
    def test_a_missing_reproducer_reads_as_none_not_empty(self):
        """None (no file) and b"" (empty file) are different, and both matter."""
        assert reference_poc("arvo:1", _run=_runner(poc=None)) is None
        assert reference_poc("arvo:1", _run=_runner(poc=b"")) == b""


class TestScoreableFilter:
    def test_only_admitted_tasks_survive(self):
        real = b"good"

        def run_for(task_id):
            return _runner(poc=real if task_id != "arvo:3938" else b"", manifest_ok=False)

        def backend(task_id, poc, mode, **kwargs):
            if task_id == "arvo:3938":
                return 1 if mode != "fix" else 0      # crashes on anything
            return 1 if poc == real and mode != "fix" else 0

        kept = [
            t for t in ("arvo:368", "arvo:3938", "arvo:10400")
            if admit(t, _run=run_for(t), _backend=backend).scoreable
        ]
        assert kept == ["arvo:368", "arvo:10400"]
