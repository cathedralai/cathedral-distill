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

import pytest

from cathedral_distill.corpus_admission import (
    CONTROL_INPUTS,
    MANIFEST_ABSENT_SIGNATURES,
    PublicAnswerProbeError,
    admit,
    admit_private_manifest,
    answer_is_public,
    probe_public_answer_image,
    reference_poc,
    require_admitted_private_manifest,
    scoreable,
)
from cathedral_distill.cybergym_repro_manifest import (
    ReproManifestError,
    load_private_repro_manifest,
)


def _completed(stdout: bytes = b"", returncode: int = 0, stderr: bytes = b""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _runner(*, poc: bytes | None, manifest_ok: bool = True):
    """Fake `docker`: serves a baked reproducer and a registry manifest lookup.

    The unpullable case answers with a recognised not-found message, because a
    bare non-zero exit no longer means "absent" -- it means the probe errored
    (issue #78), which is a different verdict these tests also exercise.
    """

    def run(argv, **kwargs):
        if "manifest" in argv:
            if manifest_ok:
                return _completed(returncode=0)
            return _completed(returncode=1, stderr=b"manifest unknown: manifest unknown")
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


def _private_manifest(task_id: str):
    slug = task_id.replace(":", "-")
    return load_private_repro_manifest({
        "schema": "cathedral_cybergym_private_repro_manifest_v1",
        "source_epoch": 21,
        "tasks": [{
            "task_id": task_id,
            "level": 2,
            "disclosed_at": "2026-07-27T11:00:00Z",
            "vulnerable_image": f"registry.test/{slug}-vul@sha256:{'ab' * 32}",
            "fixed_image": f"registry.test/{slug}-fix@sha256:{'cd' * 32}",
            "context": {},
        }],
    })


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


class TestPublicAnswerProbeFailsClosed:
    """Regression for issue #78: an unanswered registry probe must refuse, not admit.

    The old probe returned "not public" both when `docker manifest inspect`
    raised and when it exited non-zero -- so on an egress-restricted or
    rate-limited host every publicly-pullable task was stamped admissible on
    the public-answer axis, and its baked answer was one `docker run` away.
    """

    @pytest.mark.parametrize("signature", MANIFEST_ABSENT_SIGNATURES)
    def test_a_recognised_absence_message_reads_as_not_public(self, signature):
        """Only the registry saying "no such image" may count as no leak."""

        def run(argv, **kwargs):
            assert "manifest" in argv
            return _completed(returncode=1, stderr=signature.encode())

        probe = probe_public_answer_image("registry.test/x-vul", poc=b"x", _run=run)
        assert probe.public is False
        assert probe.errored is False

    def test_a_nonzero_exit_with_an_unrecognised_message_is_an_error_not_an_absence(self):
        """The Docker Hub rate limit is the canonical way issue #78 fires."""

        def run(argv, **kwargs):
            return _completed(
                returncode=1,
                stderr=b"toomanyrequests: You have reached your pull rate limit",
            )

        probe = probe_public_answer_image("registry.test/x-vul", poc=b"x", _run=run)
        assert probe.errored is True
        assert probe.public is False
        assert "toomanyrequests" in probe.detail

    def test_a_probe_exception_is_an_error_not_an_absence(self):
        def run(argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=120)

        probe = probe_public_answer_image("registry.test/x-vul", poc=b"x", _run=run)
        assert probe.errored is True
        assert probe.public is False
        assert "TimeoutExpired" in probe.detail

    def test_an_errored_attempt_is_retried_and_a_late_answer_is_believed(self):
        """One retry is cheap and transient faults are the common case."""
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            if len(calls) == 1:
                raise OSError("connection reset")
            return _completed(returncode=1, stderr=b"manifest unknown")

        probe = probe_public_answer_image("registry.test/x-vul", poc=b"x", _run=run)
        assert probe.errored is False
        assert probe.public is False
        assert len(calls) == 2

    def test_a_persistent_error_stops_after_the_retry_and_stays_an_error(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            raise OSError("no route to host")

        probe = probe_public_answer_image("registry.test/x-vul", poc=b"x", _run=run)
        assert probe.errored is True
        assert len(calls) == 2

    def test_the_boolean_helper_raises_rather_than_guessing(self):
        """A bool cannot carry the third outcome, so it must not invent one."""

        def run(argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=120)

        with pytest.raises(PublicAnswerProbeError, match="errored rather than answering"):
            answer_is_public("arvo:1", _run=run)

    def test_admit_refuses_on_probe_error_without_calling_the_answer_public(self):
        """The composed verdict must separate "leaked" from "could not ask"."""
        real = b"\x03\x04 crash"

        def run(argv, **kwargs):
            if "manifest" in argv:
                raise subprocess.TimeoutExpired(cmd=argv, timeout=120)
            if "cat" in argv:
                return _completed(stdout=real)
            return _completed()

        result = admit(
            "arvo:10400",
            _run=run,
            _backend=_backend(crashes_on=lambda poc, mode: poc == real and mode != "fix"),
        )
        assert result.discriminates is True
        assert result.solvable is True
        assert result.scoreable is False                # refused...
        assert result.answer_is_public is False         # ...but NOT labelled a leak
        assert result.answer_probe_errored is True
        assert any(r.startswith("probe_error") for r in result.reasons)
        assert not any("read the answer without solving" in r for r in result.reasons)
        assert result.as_dict()["answer_probe_errored"] is True

    def test_a_manifest_with_an_unanswerable_probe_is_refused_at_startup(self):
        """`require_admitted_private_manifest` must not serve on an unanswered probe."""
        manifest = _private_manifest("arvo:10400")
        real = b"pinned crash"

        def run(argv, **kwargs):
            if "manifest" in argv:
                return _completed(returncode=1, stderr=b"i/o timeout")
            if "cat" in argv:
                return _completed(stdout=real)
            raise AssertionError(argv)

        def backend(_task_id, poc, mode, **kwargs):
            return int(poc == real and mode == "vul")

        with pytest.raises(ReproManifestError, match="probe_error"):
            require_admitted_private_manifest(manifest, _run=run, _backend=backend)


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


class TestPrivateManifestAdmission:
    def test_checks_the_manifests_pinned_images_and_bound_backend(self):
        manifest = _private_manifest("arvo:10400")
        task = manifest.task("arvo:10400")
        real = b"known differential crash"
        seen = {"images": [], "backend": []}

        def run(argv, **kwargs):
            if "manifest" in argv:
                # Public-answer detection must be anonymous, not reuse the
                # validator host's private-registry credentials.
                assert "--config" in argv
                assert argv[-1] == task.vulnerable_image
                return _completed(returncode=1, stderr=b"manifest unknown")
            if "cat" in argv:
                assert argv[-2] == task.vulnerable_image
                seen["images"].append(argv[-2])
                return _completed(stdout=real)
            raise AssertionError(argv)

        def backend(task_id, poc, mode, *, manifest, **kwargs):
            assert manifest is pinned
            assert manifest.task(task_id).vulnerable_image == task.vulnerable_image
            seen["backend"].append((task_id, poc, mode))
            return int(poc == real and mode == "vul")

        pinned = manifest
        result = admit_private_manifest(manifest, _run=run, _backend=backend)

        assert len(result) == 1 and result[0].scoreable
        assert seen["images"] == [task.vulnerable_image]
        assert any(mode == "fix" for _task_id, _poc, mode in seen["backend"])

    def test_probe_run_drives_the_registry_probe_not_the_reproduction(self):
        """The anonymous registry probe and the docker differential are DISTINCT seams:
        passing a probe runner must not starve the reproduction backend of a real runner
        (the reseal-on-rig bug — docker_reproduce_backend would run its differential
        through a function that only answers `manifest inspect`)."""
        manifest = _private_manifest("arvo:10400")
        task = manifest.task("arvo:10400")
        real = b"known differential crash"
        routed = {"backend_run": [], "probe": []}

        def backend_run(argv, **kwargs):  # only the reproduction should reach here
            routed["backend_run"].append(argv[:2])
            return _completed(stdout=real) if "cat" in argv else _completed()

        def probe_run(argv, **kwargs):    # only the anonymous registry probe
            routed["probe"].append(argv)
            assert "manifest" in argv and "--config" in argv
            return _completed(returncode=1, stderr=b"manifest unknown")

        def backend(task_id, poc, mode, *, _run, **kwargs):
            # the backend must receive the REPRODUCTION runner, never the probe
            assert _run is backend_run, "reproduction backend was handed the registry probe"
            return int(poc == real and mode == "vul")

        result = admit_private_manifest(
            manifest, _run=backend_run, probe_run=probe_run, _backend=backend)
        assert result[0].scoreable and result[0].answer_is_public is False
        assert routed["probe"], "the anonymous probe was never called"

    def test_refuses_a_degenerate_pinned_task_before_it_can_be_served(self):
        manifest = _private_manifest("arvo:3938")

        def run(argv, **kwargs):
            if "manifest" in argv:
                return _completed(returncode=1, stderr=b"manifest unknown")
            if "cat" in argv:
                return _completed(stdout=b"")
            raise AssertionError(argv)

        def backend(_task_id, _poc, mode, **kwargs):
            return int(mode == "vul")

        with pytest.raises(ReproManifestError, match="arvo:3938") as excinfo:
            require_admitted_private_manifest(manifest, _run=run, _backend=backend)
        assert "control inputs" in str(excinfo.value)
