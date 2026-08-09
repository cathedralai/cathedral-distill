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
    disclosed_origin_fingerprints,
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


def _private_manifest_ctx(task_id: str, context: dict, *, level: int = 2, origin_terms=None):
    """A private manifest whose one task carries `context`, disclosed at `level`."""
    slug = task_id.replace(":", "-")
    task = {
        "task_id": task_id,
        "level": level,
        "disclosed_at": "2026-07-27T11:00:00Z",
        "vulnerable_image": f"registry.test/{slug}-vul@sha256:{'ab' * 32}",
        "fixed_image": f"registry.test/{slug}-fix@sha256:{'cd' * 32}",
        "context": context,
    }
    if origin_terms is not None:
        task["origin_terms"] = list(origin_terms)
    return load_private_repro_manifest({
        "schema": "cathedral_cybergym_private_repro_manifest_v1",
        "source_epoch": 21,
        "tasks": [task],
    })


# The exact disclosed sanitizer_trace `arvo:900001` serves on the live rig (:8672):
# a private, digest-pinned image, but the metadata names the public bug.
_LEAKY_TRACE = {
    "description": "re-sealed real OSS-Fuzz bug",
    "sanitizer_trace": "AddressSanitizer: heap-use-after-free src/cff/cffparse.c:440 in cff_parse_num",
}
_CLEAN_TRACE = {"description": "re-sealed real OSS-Fuzz bug", "sanitizer_trace": "AddressSanitizer"}


class TestDisclosureFingerprint:
    """A privately-sealed image still leaks its answer if the DISPATCH fingerprints
    the public origin bug — the miner pulls the public twin's reproducer instead of
    solving. `answer_is_public` checks OUR image's pullability; this checks the
    metadata channel that is orthogonal to it."""

    def test_a_disclosed_source_location_is_a_fingerprint(self):
        assert disclosed_origin_fingerprints(2, _LEAKY_TRACE) == ("src/cff/cffparse.c:440",)

    def test_a_bug_class_alone_is_not_a_fingerprint(self):
        assert disclosed_origin_fingerprints(2, _CLEAN_TRACE) == ()
        # nor is the generic scaffolding + a hyphenated bug class
        assert disclosed_origin_fingerprints(
            2, {"description": "re-sealed real OSS-Fuzz bug", "sanitizer_trace": "heap-use-after-free"}
        ) == ()

    def test_a_field_not_disclosed_at_this_level_is_not_a_leak(self):
        # level 1 discloses only `description`; the leaky sanitizer_trace is withheld.
        assert disclosed_origin_fingerprints(1, _LEAKY_TRACE) == ()
        # level 0 discloses nothing at all.
        assert disclosed_origin_fingerprints(0, _LEAKY_TRACE) == ()

    def test_the_level_3_patch_is_policed_by_forbidden_terms_not_the_regex(self):
        """A diff always names source files, so the source-location regex cannot tell a
        genericised patch from a raw one and is NOT applied to the patch (else every
        level-3 task refuses). The patch is policed by forbidden_terms — the specific
        stripped identifiers — which passes a genericised patch and catches a raw one."""
        raw = "--- a/src/cff/cffparse.c\n+++ b/src/cff/cffparse.c\n@@ -440 +440 @@\n- bad\n+ ok"
        generic = "--- a/parser.c\n+++ b/parser.c\n@@ -10 +10 @@\n- bad\n+ ok"
        # genericised patch, no known-origin terms: passes (not a fail-closed footgun)
        assert disclosed_origin_fingerprints(
            3, {"description": "x", "sanitizer_trace": "AddressSanitizer", "patch": generic}) == ()
        # raw patch still naming the stripped source: caught via forbidden_terms
        assert disclosed_origin_fingerprints(
            3, {"description": "x", "sanitizer_trace": "AddressSanitizer", "patch": raw},
            forbidden_terms=["cffparse.c"]) == ("cffparse.c",)

    def test_generic_asan_runtime_frames_do_not_over_refuse(self):
        """Generic ASan/libc runtime frames must not be mistaken for a bug fingerprint —
        the earlier auto-symbol heuristic refused these. The symbol channel is policed by
        forbidden_terms (the sealer's known crash symbol), not a frame heuristic."""
        ctx = {"description": "re-sealed bug",
               "sanitizer_trace": "AddressSanitizer: heap-use-after-free\n"
                                  " #0 in __interceptor_memcpy\n #1 in __libc_start_main"}
        assert disclosed_origin_fingerprints(2, ctx) == ()
        # the actual crash symbol IS caught when the sealer supplies it as a forbidden term
        assert disclosed_origin_fingerprints(
            2, {"description": "x", "sanitizer_trace": "AddressSanitizer: uaf in cff_parse_num"},
            forbidden_terms=["cff_parse_num"]) == ("cff_parse_num",)

    def test_ambiguous_single_letter_extensions_do_not_false_positive(self):
        ctx = {"description": "built with 2.31.s on macos.m", "sanitizer_trace": "AddressSanitizer"}
        assert disclosed_origin_fingerprints(2, ctx) == ()

    def test_forbidden_terms_catch_a_project_or_symbol_the_sealer_hid(self):
        ctx = {"description": "a freetype2 bug", "sanitizer_trace": "AddressSanitizer"}
        assert disclosed_origin_fingerprints(2, ctx, forbidden_terms=["freetype2"]) == ("freetype2",)
        # case-insensitive, and only over disclosed fields
        assert disclosed_origin_fingerprints(0, ctx, forbidden_terms=["FreeType2"]) == ()

    def test_a_fingerprinted_task_is_refused_even_though_its_image_is_private(self):
        """The `arvo:900001` regression: differential passes, image is unpullable, yet
        the disclosed crash site fingerprints the public bug, so it is NOT scoreable."""
        manifest = _private_manifest_ctx("arvo:900001", _LEAKY_TRACE)
        real = b"known differential crash"

        def run(argv, **kwargs):
            if "manifest" in argv:
                return _completed(returncode=1, stderr=b"manifest unknown")  # private
            if "cat" in argv:
                return _completed(stdout=real)
            raise AssertionError(argv)

        def backend(task_id, poc, mode, **kwargs):
            return int(poc == real and mode == "vul")

        (result,) = admit_private_manifest(manifest, _run=run, _backend=backend)
        assert result.discriminates and result.solvable          # a genuine vuln...
        assert result.answer_is_public is False                  # ...with a private image...
        assert result.disclosure_leaks_origin is True            # ...but the metadata leaks it
        assert result.scoreable is False
        assert any("cffparse.c:440" in r and "public" in r for r in result.reasons)

    def test_genericising_the_disclosure_restores_scoreability(self):
        manifest = _private_manifest_ctx("arvo:900001", _CLEAN_TRACE)
        real = b"known differential crash"

        def run(argv, **kwargs):
            if "manifest" in argv:
                return _completed(returncode=1, stderr=b"manifest unknown")
            if "cat" in argv:
                return _completed(stdout=real)
            raise AssertionError(argv)

        def backend(task_id, poc, mode, **kwargs):
            return int(poc == real and mode == "vul")

        (result,) = admit_private_manifest(manifest, _run=run, _backend=backend)
        assert result.disclosure_leaks_origin is False
        assert result.scoreable is True

    def test_forbidden_terms_flow_through_admission(self):
        manifest = _private_manifest_ctx(
            "arvo:900002", {"description": "a freetype2 bug", "sanitizer_trace": "AddressSanitizer"}
        )
        real = b"known differential crash"

        def run(argv, **kwargs):
            if "manifest" in argv:
                return _completed(returncode=1, stderr=b"manifest unknown")
            if "cat" in argv:
                return _completed(stdout=real)
            raise AssertionError(argv)

        def backend(task_id, poc, mode, **kwargs):
            return int(poc == real and mode == "vul")

        (result,) = admit_private_manifest(
            manifest, _run=run, _backend=backend, forbidden_terms=["freetype2"]
        )
        assert result.disclosure_leaks_origin is True and result.scoreable is False

    def test_task_origin_terms_are_enforced_without_a_caller_passing_them(self):
        """#131 enforced-by-construction: the manifest carries the sealer's stripped
        origin identifiers privately, and admission uses them automatically — no caller
        needs to remember `forbidden_terms`. A disclosure naming a hidden term is refused."""
        manifest = _private_manifest_ctx(
            "arvo:900001",
            {"description": "re-sealed bug", "sanitizer_trace": "AddressSanitizer: uaf in cff_parse_num"},
            origin_terms=["freetype2", "cff_parse_num", "cffparse.c"],
        )
        real = b"known differential crash"

        def run(argv, **kwargs):
            if "manifest" in argv:
                return _completed(returncode=1, stderr=b"manifest unknown")
            if "cat" in argv:
                return _completed(stdout=real)
            raise AssertionError(argv)

        def backend(task_id, poc, mode, **kwargs):
            return int(poc == real and mode == "vul")

        # NOTE: no forbidden_terms passed — the task's own origin_terms drive it.
        (result,) = admit_private_manifest(manifest, _run=run, _backend=backend)
        assert result.disclosure_leaks_origin is True and result.scoreable is False
        assert any("cff_parse_num" in r for r in result.reasons)

    def test_a_genericised_disclosure_with_origin_terms_recorded_is_scoreable(self):
        """The seal-time genericised context (no hidden term present) passes, and the
        private origin_terms are never in the dispatched context."""
        manifest = _private_manifest_ctx(
            "arvo:900001",
            {"description": "re-sealed bug", "sanitizer_trace": "AddressSanitizer: heap-use-after-free"},
            origin_terms=["freetype2", "cff_parse_num", "cffparse.c"],
        )
        task = manifest.task("arvo:900001")
        assert "origin_terms" not in task.context  # private, never dispatched
        real = b"known differential crash"

        def run(argv, **kwargs):
            if "manifest" in argv:
                return _completed(returncode=1, stderr=b"manifest unknown")
            if "cat" in argv:
                return _completed(stdout=real)
            raise AssertionError(argv)

        def backend(task_id, poc, mode, **kwargs):
            return int(poc == real and mode == "vul")

        (result,) = admit_private_manifest(manifest, _run=run, _backend=backend)
        assert result.disclosure_leaks_origin is False and result.scoreable is True

    def test_origin_terms_are_validated_and_digest_bound(self):
        import copy
        base = {
            "schema": "cathedral_cybergym_private_repro_manifest_v1", "source_epoch": 21,
            "tasks": [{"task_id": "arvo:1", "level": 2, "disclosed_at": "2026-07-27T11:00:00Z",
                       "vulnerable_image": f"registry.test/a-vul@sha256:{'ab' * 32}",
                       "fixed_image": f"registry.test/a-fix@sha256:{'cd' * 32}", "context": {}}]}
        for bad_terms in (["", "ok"], "notalist", ["dup", "dup"]):
            bad = copy.deepcopy(base)
            bad["tasks"][0]["origin_terms"] = bad_terms
            with pytest.raises(ReproManifestError):
                load_private_repro_manifest(bad)
        # present terms change the manifest digest (tamper-evidence); absent = default ()
        withterms = copy.deepcopy(base)
        withterms["tasks"][0]["origin_terms"] = ["freetype2"]
        assert load_private_repro_manifest(base).digest != load_private_repro_manifest(withterms).digest
        # a padded term is stored stripped, so it is policed as the bare token
        padded = copy.deepcopy(base)
        padded["tasks"][0]["origin_terms"] = ["cff_parse_num "]
        assert load_private_repro_manifest(padded).task("arvo:1").origin_terms == ("cff_parse_num",)


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
