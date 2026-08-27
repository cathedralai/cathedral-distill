"""The admission stamp: `admitted: true` must be earned, bound, and re-checkable.

Issue #78's second half: `admit_pool` stamped in-memory objects but nothing
serialized them, so a holdout manifest's `admitted: true` was an operator's
typed claim — no record of when the gate decided or which image bytes it decided
against, and the tag-addressed upstream image could mutate after admission with
the boolean surviving (TOCTOU). These tests hold the stamping tool and the
loader to the closed contract: every emitted `admitted: true` was affirmed by
the gate in THIS run and names the content digest it inspected; every refusal —
including a probe that never answered — is stamped false with its reasons, never
dropped; and a manifest whose stamp contradicts itself is refused at load.

All subprocess and crash-backend interaction is injected, as everywhere else in
the admission stack: zero real Docker.
"""
from __future__ import annotations

import datetime as dt
import json
import subprocess

import pytest

from cathedral_distill.corpus_admission_stamp import (
    digest_matches,
    main,
    stamp_admissions,
    stamp_holdout_file,
)
from cathedral_distill.cybergym_holdout import HoldoutError, load_holdout

_REAL = b"\x03\x04 crash"
_DIGEST = "n132/arvo@sha256:" + "ab" * 32
_NOW = dt.datetime(2026, 8, 4, 12, 0, 0, tzinfo=dt.timezone.utc)
_clock = lambda: _NOW  # noqa: E731 - a pinned clock, injected where a stamp needs a time


def _completed(stdout: bytes = b"", returncode: int = 0, stderr: bytes = b""):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


def _runner(*, poc: bytes | None = _REAL, probe: str = "absent",
            digest: str | None = _DIGEST):
    """Fake `docker` for the three calls stamping makes per task.

    `probe` is the anonymous registry lookup's behaviour: "absent" answers with
    a recognised not-found message (admissible on the public axis), "public"
    resolves the image, "error" is an unrecognised failure (the rate-limit
    shape issue #78 is about). `digest` is what the credentialed local
    `image inspect --format` reports; None means the digest cannot be resolved.
    """

    def run(argv, **kwargs):
        if "--format" in argv:  # credentialed digest lookup, local image store
            if digest is None:
                return _completed(returncode=1, stderr=b"Error: No such image")
            return _completed(stdout=digest.encode() + b"\n")
        if "manifest" in argv:  # anonymous registry probe
            assert "--config" in argv  # never the validator's credentials
            if probe == "absent":
                return _completed(returncode=1, stderr=b"manifest unknown")
            if probe == "public":
                return _completed(returncode=0)
            return _completed(
                returncode=1,
                stderr=b"toomanyrequests: You have reached your pull rate limit",
            )
        if "cat" in argv:  # reference reproducer extraction
            if poc is None:
                return _completed(returncode=1)
            return _completed(stdout=poc)
        raise AssertionError(f"unexpected docker call: {argv}")

    return run


def _backend(task_id, poc, mode, **kwargs):
    """A well-behaved task: only the reference crashes vul, nothing crashes fix."""
    return int(poc == _REAL and mode != "fix")


def _entry(task_id: str = "arvo:10400", **over) -> dict:
    entry = {
        "task_id": task_id,
        "level": 1,
        "binary_digest": "sha256:" + "cd" * 32,
        "disclosed_at": "2026-07-20T00:00:00Z",
    }
    entry.update(over)
    return entry


def _stamp(entries, **over):
    kwargs = dict(_run=_runner(), _backend=_backend, now=_clock)
    kwargs.update(over)
    return stamp_admissions(entries, **kwargs)


class TestStampingHappyPath:
    def test_a_public_catalog_id_is_stamped_refused_as_leaking(self):
        # #157 retires the tag-path affirm: a public-catalog id (the only kind the stamp
        # tool can map) is refused at admission, so the stamp RECORDS the refusal
        # (admitted:false) with the leak reason rather than dropping it, and never binds
        # an image digest for a task it will not score. Affirming a scoreable holdout now
        # belongs to the sealed private-manifest flow (`synthvuln:` ids), not this tool.
        [stamped] = _stamp([_entry()])
        assert stamped["admitted"] is False
        record = stamped["admission"]
        assert record["admitted"] is False
        assert record["probe"] == "not_public"
        assert record["image_digest"] is None
        assert record["admitted_at"] == "2026-08-04T12:00:00Z"
        assert any("public catalog entry arvo:10400" in reason for reason in record["reasons"])

    def test_the_entry_body_and_context_survive_the_stamp(self):
        context = {"description": "heap overflow in the length parser"}
        [stamped] = _stamp([_entry(context=context)])
        assert stamped["task_id"] == "arvo:10400"
        assert stamped["level"] == 1
        assert stamped["binary_digest"] == "sha256:" + "cd" * 32
        assert stamped["disclosed_at"] == "2026-07-20T00:00:00Z"
        assert stamped["context"] == context

    def test_a_refused_catalog_id_round_trips_through_load_holdout(self):
        """A stamped refusal (admitted:false) is still a valid manifest the loader
        accepts — the refusal is auditable in the artifact — and no image digest is
        bound for a task that will not be scored (#157)."""
        stamped = _stamp([_entry()])
        holdout = load_holdout(stamped)
        [task] = holdout.pool._tasks
        assert task.admitted is False
        assert holdout.image_digest("arvo:10400") is None
        assert holdout.image_digest("arvo:absent") is None


class TestStampingFailsClosed:
    def test_a_probe_error_is_stamped_refused_never_dropped(self):
        """The unanswered probe keeps its refusal in the artifact: the entry
        stays in the manifest, `admitted: false`, with the gate's probe_error
        reason verbatim — dropping it would hide the retryable state #79's
        triage distinction exists to expose."""
        [stamped] = _stamp([_entry()], _run=_runner(probe="error"))
        assert stamped["admitted"] is False
        record = stamped["admission"]
        assert record["probe"] == "probe_error"
        assert record["image_digest"] is None
        assert any(reason.startswith("probe_error") for reason in record["reasons"])
        assert "toomanyrequests" in " ".join(record["reasons"])

    def test_a_public_answer_is_stamped_refused_as_public(self):
        [stamped] = _stamp([_entry()], _run=_runner(probe="public"))
        assert stamped["admitted"] is False
        assert stamped["admission"]["probe"] == "public"
        assert any("publicly pullable" in reason
                   for reason in stamped["admission"]["reasons"])

    def test_a_public_catalog_id_is_refused_before_any_digest_resolution(self):
        """#157 short-circuits before the digest-binding branch: the gate already
        refused the catalog id, so `resolve_image_digest` is never reached and the
        'cannot be bound' reason (which only fires for a scoreable-but-unbindable task)
        does not appear — the leak reason does."""
        [stamped] = _stamp([_entry()], _run=_runner(digest=None))
        assert stamped["admitted"] is False
        assert stamped["admission"]["image_digest"] is None
        assert any("public catalog entry" in reason
                   for reason in stamped["admission"]["reasons"])
        assert not any("cannot be bound" in reason
                       for reason in stamped["admission"]["reasons"])

    def test_a_prior_stamp_is_rederived_not_trusted(self):
        """Re-stamping re-decides from scratch: a stale admitted-true stamp on a
        task the gate now refuses must vanish, digest and all — trusting it
        would rebuild the honor system one level up."""
        stale = {
            "admitted": True,
            "probe": "not_public",
            "reasons": [],
            "admitted_at": "2025-01-01T00:00:00Z",
            "image_digest": "n132/arvo@sha256:" + "ee" * 32,
        }
        [stamped] = _stamp([_entry(admitted=True, admission=stale)],
                           _run=_runner(probe="error"))
        assert stamped["admitted"] is False
        assert stamped["admission"]["probe"] == "probe_error"
        assert stamped["admission"]["image_digest"] is None
        assert stamped["admission"]["admitted_at"] == "2026-08-04T12:00:00Z"

    def test_a_malformed_manifest_is_refused_before_any_docker_runs(self):
        """Whole-manifest validation precedes the first container: one bad entry
        refuses the run outright rather than stamping the good ones and
        surprising the operator halfway through."""

        def run(argv, **kwargs):
            raise AssertionError(f"docker was invoked for a malformed manifest: {argv}")

        good, bad = _entry("arvo:1"), {"task_id": "arvo:2", "level": 1}
        with pytest.raises(HoldoutError, match="missing keys"):
            stamp_admissions([good, bad], _run=run, _backend=_backend, now=_clock)

    def test_a_non_list_manifest_is_refused(self):
        with pytest.raises(HoldoutError, match="must be a list"):
            _stamp("not-a-list")
        with pytest.raises(HoldoutError, match="must be an object"):
            _stamp(["not-an-entry"])


class TestLoaderEnforcesTheStamp:
    """`load_holdout` validates a stamp wherever one appears, on the one ingest
    path every holdout passes through — a contradictory manifest is refused at
    load, not discovered at payout."""

    def _admission(self, **over) -> dict:
        record = {
            "admitted": True,
            "probe": "not_public",
            "reasons": [],
            "admitted_at": "2026-08-04T12:00:00Z",
            "image_digest": _DIGEST,
        }
        record.update(over)
        return record

    def test_a_stamp_contradicting_the_entry_flag_is_refused(self):
        entry = _entry(admitted=True, admission=self._admission(admitted=False))
        with pytest.raises(HoldoutError, match="contradicts its own stamp"):
            load_holdout([entry])

    def test_an_admitted_stamp_recording_a_probe_error_is_refused(self):
        entry = _entry(admitted=True, admission=self._admission(probe="probe_error"))
        with pytest.raises(HoldoutError, match="never admits on an unanswered"):
            load_holdout([entry])

    def test_an_admitted_stamp_without_a_digest_is_refused(self):
        entry = _entry(admitted=True, admission=self._admission(image_digest=None))
        with pytest.raises(HoldoutError, match="carries no image_digest"):
            load_holdout([entry])

    def test_a_malformed_digest_is_refused(self):
        entry = _entry(admitted=True,
                       admission=self._admission(image_digest="sha256:short"))
        with pytest.raises(HoldoutError, match="image_digest"):
            load_holdout([entry])

    def test_an_unknown_probe_outcome_is_refused(self):
        entry = _entry(admitted=True, admission=self._admission(probe="maybe"))
        with pytest.raises(HoldoutError, match="admission.probe"):
            load_holdout([entry])

    def test_a_non_object_stamp_is_refused(self):
        with pytest.raises(HoldoutError, match="must be an object"):
            load_holdout([_entry(admitted=True, admission="yes really")])

    def test_an_unparseable_admitted_at_is_refused(self):
        entry = _entry(admitted=True,
                       admission=self._admission(admitted_at="yesterday-ish"))
        with pytest.raises(HoldoutError, match="admitted_at"):
            load_holdout([entry])

    def test_a_refused_stamp_loads_and_the_task_cannot_be_drawn(self):
        """A stamped refusal is a valid manifest state: it loads, carries its
        reasons for triage, and the pool still cannot draw it."""
        entry = _entry(admitted=False, admission=self._admission(
            admitted=False, probe="probe_error", image_digest=None,
            reasons=["probe_error: the registry never answered"]))
        holdout = load_holdout([entry])
        [task] = holdout.pool._tasks
        assert task.admitted is False
        assert holdout.image_digest("arvo:10400") is None

    def test_a_legacy_entry_without_a_stamp_still_loads(self):
        """The stamp is how `admitted` is earned going forward, not a
        retroactive invalidation of every existing manifest — an unstamped
        entry loads exactly as before, digest accessor answering None."""
        holdout = load_holdout([_entry(admitted=True)])
        [task] = holdout.pool._tasks
        assert task.admitted is True
        assert holdout.image_digest("arvo:10400") is None


class TestDigestMatches:
    def test_repo_qualified_and_bare_forms_of_one_digest_match(self):
        assert digest_matches(_DIGEST, "sha256:" + "ab" * 32)
        assert digest_matches("sha256:" + "ab" * 32, _DIGEST)
        assert digest_matches(_DIGEST, "other-repo@sha256:" + "ab" * 32)

    def test_different_content_never_matches(self):
        assert not digest_matches(_DIGEST, "n132/arvo@sha256:" + "ff" * 32)

    def test_absence_on_either_side_fails_closed(self):
        """No digest is never a benign pass — the unbound state is the one
        enforcement exists to refuse."""
        assert not digest_matches(None, _DIGEST)
        assert not digest_matches(_DIGEST, None)
        assert not digest_matches(None, None)
        assert not digest_matches("", "")
        assert not digest_matches("not-a-digest", "not-a-digest")


class TestFileRoundTripAndCli:
    def test_stamping_a_file_writes_a_new_manifest_preserving_its_shape(self, tmp_path):
        source = tmp_path / "holdout.json"
        out = tmp_path / "holdout.stamped.json"
        source.write_text(json.dumps(
            {"schema": "cathedral-holdout-v1", "tasks": [_entry()]}))
        stamp_holdout_file(source, out, _run=_runner(), _backend=_backend, now=_clock)
        written = json.loads(out.read_text())
        assert written["schema"] == "cathedral-holdout-v1"  # other top-level keys survive
        [stamped] = written["tasks"]
        assert stamped["admitted"] is False  # catalog id refused (#157)
        assert stamped["admission"]["image_digest"] is None
        # And the artifact on disk is loadable, the refusal intact.
        holdout = load_holdout(written["tasks"])
        assert holdout.image_digest("arvo:10400") is None

    def test_a_bare_list_manifest_stays_a_bare_list(self, tmp_path):
        source = tmp_path / "holdout.json"
        out = tmp_path / "stamped.json"
        source.write_text(json.dumps([_entry()]))
        stamp_holdout_file(source, out, _run=_runner(), _backend=_backend, now=_clock)
        written = json.loads(out.read_text())
        assert isinstance(written, list) and written[0]["admitted"] is False  # catalog id refused (#157)

    def test_overwriting_the_input_is_refused(self, tmp_path):
        source = tmp_path / "holdout.json"
        source.write_text(json.dumps([_entry()]))
        with pytest.raises(HoldoutError, match="refusing to overwrite"):
            stamp_holdout_file(source, source, _run=_runner(), _backend=_backend)

    def test_the_cli_refuses_a_missing_or_invalid_manifest(self, tmp_path, capsys):
        assert main([str(tmp_path / "nope.json")]) == 2
        assert "cannot read holdout manifest" in capsys.readouterr().err
        bad = tmp_path / "bad.json"
        bad.write_text("{not json")
        assert main([str(bad)]) == 2
        assert "not valid JSON" in capsys.readouterr().err
        assert not (tmp_path / "bad.json.stamped.json").exists()
