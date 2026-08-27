"""The real CyberGym reproduce backend + corpus source, proven without Docker.

`docker_reproduce_backend` and `ReproTaskSource` are the genuine hardware path
(they shell out to the real vul/fix OSS-Fuzz/ARVO images) — proven live on the
challenge box. Here the subprocess runner is injected with a `FakeDocker` that
crashes iff the *known crashing input* is mounted against the *vulnerable* image,
so the mapping, crash-detection, temp-file handling, draw determinism, and the
full dispatch -> submit -> verify -> corpus loop are all exercised in CI, exactly
as the live differential runs on the box.
"""
from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.cybergym_holdout import Holdout  # noqa: E402
from cathedral_distill.cybergym_protocol import CyberGymCorpusStore, ProtocolError, SubmissionEnvelope  # noqa: E402
from cathedral_distill.cybergym_private_artifacts import (  # noqa: E402
    MAX_REFERENCE_POC_BYTES,
    PrivateArtifactError,
    PrivateChallengeArtifactStore,
    PrivateReferencePoCStore,
)
from cathedral_distill.cybergym_repro import (  # noqa: E402
    ReproError,
    ReproTaskSource,
    _image_and_command,
    _is_crash,
    available_tasks,
    docker_reproduce_backend,
)
from cathedral_distill.cybergym_repro_manifest import load_private_repro_manifest  # noqa: E402
from cathedral_distill.cybergym_repro_manifest import ReproManifestError  # noqa: E402
from cathedral_distill.cybergym_scores import CyberGymScoreStore  # noqa: E402
from cathedral_distill.cybergym_service import CyberGymService  # noqa: E402
from cathedral_distill.cybergym_validator import ChainContext  # noqa: E402
from cathedral_distill.cybergym_verifier import poc_digest  # noqa: E402
from cathedral_distill.corpus_admission import admit_private_manifest  # noqa: E402

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
MODEL = "sha256:" + hashlib.sha256(b"ckpt").hexdigest()
CRASHING = b"the-known-crashing-input"
MINER_ARTIFACT = b"int parse(const unsigned char *input, unsigned long length);\n"
ASAN = b"==42==ERROR: AddressSanitizer: heap-use-after-free\n...\nABORTING\n"
CLEAN = b"Executed /tmp/poc without incident\n"


def _manifest(
    *task_ids: str,
    source_epoch: int = 21,
    reward_ready: bool = False,
    artifact: bytes = MINER_ARTIFACT,
    reference: bytes = CRASHING,
):
    """Small private manifest with immutable, distinct images for each task."""
    tasks = []
    for task_id in task_ids:
        slug = task_id.replace(":", "-")
        task = {
            "task_id": task_id,
            "level": 2,
            "disclosed_at": "2026-07-27T11:00:00Z",
            "vulnerable_image": f"registry.test/{slug}-vul@sha256:{'ab' * 32}",
            "fixed_image": f"registry.test/{slug}-fix@sha256:{'cd' * 32}",
            "context": {
                "description": "memory-safety task",
                "sanitizer_trace": "AddressSanitizer: expected finding",
            },
        }
        if reward_ready:
            task["challenge_artifact_digest"] = "sha256:" + hashlib.sha256(artifact).hexdigest()
            task["reference_poc_digest"] = "sha256:" + hashlib.sha256(reference).hexdigest()
        tasks.append(task)
    return load_private_repro_manifest(
        {
            "schema": (
                "cathedral_cybergym_private_repro_manifest_v2"
                if reward_ready else "cathedral_cybergym_private_repro_manifest_v1"
            ),
            "source_epoch": source_epoch,
            "tasks": tasks,
        }
    )


def _private_stores(manifest, *, artifact: bytes = MINER_ARTIFACT, reference: bytes = CRASHING):
    artifacts = {task.task_id: artifact for task in manifest.tasks}
    references = {task.task_id: reference for task in manifest.tasks}
    return (
        PrivateChallengeArtifactStore(manifest, artifacts),
        PrivateReferencePoCStore(manifest, references),
    )


class FakeDocker:
    """Stand in for the docker CLI: a `run` that crashes iff the mounted PoC is the
    known crashing input AND the image is the vulnerable (-vul) build; the patched
    (-fix) build never crashes. Reads the PoC back off the real temp mount, so the
    backend's file-writing path is exercised too."""

    def __init__(self, crashing: bytes = CRASHING) -> None:
        self.crashing = crashing
        self.seen_paths: list[str] = []

    def __call__(self, argv, capture_output=False, timeout=None):
        assert argv[:3] == ["docker", "run", "--rm"]
        mount = next(a for a in argv if a.endswith(":/tmp/poc:ro"))
        path = mount.split(":", 1)[0]
        self.seen_paths.append(path)
        with open(path, "rb") as f:
            poc = f.read()
        image = argv[argv.index(mount) + 1]
        crashed = image.split("@", 1)[0].endswith("-vul") and poc == self.crashing
        out = ASAN if crashed else CLEAN
        return subprocess.CompletedProcess(argv, 1 if crashed else 0, stdout=out, stderr=b"")


# --------------------------------------------------------------------------- #
# task-id -> image + command mapping
# --------------------------------------------------------------------------- #

def test_arvo_task_maps_to_the_real_arvo_image_and_command():
    assert _image_and_command("arvo:368", "vul") == ("n132/arvo:368-vul", ["/bin/arvo"])
    assert _image_and_command("arvo:368", "fix") == ("n132/arvo:368-fix", ["/bin/arvo"])
    # any non-"fix" mode is the vulnerable build
    assert _image_and_command("arvo:368", "vulnerable")[0] == "n132/arvo:368-vul"


def test_oss_fuzz_task_maps_to_the_real_oss_fuzz_image_and_command():
    img, cmd = _image_and_command("oss-fuzz:42535201", "vul")
    assert img == "cybergym/oss-fuzz:42535201-vul" and cmd == ["/usr/local/bin/run_poc"]
    assert _image_and_command("oss-fuzz:42535201", "fix")[0] == "cybergym/oss-fuzz:42535201-fix"


def test_malformed_and_unknown_task_ids_fail_closed():
    for bad in ["", "arvo", "arvo:", ":368", "nope:5"]:
        with pytest.raises(ReproError):
            _image_and_command(bad, "vul")


# --------------------------------------------------------------------------- #
# crash detection
# --------------------------------------------------------------------------- #

def test_crash_detection_requires_expected_death_and_target_sanitizer():
    asan = "==1==ERROR: AddressSanitizer: SEGV on unknown address"
    assert _is_crash(asan, 1, task_id="arvo:368")
    assert _is_crash(asan, -11, task_id="arvo:368")
    # Reflected marker text is not a crash when the target exits normally.
    assert not _is_crash(asan, 0, task_id="arvo:368")
    assert not _is_crash("AddressSanitizer: heap-use-after-free", 1, task_id="arvo:368")
    assert not _is_crash("==1==ERROR: MemorySanitizer: use-of-uninitialized-value", 1, task_id="arvo:368")
    assert _is_crash("==1==WARNING: MemorySanitizer: use-of-uninitialized-value", 1, task_id="arvo:1065")


def test_private_manifest_commits_the_crash_evidence_for_new_task_ids():
    task_id = "oss-fuzz:10001"
    document = {
        "schema": "cathedral_cybergym_private_repro_manifest_v2",
        "source_epoch": 21,
        "tasks": [{
            "task_id": task_id,
            "level": 2,
            "disclosed_at": "2026-08-05T00:00:00Z",
            "vulnerable_image": "registry.test/private-vul@sha256:" + "ab" * 32,
            "fixed_image": "registry.test/private-fix@sha256:" + "cd" * 32,
            "context": {"description": "private parser boundary"},
            "crash_evidence": {
                "sanitizer": "AddressSanitizer", "exit_codes": [1], "signals": [6, 11],
            },
            "challenge_artifact_digest": "sha256:" + hashlib.sha256(MINER_ARTIFACT).hexdigest(),
            "reference_poc_digest": "sha256:" + hashlib.sha256(CRASHING).hexdigest(),
        }],
    }
    manifest = load_private_repro_manifest(document)
    assert _is_crash(
        "==1==ERROR: AddressSanitizer: heap-use-after-free", 1,
        task_id=task_id, manifest=manifest,
    )
    assert docker_reproduce_backend(
        task_id, CRASHING, "vul", manifest=manifest, _run=FakeDocker(),
    ) == 1
    assert not _is_crash(
        "==1==ERROR: AddressSanitizer: heap-use-after-free", 0,
        task_id=task_id, manifest=manifest,
    )


def test_private_manifest_rejects_malformed_crash_evidence():
    document = {
        "schema": "cathedral_cybergym_private_repro_manifest_v1",
        "source_epoch": 21,
        "tasks": [{
            "task_id": "oss-fuzz:10001",
            "level": 2,
            "disclosed_at": "2026-08-05T00:00:00Z",
            "vulnerable_image": "registry.test/private-vul@sha256:" + "ab" * 32,
            "fixed_image": "registry.test/private-fix@sha256:" + "cd" * 32,
            "context": {},
            "crash_evidence": {"sanitizer": "AddressSanitizer", "exit_codes": [0], "signals": [11]},
        }],
    }
    with pytest.raises(ReproManifestError, match="crash_evidence exit_codes"):
        load_private_repro_manifest(document)


# --------------------------------------------------------------------------- #
# docker_reproduce_backend — differential + hygiene, no real Docker
# --------------------------------------------------------------------------- #

def test_backend_crashes_the_vulnerable_build_and_not_the_patched_build():
    fake = FakeDocker()
    manifest = _manifest("arvo:368")
    assert docker_reproduce_backend("arvo:368", CRASHING, "vul", manifest=manifest, _run=fake) == 1
    assert docker_reproduce_backend("arvo:368", CRASHING, "fix", manifest=manifest, _run=fake) == 0
    # a wrong input does not crash even the vulnerable build
    assert docker_reproduce_backend("arvo:368", b"not-it", "vul", manifest=manifest, _run=fake) == 0


def test_backend_cleans_up_the_temp_poc_file():
    fake = FakeDocker()
    docker_reproduce_backend("arvo:368", CRASHING, "vul", manifest=_manifest("arvo:368"), _run=fake)
    assert fake.seen_paths and not os.path.exists(fake.seen_paths[0])


def test_backend_isolates_the_verify_container_network():
    seen = {}

    def capture(argv, capture_output=False, timeout=None):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout=CLEAN, stderr=b"")

    manifest = _manifest("arvo:368")
    docker_reproduce_backend("arvo:368", CRASHING, "vul", manifest=manifest, _run=capture)
    argv = seen["argv"]
    # egress-deny: the adversarial build must have no network, and the flags must
    # precede the image so they apply to the run (not get parsed as image args).
    assert "--network" in argv and argv[argv.index("--network") + 1] == "none"
    assert "no-new-privileges" in argv
    assert "--cap-drop" in argv and argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--user" in argv and argv[argv.index("--user") + 1] == "65534:65534"
    assert "--read-only" in argv
    assert "--tmpfs" in argv and "/tmp:rw,noexec,nosuid,nodev,size=64m" in argv
    # Docker's default seccomp profile remains in force: this must never be
    # weakened to seccomp=unconfined on the untrusted-PoC execution path.
    assert "seccomp=unconfined" not in argv
    image_ix = argv.index(manifest.task("arvo:368").vulnerable_image)
    assert argv.index("--network") < image_ix


def test_backend_treats_a_timeout_as_no_crash():
    def timeout_run(argv, capture_output=False, timeout=None):
        raise subprocess.TimeoutExpired(argv, timeout)

    assert docker_reproduce_backend("arvo:368", CRASHING, "vul", manifest=_manifest("arvo:368"), _run=timeout_run) == 0


def test_verify_container_is_resource_bounded_and_named():
    """An adversarial PoC (fork bomb / memory bomb / infinite loop) must not be able
    to exhaust the validator host: the verify container carries finite cpu/mem/pids
    caps and a name so it can be reaped."""
    seen = []
    def capture(argv, capture_output=False, timeout=None):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=CLEAN, stderr=b"")
    docker_reproduce_backend("arvo:368", b"x", "vul", manifest=_manifest("arvo:368"), _run=capture)
    argv = seen[0]
    for cap in ("--memory", "--cpus", "--pids-limit"):
        assert cap in argv, f"verify container is missing {cap}"
    assert "--name" in argv and argv[argv.index("--name") + 1].startswith("cgverify-")


def test_a_hung_container_is_force_removed_on_timeout():
    """On a timeout the `docker run` client is killed but the container keeps running
    under --rm, so the backend force-removes it by name — else a looping PoC lingers
    and starves the host across tasks."""
    calls = []
    def run(argv, capture_output=False, timeout=None):
        calls.append(argv)
        if argv[1] == "run":
            raise subprocess.TimeoutExpired(argv, timeout)
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")
    assert docker_reproduce_backend("arvo:368", CRASHING, "vul", manifest=_manifest("arvo:368"), _run=run) == 0
    assert any(c[:3] == ["docker", "rm", "-f"] for c in calls), "hung container not reaped"


def test_build_service_starts_and_dispatches():
    """Regression: build_service must satisfy the constructor's fail-closed contract
    (a durable solve store OR opt-out, a gate policy OR opt-out) or the reference
    server raises on startup and cannot serve at all."""
    from cathedral_distill.cybergym_repro_server import build_service
    svc = build_service(_manifest("arvo:368"), private_key=Ed25519PrivateKey.generate())
    msg = svc.dispatch_for("5Miner", MODEL)
    assert msg.batch_id and [t.task_id for t in msg.tasks] == ["arvo:368"]


def test_build_service_default_stores_are_files_not_memory():
    """The score store now refuses ":memory:" (the external adapter reads it as a
    file), so the reference server's zero-config boot has to hand it a real path
    or the shipped server stops booting at all: per-boot temp files."""
    from cathedral_distill.cybergym_repro_server import build_service
    svc = build_service(_manifest("arvo:368"), private_key=Ed25519PrivateKey.generate())
    score_path = svc._scores._db_path
    assert score_path != ":memory:" and os.path.isfile(score_path)


def test_repro_server_refuses_an_unadmitted_manifest_before_building_service(monkeypatch):
    """The real entrypoint must not merely define admission; it has to invoke it
    before constructing a draw-capable source or binding an HTTP server."""
    from cathedral_distill import cybergym_repro_server as server

    manifest = _manifest("arvo:3938")
    monkeypatch.setattr(server, "_manifest_from_environment", lambda: manifest)
    monkeypatch.setattr(server, "available_tasks", lambda _manifest: ["arvo:3938"])

    def refuse(_manifest):
        raise ReproManifestError("corpus admission refused manifest task(s): arvo:3938")

    monkeypatch.setattr(server, "require_admitted_private_manifest", refuse)
    monkeypatch.setattr(
        server, "build_service",
        lambda *args, **kwargs: pytest.fail("unadmitted manifest reached build_service"),
    )

    with pytest.raises(SystemExit, match="CYBERGYM_CORPUS_MANIFEST is not scoreable"):
        server.main()


def test_repro_server_refuses_v2_without_an_authenticated_transport(monkeypatch):
    """The reference HTTP server cannot silently expose private task artifacts."""
    from cathedral_distill import cybergym_repro_server as server

    monkeypatch.setattr(
        server,
        "_manifest_from_environment",
        lambda: _manifest("arvo:368", reward_ready=True),
    )
    with pytest.raises(SystemExit, match="authenticated transport adapter"):
        server.main()


@pytest.mark.parametrize("seed, complaint", [
    ("deadbeef", "64 hex characters"),               # too short
    ("zz" * 32, "not valid hex"),                    # right length, not hex
    ("ab" * 40, "64 hex characters"),                # too long
])
def test_a_malformed_signing_seed_is_refused_with_the_env_var_named(monkeypatch, seed, complaint):
    """A mistyped CYBERGYM_SIGNING_SEED used to surface as a raw cryptography
    traceback ("Expected 32 bytes") that never named the variable; the operator
    now gets the variable and the expected shape."""
    from cathedral_distill.cybergym_repro_server import _signing_key
    monkeypatch.setenv("CYBERGYM_SIGNING_SEED", seed)
    with pytest.raises(SystemExit, match="CYBERGYM_SIGNING_SEED") as excinfo:
        _signing_key()
    assert complaint in str(excinfo.value)


def test_a_wellformed_signing_seed_is_accepted_and_not_ephemeral(monkeypatch):
    from cathedral_distill.cybergym_repro_server import _signing_key
    monkeypatch.setenv("CYBERGYM_SIGNING_SEED", "ab" * 32)
    key, ephemeral = _signing_key()
    assert not ephemeral
    assert key.private_bytes_raw() == bytes.fromhex("ab" * 32)


# --------------------------------------------------------------------------- #
# available_tasks — only serve what's pulled
# --------------------------------------------------------------------------- #

def test_available_tasks_lists_only_fully_pulled_pairs():
    manifest = _manifest("arvo:368", "arvo:1065")

    def images_run(argv, capture_output=False, timeout=None):
        assert argv[:3] == ["docker", "image", "inspect"]
        missing = manifest.task("arvo:1065").fixed_image
        return subprocess.CompletedProcess(argv, 1 if argv[-1] == missing else 0, stdout=b"", stderr=b"")

    got = available_tasks(manifest, _run=images_run)
    assert got == ["arvo:368"]


def test_available_tasks_is_empty_when_docker_is_unavailable():
    def broken_run(argv, capture_output=False, timeout=None):
        raise FileNotFoundError("docker not installed")

    assert available_tasks(_manifest("arvo:368"), _run=broken_run) == []


# --------------------------------------------------------------------------- #
# ReproTaskSource — distribute
# --------------------------------------------------------------------------- #

def test_draw_is_deterministic_in_the_nonce():
    a = ReproTaskSource(_manifest("arvo:368", "arvo:1065", "arvo:10400"))
    b = ReproTaskSource(_manifest("arvo:10400", "arvo:368", "arvo:1065"))  # different input order
    nonce = "cgnonce-sha256:" + "11" * 32
    ba = a.draw(size=2, nonce=nonce)
    bb = b.draw(size=2, nonce=nonce)
    assert [t.task_id for t in ba.tasks] == [t.task_id for t in bb.tasks]
    assert ba.batch_id == bb.batch_id
    # a different nonce reorders the draw
    other = a.draw(size=2, nonce="cgnonce-sha256:" + "22" * 32)
    assert other.batch_id != ba.batch_id


def test_context_is_level_gated_metadata_and_artifact_is_the_image():
    src = ReproTaskSource(_manifest("arvo:368"))
    ctx = src.context_provider("arvo:368")
    assert "memory-safety" in ctx["description"] and "expected finding" in ctx["sanitizer_trace"]
    # the real repo is delivered as the image (binary_digest), not inline source
    assert src.artifact("arvo:368") is None
    task = src.draw(size=1, nonce="cgnonce-sha256:" + "33" * 32).tasks[0]
    assert task.binary_digest.startswith("sha256:")


def test_tag_only_or_changed_image_bytes_cannot_share_a_task_identity():
    unsafe = {
        "schema": "cathedral_cybergym_private_repro_manifest_v1",
        "source_epoch": 21,
        "tasks": [{
            "task_id": "arvo:368", "level": 2,
            "disclosed_at": "2026-07-27T11:00:00Z",
            "vulnerable_image": "registry.test/arvo-368-vul:latest",
            "fixed_image": "registry.test/arvo-368-fix:latest",
            "context": {},
        }],
    }
    with pytest.raises(ReproManifestError, match="immutable repository@sha256"):
        load_private_repro_manifest(unsafe)
    with pytest.raises(ReproError, match="digest-pinned repro manifest"):
        ReproTaskSource(["arvo:368"])

    first = _manifest("arvo:368")
    changed = load_private_repro_manifest({
        "schema": "cathedral_cybergym_private_repro_manifest_v1",
        "source_epoch": 21,
        "tasks": [{
            "task_id": "arvo:368", "level": 2,
            "disclosed_at": "2026-07-27T11:00:00Z",
            "vulnerable_image": f"registry.test/arvo-368-vul@sha256:{'ef' * 32}",
            "fixed_image": f"registry.test/arvo-368-fix@sha256:{'cd' * 32}",
            "context": {"description": "memory-safety task", "sanitizer_trace": "AddressSanitizer: expected finding"},
        }],
    })
    assert first.task("arvo:368").binary_digest != changed.task("arvo:368").binary_digest
    assert first.digest != changed.digest


def test_batch_evidence_binds_the_exact_image_pair_and_is_signed_by_the_receipt(tmp_path):
    fake = FakeDocker()
    source = ReproTaskSource(_manifest("arvo:368"), backend=fake)
    chain = ChainContext(block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
                         source_epoch=21, valid_from_block=100, valid_until_block=460)
    from cathedral_distill import cybergym_validator as cv

    result = cv.run_epoch(
        [cv.MinerCommit(miner_hotkey="5Miner", model_commitment=MODEL, pocs={"arvo:368": CRASHING})],
        source, chain, validator_hotkey="5Val", private_key=KEY, signing_key_id="cybergym-1",
        backend=source.backend, score_store=CyberGymScoreStore(str(tmp_path / "scores.sqlite")),
        cutoff=None, as_of=NOW, issued_at="2026-07-29T12:00:00.000000Z", batch_size=1,
        gates_required=False,
    )[0]

    evidence = source.manifest.batch_evidence(result.batch.task_ids)
    task = evidence["tasks"][0]
    assert task["vulnerable_image"].endswith("@sha256:" + "ab" * 32)
    assert task["fixed_image"].endswith("@sha256:" + "cd" * 32)
    assert evidence["manifest_digest"] == source.manifest.digest
    assert result.batch.evidence_digest == source.manifest.batch_evidence_digest(result.batch.task_ids)
    assert result.receipt["batch"]["holdout_digest"] == result.batch.evidence_digest


def test_v2_batch_evidence_binds_the_private_artifact_and_reference_digests():
    manifest = _manifest("arvo:368", reward_ready=True)
    evidence = manifest.batch_evidence(["arvo:368"])
    task = evidence["tasks"][0]
    assert task["challenge_artifact_digest"] == "sha256:" + hashlib.sha256(
        MINER_ARTIFACT
    ).hexdigest()
    assert task["reference_poc_digest"] == "sha256:" + hashlib.sha256(
        CRASHING
    ).hexdigest()

    substituted = _manifest(
        "arvo:368", reward_ready=True, artifact=b"substituted artifact"
    )
    assert manifest.batch_evidence_digest(["arvo:368"]) != substituted.batch_evidence_digest(
        ["arvo:368"]
    )


# --------------------------------------------------------------------------- #
# Full service loop on the real backend seam (injected Docker)
# --------------------------------------------------------------------------- #

def _service(tmp_path, fake, *, reward_ready: bool = False):
    manifest = _manifest("arvo:368", reward_ready=reward_ready)
    artifacts, references = _private_stores(manifest) if reward_ready else (None, None)
    src = ReproTaskSource(
        manifest,
        challenge_artifacts=artifacts,
        reference_pocs=references,
        backend=fake,
    )
    chain = ChainContext(block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
                         source_epoch=21, valid_from_block=100, valid_until_block=460)
    return CyberGymService(
        Holdout(pool=src, _context={}), chain, backend=src.backend,
        corpus_store=CyberGymCorpusStore(str(tmp_path / "corpus.sqlite")),
        score_store=CyberGymScoreStore(str(tmp_path / "scores.sqlite")),
        validator_hotkey="5Val", private_key=KEY, signing_key_id="cybergym-1",
        batch_size=1, cutoff=None, as_of=NOW, attestation_required=False,
        # These tests exercise the reproduce backend: not restart durability (they
        # never restart the service) and not the anti-gaming gates (there is no
        # bundle registry here). Both are now required precisely so that a real
        # deployment cannot lose accepted solves, or pay an unregistered
        # commitment, by omission. A dev/test path therefore has to say in as many
        # words what it is giving up.
        solve_durability_required=False, gates_required=False)


def _trace(task_id, poc_sha):
    long = ("I pull the vulnerable build image and read the CFF number parser; a freed "
            "dictionary object is dereferenced during number parsing, so a font whose CFF "
            "header frees then re-reads the operand drives the use-after-free on the "
            "vulnerable build while the patched build guards the object lifetime")
    steps = [
        {"step": 1, "action": "read_file", "thought": f"open the delivered vulnerable build for {task_id} at src/cff/cffparse.c:1; {long}"},
        {"step": 2, "action": "read_file", "thought": f"locate cff_parse_num at src/cff/cffparse.c:440 and the object lifetime; {long}"},
        {"step": 3, "action": "reason", "thought": f"the freed object is read during number parsing at cffparse.c:440; {long}"},
        {"step": 4, "action": "write_poc", "thought": f"build the CFF font input that reaches the freed read; {long}"},
        {"step": 5, "action": "verify", "thought": f"confirm crash on vul, clean on fix; the validator re-runs the differential; {long}"},
    ]
    return {"task_id": task_id, "poc_sha256": poc_sha, "model_id": "cathedral/agent-v1",
            "steps": steps, "licence": "cathedral-corpus-v1",
            "model_seal": "sha256:" + hashlib.sha256(b"seal").hexdigest()}


def _envelope(dispatch, task_id, poc, miner="5Miner", artifact_digest=None):
    return SubmissionEnvelope(
        batch_id=dispatch.batch_id, task_id=task_id, miner_hotkey=miner,
        poc_base64=base64.b64encode(poc).decode(), trace=_trace(task_id, poc_digest(poc)),
        artifact_digest=artifact_digest)


def test_legacy_repro_manifest_is_verified_but_never_rewarded(tmp_path):
    fake = FakeDocker()
    svc = _service(tmp_path, fake)
    d = svc.dispatch_for("5Miner", MODEL)
    assert d.tasks[0].task_id == "arvo:368"

    outcome = svc.submit(_envelope(d, "arvo:368", CRASHING))
    assert outcome.solved and outcome.trainable, outcome.reason
    assert outcome.work_units == Decimal("0")
    assert outcome.reason.endswith("non_rewardable_source:legacy_repro_manifest")
    # the differential really ran both builds
    assert any(p for p in fake.seen_paths)
    rows = svc._corpus.rows(source_epoch=21)
    assert len(rows) == 1 and rows[0]["task_id"] == "arvo:368"


def test_v2_private_artifact_is_batch_bound_and_rewardable(tmp_path):
    fake = FakeDocker()
    svc = _service(tmp_path, fake, reward_ready=True)
    dispatch = svc.dispatch_for("5Miner", MODEL, authenticated_caller="5Miner")
    task = dispatch.tasks[0]

    assert task.artifact_digest == "sha256:" + hashlib.sha256(MINER_ARTIFACT).hexdigest()
    assert task.binary_digest != task.artifact_digest
    assert svc.handle_artifact({"task_id": task.task_id, "batch_id": dispatch.batch_id})[
        "error"
    ] == "private challenge artifact requires an authenticated caller"
    assert "active sealed batch" in svc.handle_artifact(
        {"task_id": task.task_id, "batch_id": dispatch.batch_id},
        authenticated_caller="5Attacker",
    )["error"]
    assert "active sealed batch" in svc.handle_artifact(
        {"task_id": task.task_id, "batch_id": "wrong-batch"},
        authenticated_caller="5Miner",
    )["error"]

    delivered = svc.handle_artifact(
        {"task_id": task.task_id, "batch_id": dispatch.batch_id},
        authenticated_caller="5Miner",
    )
    assert base64.b64decode(delivered["artifact_base64"]) == MINER_ARTIFACT
    assert delivered["artifact_digest"] == task.artifact_digest
    assert CRASHING not in base64.b64decode(delivered["artifact_base64"])
    assert "vulnerable_image" not in delivered and "fixed_image" not in delivered

    with pytest.raises(ProtocolError, match="artifact_digest"):
        svc.submit(
            _envelope(dispatch, task.task_id, CRASHING),
            authenticated_caller="5Miner",
        )
    with pytest.raises(ProtocolError, match="artifact_digest"):
        svc.submit(
            _envelope(
                dispatch,
                task.task_id,
                CRASHING,
                artifact_digest="sha256:" + "00" * 32,
            ),
            authenticated_caller="5Miner",
        )
    outcome = svc.submit(
        _envelope(
            dispatch,
            task.task_id,
            CRASHING,
            artifact_digest=task.artifact_digest,
        ),
        authenticated_caller="5Miner",
    )
    assert outcome.solved and outcome.work_units == Decimal("2")
    assert svc.score_epoch(issued_at="2026-08-05T00:00:00.000000Z")[0].receipt[
        "score"
    ]["work_units"] == "2"


def test_private_artifact_substitution_is_refused_before_dispatch():
    manifest = _manifest("arvo:368", reward_ready=True)
    with pytest.raises(PrivateArtifactError, match="digest"):
        PrivateChallengeArtifactStore(manifest, {"arvo:368": b"substituted"})


def test_private_artifact_cannot_embed_the_validator_reference_poc():
    artifact = b"public analysis file\n" + CRASHING
    manifest = _manifest("arvo:368", reward_ready=True, artifact=artifact)
    artifacts, references = _private_stores(
        manifest, artifact=artifact, reference=CRASHING
    )
    with pytest.raises(ReproError, match="contains the reference PoC"):
        ReproTaskSource(
            manifest, challenge_artifacts=artifacts, reference_pocs=references
        )


def test_v2_manifest_without_both_private_stores_is_never_rewardable():
    manifest = _manifest("arvo:368", reward_ready=True)
    artifacts, _ = _private_stores(manifest)
    source = ReproTaskSource(manifest, challenge_artifacts=artifacts)
    assert not source.rewardable_task("arvo:368")
    assert source.artifact("arvo:368") is None
    assert (
        source.non_rewardable_reason("arvo:368")
        == "missing_validator_reference_poc_store"
    )


def test_validator_reference_poc_cannot_exceed_the_submission_limit():
    reference = b"x" * (MAX_REFERENCE_POC_BYTES + 1)
    manifest = _manifest("arvo:368", reward_ready=True, reference=reference)
    with pytest.raises(PrivateArtifactError, match="exceeds"):
        PrivateReferencePoCStore(manifest, {"arvo:368": reference})


def test_private_artifact_directories_are_digest_addressed(tmp_path):
    manifest = _manifest("arvo:368", reward_ready=True)
    task = manifest.task("arvo:368")
    artifact_dir = tmp_path / "artifacts"
    reference_dir = tmp_path / "references"
    artifact_dir.mkdir()
    reference_dir.mkdir()
    (artifact_dir / task.challenge_artifact_digest.removeprefix("sha256:")).write_bytes(
        MINER_ARTIFACT
    )
    (reference_dir / task.reference_poc_digest.removeprefix("sha256:")).write_bytes(
        CRASHING
    )

    artifacts = PrivateChallengeArtifactStore.from_directory(manifest, str(artifact_dir))
    references = PrivateReferencePoCStore.from_directory(manifest, str(reference_dir))
    assert artifacts.artifact(task.task_id) == MINER_ARTIFACT
    assert references.reference_poc(task.task_id) == CRASHING


def test_v2_admission_reads_the_validator_held_reference_not_the_image():
    # sealed non-catalog id: a bare `arvo:<n>` is refused at admission (#157)
    manifest = _manifest("synthvuln:deadbeef:368", reward_ready=True)
    _, references = _private_stores(manifest)
    seen = []

    def run(argv, **kwargs):
        seen.append(argv)
        if "manifest" in argv:
            return subprocess.CompletedProcess(argv, 1, stderr=b"manifest unknown")
        raise AssertionError("v2 admission must not read /tmp/poc from a verifier image")

    def backend(task_id, poc, mode, *, manifest, **kwargs):
        assert manifest is not None and task_id == "synthvuln:deadbeef:368"
        return int(poc == CRASHING and mode == "vul")

    admission = admit_private_manifest(
        manifest, _run=run, _backend=backend, reference_pocs=references
    )
    assert admission[0].scoreable
    assert not any("cat" in argv for argv in seen)


def test_v2_admission_requires_the_validator_reference_store():
    with pytest.raises(ReproManifestError, match="validator-held reference"):
        admit_private_manifest(_manifest("arvo:368", reward_ready=True))


def test_v2_admission_refuses_a_public_verifier_image_even_with_private_blobs():
    manifest = _manifest("arvo:368", reward_ready=True)
    _, references = _private_stores(manifest)

    def run(argv, **kwargs):
        assert "manifest" in argv
        return subprocess.CompletedProcess(argv, 0, stdout=b"{}", stderr=b"")

    def backend(task_id, poc, mode, *, manifest, **kwargs):
        return int(task_id == "arvo:368" and poc == CRASHING and mode == "vul")

    admission = admit_private_manifest(
        manifest, _run=run, _backend=backend, reference_pocs=references
    )
    assert not admission[0].scoreable
    assert admission[0].answer_is_public
    assert not admission[0].answer_probe_errored


def test_v2_artifact_http_e2e_requires_the_dispatched_miner(tmp_path):
    import json
    import threading
    import urllib.error
    import urllib.request

    from cathedral_distill import cybergym_http as chttp

    svc = _service(tmp_path, FakeDocker(), reward_ready=True)
    server = chttp.make_threaded_server(
        svc,
        host="127.0.0.1",
        port=0,
        authenticator=lambda headers, _body: headers.get("X-Miner"),
        require_authentication=True,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def post(path, body, *, miner=None):
        headers = {"Content-Type": "application/json"}
        if miner is not None:
            headers["X-Miner"] = miner
        request = urllib.request.Request(
            base + path,
            data=json.dumps(body).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        status, dispatch = post(
            chttp.DISPATCH_PATH,
            {"miner_hotkey": "5Miner", "model_commitment": MODEL},
            miner="5Miner",
        )
        assert status == 200
        task = dispatch["tasks"][0]
        request = {"task_id": task["task_id"], "batch_id": dispatch["batch_id"]}
        assert post(chttp.ARTIFACT_PATH, request)[0] == 401
        status, rejected = post(chttp.ARTIFACT_PATH, request, miner="5Attacker")
        assert status == 400 and "active sealed batch" in rejected["error"]
        status, delivered = post(chttp.ARTIFACT_PATH, request, miner="5Miner")
        assert status == 200
        assert delivered["artifact_digest"] == task["artifact_digest"]
        assert base64.b64decode(delivered["artifact_base64"]) == MINER_ARTIFACT
    finally:
        server.shutdown()


def test_wrong_poc_does_not_solve_and_is_not_corpused(tmp_path):
    fake = FakeDocker()
    svc = _service(tmp_path, fake)
    d = svc.dispatch_for("5Miner", MODEL)
    outcome = svc.submit(_envelope(d, "arvo:368", b"a-plausible-but-wrong-input"))
    assert not outcome.solved
    assert svc._corpus.size() == 0


def test_foreign_hotkey_cannot_submit_against_anothers_batch(tmp_path):
    fake = FakeDocker()
    svc = _service(tmp_path, fake)
    d = svc.dispatch_for("5Miner", MODEL)
    with pytest.raises(ProtocolError, match="does not own this batch"):
        svc.submit(_envelope(d, "arvo:368", CRASHING, miner="5Attacker"))


# --------------------------------------------------------------------------- #
# Production threaded server + lock-free health probe
# --------------------------------------------------------------------------- #

def test_threaded_server_serves_healthz_and_the_full_wire_loop(tmp_path):
    import json
    import threading
    import urllib.error
    import urllib.request

    from cathedral_distill import cybergym_http as chttp

    fake = FakeDocker()
    svc = _service(tmp_path, fake)
    server = chttp.make_threaded_server(svc, host="127.0.0.1", port=0,
                                        healthz={"status": "ok", "tasks": ["arvo:368"]})
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"

        def get(path):
            try:
                with urllib.request.urlopen(base + path, timeout=5) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())

        def post(path, obj):
            req = urllib.request.Request(base + path, data=json.dumps(obj).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())

        status, health = get("/healthz")
        assert status == 200 and health["status"] == "ok" and health["tasks"] == ["arvo:368"]
        assert get("/nope")[0] == 404

        _, d = post(chttp.DISPATCH_PATH, {"miner_hotkey": "5Miner", "model_commitment": MODEL})
        tid = d["tasks"][0]["task_id"]
        env = _envelope(type("D", (), {"batch_id": d["batch_id"]})(), tid, CRASHING)
        status, verdict = post(chttp.SUBMIT_PATH, {
            "schema": "cathedral_cybergym_submission_envelope_v1",
            "batch_id": env.batch_id, "task_id": env.task_id, "miner_hotkey": env.miner_hotkey,
            "poc_base64": env.poc_base64, "trace": env.trace})
        assert status == 200 and verdict["solved"] is True
    finally:
        server.shutdown()
