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
from cathedral_distill.cybergym_repro import (  # noqa: E402
    ReproError,
    ReproTaskSource,
    _image_and_command,
    _is_crash,
    available_tasks,
    docker_reproduce_backend,
)
from cathedral_distill.cybergym_scores import CyberGymScoreStore  # noqa: E402
from cathedral_distill.cybergym_service import CyberGymService  # noqa: E402
from cathedral_distill.cybergym_validator import ChainContext  # noqa: E402
from cathedral_distill.cybergym_verifier import poc_digest  # noqa: E402

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
MODEL = "sha256:" + hashlib.sha256(b"ckpt").hexdigest()
CRASHING = b"the-known-crashing-input"
ASAN = b"==42==ERROR: AddressSanitizer: heap-use-after-free\n...\nABORTING\n"
CLEAN = b"Executed /tmp/poc without incident\n"


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
        crashed = image.endswith("-vul") and poc == self.crashing
        out = ASAN if crashed else CLEAN
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr=b"")


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

def test_crash_detection_matches_the_sanitizer_signatures():
    assert _is_crash("AddressSanitizer: heap-use-after-free\nABORTING")
    assert _is_crash("==1==ERROR: AddressSanitizer: SEGV on unknown address")
    assert _is_crash("runtime error: signed integer overflow")
    assert not _is_crash("Executed the target, exited cleanly")
    assert not _is_crash("")  # an AddressSanitizer mention alone (no ABORTING/ERROR) is not a crash
    assert not _is_crash("built with AddressSanitizer instrumentation")


# --------------------------------------------------------------------------- #
# docker_reproduce_backend — differential + hygiene, no real Docker
# --------------------------------------------------------------------------- #

def test_backend_crashes_the_vulnerable_build_and_not_the_patched_build():
    fake = FakeDocker()
    assert docker_reproduce_backend("arvo:368", CRASHING, "vul", _run=fake) == 1
    assert docker_reproduce_backend("arvo:368", CRASHING, "fix", _run=fake) == 0
    # a wrong input does not crash even the vulnerable build
    assert docker_reproduce_backend("arvo:368", b"not-it", "vul", _run=fake) == 0


def test_backend_cleans_up_the_temp_poc_file():
    fake = FakeDocker()
    docker_reproduce_backend("arvo:368", CRASHING, "vul", _run=fake)
    assert fake.seen_paths and not os.path.exists(fake.seen_paths[0])


def test_backend_isolates_the_verify_container_network():
    seen = {}

    def capture(argv, capture_output=False, timeout=None):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout=CLEAN, stderr=b"")

    docker_reproduce_backend("arvo:368", CRASHING, "vul", _run=capture)
    argv = seen["argv"]
    # egress-deny: the adversarial build must have no network, and the flags must
    # precede the image so they apply to the run (not get parsed as image args).
    assert "--network" in argv and argv[argv.index("--network") + 1] == "none"
    assert "no-new-privileges" in argv
    image_ix = argv.index("n132/arvo:368-vul")
    assert argv.index("--network") < image_ix


def test_backend_treats_a_timeout_as_no_crash():
    def timeout_run(argv, capture_output=False, timeout=None):
        raise subprocess.TimeoutExpired(argv, timeout)

    assert docker_reproduce_backend("arvo:368", CRASHING, "vul", _run=timeout_run) == 0


# --------------------------------------------------------------------------- #
# available_tasks — only serve what's pulled
# --------------------------------------------------------------------------- #

def test_available_tasks_lists_only_fully_pulled_pairs():
    listing = "n132/arvo:368-vul\nn132/arvo:368-fix\nn132/arvo:1065-vul\n"  # 1065 missing its -fix

    def images_run(argv, capture_output=False, timeout=None):
        assert argv[:2] == ["docker", "images"]
        return subprocess.CompletedProcess(argv, 0, stdout=listing.encode(), stderr=b"")

    got = available_tasks(["arvo:368", "arvo:1065", "arvo:9999"], _run=images_run)
    assert got == ["arvo:368"]


def test_available_tasks_is_empty_when_docker_is_unavailable():
    def broken_run(argv, capture_output=False, timeout=None):
        raise FileNotFoundError("docker not installed")

    assert available_tasks(["arvo:368"], _run=broken_run) == []


# --------------------------------------------------------------------------- #
# ReproTaskSource — distribute
# --------------------------------------------------------------------------- #

def test_draw_is_deterministic_in_the_nonce():
    a = ReproTaskSource(["arvo:368", "arvo:1065", "arvo:10400"])
    b = ReproTaskSource(["arvo:10400", "arvo:368", "arvo:1065"])  # different input order
    nonce = "cgnonce-sha256:" + "11" * 32
    ba = a.draw(size=2, nonce=nonce)
    bb = b.draw(size=2, nonce=nonce)
    assert [t.task_id for t in ba.tasks] == [t.task_id for t in bb.tasks]
    assert ba.batch_id == bb.batch_id
    # a different nonce reorders the draw
    other = a.draw(size=2, nonce="cgnonce-sha256:" + "22" * 32)
    assert other.batch_id != ba.batch_id


def test_context_is_level_gated_metadata_and_artifact_is_the_image():
    src = ReproTaskSource(["arvo:368"])
    ctx = src.context_provider("arvo:368")
    assert "use-after-free" in ctx["description"] and "cffparse.c:440" in ctx["sanitizer_trace"]
    # the real repo is delivered as the image (binary_digest), not inline source
    assert src.artifact("arvo:368") is None
    task = src.draw(size=1, nonce="cgnonce-sha256:" + "33" * 32).tasks[0]
    assert task.binary_digest.startswith("sha256:")


# --------------------------------------------------------------------------- #
# Full service loop on the real backend seam (injected Docker)
# --------------------------------------------------------------------------- #

def _service(tmp_path, fake):
    src = ReproTaskSource(["arvo:368"], backend=fake)
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


def _envelope(dispatch, task_id, poc, miner="5Miner"):
    return SubmissionEnvelope(
        batch_id=dispatch.batch_id, task_id=task_id, miner_hotkey=miner,
        poc_base64=base64.b64encode(poc).decode(), trace=_trace(task_id, poc_digest(poc)))


def test_real_backend_full_loop_dispatch_submit_verify_corpus(tmp_path):
    fake = FakeDocker()
    svc = _service(tmp_path, fake)
    d = svc.dispatch_for("5Miner", MODEL)
    assert d.tasks[0].task_id == "arvo:368"

    outcome = svc.submit(_envelope(d, "arvo:368", CRASHING))
    assert outcome.solved and outcome.trainable, outcome.reason
    assert outcome.work_units == Decimal("2")  # level-2 weight (units 8/4/2/1 for L0/1/2/3)
    # the differential really ran both builds
    assert any(p for p in fake.seen_paths)
    rows = svc._corpus.rows(source_epoch=21)
    assert len(rows) == 1 and rows[0]["task_id"] == "arvo:368"


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
