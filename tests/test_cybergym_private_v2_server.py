"""Deployment contract for the loopback private-v2 CyberGym verifier."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import urllib.error
import urllib.request

from cathedral_distill import cybergym_private_v2_server as private_server
from cathedral_distill.cybergym_http import make_threaded_server

TASK = "oss-fuzz:10001"
MINER = "5PrivateE2EMiner"
ARTIFACT = b"int parse(const unsigned char *input, unsigned long length);\n"
REFERENCE = b"private-v2-reference-poc"


def _post(base, path, body, *, token=None):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
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


def _configure_private_v2(tmp_path, monkeypatch):
    artifact_digest = hashlib.sha256(ARTIFACT).hexdigest()
    reference_digest = hashlib.sha256(REFERENCE).hexdigest()
    manifest = {
        "schema": "cathedral_cybergym_private_repro_manifest_v2",
        "source_epoch": 21,
        "tasks": [
            {
                "task_id": TASK,
                "level": 2,
                "disclosed_at": "2026-08-01T00:00:00Z",
                "vulnerable_image": "registry.private/cg/oss@sha256:" + "ab" * 32,
                "fixed_image": "registry.private/cg/oss@sha256:" + "cd" * 32,
                "context": {"description": "private parser boundary task"},
                "challenge_artifact_digest": "sha256:" + artifact_digest,
                "reference_poc_digest": "sha256:" + reference_digest,
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    artifact_dir = tmp_path / "artifacts"
    reference_dir = tmp_path / "references"
    artifact_dir.mkdir()
    reference_dir.mkdir()
    (artifact_dir / artifact_digest).write_bytes(ARTIFACT)
    (reference_dir / reference_digest).write_bytes(REFERENCE)
    token_path = tmp_path / "token"
    token_path.write_text("private-v2-token\n", encoding="utf-8")
    token_path.chmod(0o600)
    values = {
        "CYBERGYM_E2E_ALLOW_UNATTESTED": "1",
        "CYBERGYM_E2E_MINER_HOTKEY": MINER,
        "CYBERGYM_E2E_BEARER_TOKEN_FILE": str(token_path),
        "CYBERGYM_SIGNING_SEED": "12" * 32,
        "CYBERGYM_CORPUS_MANIFEST": str(manifest_path),
        "CYBERGYM_CHALLENGE_ARTIFACT_DIR": str(artifact_dir),
        "CYBERGYM_REFERENCE_POC_DIR": str(reference_dir),
        "CYBERGYM_CORPUS_DB": str(tmp_path / "corpus.sqlite"),
        "CYBERGYM_SCORE_DB": str(tmp_path / "score.sqlite"),
        "CYBERGYM_SOLVE_DB": str(tmp_path / "solve.sqlite"),
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return "private-v2-token"


def test_private_v2_server_binds_bearer_identity_to_the_sealed_artifact(
    tmp_path, monkeypatch
):
    token = _configure_private_v2(tmp_path, monkeypatch)
    monkeypatch.setattr(private_server, "available_tasks", lambda _manifest: [TASK])
    monkeypatch.setattr(
        private_server,
        "require_admitted_private_manifest",
        lambda _manifest, *, reference_pocs: (),
    )
    service = private_server.build_service_from_environment()
    server = make_threaded_server(
        service,
        host="127.0.0.1",
        port=0,
        authenticator=private_server.authenticated_miner_from_environment(),
        require_authentication=True,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        request = {"miner_hotkey": MINER, "model_commitment": "sha256:" + "ef" * 32}
        status, _ = _post(base, "/cybergym/dispatch", request)
        assert status == 401
        status, rejected = _post(
            base,
            "/cybergym/dispatch",
            {**request, "miner_hotkey": "5OtherMiner"},
            token=token,
        )
        assert status == 400
        assert "authenticated caller" in rejected["error"]
        status, dispatched = _post(base, "/cybergym/dispatch", request, token=token)
        assert status == 200
        task = dispatched["tasks"][0]
        status, artifact = _post(
            base,
            "/cybergym/artifact",
            {"task_id": TASK, "batch_id": dispatched["batch_id"]},
            token=token,
        )
        assert status == 200
        assert base64.b64decode(artifact["artifact_base64"]) == ARTIFACT
        assert artifact["artifact_digest"] == task["artifact_digest"]
        assert REFERENCE not in base64.b64decode(artifact["artifact_base64"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_private_v2_server_refuses_a_group_readable_bearer_file(tmp_path, monkeypatch):
    _configure_private_v2(tmp_path, monkeypatch)
    token_path = tmp_path / "token"
    token_path.chmod(0o640)
    try:
        private_server.authenticated_miner_from_environment()
    except SystemExit as exc:
        assert "group- or world-readable" in str(exc)
    else:  # pragma: no cover - an insecure deployment must never authenticate
        raise AssertionError("private-v2 server accepted an insecure bearer file")
