"""Serving the root-signed key registry, so a receipt's signer can be resolved.

Until validators can fetch a registry, no live receipt has a resolvable signer.
Serving it is safe from anywhere — the trust is the root signature and the anchored
`root.pub`, not the transport — but three things have to hold or serving it is worse
than not:

* **verified before served.** An unverifiable registry handed out here fails at
  every consumer at once, as receipts mysteriously not verifying, instead of once
  here with a reason;
* **stale is refused.** `verify_key_registry` bounds `generated_at + max_age`
  (24h by default) INDEPENDENTLY of the registry's own `valid_until`. A registry
  signed with a year-long window is refused by every default-configured fetcher the
  next day, so serving it just relocates the failure;
* **verbatim bytes.** `registry_digest` hashes the raw bytes, so re-serialising the
  JSON changes the published digest even where the signature still verifies.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym_http as chttp  # noqa: E402
from cathedral_distill import receipt_keys as rk  # noqa: E402
from cathedral_distill import served_keys as sk  # noqa: E402

ROOT = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_ROOT = Ed25519PrivateKey.from_private_bytes(bytes(range(9, 41)))
SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
ROOTS = {"root": ROOT.public_key().public_bytes_raw()}
GENERATED = datetime(2026, 7, 30, tzinfo=UTC)


def _registry_bytes(generated="2026-07-30T00:00:00Z", until="2027-07-30T00:00:00Z",
                    root=ROOT, key_id="cybergym-1"):
    unsigned = {
        "schema": rk.REGISTRY_SCHEMA, "release": 1,
        "generated_at": generated, "valid_from": "2026-07-30T00:00:00Z",
        "valid_until": until, "registry_key_id": "root",
        "keys": [{
            "key_id": key_id,
            "public_key_base64": base64.b64encode(
                SIGNER.public_key().public_bytes_raw()).decode(),
            "valid_from": "2026-07-30T00:00:00Z", "valid_until": until,
            "status": "active",
        }],
    }
    signed = rk.sign_key_registry(unsigned, root.private_bytes_raw())
    return json.dumps(signed, indent=2).encode()  # indented: verbatim matters


def _write(tmp_path, body, name="registry.signed.json"):
    path = tmp_path / name
    path.write_bytes(body)
    return path


def _served(tmp_path, body=None, *, at=GENERATED + timedelta(hours=1), roots=None):
    path = _write(tmp_path, body if body is not None else _registry_bytes())
    clock = at if callable(at) else (lambda: at)
    return sk.ServedKeyRegistry(path, roots or ROOTS, clock=clock), path


# --------------------------------------------------------------------------- #
# Verified before served
# --------------------------------------------------------------------------- #


def test_a_verified_registry_serves_its_exact_bytes(tmp_path):
    body = _registry_bytes()
    served, _ = _served(tmp_path, body)
    assert served.body() == body                    # byte-for-byte, indentation kept
    assert served.state() == sk.SERVED
    assert served.status()["digest"] == rk.registry_digest(body)
    assert served.etag() == f'"{rk.registry_digest(body)}"'


def test_serving_requires_the_anchoring_root(tmp_path):
    """A relay that cannot verify cannot tell a rotation from a mistake."""
    with pytest.raises(sk.ServedRegistryError, match="requires the trusted root"):
        sk.ServedKeyRegistry(_write(tmp_path, _registry_bytes()), {})


def test_a_registry_signed_by_an_untrusted_root_is_refused(tmp_path):
    body = _registry_bytes(root=OTHER_ROOT)
    with pytest.raises(sk.ServedRegistryError, match="does not verify"):
        sk.ServedKeyRegistry(_write(tmp_path, body), ROOTS,
                             clock=lambda: GENERATED + timedelta(hours=1)).body()


def test_a_tampered_registry_is_refused(tmp_path):
    body = bytearray(_registry_bytes())
    body[body.index(b'"release": 1')] = ord(" ")  # corrupt a signed field
    with pytest.raises(sk.ServedRegistryError):
        sk.ServedKeyRegistry(_write(tmp_path, bytes(body)), ROOTS,
                             clock=lambda: GENERATED + timedelta(hours=1)).body()


def test_a_missing_file_is_refused_with_the_path(tmp_path):
    served = sk.ServedKeyRegistry(tmp_path / "absent.json", ROOTS)
    with pytest.raises(sk.ServedRegistryError, match="cannot be read"):
        served.body()
    assert served.state() == sk.UNVERIFIED
    assert served.status()["available"] is False


def test_an_oversized_file_is_refused_before_it_is_read(tmp_path):
    path = tmp_path / "huge.json"
    path.write_bytes(b"x" * (rk.MAX_REGISTRY_BYTES + 1))
    with pytest.raises(sk.ServedRegistryError, match="over the"):
        sk.ServedKeyRegistry(path, ROOTS).body()


# --------------------------------------------------------------------------- #
# Staleness: the trap
# --------------------------------------------------------------------------- #


def test_a_stale_registry_is_refused_even_though_its_window_is_open(tmp_path):
    """valid_until is a year out; the binding constraint is generated_at + 24h."""
    body = _registry_bytes(until="2027-07-30T00:00:00Z")
    served, _ = _served(tmp_path, body, at=GENERATED + timedelta(hours=25))

    assert served.state() == sk.STALE
    with pytest.raises(sk.ServedRegistryError) as caught:
        served.body()
    message = str(caught.value)
    assert "stale" in message
    assert "max_age_seconds=86400" in message
    assert "`valid_until` being far off does not extend this" in message

    # and this is not the module being conservative: the real verifier agrees
    with pytest.raises(rk.ReceiptKeyError, match="too stale"):
        rk.verify_key_registry(body, ROOTS, now=GENERATED + timedelta(hours=25))


def test_the_freshness_deadline_is_reported_before_it_passes(tmp_path):
    served, _ = _served(tmp_path, at=GENERATED + timedelta(hours=1))
    status = served.status()
    assert status["state"] == sk.SERVED
    assert status["generated_at"] == "2026-07-30T00:00:00Z"
    assert status["fresh_until"] == "2026-07-31T00:00:00Z"
    assert status["max_age_seconds"] == 86_400


def test_re_signing_restores_service(tmp_path):
    """The fix for stale is a new generated_at, and it needs no restart."""
    now = {"t": GENERATED + timedelta(hours=25)}
    path = _write(tmp_path, _registry_bytes())
    served = sk.ServedKeyRegistry(path, ROOTS, clock=lambda: now["t"])
    assert served.state() == sk.STALE

    path.write_bytes(_registry_bytes(generated="2026-07-31T00:00:00Z"))
    os.utime(path, ns=(0, 1))  # force a distinct mtime
    assert served.body().startswith(b"{")
    assert served.state() == sk.SERVED


# --------------------------------------------------------------------------- #
# Rotation
# --------------------------------------------------------------------------- #


def test_a_rotation_is_picked_up_without_a_restart(tmp_path):
    served, path = _served(tmp_path)
    first = served.body()

    path.write_bytes(_registry_bytes(key_id="cybergym-2"))
    os.utime(path, ns=(0, 1))
    second = served.body()

    assert second != first
    assert b"cybergym-2" in second
    assert served.status()["digest"] == rk.registry_digest(second)


def test_a_rotation_that_does_not_verify_keeps_the_last_good_copy(tmp_path):
    """A bad rotation must not take the good registry off the air."""
    served, path = _served(tmp_path)
    good = served.body()

    path.write_bytes(_registry_bytes(root=OTHER_ROOT))  # wrong root
    os.utime(path, ns=(0, 1))

    assert served.body() == good                    # still the verified one
    assert "does not verify" in served.status()["detail"]


# --------------------------------------------------------------------------- #
# Over the wire
# --------------------------------------------------------------------------- #


def _service(tmp_path):
    """A minimal real service, reusing the status-endpoint fixture shape."""
    from cathedral_distill.cybergym_holdout import load_holdout
    from cathedral_distill.cybergym_protocol import CyberGymCorpusStore
    from cathedral_distill.cybergym_scores import CyberGymScoreStore, CyberGymSolveStore
    from cathedral_distill.cybergym_service import CyberGymService
    from cathedral_distill.cybergym_validator import ChainContext
    import hashlib

    dg = lambda s: "sha256:" + hashlib.sha256(s.encode()).hexdigest()  # noqa: E731
    manifest = [{"task_id": "arvo:1", "level": 0, "binary_digest": dg("b1"),
                 "disclosed_at": "2026-07-27T00:00:00Z"}]
    return CyberGymService(
        load_holdout(manifest),
        ChainContext(block=100, block_hash="0x" + "cd" * 32, network="finney",
                     netuid=39, source_epoch=11, valid_from_block=100,
                     valid_until_block=460),
        backend=lambda *_a: 0,
        corpus_store=CyberGymCorpusStore(str(tmp_path / "c.sqlite")),
        score_store=CyberGymScoreStore(str(tmp_path / "s.sqlite")),
        solve_store=CyberGymSolveStore(str(tmp_path / "v.sqlite")),
        validator_hotkey="5Val", private_key=SIGNER, signing_key_id="cybergym-1",
        batch_size=1, cutoff=datetime(2026, 7, 20, tzinfo=UTC),
        as_of=datetime(2026, 7, 27, tzinfo=UTC),
        attestation_required=False, gates_required=False,
    )


def _serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def _get(base, path, headers=None):
    req = urllib.request.Request(base + path, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def test_the_keys_route_serves_verbatim_with_an_etag(tmp_path):
    body = _registry_bytes()
    served, _ = _served(tmp_path, body)
    server = chttp.make_server(_service(tmp_path), port=0, key_registry=served)
    thread = _serve(server)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        code, got, headers = _get(base, chttp.KEYS_PATH)
        assert code == 200
        assert got == body                                  # verbatim
        assert headers["ETag"] == f'"{rk.registry_digest(body)}"'
        assert headers["Access-Control-Allow-Origin"] == "*"

        # a fetcher that already has it revalidates for free
        code, empty, _ = _get(base, chttp.KEYS_PATH,
                              {"If-None-Match": headers["ETag"]})
        assert code == 304 and empty == b""

        # and it round-trips through the real verifier
        registry = rk.verify_key_registry(
            got, ROOTS, now=GENERATED + timedelta(hours=1))
        assert registry.resolve("cybergym-1", at=GENERATED + timedelta(hours=1))
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_the_keys_route_reports_503_when_stale_rather_than_serving(tmp_path):
    served, _ = _served(tmp_path, at=GENERATED + timedelta(hours=25))
    server = chttp.make_server(_service(tmp_path), port=0, key_registry=served)
    thread = _serve(server)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        code, body, _ = _get(base, chttp.KEYS_PATH)
        assert code == 503
        assert "stale" in json.loads(body)["error"]
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_an_unconfigured_host_says_so_rather_than_404(tmp_path):
    server = chttp.make_server(_service(tmp_path), port=0)
    thread = _serve(server)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        code, body, _ = _get(base, chttp.KEYS_PATH)
        assert code == 503
        assert "no key registry is configured" in json.loads(body)["error"]
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_status_reports_the_served_registry(tmp_path):
    """Closes the loop: which key signed, and is the registry resolving it fresh."""
    served, _ = _served(tmp_path)
    server = chttp.make_server(_service(tmp_path), port=0, key_registry=served)
    thread = _serve(server)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        code, body, _ = _get(base, chttp.STATUS_PATH)
        assert code == 200
        payload = json.loads(body)
        block = payload["key_registry"]
        assert block["state"] == sk.SERVED and block["available"] is True
        assert block["fresh_until"] == "2026-07-31T00:00:00Z"
        # the signing key the epoch reports is IN the registry being served
        assert payload["epoch"]["signing_key_id"] == "cybergym-1"
        assert block["digest"].startswith("sha256:")
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_status_omits_the_block_when_no_registry_is_served(tmp_path):
    server = chttp.make_server(_service(tmp_path), port=0)
    thread = _serve(server)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        payload = json.loads(_get(base, chttp.STATUS_PATH)[1])
        assert "key_registry" not in payload
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_the_threaded_server_serves_keys_healthz_and_status(tmp_path):
    served, _ = _served(tmp_path)
    server = chttp.make_threaded_server(_service(tmp_path), host="127.0.0.1", port=0,
                                        healthz={"status": "ok"}, key_registry=served)
    thread = _serve(server)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        assert _get(base, "/healthz")[0] == 200
        assert _get(base, chttp.STATUS_PATH)[0] == 200
        assert _get(base, chttp.KEYS_PATH)[0] == 200
        assert _get(base, "/nope")[0] == 404
    finally:
        server.shutdown()
        thread.join(timeout=5)
