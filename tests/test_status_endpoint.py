"""The live status read surface: `build_status`, its cache, and `GET /v1/status`.

Three things this has to get right, because a status page is the one surface an
outsider sees and it must not become a way in:

* it discloses only what a receipt verifier or the chain already gives away, and
  in particular NOT the draw parameters that would let a miner time or shape a
  submission (`batch_size`, `cutoff`, `as_of`, level weights, gate policy);
* it never raises and never writes, so a locked store degrades one section rather
  than taking the page down or corrupting an epoch;
* it is cached, so an anonymous unauthenticated route cannot be used to put
  arbitrary load on the same SQLite the submit path writes.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym_http as chttp  # noqa: E402
from cathedral_distill import status as st  # noqa: E402
from cathedral_distill.cybergym_holdout import load_holdout  # noqa: E402
from cathedral_distill.cybergym_protocol import CyberGymCorpusStore  # noqa: E402
from cathedral_distill.cybergym_scores import (  # noqa: E402
    CyberGymScoreStore,
    CyberGymSolveStore,
)
from cathedral_distill.cybergym_service import CyberGymService  # noqa: E402
from cathedral_distill.cybergym_validator import ChainContext  # noqa: E402
from cathedral_distill.cybergym_verifier import poc_digest  # noqa: E402

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
CUTOFF = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
BLOCK_HASH = "0x" + "cd" * 32
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
MODEL = "sha256:" + hashlib.sha256(b"ckpt").hexdigest()
SOURCE_EPOCH = 11


def _dg(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _manifest():
    return [
        {"task_id": "arvo:1", "level": 0, "binary_digest": _dg("b1"),
         "disclosed_at": "2026-07-27T00:00:00Z", "admitted": True},
        {"task_id": "arvo:2", "level": 2, "binary_digest": _dg("b2"),
         "disclosed_at": "2026-07-27T00:00:00Z", "admitted": True},
    ]


def _service(tmp_path, solved=("arvo:1",)):
    def backend(task_id, poc, mode):
        return 1 if (task_id in set(solved) and mode == "vul") else 0

    return CyberGymService(
        load_holdout(_manifest()),
        ChainContext(block=100, block_hash=BLOCK_HASH, network="finney", netuid=39,
                     source_epoch=SOURCE_EPOCH, valid_from_block=100,
                     valid_until_block=460),
        backend=backend,
        corpus_store=CyberGymCorpusStore(str(tmp_path / "corpus.sqlite")),
        score_store=CyberGymScoreStore(str(tmp_path / "scores.sqlite")),
        solve_store=CyberGymSolveStore(str(tmp_path / "solves.sqlite")),
        validator_hotkey="5Val", private_key=KEY, signing_key_id="cybergym-1",
        batch_size=2, cutoff=CUTOFF, as_of=NOW, attestation_required=False,
        gates_required=False,
    )


def _good_trace(task_id, poc_sha256):
    long = ("I walk the parser and read the length field then compare it against the "
            "destination buffer size to see whether an attacker controlled value can "
            "exceed the allocation and corrupt adjacent heap metadata on the vulnerable "
            "build only")
    steps = [
        {"step": 1, "thought": f"open the target and read valid.c:1897; {long}", "action": "read_file"},
        {"step": 2, "thought": f"cross-check parse.c:44 and util.c:210; {long}", "action": "read_file"},
        {"step": 3, "thought": f"the length at valid.c:1900 is trusted; {long}", "action": "reason"},
        {"step": 4, "thought": f"write the PoC with an oversized header; {long}", "action": "write_poc"},
        {"step": 5, "thought": f"confirm the sanitizer fires on vul not fix; {long}", "action": "verify"},
    ]
    return {"task_id": task_id, "poc_sha256": poc_sha256, "model_id": "cathedral/agent-v1",
            "steps": steps, "licence": "cathedral-corpus-v1", "model_seal": _dg("seal")}


def _solve(svc, miner="5Miner"):
    """Drive one accepted solve through the service so status has something live."""
    dispatch = svc.handle_dispatch({"miner_hotkey": miner, "model_commitment": MODEL})
    poc = b"exploit-bytes-for-arvo-1"
    envelope = {
        "schema": "cathedral_cybergym_submission_envelope_v1",
        "batch_id": dispatch["batch_id"], "task_id": "arvo:1", "miner_hotkey": miner,
        "poc_base64": base64.b64encode(poc).decode(),
        "trace": _good_trace("arvo:1", poc_digest(poc)),
    }
    verdict = svc.handle_submit(json.dumps(envelope).encode())
    assert verdict["accepted"], verdict
    return verdict


# --------------------------------------------------------------------------- #
# The payload
# --------------------------------------------------------------------------- #


def test_status_reports_the_epochs_public_identity(tmp_path):
    payload = st.build_status(_service(tmp_path))

    assert payload["schema"] == st.SCHEMA
    assert payload["generated_at"].endswith("Z")
    assert payload["lane"] == {
        "lane_id": "cathedral_cybergym",
        "receipt_schema": "cathedral_cybergym_receipt_v1",
    }
    epoch = payload["epoch"]
    assert epoch["available"] is True
    assert epoch["source_epoch"] == SOURCE_EPOCH
    assert epoch["network"] == "finney" and epoch["netuid"] == 39
    # the window a receipt is authorized against, which a verifier needs
    assert epoch["valid_from_block"] == 100 and epoch["valid_until_block"] == 460
    # and the signer, without which no live receipt has a resolvable key
    assert epoch["signing_key_id"] == "cybergym-1"
    assert epoch["signing_public_key_digest"].startswith("sha256:")
    assert epoch["validator_hotkey"] == "5Val"
    assert epoch["manifest_digest"].startswith("sha256:")


def test_status_withholds_the_draw_parameters(tmp_path):
    """Publishing these would tell a miner how to time and shape a submission."""
    svc = _service(tmp_path)
    payload = st.build_status(svc)
    text = json.dumps(payload)

    for private in ("batch_size", "cutoff", "as_of", "level_weights", "gate_policy",
                    "credit_synthetic_tasks", "gates_required", "block_hash"):
        assert private not in payload["epoch"], private
        assert private not in text, private

    # The full manifest DOES carry them; the digest is what lets someone holding
    # it check this validator without the endpoint handing them out.
    manifest = svc.epoch_manifest()
    assert {"batch_size", "cutoff", "as_of", "level_weights"} <= set(manifest)
    _, digest = CyberGymSolveStore.canonical_manifest(manifest)
    assert payload["epoch"]["manifest_digest"] == digest


def test_an_open_epoch_with_no_scoring_pass_is_not_an_error(tmp_path):
    """Empty is a normal answer. Reporting it unavailable makes healthy look broken."""
    payload = st.build_status(_service(tmp_path))
    assert payload["state"]["state"] == "open"
    assert payload["leaderboard"]["available"] is True
    assert payload["leaderboard"]["top"] == []
    assert payload["leaderboard"]["scored_miners"] == 0
    assert payload["participation"]["available"] is True


def test_participation_moves_while_the_epoch_is_open(tmp_path):
    svc = _service(tmp_path)
    before = st.build_status(svc)["participation"]
    assert before["committed"] == 0 and before["durable_solves"] == 0

    _solve(svc)

    after = st.build_status(svc)["participation"]
    assert after["committed"] == 1
    assert after["durable_solves"] == 1
    assert after["pending"] == 1  # solved, not yet scored
    assert after["scored"] == 0


def test_the_leaderboard_ranks_scored_units_highest_first(tmp_path):
    svc = _service(tmp_path)
    _solve(svc, miner="5Miner")
    svc.score_epoch(issued_at="2026-07-27T12:00:00.000000Z")

    payload = st.build_status(svc)
    board = payload["leaderboard"]
    assert board["available"] is True
    assert board["scored_miners"] == 1
    assert board["truncated"] is False
    (row,) = board["top"]
    assert row == {"rank": 1, "miner_hotkey": "5Miner", "earned_units": "8"}
    assert board["total_earned_units"] == "8"
    # units are strings, never floats: a Decimal must not round-trip through one
    assert isinstance(row["earned_units"], str)
    assert payload["state"]["state"] == "closed"
    assert payload["participation"]["scored"] == 1


def test_the_leaderboard_truncates_and_says_so(tmp_path):
    svc = _service(tmp_path)
    _solve(svc)
    svc.score_epoch(issued_at="2026-07-27T12:00:00.000000Z")
    payload = st.build_status(svc, leaderboard_limit=0)
    assert payload["leaderboard"]["top"] == []
    assert payload["leaderboard"]["truncated"] is True
    assert payload["leaderboard"]["scored_miners"] == 1


def test_the_corpus_grows_only_with_verified_trainable_solves(tmp_path):
    """size() IS the product (README: "the data is the product"), so it must move
    only on a genuinely corpus-eligible solve, and be visible before scoring."""
    svc = _service(tmp_path)
    before = st.build_status(svc)["corpus"]
    assert before == {
        "available": True,
        "total_rows": 0,
        "this_epoch_rows": 0,
        "excluded_duplicates": 0,
        "this_epoch_excluded_duplicates": 0,
    }

    _solve(svc)  # solved + trainable trace -> corpus-eligible, before any scoring pass

    after = st.build_status(svc)["corpus"]
    assert after["available"] is True
    assert after["total_rows"] == 1
    assert after["this_epoch_rows"] == 1


# --------------------------------------------------------------------------- #
# Failing soft
# --------------------------------------------------------------------------- #


def test_one_unreadable_store_degrades_its_section_only(tmp_path):
    svc = _service(tmp_path)
    svc._scores.close()  # simulate a store that cannot answer

    payload = st.build_status(svc)
    # the epoch block does not touch the score store, so it still serves
    assert payload["epoch"]["available"] is True
    assert payload["state"]["available"] is False
    assert "detail" in payload["state"]
    assert payload["leaderboard"]["available"] is False


def test_corpus_degrades_on_its_own_when_that_store_is_unreadable(tmp_path):
    svc = _service(tmp_path)
    svc._corpus.close()

    payload = st.build_status(svc)
    assert payload["epoch"]["available"] is True
    assert payload["corpus"]["available"] is False
    assert "detail" in payload["corpus"]


def test_an_unreadable_manifest_does_not_take_the_payload_down(tmp_path):
    svc = _service(tmp_path)

    def explode():
        raise RuntimeError("manifest unavailable")

    svc.epoch_manifest = explode  # type: ignore[method-assign]
    payload = st.build_status(svc)
    assert payload["schema"] == st.SCHEMA
    assert payload["epoch"]["available"] is False
    assert "manifest unavailable" in payload["epoch"]["detail"]
    # with no epoch there is nothing to key the other sections on, and they say so
    for section in ("state", "participation", "leaderboard"):
        assert payload[section]["available"] is False


def test_build_status_writes_nothing(tmp_path):
    """A public read must not be able to mutate an epoch."""
    svc = _service(tmp_path)
    _solve(svc)
    before = (svc._solves.size(), len(svc._scores.epoch_scores(SOURCE_EPOCH)),
              svc._scores.epoch_state(SOURCE_EPOCH))
    for _ in range(5):
        st.build_status(svc)
    after = (svc._solves.size(), len(svc._scores.epoch_scores(SOURCE_EPOCH)),
             svc._scores.epoch_state(SOURCE_EPOCH))
    assert before == after


# --------------------------------------------------------------------------- #
# The cache
# --------------------------------------------------------------------------- #


def test_the_cache_serves_one_build_per_window():
    clock = {"t": 100.0}
    builds = {"n": 0}

    def build():
        builds["n"] += 1
        return {"schema": st.SCHEMA, "build": builds["n"]}

    cache = st.StatusCache(build, ttl_secs=5.0, clock=lambda: clock["t"])
    assert cache.get()["build"] == 1
    clock["t"] += 4.9
    assert cache.get()["build"] == 1  # still the same window
    assert cache.get()["cache"]["age_secs"] == pytest.approx(4.9)
    clock["t"] += 0.2
    assert cache.get()["build"] == 2  # window expired
    assert builds["n"] == 2


def test_a_failed_build_is_not_cached():
    calls = {"n": 0}

    def build():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("store locked")
        return {"schema": st.SCHEMA, "ok": True}

    cache = st.StatusCache(build, ttl_secs=60.0)
    with pytest.raises(RuntimeError, match="store locked"):
        cache.get()
    assert cache.get()["ok"] is True  # the next request retries rather than serving it


def test_the_cache_does_not_hand_out_its_own_payload(tmp_path):
    """A caller mutating the response must not corrupt what the next one gets."""
    cache = st.StatusCache(lambda: {"schema": st.SCHEMA, "epoch": {"n": 1}}, ttl_secs=60.0)
    first = cache.get()
    first["injected"] = True
    assert "injected" not in cache.get()


def test_the_cache_takes_the_lock_when_given_one(tmp_path):
    """On a threaded server the build shares the service lock; prove it is held."""
    svc = _service(tmp_path)
    lock = threading.Lock()
    cache = st.StatusCache.for_service(svc, ttl_secs=0.0, lock=lock)

    held: list[bool] = []
    real = st.build_status

    def spy(service, **kw):
        held.append(lock.locked())
        return real(service, **kw)

    st.build_status = spy  # type: ignore[assignment]
    try:
        cache.get()
    finally:
        st.build_status = real  # type: ignore[assignment]
    assert held == [True]


# --------------------------------------------------------------------------- #
# Over the wire
# --------------------------------------------------------------------------- #


def _get(base, path):
    req = urllib.request.Request(base + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read()), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read()), dict(exc.headers)


def _serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def test_the_status_route_serves_over_http(tmp_path):
    svc = _service(tmp_path)
    _solve(svc)
    svc.score_epoch(issued_at="2026-07-27T12:00:00.000000Z")
    server = chttp.make_server(svc, port=0)
    thread = _serve(server)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        status, payload, headers = _get(base, chttp.STATUS_PATH)
        assert status == 200
        assert payload["schema"] == st.SCHEMA
        assert payload["leaderboard"]["top"][0]["miner_hotkey"] == "5Miner"
        # a static page on another origin has to be able to read it
        assert headers["Access-Control-Allow-Origin"] == "*"
        assert headers["Content-Type"] == "application/json"
        # a query string still routes
        assert _get(base, chttp.STATUS_PATH + "?t=1")[0] == 200
        # and nothing else answers GET
        assert _get(base, "/v1/nope")[0] == 404
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_the_mutating_routes_stay_same_origin(tmp_path):
    """CORS on the read surface must not leak onto the authenticated POSTs.

    A browser that could drive dispatch/submit cross-site would let any page a
    miner visits act as that miner against this validator.
    """
    svc = _service(tmp_path)
    server = chttp.make_server(svc, port=0)
    thread = _serve(server)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        req = urllib.request.Request(
            base + chttp.DISPATCH_PATH,
            data=json.dumps({"miner_hotkey": "5Miner", "model_commitment": MODEL}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            assert "Access-Control-Allow-Origin" not in dict(resp.headers)
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_preflight_is_answered_for_the_status_route_only(tmp_path):
    svc = _service(tmp_path)
    server = chttp.make_server(svc, port=0)
    thread = _serve(server)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        req = urllib.request.Request(base + chttp.STATUS_PATH, method="OPTIONS")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 204
            assert dict(resp.headers)["Access-Control-Allow-Methods"] == "GET, OPTIONS"

        bad = urllib.request.Request(base + chttp.SUBMIT_PATH, method="OPTIONS")
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(bad, timeout=5)
        assert caught.value.code == 404
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_the_threaded_server_serves_both_healthz_and_status(tmp_path):
    """The production server's /healthz override must not shadow /v1/status."""
    svc = _service(tmp_path)
    server = chttp.make_threaded_server(svc, host="127.0.0.1", port=0,
                                        healthz={"status": "ok", "role": "cybergym"})
    thread = _serve(server)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        code, health, _ = _get(base, "/healthz")
        assert code == 200 and health["role"] == "cybergym"
        code, payload, headers = _get(base, chttp.STATUS_PATH)
        assert code == 200
        assert payload["schema"] == st.SCHEMA
        assert payload["epoch"]["source_epoch"] == SOURCE_EPOCH
        assert headers["Access-Control-Allow-Origin"] == "*"
        assert _get(base, "/nope")[0] == 404
    finally:
        server.shutdown()
        thread.join(timeout=5)
