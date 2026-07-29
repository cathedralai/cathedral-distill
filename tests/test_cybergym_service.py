"""CyberGym runnable end-to-end: holdout -> dispatch -> submit -> verify -> corpus
-> score -> persist -> compose, over both the direct API and the stdlib HTTP shim.

Proves the lane actually runs as a service (against the injected stub backend, no
CyberGym binaries): a miner fetches its sealed batch, POSTs a PoC + trajectory, the
validator verifies the differential crash and the trace floor, the solve lands in
the corpus, the epoch scores into the cybergym_scores table, and the persisted
score composes into a lane_feed vector.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import threading
import urllib.request
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym_http as chttp  # noqa: E402
from cathedral_distill import lane_feed as lf  # noqa: E402
from cathedral_distill.cybergym_holdout import HoldoutError, load_holdout  # noqa: E402
from cathedral_distill.cybergym_protocol import CyberGymCorpusStore, ProtocolError, SubmissionEnvelope  # noqa: E402
from cathedral_distill.cybergym_scores import CyberGymScoreStore  # noqa: E402
from cathedral_distill.cybergym_service import CyberGymService  # noqa: E402
from cathedral_distill.cybergym_validator import ChainContext  # noqa: E402
from cathedral_distill.cybergym_verifier import poc_digest  # noqa: E402

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
CUTOFF = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
ISSUED = "2026-07-27T12:00:00.000000Z"
BLOCK_HASH = "0x" + "cd" * 32
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
MODEL = "sha256:" + hashlib.sha256(b"ckpt").hexdigest()
SOURCE_EPOCH = 11


def _dg(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _manifest():
    return [
        {"task_id": "arvo:1", "level": 0, "binary_digest": _dg("b1"),
         "disclosed_at": "2026-07-27T00:00:00Z"},
        {"task_id": "arvo:2", "level": 2, "binary_digest": _dg("b2"),
         "disclosed_at": "2026-07-27T00:00:00Z",
         "context": {"description": "a heap overflow in the length parser",
                     "sanitizer_trace": "AddressSanitizer: heap-buffer-overflow valid.c:1900",
                     "patch": "--- a/valid.c\n+++ b/valid.c\n@@ bound the length @@"}},
    ]


def _chain():
    return ChainContext(block=100, block_hash=BLOCK_HASH, network="finney", netuid=39,
                        source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460)


def _backend(solved_ids):
    def run(task_id, poc, mode):
        return 1 if (task_id in solved_ids and mode == "vul") else 0
    return run


def _service(tmp_path, solved=("arvo:1",)):
    return CyberGymService(
        load_holdout(_manifest()), _chain(),
        backend=_backend(set(solved)),
        corpus_store=CyberGymCorpusStore(str(tmp_path / "corpus.sqlite")),
        score_store=CyberGymScoreStore(str(tmp_path / "scores.sqlite")),
        validator_hotkey="5Val", private_key=KEY, signing_key_id="cybergym-1",
        batch_size=2, cutoff=CUTOFF, as_of=NOW,
    )


def _good_trace(task_id, poc_sha256):
    long = ("I walk the parser and read the length field then compare it against the "
            "destination buffer size to see whether an attacker controlled value can "
            "exceed the allocation and corrupt adjacent heap metadata on the vulnerable "
            "build only")
    steps = [
        {"step": 1, "thought": f"open the target and read valid.c:1897 where the header length is parsed; {long}", "action": "read_file"},
        {"step": 2, "thought": f"cross-check parse.c:44 and util.c:210 for the bound; {long}", "action": "read_file"},
        {"step": 3, "thought": f"the length at valid.c:1900 is trusted, so an oversized header overflows the 64-byte buffer; {long}", "action": "reason"},
        {"step": 4, "thought": f"write the PoC with an oversized length header to trigger the overflow; {long}", "action": "write_poc"},
        {"step": 5, "thought": f"confirm the sanitizer fires on vul and not fix at valid.c:1900; {long}", "action": "verify"},
    ]
    return {"task_id": task_id, "poc_sha256": poc_sha256, "model_id": "cathedral/agent-v1",
            "steps": steps, "licence": "cathedral-corpus-v1", "model_seal": _dg("seal")}


def _envelope(dispatch_msg, task_id, poc_bytes, miner="5Miner"):
    digest = poc_digest(poc_bytes)
    return SubmissionEnvelope(
        batch_id=dispatch_msg.batch_id, task_id=task_id, miner_hotkey=miner,
        poc_base64=base64.b64encode(poc_bytes).decode(), trace=_good_trace(task_id, digest))


# --------------------------------------------------------------------------- #
# Full loop through the direct API
# --------------------------------------------------------------------------- #

def test_dispatch_submit_score_compose_end_to_end(tmp_path):
    svc = _service(tmp_path)

    d = svc.dispatch_for("5Miner", MODEL)
    assert {t.task_id for t in d.tasks} == {"arvo:1", "arvo:2"}
    # level-gated context flows from the holdout manifest
    assert d.task("arvo:1").context == {}                       # level 0: blind
    assert set(d.task("arvo:2").context) == {"description", "sanitizer_trace"}  # level 2, no patch

    outcome = svc.submit(_envelope(d, "arvo:1", b"exploit-bytes-for-arvo-1"))
    assert outcome.solved and outcome.trainable
    assert outcome.work_units == Decimal("8")                   # level0 weight

    # the solve landed in the corpus, verbatim
    rows = svc._corpus.rows(source_epoch=SOURCE_EPOCH)
    assert len(rows) == 1 and rows[0]["task_id"] == "arvo:1"

    # epoch scores into the cybergym_scores table
    results = svc.score_epoch(issued_at=ISSUED)
    assert len(results) == 1
    assert svc._scores.epoch_scores(SOURCE_EPOCH) == {"5Miner": Decimal("8")}

    # the persisted score composes into a lane_feed vector
    lane = svc.compose_lane(allocation=Decimal("0.90"))
    assert [c.miner_hotkey for c in lane.contributions] == ["5Miner"]
    feed = lf.compose_vector([lane], burn_hotkey="5Burn")       # 0.90 + 0.10 burn == 1
    assert {w["miner_hotkey"] for w in feed["weights"]} == {"5Miner"}
    assert feed["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(10.0)


def test_unsolved_submission_scores_zero_and_no_corpus(tmp_path):
    svc = _service(tmp_path, solved=())  # backend solves nothing
    d = svc.dispatch_for("5Miner", MODEL)
    outcome = svc.submit(_envelope(d, "arvo:1", b"not-an-exploit"))
    assert not outcome.solved and not outcome.trainable
    assert svc._corpus.size() == 0
    svc.score_epoch(issued_at=ISSUED)
    assert svc._scores.epoch_scores(SOURCE_EPOCH) == {}


# --------------------------------------------------------------------------- #
# Reject paths
# --------------------------------------------------------------------------- #

def test_submit_to_unknown_batch_is_refused(tmp_path):
    svc = _service(tmp_path)
    env = SubmissionEnvelope(batch_id="sha256:" + "00" * 32, task_id="arvo:1",
                             miner_hotkey="5Miner", poc_base64=base64.b64encode(b"x").decode(),
                             trace=_good_trace("arvo:1", poc_digest(b"x")))
    with pytest.raises(ProtocolError, match="unknown or expired batch"):
        svc.submit(env)


def test_submit_with_foreign_hotkey_is_refused(tmp_path):
    svc = _service(tmp_path)
    d = svc.dispatch_for("5Miner", MODEL)
    with pytest.raises(ProtocolError, match="does not own this batch"):
        svc.submit(_envelope(d, "arvo:1", b"exploit", miner="5Attacker"))


def test_handle_submit_never_raises(tmp_path):
    svc = _service(tmp_path)
    result = svc.handle_submit(b"{not json")
    assert result["accepted"] is False and "error" in result


def test_holdout_manifest_validation():
    with pytest.raises(HoldoutError, match="missing keys"):
        load_holdout([{"task_id": "arvo:1", "level": 0}])
    with pytest.raises(HoldoutError, match="level must be"):
        load_holdout([{"task_id": "arvo:1", "level": 9, "binary_digest": _dg("b"),
                       "disclosed_at": "2026-07-27T00:00:00Z"}])
    with pytest.raises(HoldoutError, match="list of task entries"):
        load_holdout("not-a-list")


# --------------------------------------------------------------------------- #
# The stdlib HTTP shim — same loop over the wire
# --------------------------------------------------------------------------- #

def _post(base, path, payload):
    data = payload if isinstance(payload, (bytes, bytearray)) else json.dumps(payload).encode()
    req = urllib.request.Request(base + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_http_shim_dispatch_and_submit(tmp_path):
    svc = _service(tmp_path)
    server = chttp.make_server(svc, port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        status, dispatch_doc = _post(base, chttp.DISPATCH_PATH,
                                     {"miner_hotkey": "5Miner", "model_commitment": MODEL})
        assert status == 200 and dispatch_doc["schema"] == "cathedral_cybergym_dispatch_v1"
        batch_id = dispatch_doc["batch_id"]

        poc = b"exploit-bytes-for-arvo-1"
        envelope = {"schema": "cathedral_cybergym_submission_envelope_v1", "batch_id": batch_id,
                    "task_id": "arvo:1", "miner_hotkey": "5Miner",
                    "poc_base64": base64.b64encode(poc).decode(),
                    "trace": _good_trace("arvo:1", poc_digest(poc))}
        status, verdict = _post(base, chttp.SUBMIT_PATH, envelope)
        assert status == 200
        assert verdict["accepted"] and verdict["solved"] and verdict["trainable"]
        assert verdict["work_units"] == "8"

        # an unknown route and a bad batch both fail closed over the wire
        assert _post(base, "/nope", {})[0] == 404
        bad = dict(envelope, batch_id="sha256:" + "00" * 32)
        status, verdict = _post(base, chttp.SUBMIT_PATH, bad)
        assert status == 400 and verdict["accepted"] is False
    finally:
        server.shutdown()
        thread.join(timeout=5)

    # the solve made it into the corpus through the wire path
    assert svc._corpus.size() == 1
