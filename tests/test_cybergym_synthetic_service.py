"""The live CyberGym service, wired to the nonce-seeded synthetic generator
instead of a disclosure-timed corpus — proves the un-cheatable holdout (already
proven standalone in `test_cybergym_synthetic.py`) actually plugs into the real
dispatch -> submit -> verify -> corpus -> score -> compose path a miner and
validator run against, not just the demo scripts.

`SyntheticTaskSource` (cybergym_synthetic.py) satisfies the exact same draw/
context/backend interface `TaskPool` + a corpus manifest does, so
`CyberGymService` runs identically either way — this file exercises that
service exactly as `test_cybergym_service.py` does, just built from
`synthetic_holdout()` instead of `load_holdout(manifest)`.
"""
from __future__ import annotations

import base64
import hashlib
import re
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import lane_feed as lf  # noqa: E402
from cathedral_distill.cybergym_protocol import CyberGymCorpusStore, ProtocolError, SubmissionEnvelope  # noqa: E402
from cathedral_distill.cybergym_scores import CyberGymScoreStore, CyberGymSolveStore  # noqa: E402
from cathedral_distill.cybergym_service import CyberGymService  # noqa: E402
from cathedral_distill.cybergym_synthetic import SyntheticTaskSource, synthetic_holdout  # noqa: E402
from cathedral_distill.cybergym_validator import ChainContext  # noqa: E402
from cathedral_distill.cybergym_verifier import poc_digest  # noqa: E402

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
CUTOFF = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)  # unused by the synthetic path; kept for parity
ISSUED = "2026-07-29T12:00:00.000000Z"
BLOCK_HASH = "0x" + "ab" * 32
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
MODEL = "sha256:" + hashlib.sha256(b"ckpt").hexdigest()
SOURCE_EPOCH = 21


def _dg(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _chain(*, source_epoch: int = SOURCE_EPOCH, block: int = 100, block_hash: str = BLOCK_HASH):
    return ChainContext(block=block, block_hash=block_hash, network="finney", netuid=39,
                        source_epoch=source_epoch, valid_from_block=block, valid_until_block=block + 360)


def _service(tmp_path, *, batch_size: int = 2, chain=None):
    holdout, backend = synthetic_holdout()
    return CyberGymService(
        holdout, chain or _chain(),
        backend=backend,
        corpus_store=CyberGymCorpusStore(str(tmp_path / "corpus.sqlite")),
        score_store=CyberGymScoreStore(str(tmp_path / "scores.sqlite")),
        solve_store=CyberGymSolveStore(str(tmp_path / "solves.sqlite")),
        validator_hotkey="5Val", private_key=KEY, signing_key_id="cybergym-1",
        batch_size=batch_size, cutoff=CUTOFF, as_of=NOW, attestation_required=False,
    )


def _craft_overflow(source: str) -> bytes:
    """A genuine solve: read the revealed pseudo-C, extract the magic + buffer
    size, and overflow by exactly one byte beyond the buffer — this crashes
    both synthetic bug classes (missing_bounds_check needs n>buf; off_by_one
    needs n>=buf; n=buf+1 satisfies both), matching cg_demo_synthetic.py."""
    magic = bytes(int(h, 16) for h in re.findall(r'\\x([0-9a-f]{2})', source))
    buf = int(re.search(r"char buf\[(\d+)\]", source).group(1))
    n = buf + 1
    return magic + n.to_bytes(2, "big") + b"A" * n


def _good_trace(task_id: str, poc_sha256: str) -> dict:
    long = ("I read the parser's memcpy call to see exactly how many bytes get "
            "copied relative to the declared buffer size, which tells me the "
            "minimal input that overflows it on the vulnerable build only")
    steps = [
        {"step": 1, "thought": f"open synth.c:1 and find the magic check at synth.c:2; {long}", "action": "read_file"},
        {"step": 2, "thought": f"read the buf[] declaration at synth.c:4 and the memcpy at synth.c:5; {long}", "action": "read_file"},
        {"step": 3, "thought": f"the copy size relative to buf's size determines the overflow; {long}", "action": "reason"},
        {"step": 4, "thought": f"write a PoC one byte past the buffer to trigger it; {long}", "action": "write_poc"},
        {"step": 5, "thought": f"confirm it crashes vul and not fix; {long}", "action": "verify"},
    ]
    return {"task_id": task_id, "poc_sha256": poc_sha256, "model_id": "cathedral/agent-v1",
            "steps": steps, "licence": "cathedral-corpus-v1", "model_seal": _dg("seal")}


def _envelope(dispatch_msg, task_id, poc_bytes, *, miner="5Miner"):
    digest = poc_digest(poc_bytes)
    return SubmissionEnvelope(
        batch_id=dispatch_msg.batch_id, task_id=task_id, miner_hotkey=miner,
        poc_base64=base64.b64encode(poc_bytes).decode(), trace=_good_trace(task_id, digest))


# --------------------------------------------------------------------------- #
# Full loop, genuine analysis, through the live service
# --------------------------------------------------------------------------- #

def test_synthetic_dispatch_submit_score_compose_end_to_end(tmp_path):
    svc = _service(tmp_path)
    d = svc.dispatch_for("5Miner", MODEL)
    assert len(d.tasks) == 2
    # level 0 (the batch's first task, per generate_holdout's level cycling) is blind
    assert d.tasks[0].level == 0 and d.tasks[0].context == {}
    task_id = d.tasks[0].task_id
    assert task_id.startswith("synthvuln:")

    # The miner analyses the vulnerable program — the always-available ARTIFACT
    # (what CyberGym hands a miner as the vulnerable build), fetched by task id
    # regardless of level; the level-gated context carries only hints.
    revealed = svc.holdout.pool.artifact(task_id)
    poc = _craft_overflow(revealed)

    outcome = svc.submit(_envelope(d, task_id, poc))
    assert outcome.solved and outcome.trainable, outcome.reason
    assert outcome.work_units == Decimal("8")  # level0 weight

    rows = svc._corpus.rows(source_epoch=SOURCE_EPOCH)
    assert len(rows) == 1 and rows[0]["task_id"] == task_id

    results = svc.score_epoch(issued_at=ISSUED)
    assert len(results) == 1
    assert svc._scores.epoch_scores(SOURCE_EPOCH) == {"5Miner": Decimal("8")}

    lane = svc.compose_lane(allocation=Decimal("0.90"))
    assert [c.miner_hotkey for c in lane.contributions] == ["5Miner"]
    feed = lf.compose_vector([lane], burn_hotkey="5Burn")
    assert {w["miner_hotkey"] for w in feed["weights"]} == {"5Miner"}
    assert feed["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(10.0)


def test_artifact_delivers_the_vulnerable_program_for_a_dispatched_task(tmp_path):
    # A wire-only miner has no program otherwise — the artifact route delivers the
    # 'vulnerable build' it analyses, for every dispatched task INCLUDING blind L0.
    svc = _service(tmp_path)
    d = svc.dispatch_for("5Miner", MODEL)
    for dt in d.tasks:
        program = svc.artifact_for(dt.task_id)
        assert "memcpy" in program and "char buf[" in program        # the real program
        # a blind L0 task carries no context hint, but the program is still delivered
        if dt.level == 0:
            assert dt.context == {}
    # and via the transport-agnostic handler
    got = svc.handle_artifact({"task_id": d.tasks[0].task_id})
    assert "memcpy" in got["program"] and got["task_id"] == d.tasks[0].task_id


def test_artifact_route_is_not_a_holdout_oracle(tmp_path):
    # The holdout is secret: the service must NEVER generate-and-reveal a program
    # for a task it did not dispatch (else the route leaks arbitrary challenges).
    svc = _service(tmp_path)
    svc.dispatch_for("5Miner", MODEL)
    with pytest.raises(ProtocolError, match="no such dispatched task"):
        svc.artifact_for("synthvuln:deadbeef:0")             # never dispatched
    assert svc.handle_artifact({"task_id": "synthvuln:deadbeef:0"}) == {"error": "no such dispatched task"}
    assert "error" in svc.handle_artifact({})                # missing task_id


def test_artifact_delivered_over_the_http_wire(tmp_path):
    import json
    import threading
    import urllib.request

    from cathedral_distill import cybergym_http as chttp

    svc = _service(tmp_path)
    server = chttp.make_server(svc, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"

        def post(path, obj):
            req = urllib.request.Request(base + path, data=json.dumps(obj).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())

        _, d = post(chttp.DISPATCH_PATH, {"miner_hotkey": "5Miner", "model_commitment": MODEL})
        tid = d["tasks"][0]["task_id"]
        status, art = post(chttp.ARTIFACT_PATH, {"task_id": tid})
        assert status == 200 and "memcpy" in art["program"] and art["task_id"] == tid
        # un-dispatched task refused over the wire (no holdout oracle)
        assert post(chttp.ARTIFACT_PATH, {"task_id": "synthvuln:ffff:9"})[0] == 400
    finally:
        server.shutdown()


def test_artifact_is_solvable_blind_end_to_end(tmp_path):
    # The gap this closes: a level-0 (blind) task, unsolvable over the wire before
    # because no program was delivered, is now solvable from the artifact alone.
    svc = _service(tmp_path)
    d = svc.dispatch_for("5Miner", MODEL)
    l0 = next(t for t in d.tasks if t.level == 0)
    program = svc.artifact_for(l0.task_id)                   # fetched, no hint
    poc = _craft_overflow(program)
    outcome = svc.submit(_envelope(d, l0.task_id, poc))
    assert outcome.solved and outcome.work_units == Decimal("8")  # level-0 weight


def test_synthetic_cheater_with_a_looked_up_poc_does_not_solve(tmp_path):
    # The public-dataset-cheat scenario, through the live service: a "known
    # crashing input" that has nothing to do with THIS nonce's generated bug.
    svc = _service(tmp_path)
    d = svc.dispatch_for("5Miner", MODEL)
    task_id = d.tasks[0].task_id
    cheat_poc = b"AAAA" + b"\xff\xff" + b"\x90" * 400  # wrong magic -> format-guarded out

    outcome = svc.submit(_envelope(d, task_id, cheat_poc))
    assert not outcome.solved and not outcome.trainable
    assert svc._corpus.size() == 0
    svc.score_epoch(issued_at=ISSUED)
    assert svc._scores.epoch_scores(SOURCE_EPOCH) == {}


# --------------------------------------------------------------------------- #
# The properties that make it un-cheatable, proven through the live service
# --------------------------------------------------------------------------- #

def _at(tmp_path, name):
    sub = tmp_path / name
    sub.mkdir()
    return sub


def test_two_independent_validators_dispatch_the_identical_batch(tmp_path):
    # Two SEPARATE CyberGymService instances (fresh SyntheticTaskSource each,
    # standing in for two independent validator processes) draw for the same
    # miner/model/chain -> byte-identical dispatch, with no coordination.
    svc_a = _service(_at(tmp_path, "a"))
    svc_b = _service(_at(tmp_path, "b"))
    d_a = svc_a.dispatch_for("5Miner", MODEL)
    d_b = svc_b.dispatch_for("5Miner", MODEL)
    assert d_a.batch_id == d_b.batch_id
    assert d_a.nonce == d_b.nonce
    assert [t.task_id for t in d_a.tasks] == [t.task_id for t in d_b.tasks]
    assert [t.binary_digest for t in d_a.tasks] == [t.binary_digest for t in d_b.tasks]


def test_different_miners_in_the_same_epoch_get_different_batches(tmp_path):
    svc = _service(tmp_path)
    d1 = svc.dispatch_for("5MinerOne", MODEL)
    d2 = svc.dispatch_for("5MinerTwo", MODEL)
    assert d1.nonce != d2.nonce
    assert {t.task_id for t in d1.tasks} != {t.task_id for t in d2.tasks}


def test_the_same_miner_gets_a_different_batch_next_epoch(tmp_path):
    svc_e1 = _service(_at(tmp_path, "e1"), chain=_chain(source_epoch=21))
    svc_e2 = _service(_at(tmp_path, "e2"), chain=_chain(source_epoch=22))
    d1 = svc_e1.dispatch_for("5Miner", MODEL)
    d2 = svc_e2.dispatch_for("5Miner", MODEL)
    assert d1.nonce != d2.nonce
    assert {t.task_id for t in d1.tasks} != {t.task_id for t in d2.tasks}


def test_synthetic_source_alone_never_needs_a_pre_existing_pool():
    # Unlike TaskPool, a fresh SyntheticTaskSource can draw immediately — no
    # manifest, no "holdout is exhausted" failure mode, unlimited supply.
    source = SyntheticTaskSource()
    batch = source.draw(size=5, nonce="cgnonce-sha256:" + "11" * 32, as_of=NOW, cutoff=CUTOFF)
    assert len(batch.tasks) == 5
    # a second draw, larger, still just generates more — no exhaustion
    batch2 = source.draw(size=50, nonce="cgnonce-sha256:" + "22" * 32, as_of=NOW, cutoff=CUTOFF)
    assert len(batch2.tasks) == 50


# --------------------------------------------------------------------------- #
# Reject paths carry over unchanged (same protocol, different source)
# --------------------------------------------------------------------------- #

def test_synthetic_submit_to_unknown_batch_is_refused(tmp_path):
    svc = _service(tmp_path)
    env = SubmissionEnvelope(batch_id="sha256:" + "00" * 32, task_id="synthvuln:x:0",
                             miner_hotkey="5Miner", poc_base64=base64.b64encode(b"x").decode(),
                             trace=_good_trace("synthvuln:x:0", poc_digest(b"x")))
    with pytest.raises(ProtocolError, match="unknown or expired batch"):
        svc.submit(env)


def test_synthetic_submit_with_foreign_hotkey_is_refused(tmp_path):
    svc = _service(tmp_path)
    d = svc.dispatch_for("5Miner", MODEL)
    with pytest.raises(ProtocolError, match="does not own this batch"):
        svc.submit(_envelope(d, d.tasks[0].task_id, b"exploit", miner="5Attacker"))
