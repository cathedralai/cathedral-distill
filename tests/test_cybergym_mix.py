"""Weighted task-source mixing + the off-reward liveness canary.

Proves the two properties that make `cybergym_mix` safe to run live: the mixed
batch is byte-identical across independent validators (deterministic
apportionment + sub-nonces), and the public-canary channel produces a
`LivenessReport` with no receipt and no work units — a public, lookup-farmable
task can never move a reward. Also drives the mix through the real
`CyberGymService` loop (dispatch -> genuine solve -> score -> compose) so the
blend is exercised end to end, not just in isolation.
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
from cathedral_distill.cybergym import Level, Task  # noqa: E402
from cathedral_distill.cybergym_batch import Batch, PooledTask, TaskPool, batch_id_for  # noqa: E402
from cathedral_distill.cybergym_mix import (  # noqa: E402
    CorpusSource,
    LivenessReport,
    MixError,
    MixedTaskSource,
    SourceSpec,
    apportion,
    probe_liveness,
)
from cathedral_distill.cybergym_protocol import CyberGymCorpusStore, SubmissionEnvelope  # noqa: E402
from cathedral_distill.cybergym_scores import CyberGymScoreStore, CyberGymSolveStore  # noqa: E402
from cathedral_distill.cybergym_service import CyberGymService  # noqa: E402
from cathedral_distill.cybergym_synthetic import SyntheticTaskSource, generate_bug  # noqa: E402
from cathedral_distill.cybergym_validator import ChainContext  # noqa: E402
from cathedral_distill.cybergym_verifier import poc_digest  # noqa: E402

NONCE = "cgnonce-sha256:" + "ab" * 32
NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
CUTOFF = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
ISSUED = "2026-07-29T12:00:00.000000Z"
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
MODEL = "sha256:" + hashlib.sha256(b"ckpt").hexdigest()
SOURCE_EPOCH = 21


def _dg(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _syn(**kw) -> SourceSpec:
    return SourceSpec(kw["key"], SyntheticTaskSource(), kw["weight"])


class _FakeSource:
    """A source emitting a fixed, ordered id list — for exact apportionment,
    routing, and collision tests without depending on generated ids."""

    def __init__(self, ids, *, ctx=None, solve=False):
        self._ids = list(ids)
        self._ctx = ctx or {}
        self._solve = solve

    def draw(self, *, size, nonce, as_of, cutoff):
        ids = self._ids[:size]
        tasks = tuple(Task(task_id=i, level=Level(0), binary_digest=_dg("bin")) for i in ids)
        return Batch(batch_id=batch_id_for(nonce, [t.task_id for t in tasks]), nonce=nonce, tasks=tasks)

    def context_provider(self, task_id):
        return dict(self._ctx.get(task_id, {}))

    def backend(self, task_id, poc, mode):
        return 1 if (self._solve and mode == "vul") else 0


# --------------------------------------------------------------------------- #
# Apportionment
# --------------------------------------------------------------------------- #

def test_apportion_is_exact_and_deterministic():
    specs = [SourceSpec("a", SyntheticTaskSource(), 3), SourceSpec("b", SyntheticTaskSource(), 1)]
    for size in range(0, 40):
        counts = apportion(size, specs, NONCE)
        assert sum(counts) == size                      # exact
        assert apportion(size, specs, NONCE) == counts  # deterministic across calls


def test_apportion_respects_weight_proportions():
    specs = [SourceSpec("a", SyntheticTaskSource(), 3), SourceSpec("b", SyntheticTaskSource(), 1)]
    assert apportion(8, specs, NONCE) == [6, 2]         # 3:1 over 8
    assert apportion(100, specs, NONCE) == [75, 25]


def test_apportion_leftover_tiebreak_is_nonce_stable_but_can_differ_by_nonce():
    three = [SourceSpec("a", SyntheticTaskSource(), 1), SourceSpec("b", SyntheticTaskSource(), 1),
             SourceSpec("c", SyntheticTaskSource(), 1)]
    a = apportion(5, three, "cgnonce-sha256:" + "11" * 32)
    b = apportion(5, three, "cgnonce-sha256:" + "22" * 32)
    assert sum(a) == 5 and sum(b) == 5
    # each independently deterministic; a different nonce may hand the +1 leftovers
    # to different sources, but never changes the total
    assert apportion(5, three, "cgnonce-sha256:" + "11" * 32) == a


def test_apportion_rejects_bad_size():
    specs = [SourceSpec("a", SyntheticTaskSource(), 1)]
    with pytest.raises(MixError):
        apportion(-1, specs, NONCE)


# --------------------------------------------------------------------------- #
# MixedTaskSource.draw — the two-validator-consensus property
# --------------------------------------------------------------------------- #

def _mix():
    return MixedTaskSource([SourceSpec("a", SyntheticTaskSource(), 3),
                            SourceSpec("b", SyntheticTaskSource(), 1)])


def test_two_independent_mixes_draw_the_identical_batch():
    m1, m2 = _mix(), _mix()
    b1 = m1.draw(size=8, nonce=NONCE)
    b2 = m2.draw(size=8, nonce=NONCE)
    assert b1.batch_id == b2.batch_id
    assert [t.task_id for t in b1.tasks] == [t.task_id for t in b2.tasks]
    assert [t.binary_digest for t in b1.tasks] == [t.binary_digest for t in b2.tasks]
    # provenance agrees too
    assert {t.task_id: m1.origin(t.task_id) for t in b1.tasks} == \
           {t.task_id: m2.origin(t.task_id) for t in b2.tasks}


def test_mix_batch_id_is_canonical_over_sorted_ids():
    m = _mix()
    b = m.draw(size=8, nonce=NONCE)
    ids = [t.task_id for t in b.tasks]
    assert ids == sorted(ids)
    assert b.batch_id == batch_id_for(NONCE, ids)
    assert b.nonce == NONCE


def test_mix_honours_weight_split():
    m = _mix()
    b = m.draw(size=8, nonce=NONCE)
    by_source = {}
    for t in b.tasks:
        by_source.setdefault(m.origin(t.task_id), 0)
        by_source[m.origin(t.task_id)] += 1
    assert by_source == {"a": 6, "b": 2}


def test_mix_routes_context_and_backend_to_owning_source():
    a_solves = _FakeSource(["arvo:1", "arvo:2"], ctx={"arvo:1": {"description": "A"}}, solve=True)
    b_quiet = _FakeSource(["oss-fuzz:9"], ctx={"oss-fuzz:9": {"description": "B"}}, solve=False)
    m = MixedTaskSource([SourceSpec("a", a_solves, 2), SourceSpec("b", b_quiet, 1)])
    m.draw(size=3, nonce=NONCE)
    assert m.context_provider("arvo:1") == {"description": "A"}
    assert m.context_provider("oss-fuzz:9") == {"description": "B"}
    assert m.backend("arvo:1", b"x", "vul") == 1      # a solves
    assert m.backend("oss-fuzz:9", b"x", "vul") == 0  # b does not
    # a task the mix never drew routes to nothing
    assert m.context_provider("arvo:999") == {}
    assert m.backend("arvo:999", b"x", "vul") == 0


# --------------------------------------------------------------------------- #
# Fail-closed construction + draw
# --------------------------------------------------------------------------- #

def test_mix_rejects_empty_duplicate_and_bad_specs():
    with pytest.raises(MixError, match="at least one source"):
        MixedTaskSource([])
    with pytest.raises(MixError, match="unique"):
        MixedTaskSource([SourceSpec("a", SyntheticTaskSource(), 1),
                         SourceSpec("a", SyntheticTaskSource(), 1)])
    with pytest.raises(MixError, match="positive integer"):
        SourceSpec("a", SyntheticTaskSource(), 0)
    with pytest.raises(MixError, match="draw-capable"):
        SourceSpec("a", object(), 1)


def test_mix_draw_rejects_bad_size():
    with pytest.raises(MixError):
        _mix().draw(size=0, nonce=NONCE)


def test_mix_fails_closed_on_id_collision():
    # two sources whose id spaces overlap -> ambiguous batch -> fail closed
    dup = MixedTaskSource([SourceSpec("a", _FakeSource(["arvo:1", "arvo:2"]), 1),
                           SourceSpec("b", _FakeSource(["arvo:2", "arvo:3"]), 1)])
    with pytest.raises(MixError, match="collision"):
        dup.draw(size=4, nonce=NONCE)


def test_mix_fails_closed_when_a_source_underfills():
    short = MixedTaskSource([SourceSpec("a", _FakeSource(["arvo:1"]), 1),
                             SourceSpec("b", SyntheticTaskSource(), 1)])
    with pytest.raises(MixError, match="expected"):
        short.draw(size=8, nonce=NONCE)  # source 'a' can supply only 1


def test_mix_backend_requires_a_backend_on_the_source():
    class NoBackend:
        def draw(self, *, size, nonce, as_of, cutoff):
            return Batch(batch_id=batch_id_for(nonce, ["arvo:1"]), nonce=nonce,
                         tasks=(Task(task_id="arvo:1", level=Level(0), binary_digest=_dg("b")),))
    m = MixedTaskSource([SourceSpec("a", NoBackend(), 1)])
    m.draw(size=1, nonce=NONCE)
    with pytest.raises(MixError, match="no .backend"):
        m.backend("arvo:1", b"x", "vul")


# --------------------------------------------------------------------------- #
# CorpusSource adapter + a genuine synthetic+corpus blend, both scored
# --------------------------------------------------------------------------- #

def _corpus_pool():
    tasks = [PooledTask(task_id=f"arvo:{n}", level=Level(0), binary_digest=_dg(f"c{n}"),
                        disclosed_at=NOW) for n in range(1, 6)]
    return TaskPool(tasks)


def test_corpus_source_delegates_draw_context_backend():
    pool = _corpus_pool()
    solved = {("arvo:1", "vul"): 1}
    cs = CorpusSource(pool, context={"arvo:1": {"description": "len parser"}},
                      backend=lambda tid, poc, mode: solved.get((tid, mode), 0))
    b = cs.draw(size=3, nonce=NONCE, as_of=NOW, cutoff=CUTOFF)
    assert len(b.tasks) == 3
    assert cs.context_provider("arvo:1") == {"description": "len parser"}
    assert cs.backend("arvo:1", b"x", "vul") == 1 and cs.backend("arvo:1", b"x", "fix") == 0


def test_corpus_source_without_backend_fails_closed():
    cs = CorpusSource(_corpus_pool())
    with pytest.raises(MixError, match="without a differential backend"):
        cs.backend("arvo:1", b"x", "vul")


def test_mix_routes_artifact_to_synthetic_and_none_for_corpus():
    corpus = CorpusSource(_corpus_pool(), backend=lambda *a: 0)
    m = MixedTaskSource([SourceSpec("syn", SyntheticTaskSource(), 1),
                         SourceSpec("corpus", corpus, 1)])
    b = m.draw(size=6, nonce=NONCE, as_of=NOW, cutoff=CUTOFF)
    for t in b.tasks:
        art = m.artifact(t.task_id)
        if m.origin(t.task_id) == "syn":
            assert art is not None and "memcpy" in art        # synthetic program delivered inline
        else:
            assert art is None                                # corpus binary fetched out of band
    assert m.artifact("never-drawn") is None


def test_synthetic_plus_corpus_blend_both_route_and_score():
    # corpus backend that solves every corpus task on vul; synthetic self-checks.
    corpus = CorpusSource(_corpus_pool(), context={}, backend=lambda tid, poc, mode: 1 if mode == "vul" else 0)
    m = MixedTaskSource([SourceSpec("syn", SyntheticTaskSource(), 1),
                         SourceSpec("corpus", corpus, 1)])
    b = m.draw(size=6, nonce=NONCE, as_of=NOW, cutoff=CUTOFF)
    origins = {m.origin(t.task_id) for t in b.tasks}
    assert origins == {"syn", "corpus"}
    # each task routes its differential check to the right backend
    for t in b.tasks:
        if m.origin(t.task_id) == "corpus":
            assert m.backend(t.task_id, b"x", "vul") == 1  # corpus backend
        else:
            # synthetic: a random PoC does not crash the magic-guarded parser
            assert m.backend(t.task_id, b"x", "vul") == 0


# --------------------------------------------------------------------------- #
# The mix through the real CyberGymService loop (genuine solve)
# --------------------------------------------------------------------------- #

def _craft_overflow(source: str) -> bytes:
    magic = bytes(int(h, 16) for h in re.findall(r'\\x([0-9a-f]{2})', source))
    buf = int(re.search(r"char buf\[(\d+)\]", source).group(1))
    n = buf + 1
    return magic + n.to_bytes(2, "big") + b"A" * n


def _good_trace(task_id, poc_sha256):
    long = ("I read the memcpy call to see how many bytes are copied relative to "
            "buf's size, giving the minimal overflowing input on the vulnerable build")
    steps = [
        {"step": 1, "thought": f"open synth.c:1 and find the magic at synth.c:2; {long}", "action": "read_file"},
        {"step": 2, "thought": f"read buf[] at synth.c:4 and memcpy at synth.c:5; {long}", "action": "read_file"},
        {"step": 3, "thought": f"copy size vs buf size determines the overflow; {long}", "action": "reason"},
        {"step": 4, "thought": f"write a PoC one byte past the buffer; {long}", "action": "write_poc"},
        {"step": 5, "thought": f"confirm it crashes vul and not fix; {long}", "action": "verify"},
    ]
    return {"task_id": task_id, "poc_sha256": poc_sha256, "model_id": "cathedral/agent-v1",
            "steps": steps, "licence": "cathedral-corpus-v1", "model_seal": _dg("seal")}


def test_mix_runs_through_the_live_service_end_to_end(tmp_path):
    from cathedral_distill.cybergym_holdout import Holdout

    mix = MixedTaskSource([SourceSpec("a", SyntheticTaskSource(), 1),
                           SourceSpec("b", SyntheticTaskSource(), 1)])
    chain = ChainContext(block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
                         source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460)
    svc = CyberGymService(
        Holdout(pool=mix, _context={}), chain, backend=mix.backend,
        corpus_store=CyberGymCorpusStore(str(tmp_path / "c.sqlite")),
        score_store=CyberGymScoreStore(str(tmp_path / "s.sqlite")),
        solve_store=CyberGymSolveStore(str(tmp_path / "solves.sqlite")),
        validator_hotkey="5Val", private_key=KEY, signing_key_id="cybergym-1",
        batch_size=4, cutoff=CUTOFF, as_of=NOW, attestation_required=False,
        # the mix under test is built from two SYNTHETIC sources, which are
        # non-rewarding by default; this test is about the blend reaching the score
        # path, so it takes the explicit unsafe-for-rewards override
        gates_required=False, credit_synthetic_tasks=True)

    d = svc.dispatch_for("5Miner", MODEL)
    assert len(d.tasks) == 4
    # solve every task from its vulnerable-program artifact
    for dt in d.tasks:
        src = svc.holdout.pool.artifact(dt.task_id)
        poc = _craft_overflow(src)
        env = SubmissionEnvelope(batch_id=d.batch_id, task_id=dt.task_id, miner_hotkey="5Miner",
                                 poc_base64=base64.b64encode(poc).decode(),
                                 trace=_good_trace(dt.task_id, poc_digest(poc)))
        out = svc.submit(env)
        assert out.solved, out.reason

    svc.score_epoch(issued_at=ISSUED)
    scores = svc._scores.epoch_scores(SOURCE_EPOCH)
    assert "5Miner" in scores and scores["5Miner"] > 0
    lane = svc.compose_lane(allocation=Decimal("0.90"))
    feed = lf.compose_vector([lane], burn_hotkey="5Burn")
    assert {w["miner_hotkey"] for w in feed["weights"]} == {"5Miner"}


# --------------------------------------------------------------------------- #
# The off-reward liveness canary
# --------------------------------------------------------------------------- #

def _chain():
    return ChainContext(block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
                        source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460)


def _solved_pocs_for(nonce: str, size: int) -> dict[str, bytes]:
    """Craft a genuine PoC for every synthetic task a probe will draw at `nonce`.

    The generation is deterministic: `SyntheticTaskSource.draw` produces
    `generate_bug(nonce, i, level=(0,1,2,3)[i%4])`, so regenerate each bug, read
    its revealed source, and craft the overflow — exactly what a capable miner
    does from the dispatched context.
    """
    from cathedral_distill import cybergym_synthetic as syn
    pocs: dict[str, bytes] = {}
    for i in range(size):
        bug = generate_bug(nonce, i, level=(0, 1, 2, 3)[i % 4])
        pocs[bug.task_id] = _craft_overflow(syn.render_source(bug, patched=False))
    return pocs


def test_liveness_probe_reports_pass_rate_without_reward():
    from cathedral_distill.cybergym_batch import derive_batch_nonce
    source = SyntheticTaskSource()
    chain = _chain()
    nonce = derive_batch_nonce(block=chain.block, block_hash=chain.block_hash, network=chain.network,
                               netuid=chain.netuid, source_epoch=chain.source_epoch,
                               miner_hotkey="5Miner", model_commitment=MODEL)
    pocs = _solved_pocs_for(nonce, 4)

    report = probe_liveness(source, chain, miner_hotkey="5Miner", model_commitment=MODEL,
                            pocs=pocs, backend=source.backend, size=4, as_of=NOW, cutoff=CUTOFF)
    assert isinstance(report, LivenessReport)
    assert report.dispatched == 4 and report.solved == 4
    assert report.pass_rate == Decimal("1.0000")
    assert report.meets(Decimal("0.75"))
    # off-reward by construction: the return carries no work units and produced
    # no receipt / scores row — a public canary can never move a reward
    assert not hasattr(report, "work_units")


def test_liveness_cheater_scores_zero_solves_but_still_no_reward_path():
    source = SyntheticTaskSource()
    report = probe_liveness(source, _chain(), miner_hotkey="5Miner", model_commitment=MODEL,
                            pocs={"synthvuln:x:0": b"looked-up-answer"}, backend=source.backend,
                            size=4, as_of=NOW, cutoff=CUTOFF)
    # wrong/lookup PoCs solve nothing; and either way there is no receipt or unit
    assert report.solved == 0
    assert report.pass_rate == Decimal(0)
    assert not report.meets(Decimal("0.5"))


def test_liveness_report_counts_are_consistent():
    with pytest.raises(MixError):
        LivenessReport(miner_hotkey="5Miner", dispatched=2, solved=3)  # solved > dispatched


# --------------------------------------------------------------------------- #
# Hardenings surfaced by the adversarial review
# --------------------------------------------------------------------------- #

def _public_pool():
    # disclosed BEFORE the cutoff -> public (retired, freely trainable)
    old = datetime(2026, 7, 1, tzinfo=UTC)
    return TaskPool([PooledTask(task_id=f"arvo:{n}", level=Level(0),
                                binary_digest=_dg(f"p{n}"), disclosed_at=old) for n in range(1, 6)])


def test_task_pool_draw_public_is_deterministic_and_uses_the_public_set():
    from cathedral_distill.cybergym_mix import PublicCanarySource
    pool = _public_pool()
    b1 = pool.draw_public(size=3, nonce=NONCE, cutoff=CUTOFF)
    b2 = pool.draw_public(size=3, nonce=NONCE, cutoff=CUTOFF)
    assert b1.batch_id == b2.batch_id and len(b1.tasks) == 3
    # these are public (disclosed before cutoff); the private holdout is empty here,
    # so a normal .draw would refuse — proving draw_public reads a different set
    with pytest.raises(Exception):
        pool.draw(size=3, nonce=NONCE, as_of=NOW, cutoff=CUTOFF)


def test_public_canary_source_probes_liveness_off_the_holdout():
    from cathedral_distill.cybergym_mix import PublicCanarySource
    pool = _public_pool()
    # a backend that "solves" every public task (they're known-answer canaries)
    canary = PublicCanarySource(pool, backend=lambda tid, poc, mode: 1 if mode == "vul" else 0)
    # craft is irrelevant here (backend is a stub); supply a poc per task
    nonce = _probe_nonce("5Miner")
    ids = [t.task_id for t in pool.draw_public(size=3, nonce=nonce, cutoff=CUTOFF).tasks]
    report = probe_liveness(canary, _chain(), miner_hotkey="5Miner", model_commitment=MODEL,
                            pocs={i: b"poc" for i in ids}, backend=canary.backend,
                            size=3, cutoff=CUTOFF)
    assert report.dispatched == 3 and report.solved == 3
    assert report.pass_rate == Decimal("1.0000")


def _probe_nonce(miner):
    from cathedral_distill.cybergym_batch import derive_batch_nonce
    c = _chain()
    return derive_batch_nonce(block=c.block, block_hash=c.block_hash, network=c.network,
                              netuid=c.netuid, source_epoch=c.source_epoch,
                              miner_hotkey=miner, model_commitment=MODEL)


def test_public_canary_source_requires_a_pool_and_backend():
    from cathedral_distill.cybergym_mix import PublicCanarySource
    with pytest.raises(MixError, match="draw_public"):
        PublicCanarySource(object())
    cs = PublicCanarySource(_public_pool())
    with pytest.raises(MixError, match="without a differential backend"):
        cs.backend("arvo:1", b"x", "vul")


def test_mix_normalises_sub_source_errors_to_mixerror():
    # a corpus sub-source that can't fill its share -> BatchError -> MixError
    from cathedral_distill.cybergym_mix import CorpusSource
    pool = TaskPool([PooledTask(task_id="arvo:1", level=Level(0), binary_digest=_dg("x"),
                                disclosed_at=NOW)])
    m = MixedTaskSource([SourceSpec("corpus", CorpusSource(pool, backend=lambda *a: 0), 1)])
    with pytest.raises(MixError, match="could not draw"):
        m.draw(size=3, nonce=NONCE, as_of=NOW, cutoff=CUTOFF)  # pool has 1, needs 3


def test_mix_normalises_missing_asof_cutoff_for_corpus_sources():
    from cathedral_distill.cybergym_mix import CorpusSource
    pool = _corpus_pool()
    m = MixedTaskSource([SourceSpec("corpus", CorpusSource(pool, backend=lambda *a: 0), 1)])
    # omitting as_of/cutoff makes private_holdout hit `None > None` -> TypeError,
    # which the mix normalises to a MixError rather than leaking the raw TypeError
    with pytest.raises(MixError):
        m.draw(size=2, nonce=NONCE)


def test_mix_rejects_oversize_draw():
    from cathedral_distill.cybergym_batch import MAX_BATCH
    m = _mix()
    with pytest.raises(MixError, match="MAX_BATCH"):
        m.draw(size=MAX_BATCH + 1, nonce=NONCE)


def test_mix_cross_draw_origin_guard_fires_on_reowned_id():
    # two sources sharing one fixed id; find two nonces whose single leftover slot
    # routes to different keys, so draw #2 tries to re-own draw #1's task under a
    # different source -> the cross-draw guard raises (per-draw `seen` can't catch it).
    a = _FakeSource(["arvo:7"])
    b = _FakeSource(["arvo:7"])
    m = MixedTaskSource([SourceSpec("a", a, 1), SourceSpec("b", b, 1)])
    n_a = n_b = None
    for k in range(200):
        n = f"cgnonce-sha256:{k:064x}"
        counts = apportion(1, m.specs, n)
        # specs are sorted by key: index 0 == 'a', 1 == 'b'
        if counts[0] == 1 and n_a is None:
            n_a = n
        elif counts[1] == 1 and n_b is None:
            n_b = n
        if n_a and n_b:
            break
    assert n_a and n_b, "expected both routings to exist across nonces"
    m.draw(size=1, nonce=n_a)          # arvo:7 owned by 'a'
    with pytest.raises(MixError, match="drawn from source"):
        m.draw(size=1, nonce=n_b)      # 'b' tries to re-own arvo:7
