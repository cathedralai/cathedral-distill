"""End-to-end CyberGym protocol: dispatch → solve → submit → verify → corpus.

Proves the delivery loop with an injected crash backend (no real binaries): the
validator serves a level-gated batch, the miner submits a PoC + trajectory, the
validator verifies the differential crash and the trace floor, and a
verified+trainable row lands in the corpus in the exact dataset format.
"""
from __future__ import annotations

import base64
import hashlib
import sqlite3
import sys
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym as cg  # noqa: E402
from cathedral_distill import cybergym_batch as cb  # noqa: E402
from cathedral_distill import cybergym_protocol as cp  # noqa: E402
from cathedral_distill import cybergym_validator as cv  # noqa: E402
from cathedral_distill.cybergym_verifier import poc_digest  # noqa: E402

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
CUTOFF = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
BLOCK_HASH = "0x" + "cd" * 32
MODEL = "sha256:" + hashlib.sha256(b"ckpt").hexdigest()


def _dg(seed):
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _pool():
    return cb.TaskPool([
        cb.PooledTask(task_id="arvo:1", level=cg.Level(0), binary_digest=_dg("b1"), disclosed_at=NOW, admitted=True),
        cb.PooledTask(task_id="arvo:2", level=cg.Level(2), binary_digest=_dg("b2"), disclosed_at=NOW, admitted=True),
    ])


def _chain():
    return cv.ChainContext(block=100, block_hash=BLOCK_HASH, network="finney", netuid=39,
                           source_epoch=11, valid_from_block=100, valid_until_block=460)


def _context_provider(_task_id):
    return {"description": "a heap overflow in the length parser",
            "sanitizer_trace": "AddressSanitizer: heap-buffer-overflow valid.c:1900",
            "patch": "--- a/valid.c\n+++ b/valid.c\n@@ bound the length @@"}


def _backend(solved_ids):
    def run(task_id, poc, mode):
        return 1 if (task_id in solved_ids and mode == "vul") else 0
    return run


def _dispatch():
    return cp.dispatch(_pool(), _chain(), miner_hotkey="5Miner", model_commitment=MODEL,
                       cutoff=CUTOFF, as_of=NOW, batch_size=2, context_provider=_context_provider)


def _good_trace(task_id, poc_sha256):
    # 5+ steps, read_file + write_poc, >=200 reasoning tokens, >=2 file:line refs,
    # no padded loops. Long thoughts so the token floor is genuinely cleared.
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


def _envelope(dispatch_msg, task_id, poc_bytes, trace=None):
    digest = poc_digest(poc_bytes)
    return cp.SubmissionEnvelope(
        batch_id=dispatch_msg.batch_id, task_id=task_id, miner_hotkey="5Miner",
        poc_base64=base64.b64encode(poc_bytes).decode(),
        trace=trace if trace is not None else _good_trace(task_id, digest))


# --------------------------------------------------------------------------- #
# Dispatch — level-gated context
# --------------------------------------------------------------------------- #

def test_dispatch_reveals_only_level_appropriate_context():
    d = _dispatch()
    assert {t.task_id for t in d.tasks} == {"arvo:1", "arvo:2"}
    l0 = d.task("arvo:1")   # level 0 — blind discovery, no context
    l2 = d.task("arvo:2")   # level 2 — + description + sanitizer trace, NOT the patch
    assert l0.context == {}
    assert set(l2.context) == {"description", "sanitizer_trace"}
    assert "patch" not in l2.context


def test_dispatch_is_deterministic_and_serialisable():
    a, b = _dispatch(), _dispatch()
    assert a.batch_id == b.batch_id and a.nonce == b.nonce
    assert a.to_dict()["schema"] == cp.DISPATCH_SCHEMA


# --------------------------------------------------------------------------- #
# Full loop — solve → submit → verify → corpus
# --------------------------------------------------------------------------- #

def test_solved_trainable_submission_scores_and_enters_corpus(tmp_path):
    d = _dispatch()
    env = _envelope(d, "arvo:1", b"exploit-bytes-for-arvo-1")
    outcome = cp.process_submission(env, d, _backend({"arvo:1"}))
    assert outcome.solved and outcome.trainable
    assert outcome.reason == "solved_trainable"
    assert outcome.work_units == Decimal("8")     # level0 weight
    assert outcome.bonus == pytest.approx(0.30)   # trace 0.20 + seal 0.10

    store = cp.CyberGymCorpusStore(str(tmp_path / "corpus.sqlite"))
    assert store.record(outcome) is True
    rows = store.rows(source_epoch=11)
    assert len(rows) == 1
    row = rows[0]
    assert row["task_id"] == "arvo:1" and row["model_id"] == "cathedral/agent-v1"
    assert row["poc_sha256"] == outcome.poc_sha256
    assert len(row["steps"]) == 5                 # the trajectory, verbatim
    assert row["steps"][3]["action"] == "write_poc"


def test_corpus_deduplicates_trace_variants_by_epoch_task_and_poc(tmp_path):
    """Trace wording must not turn one solved PoC into many training examples."""
    d = _dispatch()
    poc = b"one-canonical-exploit"
    first = cp.process_submission(_envelope(d, "arvo:1", poc), d, _backend({"arvo:1"}))
    variant_trace = _good_trace("arvo:1", poc_digest(poc))
    variant_trace["steps"][-1]["output"] = "same PoC; independently recorded trace variant"
    variant = cp.process_submission(
        _envelope(d, "arvo:1", poc, variant_trace), d, _backend({"arvo:1"})
    )
    assert first.trace_id != variant.trace_id

    store = cp.CyberGymCorpusStore(str(tmp_path / "corpus.sqlite"))
    assert store.record(first) is True
    assert store.record(variant) is True
    assert store.size() == 1
    assert store.audit() == {
        "canonical_solves": 1,
        "excluded_duplicates": 1,
        "recorded_duplicate_variants": 1,
    }

    # A new PoC and a new source epoch remain separately auditable examples.
    changed_poc = cp.process_submission(
        _envelope(d, "arvo:1", b"different-exploit"), d, _backend({"arvo:1"})
    )
    assert store.record(changed_poc) is True
    assert store.record(replace(first, source_epoch=12)) is True
    assert store.size() == 3


def test_corpus_bounds_duplicate_trace_audit_metadata(tmp_path):
    d = _dispatch()
    poc = b"same-exploit-many-traces"
    store = cp.CyberGymCorpusStore(str(tmp_path / "corpus.sqlite"))
    assert store.record(
        cp.process_submission(_envelope(d, "arvo:1", poc), d, _backend({"arvo:1"}))
    )
    for index in range(4):
        trace = _good_trace("arvo:1", poc_digest(poc))
        trace["steps"][-1]["output"] = f"variant-{index}"
        outcome = cp.process_submission(
            _envelope(d, "arvo:1", poc, trace), d, _backend({"arvo:1"})
        )
        assert store.record(outcome) is True

    assert store.audit() == {
        "canonical_solves": 1,
        "excluded_duplicates": 4,
        "recorded_duplicate_variants": store.MAX_DUPLICATE_AUDIT_VARIANTS,
    }


def test_corpus_migrates_legacy_trace_identity_to_canonical_solve_identity(tmp_path):
    """Startup preserves a bounded audit trail before enforcing the unique index."""
    path = tmp_path / "legacy-corpus.sqlite"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE cybergym_corpus ("
        "trace_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, level INTEGER NOT NULL, "
        "source_epoch INTEGER NOT NULL, miner_hotkey TEXT NOT NULL, model_id TEXT NOT NULL, "
        "poc_sha256 TEXT NOT NULL, licence TEXT NOT NULL, model_seal TEXT NOT NULL, "
        "work_units TEXT NOT NULL, steps_json TEXT NOT NULL)"
    )
    base = ("arvo:1", 0, 11, "5Miner", "model", "sha256:deadbeef", "licence", "seal", "8", "[]")
    connection.execute(
        "INSERT INTO cybergym_corpus VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("trace-a", *base)
    )
    connection.execute(
        "INSERT INTO cybergym_corpus VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("trace-b", *base)
    )
    connection.commit()
    connection.close()

    store = cp.CyberGymCorpusStore(str(path))
    assert [row["trace_id"] for row in store.rows()] == ["trace-a"]
    assert store.audit() == {
        "canonical_solves": 1,
        "excluded_duplicates": 1,
        "recorded_duplicate_variants": 1,
    }


def test_submission_roundtrips_through_json(tmp_path):
    d = _dispatch()
    env = _envelope(d, "arvo:1", b"exploit-bytes")
    parsed = cp.SubmissionEnvelope.from_json(__import__("json").dumps(env.to_dict()))
    outcome = cp.process_submission(parsed, d, _backend({"arvo:1"}))
    assert outcome.trainable


# --------------------------------------------------------------------------- #
# Reject / non-corpus paths
# --------------------------------------------------------------------------- #

def test_unsolved_earns_zero_and_no_corpus_row(tmp_path):
    d = _dispatch()
    env = _envelope(d, "arvo:1", b"not-an-exploit")
    outcome = cp.process_submission(env, d, _backend(set()))  # backend solves nothing
    assert not outcome.solved and not outcome.trainable
    assert outcome.work_units == Decimal("0")
    assert outcome.reason.startswith("not_solved")
    store = cp.CyberGymCorpusStore(str(tmp_path / "c.sqlite"))
    assert store.record(outcome) is False and store.size() == 0


def test_solved_but_thin_trace_scores_without_bonus_and_no_corpus(tmp_path):
    d = _dispatch()
    poc = b"exploit-bytes"
    thin = {"task_id": "arvo:1", "poc_sha256": poc_digest(poc), "model_id": "m",
            "steps": [{"step": 1, "thought": "did it", "action": "write_poc"}],
            "licence": "cathedral-corpus-v1", "model_seal": _dg("seal")}
    outcome = cp.process_submission(_envelope(d, "arvo:1", poc, thin), d, _backend({"arvo:1"}))
    assert outcome.solved and not outcome.trainable      # solved counts...
    assert outcome.work_units == Decimal("8")            # ...for the exploit
    assert outcome.bonus == pytest.approx(0.10)          # seal only — the floor gates the trace bonus
    assert outcome.reason.startswith("solved_trace_below_floor")
    store = cp.CyberGymCorpusStore(str(tmp_path / "c.sqlite"))
    assert store.record(outcome) is False                # and never enters the corpus


def test_off_batch_task_is_refused():
    d = _dispatch()
    env = cp.SubmissionEnvelope(batch_id=d.batch_id, task_id="arvo:999",
                                miner_hotkey="5Miner",
                                poc_base64=base64.b64encode(b"x").decode(),
                                trace=_good_trace("arvo:999", poc_digest(b"x")))
    with pytest.raises(cp.ProtocolError, match="not in this batch"):
        cp.process_submission(env, d, _backend({"arvo:999"}))


def test_wrong_batch_id_is_refused():
    d = _dispatch()
    env = _envelope(d, "arvo:1", b"x")
    env = cp.SubmissionEnvelope(batch_id="sha256:" + "00" * 32, task_id=env.task_id,
                                miner_hotkey=env.miner_hotkey, poc_base64=env.poc_base64,
                                trace=env.trace)
    with pytest.raises(cp.ProtocolError, match="batch_id"):
        cp.process_submission(env, d, _backend({"arvo:1"}))


def test_poc_digest_mismatch_is_refused():
    d = _dispatch()
    poc = b"real-exploit"
    trace = _good_trace("arvo:1", poc_digest(b"a-different-poc"))   # lies about the digest
    with pytest.raises(cp.ProtocolError, match="does not match the submitted PoC"):
        cp.process_submission(_envelope(d, "arvo:1", poc, trace), d, _backend({"arvo:1"}))


def test_unlicenced_trace_is_refused():
    d = _dispatch()
    poc = b"exploit"
    bad = _good_trace("arvo:1", poc_digest(poc))
    bad["licence"] = ""
    with pytest.raises(cp.ProtocolError, match="malformed"):
        cp.process_submission(_envelope(d, "arvo:1", poc, bad), d, _backend({"arvo:1"}))
