"""The CyberGym lane, end to end, hardware-free.

One test walks the whole loop a real epoch takes:

    build a task pool → draw a sealed batch from the private holdout →
    miners submit PoCs → verifier produces differential results →
    score the batch → build a frontier candidate → crown →
    next epoch: new batch, incumbent re-scored on it (paired), challenger judged

Everything else in the CyberGym suite checks one layer; this checks the seams,
and specifically that the paired-evaluation fix integrates with lane scoring —
the champion is never compared to a challenger across different batches.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym as cg  # noqa: E402
from cathedral_distill import cybergym_batch as cb  # noqa: E402
from cathedral_distill import cybergym_verifier as cv  # noqa: E402
from cathedral_distill import frontier as fr  # noqa: E402

BIN = "sha256:" + "ab" * 32
NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
CUTOFF = NOW - timedelta(days=30)  # model committed a month ago


def _pool(n=40):
    # A pool where the recent half is private (disclosed after cutoff) and the
    # old half is public. Levels spread across the ladder.
    levels = [cg.Level.level0, cg.Level.level1, cg.Level.level2, cg.Level.level3]
    tasks = []
    for i in range(n):
        disclosed = (NOW - timedelta(days=90) if i < n // 2
                     else NOW - timedelta(days=5))  # old vs recent
        tasks.append(cb.PooledTask(
            task_id=f"arvo:{1000 + i}", level=levels[i % 4],
            binary_digest=BIN, disclosed_at=disclosed, admitted=True))
    return cb.TaskPool(tasks)


def _backend(solvable: set[str]):
    """A deterministic verifier: tasks in `solvable` crash vul-only (solved);
    every other submission is a generic crash on both (not solved)."""
    def run(task_id: str, poc: bytes, mode: str) -> int:
        if task_id in solvable:
            return 1 if mode == "vul" else 0        # crash vul, clean fix → solved
        return 139                                   # crash both → not the vuln
    return run


def _submit_batch(batch, backend):
    subs = []
    for task in batch.tasks:
        poc = f"poc-for-{task.task_id}".encode()
        result = cv.verify_poc(task, poc, backend)
        subs.append(cg.PoCSubmission(
            task_id=task.task_id, poc_sha256=cv.poc_digest(poc), result=result))
    return subs


def _candidate(miner, score, batch_id, receipt_seed):
    return fr.Candidate(
        miner_hotkey=miner,
        bundle_digest="sha256:" + "9d" * 32,
        checkpoint_digest="sha256:" + (receipt_seed * 2) * 32,
        receipt_id="sha256:" + (receipt_seed * 2) * 32,
        score=score, latency_p50_ms=Decimal("500"), cost_usd=Decimal("2"),
        submitted_at=NOW, batch_id=batch_id, evidence_verified=True,
        attested=True, teacher_permitted=True, reproduced=True,
        contamination_detected=False, registered_bundle=True,
        independent_evaluator=True)


# --------------------------------------------------------------------------- #

def test_batch_is_drawn_only_from_the_private_holdout():
    pool = _pool()
    batch = cb.draw_batch(pool, size=10, nonce="0xnonce-epoch-1",
                          as_of=NOW, cutoff=CUTOFF)
    private_ids = {t.task_id for t in pool.private_holdout(as_of=NOW, cutoff=CUTOFF)}
    assert len(batch.tasks) == 10
    assert set(batch.task_ids) <= private_ids  # never an old, trainable task
    assert cb.verify_batch_commitment(batch)


def test_batch_draw_is_deterministic_and_nonce_bound():
    pool = _pool()
    a = cb.draw_batch(pool, size=8, nonce="0xN", as_of=NOW, cutoff=CUTOFF)
    b = cb.draw_batch(pool, size=8, nonce="0xN", as_of=NOW, cutoff=CUTOFF)
    c = cb.draw_batch(pool, size=8, nonce="0xOTHER", as_of=NOW, cutoff=CUTOFF)
    assert a.batch_id == b.batch_id          # same nonce → same batch
    assert a.batch_id != c.batch_id          # different nonce → different batch


def test_exhausted_holdout_refuses_rather_than_recycles():
    pool = _pool(n=8)  # only 4 private tasks
    try:
        cb.draw_batch(pool, size=10, nonce="0xN", as_of=NOW, cutoff=CUTOFF)
        assert False, "should have refused"
    except cb.BatchError as exc:
        assert "holdout is exhausted" in str(exc)


def test_full_loop_crowns_a_solver():
    pool = _pool()
    batch = cb.draw_batch(pool, size=10, nonce="0xepoch-1", as_of=NOW, cutoff=CUTOFF)
    # This miner solves the first three tasks in the batch.
    solvable = set(batch.task_ids[:3])
    subs = _submit_batch(batch, _backend(solvable))
    score = cg.score_batch(batch.batch_id, list(batch.tasks), subs)

    assert 0 < score.score < 1        # solved some, not all
    assert score.solved_tasks == 3
    assert score.batch_id == batch.batch_id

    frontier = fr.Frontier([fr.TrackPolicy(track="cybergym-v0")])
    decision = frontier.submit(
        "cybergym-v0", _candidate("5Alice", score.score, batch.batch_id, "a"))
    assert decision.crowned
    assert frontier.champion("cybergym-v0").batch_id == batch.batch_id


def test_paired_evaluation_across_two_epochs():
    """The integration proof: a challenger on epoch-2 is judged against the
    incumbent RE-SCORED on epoch-2, never against its stale epoch-1 score."""
    pool = _pool()
    policy = fr.TrackPolicy(track="cybergym-v0", min_margin=Decimal("0.01"))
    frontier = fr.Frontier([policy])

    # Epoch 1: Alice solves 5/10, crowns.
    b1 = cb.draw_batch(pool, size=10, nonce="0xe1", as_of=NOW, cutoff=CUTOFF)
    s1 = cg.score_batch(b1.batch_id, list(b1.tasks),
                        _submit_batch(b1, _backend(set(b1.task_ids[:5]))))
    assert frontier.submit(
        "cybergym-v0", _candidate("5Alice", s1.score, b1.batch_id, "a")).crowned

    # Epoch 2: a new sealed batch. Re-score the incumbent (Alice) on THIS batch —
    # say she only solves 2/10 here — then Bob, who solves 6/10, challenges.
    b2 = cb.draw_batch(pool, size=10, nonce="0xe2", as_of=NOW, cutoff=CUTOFF)
    alice_on_b2 = cg.score_batch(b2.batch_id, list(b2.tasks),
                                 _submit_batch(b2, _backend(set(b2.task_ids[:2]))))
    bob_on_b2 = cg.score_batch(b2.batch_id, list(b2.tasks),
                               _submit_batch(b2, _backend(set(b2.task_ids[:6]))))

    # Without the rescore, the comparison is refused (cross-batch).
    refused = frontier.submit(
        "cybergym-v0", _candidate("5Bob", bob_on_b2.score, b2.batch_id, "b"))
    assert not refused.crowned
    assert refused.reason == "champion_not_scored_on_this_batch"

    # With the rescore, Bob is judged against Alice's fresh epoch-2 number and wins.
    decision = frontier.submit(
        "cybergym-v0", _candidate("5Bob", bob_on_b2.score, b2.batch_id, "b"),
        champion_rescore=fr.ChampionRescore(
            score=alice_on_b2.score, batch_id=b2.batch_id,
            receipt_id="sha256:" + "ce" * 32))
    assert decision.crowned
    assert frontier.champion("cybergym-v0").miner_hotkey == "5Bob"


def test_verifier_maps_timeout_to_clean_not_crash():
    # A hung target must never score as a solve.
    task = cg.Task("arvo:1", cg.Level.level1, BIN)
    result = cv.verify_poc(task, b"x", lambda t, p, m: cv.TIMEOUT_CLEAN_CODE)
    assert not result.solved
    assert result.outcome == "no_crash_on_vulnerable"


def test_verifier_records_both_exit_codes():
    task = cg.Task("arvo:1", cg.Level.level1, BIN)
    result = cv.verify_poc(task, b"x", _backend({"arvo:1"}))
    assert result.vul_exit_code == 1 and result.fix_exit_code == 0
    assert result.solved
    assert "solved" in cv.crash_summary(result)
