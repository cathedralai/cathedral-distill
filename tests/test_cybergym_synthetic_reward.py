"""A solved synthetic task must contribute zero reward units.

The synthetic generator is the un-cheatable-holdout story, but the artifact it
delivers renders its own answer: `render_source` prints the 4-byte magic guard and
the exact `char buf[N]` size in plaintext, and the artifact route serves that
source for every level including level 0, which is supposed to be blind discovery.
`test_a_no_model_extractor_still_solves_every_level_0_task` measures exactly that,
and it is deliberately written to PASS while the oracle is open: 8/8 level-0 tasks
fall to two regexes and no model at all.

So the oracle is not closed here. What is closed is the payment: synthetic-source
tasks are non-rewarding on the emission path by default, and every test below
pins that a solved synthetic task persists no score and composes no contribution.
`credit_synthetic_tasks=True` is the documented, unsafe-for-rewards override.

If the artifact is ever changed to stop revealing the magic and buffer size, the
extractor test starts failing, which is the signal that this default can be
revisited.
"""
from __future__ import annotations

import hashlib
import re
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym_validator as cv  # noqa: E402
from cathedral_distill.cybergym import Level  # noqa: E402
from cathedral_distill.cybergym_batch import PooledTask, TaskPool  # noqa: E402
from cathedral_distill.cybergym_scores import (  # noqa: E402
    EPOCH_CLOSED,
    CyberGymScoreStore,
)
from cathedral_distill.cybergym_service import compose_scores_lane  # noqa: E402
from cathedral_distill.cybergym_synthetic import (  # noqa: E402
    CRASH_EXIT,
    SyntheticTaskSource,
    execute,
    generate_bug,
    is_synthetic_task,
)

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
CUTOFF = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
ISSUED = "2026-07-27T12:00:00.000000Z"
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
SOURCE_EPOCH = 11
NONCE = "cgnonce-sha256:" + "ab" * 32
MINER = "5Miner"


def _dg(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


COMMITMENT = _dg("ckpt")


def _chain():
    return cv.ChainContext(block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
                           source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460)


def _no_model_extractor(source: str) -> bytes:
    """Two regexes, no model, no search: the artifact answers its own question."""
    magic = bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-f]{2})", source))
    buffer_size = int(re.search(r"char buf\[(\d+)\]", source).group(1))
    length = buffer_size + 1  # > buf beats missing_bounds_check, >= buf beats off_by_one
    return magic + length.to_bytes(2, "big") + b"A" * length


# --------------------------------------------------------------------------- #
# The oracle, measured honestly
# --------------------------------------------------------------------------- #

def test_a_no_model_extractor_still_solves_every_level_0_task():
    """Recorded as a fact, not a wish: while this passes, synthetic stays unpaid."""
    source = SyntheticTaskSource(levels=(0,))
    batch = source.draw(size=8, nonce=NONCE)
    solved = 0
    for index, task in enumerate(batch.tasks):
        poc = _no_model_extractor(source.artifact(task.task_id))
        bug = generate_bug(NONCE, index, level=0)
        differential = (
            execute(bug, poc, patched=False) == CRASH_EXIT
            and execute(bug, poc, patched=True) != CRASH_EXIT
        )
        solved += int(differential)
    assert solved == 8, "the artifact no longer reveals its answer; revisit the reward default"


def test_synthetic_task_ids_are_identifiable():
    assert is_synthetic_task("synthvuln:abababab:0")
    assert not is_synthetic_task("arvo:1")
    assert not is_synthetic_task("oss-fuzz:12345")
    assert not is_synthetic_task(None)


# --------------------------------------------------------------------------- #
# And therefore: solved, graded, unpaid
# --------------------------------------------------------------------------- #

def _run_synthetic_epoch(tmp_path, *, credit: bool, name="scores.sqlite"):
    source = SyntheticTaskSource(levels=(0,))
    # draw the batch once to learn the ids, then solve every one of them
    nonce = cv.derive_batch_nonce(
        block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
        source_epoch=SOURCE_EPOCH, miner_hotkey=MINER, model_commitment=COMMITMENT,
    )
    batch = source.draw(size=4, nonce=nonce)
    pocs = {
        task.task_id: _no_model_extractor(source.artifact(task.task_id))
        for task in batch.tasks
    }
    store = CyberGymScoreStore(str(tmp_path / name))
    results = cv.run_epoch(
        [cv.MinerCommit(miner_hotkey=MINER, model_commitment=COMMITMENT, pocs=pocs)],
        source, _chain(), validator_hotkey="5Validator", private_key=KEY,
        signing_key_id="cybergym-1", backend=source.backend, score_store=store,
        cutoff=CUTOFF, as_of=NOW, issued_at=ISSUED, batch_size=4,
        gates_required=False, credit_synthetic_tasks=credit,
    )
    return store, results


def test_solved_synthetic_tasks_earn_zero_by_default(tmp_path):
    store, results = _run_synthetic_epoch(tmp_path, credit=False)
    result = results[0]
    # the receipt itself says zero: nothing is hidden downstream of it
    assert result.contribution["work_units"] == "0"
    assert result.receipt["score"]["solved_tasks"] == 0
    assert result.receipt["score"]["earned_units"] == "0"
    # nothing rewardable is persisted, so nothing composes and the share burns
    assert store.epoch_scores(SOURCE_EPOCH) == {MINER: Decimal("0")}
    # composing requires an explicit statement that the epoch closed (the service
    # does this in score_epoch; this test scores through run_epoch directly)
    store.mark_epoch(SOURCE_EPOCH, state=EPOCH_CLOSED, detail="scored in this test")
    lane = compose_scores_lane(store, SOURCE_EPOCH, allocation=Decimal("0.90"))
    assert list(lane.contributions) == []


def test_the_same_solves_earn_only_under_the_explicit_override(tmp_path):
    store, results = _run_synthetic_epoch(tmp_path, credit=True, name="override.sqlite")
    assert Decimal(results[0].contribution["work_units"]) > 0
    assert store.epoch_scores(SOURCE_EPOCH)[MINER] > 0
    # composing requires an explicit statement that the epoch closed (the service
    # does this in score_epoch; this test scores through run_epoch directly)
    store.mark_epoch(SOURCE_EPOCH, state=EPOCH_CLOSED, detail="scored in this test")
    lane = compose_scores_lane(store, SOURCE_EPOCH, allocation=Decimal("0.90"))
    assert [c.miner_hotkey for c in lane.contributions] == [MINER]


def test_a_real_corpus_task_still_earns_in_the_same_epoch(tmp_path):
    """The default must not be "CyberGym pays nothing": a real ARVO task in a mixed
    batch still earns while the synthetic ones beside it do not."""
    pool = TaskPool([
        PooledTask(task_id="arvo:1", level=Level(0), binary_digest=_dg("b1"), disclosed_at=NOW),
        PooledTask(task_id="arvo:2", level=Level(2), binary_digest=_dg("b2"), disclosed_at=NOW),
    ])
    store = CyberGymScoreStore(str(tmp_path / "mixed.sqlite"))
    results = cv.run_epoch(
        [cv.MinerCommit(miner_hotkey=MINER, model_commitment=COMMITMENT,
                        pocs={"arvo:1": b"poc-1", "synthvuln:deadbeef:0": b"poc-2"})],
        pool, _chain(), validator_hotkey="5Validator", private_key=KEY,
        signing_key_id="cybergym-1",
        backend=lambda task_id, poc, mode: 1 if mode == "vul" else 0,
        score_store=store, cutoff=CUTOFF, as_of=NOW, issued_at=ISSUED, batch_size=2,
        gates_required=False,
    )
    assert Decimal(results[0].contribution["work_units"]) > 0
    assert store.epoch_scores(SOURCE_EPOCH)[MINER] > 0
