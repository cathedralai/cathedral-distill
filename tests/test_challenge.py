"""Tests for validator-side spot-checking.

The properties that matter: openings must prove against the receipt's committed
root, a faked verdict must be caught when challenged, a declined opening must
fail rather than be ignored, and the challenge must be unpredictable to the miner
but identical across validators.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import challenge as ch  # noqa: E402
from cathedral_distill import eval_receipt as er  # noqa: E402

RECEIPT_ID = "sha256:" + "ab" * 32
BLOCK = "0x" + "cd" * 32


def _commit(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _tree(n=20, truth=None):
    truth = truth or {i: i % 3 != 0 for i in range(n)}
    ids = [f"item-{i:03d}" for i in range(n)]
    commits = [_commit(f"out-{i}") for i in range(n)]
    leaves = [er.item_leaf(ids[i], commits[i], truth[i]) for i in range(n)]
    return ids, commits, truth, leaves


def _open(index, ids, commits, truth, leaves, *, passed=None):
    return ch.OpenedItem(
        index=index,
        item_id=ids[index],
        output_commitment=commits[index],
        passed=truth[index] if passed is None else passed,
        proof=ch.build_proof(leaves, index),
    )


# --------------------------------------------------------------------------- #
# Merkle openings
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 20, 33])
def test_every_leaf_proves_against_the_root(n):
    _, _, _, leaves = _tree(n)
    root = er.items_root(leaves)
    for index in range(n):
        assert ch.verify_proof(ch.build_proof(leaves, index), root)


def test_proof_for_a_different_leaf_fails():
    _, _, _, leaves = _tree(8)
    root = er.items_root(leaves)
    proof = ch.build_proof(leaves, 3)
    forged = ch.MerkleProof(
        index=3, leaf=leaves[4], path=proof.path, left=proof.left
    )
    assert not ch.verify_proof(forged, root)


def test_proof_against_a_different_root_fails():
    _, _, _, leaves = _tree(8)
    other = er.items_root(list(reversed(leaves)))
    assert not ch.verify_proof(ch.build_proof(leaves, 0), other)


def test_index_out_of_range_is_rejected():
    _, _, _, leaves = _tree(4)
    with pytest.raises(ch.ChallengeError, match="out of range"):
        ch.build_proof(leaves, 9)


def test_empty_tree_cannot_be_proven():
    with pytest.raises(ch.ChallengeError, match="empty tree"):
        ch.build_proof([], 0)


# --------------------------------------------------------------------------- #
# Challenge derivation
# --------------------------------------------------------------------------- #

def test_challenge_is_reproducible_across_validators():
    a = ch.derive_challenge_indices(
        receipt_id=RECEIPT_ID, block_hash=BLOCK, item_count=200, k=10)
    b = ch.derive_challenge_indices(
        receipt_id=RECEIPT_ID, block_hash=BLOCK, item_count=200, k=10)
    assert a == b


def test_challenge_moves_with_the_block():
    # The miner commits the receipt before this block exists.
    a = ch.derive_challenge_indices(
        receipt_id=RECEIPT_ID, block_hash=BLOCK, item_count=200, k=10)
    b = ch.derive_challenge_indices(
        receipt_id=RECEIPT_ID, block_hash="0x" + "ef" * 32, item_count=200, k=10)
    assert a != b


def test_two_miners_in_one_block_face_different_challenges():
    a = ch.derive_challenge_indices(
        receipt_id=RECEIPT_ID, block_hash=BLOCK, item_count=200, k=10)
    b = ch.derive_challenge_indices(
        receipt_id="sha256:" + "99" * 32, block_hash=BLOCK, item_count=200, k=10)
    assert a != b


def test_indices_are_distinct_and_in_range():
    picked = ch.derive_challenge_indices(
        receipt_id=RECEIPT_ID, block_hash=BLOCK, item_count=50, k=20)
    assert len(picked) == len(set(picked)) == 20
    assert all(0 <= i < 50 for i in picked)


def test_k_larger_than_the_set_returns_every_item():
    picked = ch.derive_challenge_indices(
        receipt_id=RECEIPT_ID, block_hash=BLOCK, item_count=6, k=99)
    assert set(picked) == set(range(6))


# --------------------------------------------------------------------------- #
# Spot-check
# --------------------------------------------------------------------------- #

def test_honest_receipt_survives():
    ids, commits, truth, leaves = _tree()
    root = er.items_root(leaves)
    indices = [2, 5, 9]
    opened = [_open(i, ids, commits, truth, leaves) for i in indices]
    result = ch.spot_check(
        opened=opened, items_root_value=root, expected_indices=indices,
        regrade=lambda item_id, _c: truth[int(item_id.split("-")[1])])
    assert result.passed and result.reason == "spot_check_passed"


def test_faked_verdict_is_caught_on_regrade():
    # The enclave recorded a pass; the validator re-grades it as a fail.
    ids, commits, truth, leaves = _tree()
    lie = dict(truth); lie[3] = not truth[3]
    leaves_lied = [
        er.item_leaf(ids[i], commits[i], lie[i]) for i in range(len(ids))
    ]
    root = er.items_root(leaves_lied)
    opened = [_open(3, ids, commits, lie, leaves_lied)]
    result = ch.spot_check(
        opened=opened, items_root_value=root, expected_indices=[3],
        regrade=lambda item_id, _c: truth[int(item_id.split("-")[1])])
    assert not result.passed
    assert result.mismatched == (3,)
    assert "regrade_mismatch" in result.reason


def test_declining_to_open_an_item_is_a_failure():
    # Otherwise a miner simply declines whichever item it faked.
    ids, commits, truth, leaves = _tree()
    root = er.items_root(leaves)
    opened = [_open(2, ids, commits, truth, leaves)]
    result = ch.spot_check(
        opened=opened, items_root_value=root, expected_indices=[2, 7],
        regrade=lambda item_id, _c: truth[int(item_id.split("-")[1])])
    assert not result.passed
    assert result.unproven == (7,)


def test_revealed_content_must_hash_to_the_proven_leaf():
    ids, commits, truth, leaves = _tree()
    root = er.items_root(leaves)
    # Claim a different verdict than the leaf actually commits to.
    tampered = _open(4, ids, commits, truth, leaves, passed=not truth[4])
    result = ch.spot_check(
        opened=[tampered], items_root_value=root, expected_indices=[4],
        regrade=lambda item_id, _c: truth[int(item_id.split("-")[1])])
    assert not result.passed
    assert result.unproven == (4,)


def test_opening_an_unchallenged_index_is_an_error():
    ids, commits, truth, leaves = _tree()
    root = er.items_root(leaves)
    with pytest.raises(ch.ChallengeError, match="was not challenged"):
        ch.spot_check(
            opened=[_open(1, ids, commits, truth, leaves)],
            items_root_value=root, expected_indices=[2],
            regrade=lambda *_: True)


# --------------------------------------------------------------------------- #
# Budgeting
# --------------------------------------------------------------------------- #

def test_detection_probability_rises_with_challenge_size():
    p5 = ch.detection_probability(item_count=200, faked=20, challenged=5)
    p10 = ch.detection_probability(item_count=200, faked=20, challenged=10)
    p40 = ch.detection_probability(item_count=200, faked=20, challenged=40)
    assert 0 < p5 < p10 < p40 < 1
    assert p10 > 0.6  # ten of two hundred already catches a 10% fake ~65%


def test_faking_enough_to_move_a_frontier_is_caught_almost_surely():
    # Moving a frontier by 0.05 on a 200-item set means faking ~10 items.
    assert ch.detection_probability(item_count=200, faked=10, challenged=60) > 0.95


def test_no_fakes_means_nothing_to_detect():
    assert ch.detection_probability(item_count=200, faked=0, challenged=10) == 0.0


def test_challenging_more_than_the_honest_remainder_is_certain():
    assert ch.detection_probability(item_count=10, faked=5, challenged=6) == 1.0


def test_leakage_budget_flags_an_exhausted_shard():
    assert ch.leakage_after(challenged_per_epoch=10, epochs=5, shard_size=100) == 0.5
    assert ch.leakage_after(challenged_per_epoch=10, epochs=12, shard_size=100) > 1.0
