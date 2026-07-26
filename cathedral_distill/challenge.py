"""Validator-side spot-checking of an evaluation receipt.

A Bittensor validator cannot re-run a 200-item evaluation every epoch. It has no
GPU budget, it must not hold the sealed set (validators are numerous and the set
would leak), and it cannot take the miner's word. So verification has to be
*cheaper than production* — the same asymmetry that makes SAT work, where solving
is hard and checking an assignment is trivial.

The asymmetry here is a Merkle spot-check. The receipt already commits to
`items_root` over every graded item. A validator demands the opening of a few
items, re-grades exactly those with the pinned grader, and accepts or rejects the
whole receipt on that evidence.

Cheating on `m` of `n` items survives a `k`-item challenge with probability
`((n-m)/n)^k`. Ten items challenged out of two hundred catches a miner who faked
twenty with probability ~65%; faking enough to move a frontier is caught almost
surely. `detection_probability` below makes that budgetable rather than vibes.

### Why the challenge seed must come from the chain

If a miner can predict which items will be opened, it grades those honestly and
lies about the rest, and the spot-check proves nothing. So the indices derive
from a block hash that did not exist when the receipt was committed. The receipt
is the commit; the later block is the reveal. A miner choosing what to fake must
do so before knowing what will be checked.

`receipt_id` is mixed in too, so two miners in the same block face different
challenges and cannot pool their luck.

### The leakage budget

Every opened item is burned — the miner now knows one held-out item and its
verdict. That is the price of cheap verification, and it is why
`sealed_set.rotate_holdout` exists. Keep

    challenged_per_epoch × epochs_per_rotation  <  shard_size

or the set is exhausted faster than it is replaced. `leakage_after` computes it.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence

from cathedral_distill.eval_receipt import (
    EvalReceiptError,
    ITEM_NODE_DOMAIN,
    item_leaf,
    items_root,
)

CHALLENGE_DOMAIN = b"cathedral-ml-eval-challenge-v1\x00"


class ChallengeError(EvalReceiptError):
    """Raised when a spot-check cannot be constructed or fails."""


@dataclass(frozen=True)
class MerkleProof:
    """An opening for one graded item.

    `path` is bottom-up. `left` records, per step, whether the sibling sits on
    the left — a promoted odd node has no sibling at that level and is omitted
    from the path entirely, matching how `items_root` builds the tree.
    """

    index: int
    leaf: bytes
    path: tuple[bytes, ...]
    left: tuple[bool, ...]

    def __post_init__(self) -> None:
        if len(self.path) != len(self.left):
            raise ChallengeError("proof path and orientation lengths disagree")


def derive_challenge_indices(
    *, receipt_id: str, block_hash: str, item_count: int, k: int
) -> tuple[int, ...]:
    """Pick `k` distinct item indices, unpredictably but reproducibly.

    Every validator that sees the same receipt and the same block derives the
    same challenge, so no coordination is needed and no validator can steer the
    selection toward or away from a miner.
    """
    if item_count <= 0:
        raise ChallengeError("item_count must be positive")
    if k <= 0:
        raise ChallengeError("k must be positive")
    if not receipt_id or not block_hash:
        raise ChallengeError("receipt_id and block_hash are required")

    wanted = min(k, item_count)
    chosen: list[int] = []
    seen: set[int] = set()
    counter = 0
    # Rejection sampling on a counter-extended hash: uniform, and deterministic
    # for any (receipt, block) pair.
    while len(chosen) < wanted:
        digest = hashlib.sha256(
            CHALLENGE_DOMAIN
            + receipt_id.encode()
            + b"\x00"
            + block_hash.encode()
            + b"\x00"
            + counter.to_bytes(4, "big")
        ).digest()
        counter += 1
        for offset in range(0, 32, 4):
            if len(chosen) >= wanted:
                break
            index = int.from_bytes(digest[offset : offset + 4], "big") % item_count
            if index not in seen:
                seen.add(index)
                chosen.append(index)
        if counter > 4096:  # pragma: no cover - unreachable for sane item_count
            raise ChallengeError("challenge derivation failed to converge")
    return tuple(sorted(chosen))


def build_proof(leaves: Sequence[bytes], index: int) -> MerkleProof:
    """Construct the opening for one leaf, mirroring `items_root`'s tree."""
    if not leaves:
        raise ChallengeError("cannot prove an empty tree")
    if not 0 <= index < len(leaves):
        raise ChallengeError("index out of range")

    path: list[bytes] = []
    left: list[bool] = []
    level = list(leaves)
    cursor = index

    while len(level) > 1:
        pairs = len(level) - (len(level) % 2)
        if cursor < pairs:
            if cursor % 2 == 0:
                path.append(level[cursor + 1])
                left.append(False)
            else:
                path.append(level[cursor - 1])
                left.append(True)
        # else: this node is the promoted odd one — it has no sibling here, so
        # nothing is appended and it simply rises a level.
        nxt: list[bytes] = [
            hashlib.sha256(ITEM_NODE_DOMAIN + level[i] + level[i + 1]).digest()
            for i in range(0, pairs, 2)
        ]
        if len(level) % 2:
            nxt.append(level[-1])
        cursor //= 2
        level = nxt

    return MerkleProof(
        index=index, leaf=leaves[index], path=tuple(path), left=tuple(left)
    )


def verify_proof(proof: MerkleProof, root: str) -> bool:
    """Recompute the root from one opening."""
    node = proof.leaf
    for sibling, sibling_on_left in zip(proof.path, proof.left):
        node = hashlib.sha256(
            ITEM_NODE_DOMAIN + (sibling + node if sibling_on_left else node + sibling)
        ).digest()
    return ("sha256:" + node.hex()) == root


@dataclass(frozen=True)
class OpenedItem:
    """What a miner reveals for one challenged index."""

    index: int
    item_id: str
    output_commitment: str
    passed: bool
    proof: MerkleProof


@dataclass(frozen=True)
class SpotCheckResult:
    checked: int
    mismatched: tuple[int, ...]
    unproven: tuple[int, ...]

    @property
    def passed(self) -> bool:
        return not self.mismatched and not self.unproven

    @property
    def reason(self) -> str:
        if self.passed:
            return "spot_check_passed"
        if self.unproven:
            return f"merkle_opening_failed:{','.join(map(str, self.unproven))}"
        return f"regrade_mismatch:{','.join(map(str, self.mismatched))}"


def spot_check(
    *,
    opened: Sequence[OpenedItem],
    items_root_value: str,
    expected_indices: Sequence[int],
    regrade,
) -> SpotCheckResult:
    """Verify openings and re-grade them locally.

    `regrade(item_id, output_commitment) -> bool` is the validator's own verdict,
    produced by the grader digest pinned in the receipt. A receipt survives only
    if every opening proves against `items_root` *and* the validator's verdict
    matches the one the enclave recorded.

    Missing an index is a failure, not an omission: a miner that could decline to
    open an item would simply decline whichever it faked.
    """
    provided = {item.index for item in opened}
    missing = tuple(sorted(set(expected_indices) - provided))

    unproven: list[int] = list(missing)
    mismatched: list[int] = []

    for item in opened:
        if item.index not in set(expected_indices):
            raise ChallengeError(f"index {item.index} was not challenged")
        expected_leaf = item_leaf(item.item_id, item.output_commitment, item.passed)
        if item.proof.leaf != expected_leaf:
            # The revealed content does not hash to the leaf being proven.
            unproven.append(item.index)
            continue
        if not verify_proof(item.proof, items_root_value):
            unproven.append(item.index)
            continue
        if regrade(item.item_id, item.output_commitment) != item.passed:
            mismatched.append(item.index)

    return SpotCheckResult(
        checked=len(opened),
        mismatched=tuple(sorted(mismatched)),
        unproven=tuple(sorted(set(unproven))),
    )


def detection_probability(*, item_count: int, faked: int, challenged: int) -> float:
    """Probability a `challenged`-item spot-check catches `faked` bad items.

    Sampling is without replacement, so this is hypergeometric rather than the
    binomial approximation — which matters when `challenged` is a large fraction
    of `item_count`, exactly the regime a small track runs in.
    """
    if item_count <= 0 or faked < 0 or challenged < 0:
        raise ChallengeError("invalid detection parameters")
    if faked == 0:
        return 0.0
    honest = item_count - faked
    if challenged > item_count:
        challenged = item_count
    if challenged > honest:
        return 1.0
    # P(miss) = C(honest, k) / C(n, k), computed as a running product to avoid
    # large factorials.
    miss = 1.0
    for step in range(challenged):
        miss *= (honest - step) / (item_count - step)
    return 1.0 - miss


def leakage_after(*, challenged_per_epoch: int, epochs: int, shard_size: int) -> float:
    """Fraction of a shard revealed after `epochs` of spot-checking.

    Above 1.0 the shard is exhausted — every item has been shown to someone — and
    rotation is overdue.
    """
    if shard_size <= 0:
        raise ChallengeError("shard_size must be positive")
    return (challenged_per_epoch * epochs) / shard_size
