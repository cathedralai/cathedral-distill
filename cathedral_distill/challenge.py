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
    digest_bytes,
    item_leaf,
    items_root,
)

CHALLENGE_DOMAIN = b"cathedral-ml-eval-challenge-v1\x00"


class ChallengeError(EvalReceiptError):
    """Raised when a spot-check cannot be constructed or fails."""


@dataclass(frozen=True)
class MerkleProof:
    """An opening for one graded item at a fixed position.

    `path` is bottom-up sibling hashes. Orientation is NOT carried here: a
    prover-supplied direction flag would let an opening be re-oriented to verify
    at a position it was not built for. Instead `verify_proof` derives the
    orientation deterministically from `index` and the tree's `leaf_count`, so a
    proof only ever verifies at the one position it belongs to.
    """

    index: int
    leaf: bytes
    path: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int) or self.index < 0:
            raise ChallengeError("proof index must be a non-negative integer")


def _orientation(index: int, leaf_count: int) -> list[bool]:
    """Derive, per path level, whether the sibling sits on the left.

    Recomputed from position alone, mirroring `items_root`'s tree exactly: a
    promoted odd node contributes no path element at its level. This is the only
    source of orientation — the prover cannot influence it.
    """
    if not 0 <= index < leaf_count:
        raise ChallengeError("index out of range for leaf_count")
    orient: list[bool] = []
    level_size = leaf_count
    cursor = index
    while level_size > 1:
        pairs = level_size - (level_size % 2)
        if cursor < pairs:
            orient.append(cursor % 2 == 1)  # odd cursor -> sibling is on the left
        # else: promoted odd node, no sibling at this level
        cursor //= 2
        level_size = pairs // 2 + (level_size % 2)
    return orient


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
    """Construct the opening for one leaf, mirroring `items_root`'s tree.

    Only the sibling hashes are recorded; orientation is not, because a verifier
    re-derives it from the position (`_orientation`).
    """
    if not leaves:
        raise ChallengeError("cannot prove an empty tree")
    if not 0 <= index < len(leaves):
        raise ChallengeError("index out of range")

    path: list[bytes] = []
    level = list(leaves)
    cursor = index

    while len(level) > 1:
        pairs = len(level) - (len(level) % 2)
        if cursor < pairs:
            sibling = cursor + 1 if cursor % 2 == 0 else cursor - 1
            path.append(level[sibling])
        # else: this node is the promoted odd one — no sibling at this level.
        nxt: list[bytes] = [
            hashlib.sha256(ITEM_NODE_DOMAIN + level[i] + level[i + 1]).digest()
            for i in range(0, pairs, 2)
        ]
        if len(level) % 2:
            nxt.append(level[-1])
        cursor //= 2
        level = nxt

    return MerkleProof(index=index, leaf=leaves[index], path=tuple(path))


def verify_proof(proof: MerkleProof, root: str, *, leaf_count: int) -> bool:
    """Recompute the root from one opening, orientation derived from position.

    `leaf_count` is the number of graded items (the receipt's `item_count`). A
    proof only verifies at the single position `proof.index`: the orientation is
    derived from that index, so a valid opening for one position cannot be
    replayed at another.
    """
    if not 0 <= proof.index < leaf_count:
        return False
    try:
        orientation = _orientation(proof.index, leaf_count)
    except ChallengeError:
        return False
    if len(orientation) != len(proof.path):
        return False
    node = proof.leaf
    for sibling, sibling_on_left in zip(proof.path, orientation):
        node = hashlib.sha256(
            ITEM_NODE_DOMAIN + (sibling + node if sibling_on_left else node + sibling)
        ).digest()
    return ("sha256:" + node.hex()) == root


@dataclass(frozen=True)
class OpenedItem:
    """What a miner reveals for one challenged index.

    The reveal carries the actual model `output` (through the approved bounded
    channel), not only its commitment: the validator recomputes the commitment
    from those bytes AND runs the pinned grader over them, so the spot-check is an
    *independent regrade*, not merely a check that a committed verdict was
    position-bound. `output_commitment` remains for the leaf binding.

    The opening index and the proof index must agree; `spot_check` additionally
    requires both to equal a challenged index. A mismatch is not an accident to
    tolerate — it is exactly the relabelling an attacker would attempt.
    """

    index: int
    item_id: str
    output: str
    output_commitment: str
    passed: bool
    proof: MerkleProof

    def __post_init__(self) -> None:
        if self.proof.index != self.index:
            raise ChallengeError("opening index does not match its proof index")


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
    item_count: int,
    expected_indices: Sequence[int],
    regrade,
) -> SpotCheckResult:
    """Verify openings at their challenged positions and re-grade them locally.

    `item_count` is the receipt's graded-item count (the tree's leaf count), used
    to derive each proof's orientation from its position. `regrade(item_id, output)
    -> bool` is the validator's own verdict, produced by executing the grader
    digest pinned in the receipt against the REVEALED output bytes. A receipt
    survives only if every challenged index is opened, each opening's leaf binds
    that exact position and proves against `items_root`, the revealed output
    hashes to the committed digest, *and* the validator's independent regrade of
    those bytes matches the verdict the enclave recorded.

    Missing an index is a failure, not an omission: a miner that could decline to
    open an item would simply decline whichever it faked. An opening for an index
    that was not challenged is a protocol violation, not tolerated slack.
    """
    challenged = set(expected_indices)
    provided = {item.index for item in opened}
    missing = tuple(sorted(challenged - provided))

    unproven: list[int] = list(missing)
    mismatched: list[int] = []
    seen: set[int] = set()

    for item in opened:
        if item.index not in challenged:
            raise ChallengeError(f"index {item.index} was not challenged")
        if item.index in seen:
            raise ChallengeError(f"index {item.index} was opened more than once")
        seen.add(item.index)
        # The leaf must bind THIS position: item_leaf includes the index, so a
        # leaf built for another position cannot answer this challenge.
        expected_leaf = item_leaf(
            item.index, item.item_id, item.output_commitment, item.passed
        )
        if item.proof.leaf != expected_leaf:
            unproven.append(item.index)
            continue
        if not verify_proof(item.proof, items_root_value, leaf_count=item_count):
            unproven.append(item.index)
            continue
        # The revealed output must hash to the committed digest the leaf binds —
        # otherwise the miner revealed bytes it never committed to.
        if digest_bytes(item.output.encode("utf-8")) != item.output_commitment:
            unproven.append(item.index)
            continue
        # Independent regrade: run the pinned grader over the REAL output bytes,
        # not the commitment, and require it to match the recorded verdict.
        if regrade(item.item_id, item.output) != item.passed:
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
