"""Which runs in a round get the weaker model — decided in advance, provable afterwards.

`cybergym_agent_screening.ablation_verdict` compares a harness's solve rate with a capable
model against its rate with a degraded one; a harness replaying stored answers scores the same
either way. That test only works if the harness cannot tell which runs are ablated, and it is
only usable for consensus if every validator can re-derive the same assignment. Those two
requirements pull in opposite directions, and this module is the seam that satisfies both.

**Why the batch nonce cannot be reused here.** The task draw is derived from finalized chain
state precisely so anyone can reproduce it (`derive_epoch_batch_nonce`). Deriving the ablation
assignment the same way would publish it: a harness that computes which of its tasks are
ablated simply fails those on purpose, its rate drops on the ablated arm, and it passes the
check while learning nothing about whether it can reason. A test the subject can read is not a
test.

**Why a screener-held secret alone is not enough either.** If the screener picks the assignment
and announces it after the fact, nothing stops it choosing the split *after* seeing the
results — labelling whichever runs it likes as "ablated" to make a miner look honest or look
like a cheat. The assignment would be an assertion, not evidence.

So: **commit, then reveal.** The screener draws a secret, publishes
:func:`ablation_commitment` before the round, and runs it. Afterwards the secret is revealed,
every validator re-derives the assignment with :func:`assign_ablation` and checks it against
the commitment. During the round the assignment is unguessable; after it, it is a fact nobody
can retrofit.

**Ablated runs never pay.** A task graded under a deliberately weakened model is not a fair
measure of the harness, so crediting it would penalise honest miners for our test. Ablated
runs are evidence about *provenance* only; :func:`payable_tasks` is the split, and keeping it
here means a caller cannot forget it.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from decimal import Decimal
from typing import Sequence

_DOMAIN_COMMIT = b"cathedral-cybergym-ablation-commit-v1\x00"
_DOMAIN_ASSIGN = b"cathedral-cybergym-ablation-assign-v1\x00"

#: Share of a round's tasks run against the degraded model. ~30% of a 30-40 task round is
#: 9-12 ablated runs, so both arms clear `screening.MIN_ARM_OBSERVATIONS` within about two
#: rounds — the screening accumulates across rounds and no single round has to carry it.
ABLATION_FRACTION = Decimal("0.3")

MIN_SECRET_BYTES = 16


class AblationError(ValueError):
    """The ablation assignment is malformed or does not match its commitment. Fails closed."""


@dataclass(frozen=True)
class AblationPlan:
    """One round's split: which tasks were degraded, and which may be paid."""

    ablated: tuple[str, ...]
    payable: tuple[str, ...]
    commitment: str

    def __post_init__(self) -> None:
        if set(self.ablated) & set(self.payable):
            raise AblationError("a task cannot be both ablated and payable")


def ablation_commitment(secret: bytes) -> str:
    """The value published BEFORE the round, binding the screener to one assignment.

    Domain-separated from the assignment derivation so publishing the commitment reveals
    nothing about the split it commits to.
    """
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < MIN_SECRET_BYTES:
        raise AblationError(
            f"the ablation secret must be at least {MIN_SECRET_BYTES} random bytes; a "
            "guessable secret is a published assignment"
        )
    return "sha256:" + hashlib.sha256(_DOMAIN_COMMIT + bytes(secret)).hexdigest()


def assign_ablation(
    task_ids: Sequence[str], *, secret: bytes, fraction: Decimal = ABLATION_FRACTION,
) -> AblationPlan:
    """Split a round's tasks into ablated and payable, deterministically under the secret.

    Tasks are ranked by ``HMAC(secret, task_id)`` and the lowest-ranking share is ablated —
    the same ranked-selection shape the batch draw uses, so the split is uniform and carries
    no bias toward any particular task. Ties break on the task id, so the result does not
    depend on input order and two validators cannot disagree.
    """
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < MIN_SECRET_BYTES:
        raise AblationError(f"the ablation secret must be at least {MIN_SECRET_BYTES} bytes")
    if not (Decimal(0) <= fraction < Decimal(1)):
        raise AblationError("fraction must be in [0, 1)")
    ids = list(task_ids)
    if len(set(ids)) != len(ids):
        raise AblationError("task ids repeat; the split would be ambiguous")
    if not ids:
        return AblationPlan((), (), ablation_commitment(secret))

    ranked = sorted(
        ids,
        key=lambda t: (hmac.new(bytes(secret), _DOMAIN_ASSIGN + t.encode(), hashlib.sha256).digest(), t),
    )
    count = int(Decimal(len(ids)) * fraction)
    ablated = sorted(ranked[:count])
    payable = sorted(ranked[count:])
    return AblationPlan(tuple(ablated), tuple(payable), ablation_commitment(secret))


def verify_ablation(
    task_ids: Sequence[str], claimed: AblationPlan, *, secret: bytes,
    fraction: Decimal = ABLATION_FRACTION,
) -> None:
    """Check a revealed assignment against its commitment. Raises when it does not hold.

    Two things are checked and both matter: that the revealed secret really is the one
    committed to before the round, and that the claimed split is what that secret actually
    produces. Checking only the first would let a screener reveal an honest secret and
    report a different split alongside it.
    """
    if ablation_commitment(secret) != claimed.commitment:
        raise AblationError(
            "the revealed secret does not match the published commitment: the assignment "
            "could have been chosen after the results were known"
        )
    expected = assign_ablation(task_ids, secret=secret, fraction=fraction)
    if expected.ablated != tuple(claimed.ablated) or expected.payable != tuple(claimed.payable):
        raise AblationError(
            "the claimed split is not what the revealed secret produces: "
            f"expected {len(expected.ablated)} ablated, got {len(claimed.ablated)}"
        )


def payable_tasks(plan: AblationPlan) -> tuple[str, ...]:
    """The tasks a round may actually credit.

    Ablated runs are excluded, and that is a fairness rule rather than an accounting detail:
    a task graded under a deliberately weakened model is not a fair measure of the harness,
    so paying on it would charge honest miners for our own test.
    """
    return plan.payable
