"""Roles and reward accounting.

v1 has two miner classes and one validator. There is deliberately **no separate
recipe-maintainer reward** — a training miner owns its complete bundle (teacher
configuration, swarm recipe, dataset pipeline, fine-tuning config, checkpoint) and
is paid for the result. Splitting recipe ownership from execution is a later
market; adding it now would mean component attribution, which means ablation runs,
which multiplies the most expensive stage of the pipeline.

| Role                     | Supplies                            | Rewarded for            |
|--------------------------|-------------------------------------|-------------------------|
| Model Training Miner     | student models from its own recipe  | holding the frontier    |
| Compute Serving Miner    | attested TDX capacity               | verified customer usage |
| Cathedral Validator      | measurement and scoring             | correct verification    |

The same participant may hold both miner roles. That is allowed, and the two
rewards are computed independently, because otherwise the mechanism quietly
becomes self-dealing:

    a participant's hardware must not make their recipe score higher, and
    their recipe's success must not increase their serving reward.

The independence is structural here, not audited afterwards: credits land in
per-role books that no code path reads across.

### Why separation of duties, not only separation of enclaves

Two-enclave separation stops a miner's *training code* from reading the sealed eval
set. It does not stop a miner who *operates the evaluating machine* from **grinding
the score** — running the sealed eval repeatedly and submitting only its best
result. TDX protects the set's confidentiality from the host; it says nothing about
how many times the host chooses to run the container.

Two independent defences, both cheap:

1. **One authorised run per nonce and epoch** — inherited from the receipt design.
   A validator issues a fresh nonce; the receipt binds it with the epoch and block
   window, so a second attempt is not creditable.
2. **An independent evaluator** — the evaluating serving miner's coldkey must
   differ from the training miner's. In Phase 1 Cathedral evaluates in-house, so
   requiring this costs nothing, and it is a far simpler claim to defend than
   arguing about side-channel resistance.

Coldkey, not hotkey: hotkeys are cheap to mint, so a hotkey comparison would
detect nothing.

### Reserved for later

`Role.RECIPE_MAINTAINER` is intentionally absent rather than present-and-unused.
When a separate intelligence market arrives, it enters as a new role plus a third
pool; nothing here needs restructuring to accommodate it, because `RewardPools`
already validates that pools sum to exactly one rather than assuming two.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from typing import Mapping

LEDGER_SCHEMA = "cathedral_role_ledger_v1"


class Role(StrEnum):
    TRAINING_MINER = "training_miner"
    SERVING_MINER = "serving_miner"
    VALIDATOR = "cathedral_validator"


# Public-facing labels. Kept beside the enum so docs and UI cannot drift from it.
ROLE_LABELS: Mapping[Role, str] = {
    Role.TRAINING_MINER: "Model Training Miner",
    Role.SERVING_MINER: "Compute Serving Miner",
    Role.VALIDATOR: "Cathedral Validator",
}

# Roles that receive an emission pool. The validator is paid through the standard
# Bittensor validator take, not from a pool here.
EARNING_ROLES: tuple[Role, ...] = (Role.TRAINING_MINER, Role.SERVING_MINER)


class RoleError(ValueError):
    """Raised on malformed role or ledger input."""


@dataclass(frozen=True)
class Participant:
    """One economic actor, possibly holding several roles.

    Identity is the coldkey. A participant may register a distinct hotkey per role
    — encouraged, since it keeps on-chain accounting legible — but the coldkey is
    what conflict-of-interest checks compare.
    """

    coldkey: str
    hotkeys: Mapping[Role, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.coldkey:
            raise RoleError("coldkey is required")
        for role in self.hotkeys:
            if role not in set(Role):
                raise RoleError(f"unknown role: {role}")

    def holds(self, role: Role) -> bool:
        return role in self.hotkeys

    @property
    def roles(self) -> frozenset[Role]:
        return frozenset(self.hotkeys)


def is_self_evaluation(training_miner: Participant, evaluator: Participant) -> bool:
    """Whether a training miner would be evaluating its own submission.

    Compares coldkeys, because a participant can mint unlimited hotkeys and a
    hotkey comparison would therefore detect nothing.
    """
    return training_miner.coldkey == evaluator.coldkey


def assert_independent_evaluator(
    training_miner: Participant,
    evaluator: Participant,
    *,
    required: bool = True,
) -> None:
    """Enforce separation of duties for one evaluation run.

    `required=False` exists only for the hardware-free path, where there is no
    second operator to hand the work to. Production sets it true.
    """
    if required and is_self_evaluation(training_miner, evaluator):
        raise RoleError(
            "evaluator coldkey matches the training miner being evaluated: "
            "score grinding is possible, refusing the run"
        )


@dataclass(frozen=True)
class RewardPools:
    """How one epoch's emission divides between roles, before any recipient.

    These are pool sizes, not payouts. Splitting a pool among its recipients is
    `Frontier.emission_shares` for training and the existing validated-supply
    accounting for serving.
    """

    training: Decimal
    serving: Decimal
    burn: Decimal = Decimal("0.10")

    def __post_init__(self) -> None:
        for name, value in (
            ("training", self.training),
            ("serving", self.serving),
            ("burn", self.burn),
        ):
            if value < 0:
                raise RoleError(f"{name} pool must be non-negative")
        total = self.training + self.serving + self.burn
        if total != Decimal(1):
            raise RoleError(f"pools must sum to exactly 1, got {total}")

    def pool_for(self, role: Role) -> Decimal:
        if role is Role.TRAINING_MINER:
            return self.training
        if role is Role.SERVING_MINER:
            return self.serving
        raise RoleError(f"{role} has no emission pool")


class RewardLedger:
    """Per-role reward accounting with a structurally enforced independence rule.

    Credits land in per-role books that are never read across, so a participant's
    serving credit cannot influence their training credit or the reverse. No code
    path could couple them — a stronger guarantee than a test asserting they
    happen not to be coupled.
    """

    def __init__(self, pools: RewardPools) -> None:
        self._pools = pools
        self._books: dict[Role, dict[str, Decimal]] = {
            role: {} for role in EARNING_ROLES
        }

    @property
    def pools(self) -> RewardPools:
        return self._pools

    def credit(self, role: Role, coldkey: str, share: Decimal) -> None:
        """Credit a within-pool share (0..1) to one participant for one role."""
        if role not in self._books:
            raise RoleError(f"{role} does not receive pool emissions")
        if not coldkey:
            raise RoleError("coldkey is required")
        if not Decimal(0) <= share <= Decimal(1):
            raise RoleError("share must be within 0..1")
        book = self._books[role]
        book[coldkey] = book.get(coldkey, Decimal(0)) + share

    def credit_training(self, coldkey: str, share: Decimal) -> None:
        """Credit frontier holding. Never reads the serving book."""
        self.credit(Role.TRAINING_MINER, coldkey, share)

    def credit_serving(self, coldkey: str, share: Decimal) -> None:
        """Credit verified customer usage. Never reads the training book."""
        self.credit(Role.SERVING_MINER, coldkey, share)

    def role_share(self, role: Role, coldkey: str) -> Decimal:
        """This participant's share *within* the given role's pool."""
        return self._books.get(role, {}).get(coldkey, Decimal(0))

    def role_total(self, role: Role) -> Decimal:
        return sum(self._books.get(role, {}).values(), Decimal(0))

    def payout(self, coldkey: str) -> dict[str, Decimal]:
        """Emission fractions for one participant, itemised by role.

        A participant holding both roles receives the sum of two independently
        computed amounts — never a bonus for holding both.
        """
        training = self.role_share(Role.TRAINING_MINER, coldkey) * self._pools.training
        serving = self.role_share(Role.SERVING_MINER, coldkey) * self._pools.serving
        return {
            "training": training,
            "serving": serving,
            "total": training + serving,
        }

    def settle(self) -> dict[str, Decimal]:
        """Final emission fractions per destination, including burn.

        Any unallocated remainder of a pool goes to burn rather than being spread
        across whoever happens to be present — the same stance the existing
        mechanism takes for an empty verified set.
        """
        out: dict[str, Decimal] = {}
        for role in EARNING_ROLES:
            pool = self._pools.pool_for(role)
            if self.role_total(role) > Decimal(1):
                raise RoleError(f"{role.value} shares exceed its pool")
            for coldkey, share in self._books[role].items():
                key = f"{role.value}:{coldkey}"
                out[key] = out.get(key, Decimal(0)) + share * pool

        out["burn"] = Decimal(1) - sum(out.values(), Decimal(0))
        return out

    def as_report(self) -> dict[str, object]:
        return {
            "schema": LEDGER_SCHEMA,
            "pools": {
                "training": str(self._pools.training),
                "serving": str(self._pools.serving),
                "burn": str(self._pools.burn),
            },
            "settlement": {k: str(v) for k, v in sorted(self.settle().items())},
        }
