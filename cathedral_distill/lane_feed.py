"""Compose verified lane contributions into one signed SN39 feed.

Neither compute nor Distill publishes weights directly. Each verified receipt
yields a **lane contribution**; the existing signed SN39 vector is still the
publication mechanism. This module composes contributions from multiple lanes —
compute and Distill both — into the one vector, exactly as
`scaffold/publisher/mechanism_router.compose` does: each lane has an allocation
(its `weight_fraction`), each lane's per-miner work units are normalized within
the lane, and `combined[miner] = Σ allocation_lane × normalized_lane[miner]`,
with a fixed burn holding the remainder.

The output is the `build_signed_vector` shape the subnet already signs and
publishes, extended with a `lanes` block that records, per lane, the audit root
(the Merkle root over that lane's receipts), the allocation, and the per-miner
contributions — so the final vector is auditable back to the receipts that
produced it.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Mapping, Sequence

# v2: safe composition (#8928a23, issue #1 Req 6) added per-lane
# `burned_allocation` and populated `burn_snapshot.forced_burn_percentage` /
# `policy_metadata.effective_burn_allocation` from the actual composed mass —
# fields v1 either lacked or always emitted as a fixed placeholder. No known
# consumer parses this by exact key set today (unlike the receipt schemas), but
# the shape genuinely changed, so the version says so rather than a `_v1` label
# silently drifting.
LANE_FEED_SCHEMA = "cathedral_lane_feed_v2"
_QUANT = Decimal("0.000000000000000001")  # 18 dp, well inside float weight precision


class LaneFeedError(ValueError):
    """Raised when a feed cannot be composed."""


@dataclass(frozen=True)
class LaneContribution:
    """One verified miner result within a lane."""

    miner_hotkey: str
    receipt_id: str
    work_units: Decimal

    def __post_init__(self) -> None:
        if self.work_units < 0:
            raise LaneFeedError("work_units must be non-negative")


@dataclass(frozen=True)
class Lane:
    """One mechanism's contributions and its allocation of the emission."""

    lane: str
    allocation: Decimal  # the lane's weight_fraction, 0..1
    contributions: Sequence[LaneContribution] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not Decimal(0) <= self.allocation <= Decimal(1):
            raise LaneFeedError("allocation must be within 0..1")
        seen = set()
        for c in self.contributions:
            if c.miner_hotkey in seen:
                raise LaneFeedError(f"duplicate miner in lane {self.lane}: {c.miner_hotkey}")
            seen.add(c.miner_hotkey)

    def audit_root(self) -> str:
        """Merkle-ish root over this lane's receipts. Order-independent."""
        leaves = sorted(
            hashlib.sha256(
                (c.receipt_id + "\x00" + str(c.work_units)).encode()
            ).digest()
            for c in self.contributions
        )
        if not leaves:
            return "sha256:" + hashlib.sha256(b"cathedral-empty-lane-v1").hexdigest()
        acc = hashlib.sha256(b"cathedral-lane-audit-root-v1\x00")
        for leaf in leaves:
            acc.update(leaf)
        return "sha256:" + acc.hexdigest()


def compose_vector(
    lanes: Sequence[Lane],
    *,
    burn_hotkey: str,
    burn_fraction: Decimal = Decimal("0.10"),
) -> dict[str, object]:
    """Compose verified lane contributions into the PRE-burn per-miner allocation.

    This is the composition input the production publisher
    (`scaffold/publisher/weights.py::build_signed_vector`) turns into the signed
    vector and the validator applies burn to; it is NOT a competing signed vector.
    So it emits the shape that contract requires:

      * per-miner rows summing to **1.0 pre-burn**, with `base_component == 0`
        and `weight == external_component` (the validator applies the burn after
        mapping hotkeys to uids — the rows are never pre-burned);
      * `burn_snapshot = {burn_uid: null, burn_hotkey, forced_burn_percentage}`;
      * empty rows (zero supply, 100% burn) when nothing is verified.

    **Safe composition (missing lane -> burn, never another lane).** Each lane's
    `allocation` is its fraction of the *total* emission, and the allocations plus
    the base `burn_fraction` must be a complete allocation of the emission:

        Σ lane.allocation + burn_fraction == 1        (fail-closed if not)

    A lane is *contributing* only if `allocation > 0` and it has positive verified
    work. The share of any missing or invalid lane is added to the burn — it is
    NEVER redistributed to the surviving lanes:

        effective_burn = 1 − Σ(allocation of contributing lanes)
                       = burn_fraction + Σ(allocation of missing/invalid lanes)

    The per-miner rows still normalize to sum 1.0 (the pre-burn grammar); the
    *variable* effective burn is carried in `burn_snapshot.forced_burn_percentage`
    for the validator to apply, so a dropped Distill lane increases burn rather
    than inflating Compute's earners (and vice-versa). This makes the final vector
    deterministic: the same verified receipts and the same signed allocation
    always produce the same weights and the same burn.

    The `lanes` block records each contribution and its audit root for the
    publisher to bind; the publisher owns the signature and the full policy
    metadata.
    """
    if not Decimal(0) <= burn_fraction <= Decimal(1):
        raise LaneFeedError("burn_fraction must be within 0..1")

    # Completeness: the signed allocation + burn config must allocate the whole
    # emission. A gap or an overflow is an incoherent config -> fail closed.
    configured = sum((lane.allocation for lane in lanes), Decimal(0))
    if configured + burn_fraction != Decimal(1):
        raise LaneFeedError(
            "lane allocations plus burn_fraction must sum to exactly 1 "
            f"(got Σallocation={configured} + burn={burn_fraction})"
        )
    if len({lane.lane for lane in lanes}) != len(list(lanes)):
        raise LaneFeedError("duplicate lane id in the feed")

    combined: dict[str, Decimal] = {}
    lane_records: list[dict[str, object]] = []
    contributing_allocation = Decimal(0)

    for lane in sorted(lanes, key=lambda ln: ln.lane):
        total = sum((c.work_units for c in lane.contributions), Decimal(0))
        contributing = lane.allocation > 0 and total > 0
        if contributing:
            contributing_allocation += lane.allocation
            for c in lane.contributions:
                if c.work_units <= 0:
                    continue
                share = lane.allocation * (c.work_units / total)
                combined[c.miner_hotkey] = combined.get(c.miner_hotkey, Decimal(0)) + share
        lane_records.append({
            "lane": lane.lane,
            "audit_root": lane.audit_root(),
            "allocation": str(lane.allocation),
            "contributing": contributing,
            # The allocation this lane forfeited to burn because it was missing or
            # produced no verified work. 0 when the lane contributed.
            "burned_allocation": "0" if contributing else str(lane.allocation),
            "contributions": [
                {"miner_hotkey": c.miner_hotkey, "receipt_id": c.receipt_id,
                 "work_units": str(c.work_units)}
                for c in sorted(lane.contributions, key=lambda c: c.miner_hotkey)
            ],
        })

    # The share of every non-contributing lane rolls into burn; surviving lanes
    # keep exactly their configured allocation.
    effective_burn = Decimal(1) - contributing_allocation

    # PRE-burn rows: normalize the composed mass to sum exactly 1.0. The (variable)
    # burn is a snapshot the validator applies downstream, never subtracted here.
    weights: list[dict[str, object]] = []
    combined_total = sum(combined.values(), Decimal(0))
    if combined_total > 0:
        for miner in sorted(combined):
            w = (combined[miner] / combined_total).quantize(_QUANT)
            weights.append({
                "miner_hotkey": miner,
                "weight": float(w),
                "base_component": 0.0,
                "external_component": float(w),
            })

    return {
        "schema": LANE_FEED_SCHEMA,
        "pre_burn": True,
        "burn_snapshot": {
            "burn_uid": None,
            "burn_hotkey": burn_hotkey,
            "forced_burn_percentage": float(effective_burn * 100),
        },
        "policy_metadata": {
            "composer": "cathedral_distill.lane_feed",
            "pre_burn_supply": "1.0" if weights else "0",
            "base_burn_allocation": str(burn_fraction),
            "effective_burn_allocation": str(effective_burn),
            "signed_by_publisher": False,  # build_signed_vector applies the signature
        },
        "lanes": lane_records,
        "weights": weights,
    }
