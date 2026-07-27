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

LANE_FEED_SCHEMA = "cathedral_lane_feed_v1"
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
    """Compose lanes into the final per-miner weight vector, with burn.

    Mirrors the router: each lane normalizes its own work units to sum 1, then
    contributes `allocation × normalized` to each miner. A lane with no positive
    work contributes nothing (its allocation is not redistributed to peers; the
    unallocated mass falls to burn, matching the empty-verified-set stance). The
    final weights renormalize to sum 1 including burn.
    """
    if not Decimal(0) <= burn_fraction <= Decimal(1):
        raise LaneFeedError("burn_fraction must be within 0..1")

    combined: dict[str, Decimal] = {}
    lane_records: list[dict[str, object]] = []
    allocated = Decimal(0)

    for lane in sorted(lanes, key=lambda ln: ln.lane):
        total = sum((c.work_units for c in lane.contributions), Decimal(0))
        contributing = lane.allocation > 0 and total > 0
        if contributing:
            for c in lane.contributions:
                if c.work_units <= 0:
                    continue
                share = lane.allocation * (c.work_units / total)
                combined[c.miner_hotkey] = combined.get(c.miner_hotkey, Decimal(0)) + share
            allocated += lane.allocation
        lane_records.append({
            "lane": lane.lane,
            "audit_root": lane.audit_root(),
            "allocation": str(lane.allocation),
            "contributing": contributing,
            "contributions": [
                {"miner_hotkey": c.miner_hotkey, "receipt_id": c.receipt_id,
                 "work_units": str(c.work_units)}
                for c in sorted(lane.contributions, key=lambda c: c.miner_hotkey)
            ],
        })

    # Burn takes its fixed floor; any unallocated lane mass falls to burn too,
    # never to a miner who did not earn it.
    burn = burn_fraction + max(Decimal(1) - burn_fraction - allocated, Decimal(0))
    live = Decimal(1) - burn
    weights: list[dict[str, object]] = []
    combined_total = sum(combined.values(), Decimal(0))
    if combined_total > 0 and live > 0:
        for miner in sorted(combined):
            w = (live * (combined[miner] / combined_total)).quantize(_QUANT)
            weights.append({
                "miner_hotkey": miner,
                "weight": float(w),
                "base_component": 0.0,
                "external_component": float(w),
            })
    else:
        burn = Decimal(1)  # nothing verified anywhere → everything burns

    return {
        "schema": LANE_FEED_SCHEMA,
        "burn_snapshot": {
            "burn_uid": None,
            "burn_hotkey": burn_hotkey,
            "forced_burn_percentage": float(burn * 100),
        },
        "lanes": lane_records,
        "weights": weights,
    }
