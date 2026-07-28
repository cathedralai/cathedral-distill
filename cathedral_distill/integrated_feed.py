"""One configurable pipeline: verified Compute + Distill receipts -> one vector.

This is the seam issue cathedral-validator#1 asks for. The validator verifies
every lane's receipt through the *same* discipline, applies a Cathedral-signed
burn and allocation config, composes one deterministic pre-burn vector with the
missing-lane-to-burn rule, and emits an audit trail that ties each step together:

    receipt -> verification decision -> lane contribution -> configured allocation
            -> final weight

`verify_lane_receipt` is the single verification entry for all four receipt kinds
(Compute CPU, Compute GPU, Distill, CyberGym); each returns a `ReceiptDecision`
with a `PASS` / `FAIL` / `NOT_PROVEN` verdict. `compose_integrated` takes a
`ResolvedAllocation` (from `signed_config.resolve_allocation`) and the decisions,
and returns the composed feed plus the audit trail. A lane the config expects but
that produced no `PASS` contribution is composed as empty, so its share goes to
burn — never to another lane.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Callable, Mapping, Sequence

from cathedral_distill import compute_receipt as _compute
from cathedral_distill import cybergym_receipt as _cybergym
from cathedral_distill import distill_receipt as _distill
from cathedral_distill import lane_feed as _lane_feed
from cathedral_distill.signed_config import ResolvedAllocation

AUDIT_SCHEMA = "cathedral_integration_audit_v1"

# Verdicts.
PASS = "PASS"
FAIL = "FAIL"
NOT_PROVEN = "NOT_PROVEN"

# Receipt kinds -> the lane each contributes to is caller-supplied, but the kind
# selects the verifier.
KIND_COMPUTE_CPU = "compute_cpu"
KIND_COMPUTE_GPU = "compute_gpu"
KIND_DISTILL = "distill"
KIND_CYBERGYM = "cybergym"
_KINDS = frozenset({KIND_COMPUTE_CPU, KIND_COMPUTE_GPU, KIND_DISTILL, KIND_CYBERGYM})


class IntegratedFeedError(ValueError):
    """Raised when the integrated composition cannot proceed. Fails closed."""


@dataclass(frozen=True)
class ReceiptDecision:
    """One receipt's verification outcome, ready to compose and to audit."""

    lane: str
    kind: str
    receipt_id: str
    miner_hotkey: str
    verdict: str            # PASS | FAIL | NOT_PROVEN
    work_units: Decimal     # 0 unless PASS
    detail: str = ""

    @property
    def creditable(self) -> bool:
        return self.verdict == PASS and self.work_units > 0


def _raw(receipt: Mapping[str, Any], *keys: str, default: str = "<unverified>") -> str:
    for key in keys:
        value = receipt.get(key) if isinstance(receipt, Mapping) else None
        if isinstance(value, str) and value:
            return value
    return default


def verify_lane_receipt(
    kind: str,
    receipt: Mapping[str, Any],
    *,
    lane: str,
    key_registry: Any,
    source_epoch: int,
    now_iso: str | None = None,
    gpu_attestation_verifier: Callable[[Mapping[str, Any]], bool] | None = None,
    cpu_quote_verifier: Callable[[Mapping[str, Any]], bool] | None = None,
    allowed_measurements: frozenset[str] | set[str] | None = None,
    allowed_tcb_statuses: frozenset[str] | set[str] | None = None,
    allowed_advisories: frozenset[str] | set[str] | None = None,
) -> ReceiptDecision:
    """Verify one lane receipt and return its PASS / FAIL / NOT_PROVEN decision.

    A verifier that proves the receipt wrong -> `FAIL`. Evidence that cannot be
    checked at all (a GPU receipt with no attestation verifier configured) ->
    `NOT_PROVEN`, never a silent pass. Only `PASS` contributes weight.
    """
    if kind not in _KINDS:
        raise IntegratedFeedError(f"unknown receipt kind {kind!r}")
    receipt_id = _raw(receipt, "receipt_id")
    try:
        if kind in (KIND_COMPUTE_CPU, KIND_COMPUTE_GPU):
            if now_iso is None:
                raise IntegratedFeedError("compute receipts need now_iso for freshness")
            if kind == KIND_COMPUTE_GPU and gpu_attestation_verifier is None:
                # Cannot prove the GPU attestation without the verifier — not
                # proven wrong, just not proven. Fail-open is never allowed.
                return ReceiptDecision(
                    lane, kind, receipt_id, _raw(receipt, "subject_hotkey"),
                    NOT_PROVEN, Decimal(0), "no GPU attestation verifier configured",
                )
            doc = _compute.verify_receipt(
                receipt, key_registry, now_iso=now_iso, source_epoch=source_epoch,
                gpu_attestation_verifier=gpu_attestation_verifier,
                cpu_quote_verifier=cpu_quote_verifier,
                allowed_measurements=allowed_measurements,
                allowed_tcb_statuses=allowed_tcb_statuses,
                allowed_advisories=allowed_advisories,
            )
            expected = _compute.PLATFORM_CPU if kind == KIND_COMPUTE_CPU else _compute.PLATFORM_GPU
            if _compute.platform_class(doc) != expected:
                raise _compute.ComputeReceiptError(
                    f"receipt platform is not {expected}"
                )
            contribution = _compute.lane_contribution(doc)
        elif kind == KIND_DISTILL:
            if now_iso is None:
                raise IntegratedFeedError("distill receipts need now_iso for freshness")
            doc = _distill.verify_receipt(
                receipt, key_registry, now_iso=now_iso, source_epoch=source_epoch,
                allowed_measurements=allowed_measurements,
                allowed_tcb_statuses=allowed_tcb_statuses,
                allowed_advisories=allowed_advisories,
            )
            contribution = _distill.lane_contribution(doc)
        else:  # KIND_CYBERGYM
            doc = _cybergym.verify_receipt(receipt, key_registry, source_epoch=source_epoch)
            contribution = _cybergym.lane_contribution(doc)
    except (
        _compute.ComputeReceiptError,
        _distill.DistillReceiptError,
        _cybergym.CyberGymReceiptError,
    ) as exc:
        miner = _raw(receipt, "subject_hotkey", "miner_hotkey")
        return ReceiptDecision(lane, kind, receipt_id, miner, FAIL, Decimal(0), str(exc))

    return ReceiptDecision(
        lane, kind,
        contribution["receipt_id"], contribution["miner_hotkey"],
        PASS, Decimal(contribution["work_units"]), "verified",
    )


def compose_integrated(
    resolved: ResolvedAllocation,
    decisions: Sequence[ReceiptDecision],
) -> dict[str, Any]:
    """Compose verified decisions into one feed plus an audit trail.

    Every lane the allocation config expects is composed — including lanes with no
    `PASS` contribution, which compose empty so their allocation goes to burn. A
    decision whose lane is not in the allocation config is rejected fail-closed.
    """
    known_lanes = set(resolved.lane_allocations)
    for d in decisions:
        if d.lane not in known_lanes:
            raise IntegratedFeedError(
                f"decision references lane {d.lane!r} not in the allocation config"
            )

    # Group PASS contributions by lane; a miner appearing twice in a lane is a bug.
    by_lane: dict[str, list[_lane_feed.LaneContribution]] = {lane: [] for lane in known_lanes}
    seen_in_lane: dict[str, set[str]] = {lane: set() for lane in known_lanes}
    for d in decisions:
        if not d.creditable:
            continue
        if d.miner_hotkey in seen_in_lane[d.lane]:
            raise IntegratedFeedError(
                f"miner {d.miner_hotkey} has two credited receipts in lane {d.lane}"
            )
        seen_in_lane[d.lane].add(d.miner_hotkey)
        by_lane[d.lane].append(
            _lane_feed.LaneContribution(d.miner_hotkey, d.receipt_id, d.work_units)
        )

    lanes = [
        _lane_feed.Lane(lane, resolved.lane_allocations[lane], tuple(by_lane[lane]))
        for lane in sorted(known_lanes)
    ]
    feed = _lane_feed.compose_vector(
        lanes, burn_hotkey=resolved.burn_hotkey, burn_fraction=resolved.burn_fraction
    )

    # Audit trail: receipt -> decision -> contribution -> allocation -> weight.
    final_weight = {w["miner_hotkey"]: w["weight"] for w in feed["weights"]}
    lane_record = {ln["lane"]: ln for ln in feed["lanes"]}
    receipt_audit = [
        {
            "receipt_id": d.receipt_id,
            "kind": d.kind,
            "lane": d.lane,
            "verdict": d.verdict,
            "detail": d.detail,
            "miner_hotkey": d.miner_hotkey,
            "work_units": str(d.work_units),
            "lane_allocation": str(resolved.lane_allocations.get(d.lane, Decimal(0))),
            # the miner's normalized pre-burn weight in the final vector (0 if not credited)
            "final_weight": final_weight.get(d.miner_hotkey, 0.0) if d.creditable else 0.0,
        }
        for d in decisions
    ]
    audit = {
        "schema": AUDIT_SCHEMA,
        "config_versions": {
            "burn": resolved.config_versions[0],
            "allocation": resolved.config_versions[1],
        },
        "burn": {
            "hotkey": resolved.burn_hotkey,
            "base_fraction": str(resolved.burn_fraction),
            "effective_fraction": feed["policy_metadata"]["effective_burn_allocation"],
        },
        "lanes": [
            {
                "lane": lane,
                "allocation": str(resolved.lane_allocations[lane]),
                "contributing": lane_record[lane]["contributing"],
                "burned_allocation": lane_record[lane]["burned_allocation"],
                "receipts": [d.receipt_id for d in decisions if d.lane == lane],
            }
            for lane in sorted(known_lanes)
        ],
        "receipts": receipt_audit,
        "verdicts": {
            "pass": sum(1 for d in decisions if d.verdict == PASS),
            "fail": sum(1 for d in decisions if d.verdict == FAIL),
            "not_proven": sum(1 for d in decisions if d.verdict == NOT_PROVEN),
        },
    }
    return {"feed": feed, "audit": audit}


__all__ = [
    "AUDIT_SCHEMA", "PASS", "FAIL", "NOT_PROVEN",
    "KIND_COMPUTE_CPU", "KIND_COMPUTE_GPU", "KIND_DISTILL", "KIND_CYBERGYM",
    "IntegratedFeedError", "ReceiptDecision", "verify_lane_receipt", "compose_integrated",
]
