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

`verify_lane_receipts` (plural) is the entry an epoch loop should call. It is the
one that makes the two epoch-level invariants real:

  * **One bad receipt fails only itself.** Every per-receipt failure is contained,
    including the failures a typed verifier does not raise (a `KeyError` from an
    unexpected receipt shape used to escape every caller's `except` and abort the
    whole vector — every lane, every miner). A contained receipt is `FAIL` with the
    exception in its audit detail; the rest of the epoch composes normally.
  * **A replay decision is explicit.** The ledger argument is required: pass a
    `ConsumptionLedger`, or type `NO_REPLAY_LEDGER` to accept no replay
    protection. Forgetting the keyword is an error, not a silent fail-open — the
    state before this was that `ConsumptionLedger` had zero production
    instantiations while `source_epoch` equality was the only replay defense.

One receipt_id is also credited at most once *per composition*, in both the batch
verifier and `compose_integrated`: one signed receipt tagged into two lanes would
otherwise earn twice and, worse, keep a lane "contributing" that had no genuine
work of its own (capturing the share that should have gone to burn).
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Callable, Mapping, Sequence

from cathedral_distill import compute_receipt as _compute
from cathedral_distill import cybergym_receipt as _cybergym
from cathedral_distill import distill_receipt as _distill
from cathedral_distill import lane_feed as _lane_feed
from cathedral_distill.consumption_ledger import NO_REPLAY_LEDGER, ReplayError
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


@dataclass(frozen=True)
class LaneSubmission:
    """One receipt offered to one lane — the batch verifier's unit of work."""

    kind: str
    receipt: Mapping[str, Any]
    lane: str


def _resolve_ledger(consumption_ledger: Any, *, entry: str) -> Any:
    """Turn a required ledger argument into a ledger or `None`, fail-closed.

    A replay decision is never implicit on an entry that requires one: either a
    real ledger, or the typed `NO_REPLAY_LEDGER` opt-out.
    """
    if consumption_ledger is NO_REPLAY_LEDGER:
        return None
    if consumption_ledger is None:
        raise IntegratedFeedError(
            f"{entry} requires an explicit replay decision: pass a ConsumptionLedger, "
            "or consumption_ledger=NO_REPLAY_LEDGER to accept no replay protection"
        )
    return consumption_ledger


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
    current_block: int | None = None,
    gpu_attestation_verifier: Callable[[Mapping[str, Any]], bool] | None = None,
    cpu_quote_verifier: Callable[[Mapping[str, Any]], bool] | None = None,
    consumption_ledger: Any = None,
    allowed_measurements: frozenset[str] | set[str] | None = None,
    allowed_tcb_statuses: frozenset[str] | set[str] | None = None,
    allowed_advisories: frozenset[str] | set[str] | None = None,
) -> ReceiptDecision:
    """Verify one lane receipt and return its PASS / FAIL / NOT_PROVEN decision.

    A verifier that proves the receipt wrong -> `FAIL`. Evidence that cannot be
    checked at all (a GPU receipt with no attestation verifier configured) ->
    `NOT_PROVEN`, never a silent pass. Only `PASS` contributes weight.

    `current_block` is the finalized chain height: when supplied, a CyberGym
    receipt outside its signed `[valid_from_block, valid_until_block)` window is
    `FAIL`, so the composition path applies the same finalized-chain gate the
    unified `admission.verify_admission` does. Omitted -> the window is not
    checked (back-compatible). Supplying it matters for more than the verdict:
    replay consumption MUTATES state, so it must be the last step, after every
    non-mutating gate. A caller that checks the block window *after* this function
    consumed the token lets an attacker submit the receipt outside its window,
    burn the one-time token, and leave the legitimate in-window submission with
    nothing to consume.
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
            # Finalized chain context: a CyberGym receipt is authorized for a bounded
            # block window; when the caller supplies the finalized block, a receipt
            # outside its window is FAIL, not a silent PASS — the same gate the
            # unified `admission.verify_admission` applies, so the composition path
            # is not weaker than the admission verifier.
            if current_block is not None:
                first, last = int(doc["valid_from_block"]), int(doc["valid_until_block"])
                if not (first <= current_block < last):
                    raise _cybergym.CyberGymReceiptError(
                        f"finalized block {current_block} outside authorized window [{first},{last})"
                    )
            contribution = _cybergym.lane_contribution(doc)
    except (
        _compute.ComputeReceiptError,
        _distill.DistillReceiptError,
        _cybergym.CyberGymReceiptError,
    ) as exc:
        miner = _raw(receipt, "subject_hotkey", "miner_hotkey")
        return ReceiptDecision(lane, kind, receipt_id, miner, FAIL, Decimal(0), str(exc))
    except IntegratedFeedError:
        raise  # a caller/config error (unknown kind, missing now_iso), not receipt data
    except Exception as exc:  # noqa: BLE001 - see below
        # Containment. The typed verifiers raise typed errors for the receipt
        # shapes they anticipated, but an unanticipated shape raises whatever
        # Python raises — a bare KeyError on a TCB variant, a TypeError on a
        # wrong-typed field, an InvalidOperation on a malformed decimal. None of
        # those are receipt errors, so they escaped every caller's `except` and
        # aborted the entire epoch: every lane, every miner, over ONE receipt.
        # A receipt that cannot be verified fails only itself.
        miner = _raw(receipt, "subject_hotkey", "miner_hotkey")
        return ReceiptDecision(
            lane, kind, receipt_id, miner, FAIL, Decimal(0),
            f"verification raised {type(exc).__name__}: {exc}",
        )

    try:
        contribution_id = str(contribution["receipt_id"])
        contribution_miner = str(contribution["miner_hotkey"])
        work_units = Decimal(str(contribution["work_units"]))
    except Exception as exc:  # noqa: BLE001 - a malformed contribution fails itself
        miner = _raw(receipt, "subject_hotkey", "miner_hotkey")
        return ReceiptDecision(
            lane, kind, receipt_id, miner, FAIL, Decimal(0),
            f"lane contribution is malformed: {type(exc).__name__}: {exc}",
        )

    # Replay: consume the receipt_id exactly once. A receipt is derived from its
    # canonical body (nonce + epoch), so consuming its id once consumes the nonce
    # once — a resubmission of an already-credited receipt fails closed as FAIL.
    #
    # This is deliberately the LAST step. Consumption is the only irreversible
    # side effect in this function, so it happens after every non-mutating gate
    # (structure, receipt_id, anchored key, signature, measurement/TCB policy,
    # epoch, lifecycle, freshness, CPU/GPU quotes, block window). Consuming
    # earlier would let a receipt that is about to be rejected still burn its own
    # one-time token, which an attacker can use to destroy a legitimate
    # submission's only chance to be credited.
    ledger = None if consumption_ledger is NO_REPLAY_LEDGER else consumption_ledger
    if ledger is not None:
        try:
            ledger.consume(
                contribution_id, kind=f"{kind}_receipt_id", source_epoch=source_epoch,
            )
        except ReplayError as exc:
            return ReceiptDecision(
                lane, kind, contribution_id, contribution_miner,
                FAIL, Decimal(0), str(exc),
            )
        except Exception as exc:  # noqa: BLE001 - an unusable ledger never credits
            return ReceiptDecision(
                lane, kind, contribution_id, contribution_miner, FAIL, Decimal(0),
                f"replay ledger failed: {type(exc).__name__}: {exc}",
            )

    return ReceiptDecision(
        lane, kind, contribution_id, contribution_miner, PASS, work_units, "verified",
    )


def verify_lane_receipts(
    submissions: Sequence[LaneSubmission],
    *,
    key_registry: Any,
    source_epoch: int,
    consumption_ledger: Any,
    now_iso: str | None = None,
    current_block: int | None = None,
    gpu_attestation_verifier: Callable[[Mapping[str, Any]], bool] | None = None,
    cpu_quote_verifier: Callable[[Mapping[str, Any]], bool] | None = None,
    allowed_measurements: frozenset[str] | set[str] | None = None,
    allowed_tcb_statuses: frozenset[str] | set[str] | None = None,
    allowed_advisories: frozenset[str] | set[str] | None = None,
) -> list[ReceiptDecision]:
    """Verify a whole epoch's receipts. One bad receipt fails only itself.

    This is the entry an epoch loop should call, rather than looping over
    `verify_lane_receipt` itself, because it owns the two epoch-level rules:

      * **containment** — nothing a single receipt can do aborts the batch, not
        even an unknown `kind` or a missing `now_iso` (those are `FAIL` here with
        the reason in the detail, instead of an exception that takes the vector
        down with it);
      * **global once-only** — a `receipt_id` is credited at most once across the
        whole batch, so one signed receipt tagged into two lanes cannot earn twice
        (and cannot keep a lane "contributing" that had no work of its own, which
        would capture the share that should have gone to burn).

    `consumption_ledger` is required: a `ConsumptionLedger`, or the explicit
    `NO_REPLAY_LEDGER` opt-out.
    """
    ledger = _resolve_ledger(consumption_ledger, entry="verify_lane_receipts")
    decisions: list[ReceiptDecision] = []
    credited_receipt_ids: dict[str, str] = {}  # receipt_id -> lane that credited it
    for submission in submissions:
        try:
            decision = verify_lane_receipt(
                submission.kind, submission.receipt, lane=submission.lane,
                key_registry=key_registry, source_epoch=source_epoch, now_iso=now_iso,
                current_block=current_block,
                gpu_attestation_verifier=gpu_attestation_verifier,
                cpu_quote_verifier=cpu_quote_verifier,
                consumption_ledger=ledger if ledger is not None else NO_REPLAY_LEDGER,
                allowed_measurements=allowed_measurements,
                allowed_tcb_statuses=allowed_tcb_statuses,
                allowed_advisories=allowed_advisories,
            )
        except Exception as exc:  # noqa: BLE001 - including IntegratedFeedError
            decisions.append(
                ReceiptDecision(
                    str(submission.lane), str(submission.kind),
                    _raw(submission.receipt, "receipt_id"),
                    _raw(submission.receipt, "subject_hotkey", "miner_hotkey"),
                    FAIL, Decimal(0),
                    f"receipt rejected: {type(exc).__name__}: {exc}",
                )
            )
            continue
        if decision.creditable:
            first_lane = credited_receipt_ids.get(decision.receipt_id)
            if first_lane is not None:
                decision = ReceiptDecision(
                    decision.lane, decision.kind, decision.receipt_id,
                    decision.miner_hotkey, FAIL, Decimal(0),
                    f"receipt_id already credited in lane {first_lane}",
                )
            else:
                credited_receipt_ids[decision.receipt_id] = decision.lane
        decisions.append(decision)
    return decisions


def compose_integrated(
    resolved: ResolvedAllocation,
    decisions: Sequence[ReceiptDecision],
) -> dict[str, Any]:
    """Compose verified decisions into one feed plus an audit trail.

    Every lane the allocation config expects is composed — including lanes with no
    `PASS` contribution, which compose empty so their allocation goes to burn.

    Composition never aborts on one decision. Four things drop a decision to
    uncredited (its share goes to burn, and the audit records why) instead of
    raising and taking every lane and every miner with it:

      1. a lane the signed allocation config does not know;
      2. a `receipt_id` already credited in this composition — GLOBALLY, across
         lanes, so one signed receipt tagged into two lanes earns once, and the
         second lane does not become "contributing" on borrowed work;
      3. a miner already credited in the same lane;
      4. the burn hotkey as a reward subject — burn is a destination, never an
         earner, so a receipt whose subject is the configured burn address is
         never a contribution.
    """
    known_lanes = set(resolved.lane_allocations)
    burn_hotkey = str(resolved.burn_hotkey)

    by_lane: dict[str, list[_lane_feed.LaneContribution]] = {lane: [] for lane in known_lanes}
    seen_in_lane: dict[str, set[str]] = {lane: set() for lane in known_lanes}
    credited_receipt_ids: dict[str, str] = {}
    drop_reason: dict[int, str] = {}  # position in `decisions` -> why not credited
    for position, d in enumerate(decisions):
        if not d.creditable:
            continue
        if d.lane not in known_lanes:
            drop_reason[position] = f"lane {d.lane!r} is not in the allocation config"
            continue
        if d.miner_hotkey == burn_hotkey:
            drop_reason[position] = "subject is the burn hotkey, which is never an earner"
            continue
        first_lane = credited_receipt_ids.get(d.receipt_id)
        if first_lane is not None:
            drop_reason[position] = f"receipt_id already credited in lane {first_lane}"
            continue
        if d.miner_hotkey in seen_in_lane[d.lane]:
            drop_reason[position] = f"miner already credited in lane {d.lane}"
            continue
        credited_receipt_ids[d.receipt_id] = d.lane
        seen_in_lane[d.lane].add(d.miner_hotkey)
        by_lane[d.lane].append(
            _lane_feed.LaneContribution(d.miner_hotkey, d.receipt_id, d.work_units)
        )

    def credited(position: int, decision: ReceiptDecision) -> bool:
        return decision.creditable and position not in drop_reason

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
            "final_weight": (
                final_weight.get(d.miner_hotkey, 0.0) if credited(position, d) else 0.0
            ),
            # a PASS that was not credited, and why (duplicate receipt_id, unknown
            # lane, duplicate miner, burn subject) — the operator's record of a
            # verified receipt that still earned nothing.
            "credited": credited(position, d),
            "drop_reason": drop_reason.get(position, ""),
        }
        for position, d in enumerate(decisions)
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
    "NO_REPLAY_LEDGER",
    "IntegratedFeedError", "ReceiptDecision", "LaneSubmission",
    "verify_lane_receipt", "verify_lane_receipts", "compose_integrated",
]
