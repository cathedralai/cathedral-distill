"""The one fail-closed admission verifier (issue #1, P0).

A reward decision must never rest on a caller-supplied boolean or a merely
well-formed string. This module is the single entry that consumes all five
admission inputs and returns one `ADMIT` / `REJECT` / `NOT_PROVEN` decision:

  1. **the raw receipt** — parsed and signature-checked by its typed verifier;
  2. **raw hardware evidence** — the injected TDX/GPU quote verifiers and, for the
     eval lane, the injected `attestation_verified` result; a claimant can never
     supply `intel_verified` or assert its own quote passed;
  3. **the signed authorization** — the evaluator grant binding evaluator, miner,
     eval id, run nonce, source epoch, and a bounded block window;
  4. **registry / bundle state** — the anchored signing-key registry (and, per
     lane, the licence-pinned teacher / bundle registries reached through the
     injected verifiers);
  5. **finalized chain context** — the source epoch and the finalized block height,
     against which every receipt that carries a block window is checked.

Per-kind receipt body + hardware + replay checks are delegated to the typed
verifiers (`integrated_feed.verify_lane_receipt`), so each check lives in exactly
one place; this module owns the cross-cutting authorization and finalized-chain
gates and folds them into a single decision. Everything fails closed: evidence
that cannot be checked is `NOT_PROVEN`, never a silent `ADMIT`.

Two ordering rules this module has to respect, because it is the caller that
decides when the irreversible step happens:

  * **A replay decision is explicit.** `consumption_ledger` is a required
    argument: a `ConsumptionLedger`, or the typed `NO_REPLAY_LEDGER` opt-out.
    Replay protection is not something you can lose by forgetting a keyword.
  * **Nothing is consumed until every non-mutating gate has passed.** The
    finalized block window is pushed DOWN into the typed verifier (which checks it
    before it consumes) instead of being checked here afterwards. Consuming first
    and checking the window second let an attacker submit a receipt outside its
    window, burn its one-time token, and leave the legitimate in-window
    submission with nothing left to consume.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any, Callable, Mapping

from cathedral_distill import eval_receipt as _eval
from cathedral_distill import integrated_feed as _feed
from cathedral_distill.consumption_ledger import NO_REPLAY_LEDGER

# Admission verdicts (aligned with the feed's PASS/FAIL/NOT_PROVEN).
ADMIT = "ADMIT"
REJECT = "REJECT"
NOT_PROVEN = "NOT_PROVEN"

_VERDICT_FROM_FEED = {_feed.PASS: ADMIT, _feed.FAIL: REJECT, _feed.NOT_PROVEN: NOT_PROVEN}

# Kinds. The four receipt kinds are the feed's; eval is the sealed-evaluation lane
# whose creditability turns on the signed authorization + attested quote.
KIND_COMPUTE_CPU = _feed.KIND_COMPUTE_CPU
KIND_COMPUTE_GPU = _feed.KIND_COMPUTE_GPU
KIND_DISTILL = _feed.KIND_DISTILL
KIND_CYBERGYM = _feed.KIND_CYBERGYM
KIND_EVAL = "eval"
_KINDS = frozenset({KIND_COMPUTE_CPU, KIND_COMPUTE_GPU, KIND_DISTILL, KIND_CYBERGYM, KIND_EVAL})

# Kinds whose receipt carries a `[valid_from_block, valid_until_block)` window that
# the finalized block height must fall inside.
_BLOCK_WINDOW_KINDS = frozenset({KIND_CYBERGYM, KIND_EVAL})


class AdmissionError(ValueError):
    """Raised when admission cannot be evaluated at all (bad inputs). Fails closed."""


@dataclass(frozen=True)
class ChainContext:
    """Finalized chain context — the epoch a run is bound to and the finalized
    block height every windowed receipt is checked against."""

    source_epoch: int
    current_block: int
    now_iso: str | None = None


@dataclass(frozen=True)
class Admission:
    """One admission decision, ready to compose and to audit."""

    kind: str
    lane: str
    receipt_id: str
    miner_hotkey: str
    verdict: str            # ADMIT | REJECT | NOT_PROVEN
    work_units: Decimal     # 0 unless ADMIT
    detail: str = ""

    @property
    def creditable(self) -> bool:
        return self.verdict == ADMIT and self.work_units > 0


def _raw(receipt: Mapping[str, Any], *keys: str, default: str = "<unverified>") -> str:
    for key in keys:
        value = receipt.get(key) if isinstance(receipt, Mapping) else None
        if isinstance(value, str) and value:
            return value
    return default


def _block_window(receipt: Mapping[str, Any]) -> tuple[int, int]:
    first, last = receipt.get("valid_from_block"), receipt.get("valid_until_block")
    if not isinstance(first, int) or not isinstance(last, int) or isinstance(first, bool):
        raise AdmissionError("receipt is missing an integer block window")
    return first, last


def verify_admission(
    kind: str,
    receipt: Mapping[str, Any],
    *,
    lane: str,
    key_registry: Any,
    chain: ChainContext,
    # (4) registry / bundle state + replay. Required: a ConsumptionLedger, or the
    # explicit NO_REPLAY_LEDGER opt-out. Never an implicit default.
    consumption_ledger: Any,
    # (2) raw hardware evidence — injected verifiers / results, never caller booleans
    gpu_attestation_verifier: Callable[[Mapping[str, Any]], bool] | None = None,
    cpu_quote_verifier: Callable[[Mapping[str, Any]], bool] | None = None,
    attestation_verified: bool | None = None,
    # (3) signed authorization — its authority key registry (defaults to key_registry)
    authorization_key_registry: Any = None,
    authorization_at: datetime | None = None,
    allowed_measurements: frozenset[str] | set[str] | None = None,
    allowed_tcb_statuses: frozenset[str] | set[str] | None = None,
    allowed_advisories: frozenset[str] | set[str] | None = None,
) -> Admission:
    """Verify one receipt against all five inputs and return its admission decision.

    Compute/Distill/CyberGym delegate their receipt-body, hardware, block-window
    and replay checks to the typed verifier (which orders consumption last). Eval
    additionally requires a verified evaluator authorization and an injected
    attestation result. Only `ADMIT` carries work units.
    """
    if kind not in _KINDS:
        raise AdmissionError(f"unknown admission kind {kind!r}")
    if not isinstance(chain, ChainContext):
        raise AdmissionError("chain must be a ChainContext")
    if consumption_ledger is None:
        raise AdmissionError(
            "verify_admission requires an explicit replay decision: pass a "
            "ConsumptionLedger, or consumption_ledger=NO_REPLAY_LEDGER to accept no "
            "replay protection"
        )

    if kind == KIND_EVAL:
        return _admit_eval(
            receipt, lane=lane, key_registry=key_registry, chain=chain,
            attestation_verified=attestation_verified,
            authorization_key_registry=authorization_key_registry or key_registry,
            authorization_at=authorization_at, consumption_ledger=consumption_ledger,
        )

    # (1)+(2)+(4)+(5): the typed verifier owns receipt body, hardware quote, the
    # finalized block window, and replay, in that order, so the window is a gate
    # BEFORE the ledger is touched. `current_block` must be passed for that to be
    # true: without it the verifier consumed the token and the window was checked
    # here afterwards, so a receipt submitted outside its window still burned its
    # own one-time token and the legitimate in-window submission had nothing left
    # to consume.
    decision = _feed.verify_lane_receipt(
        kind, receipt, lane=lane, key_registry=key_registry,
        source_epoch=chain.source_epoch, now_iso=chain.now_iso,
        current_block=chain.current_block,
        gpu_attestation_verifier=gpu_attestation_verifier,
        cpu_quote_verifier=cpu_quote_verifier, consumption_ledger=consumption_ledger,
        allowed_measurements=allowed_measurements,
        allowed_tcb_statuses=allowed_tcb_statuses, allowed_advisories=allowed_advisories,
    )
    adm = Admission(
        kind=decision.kind, lane=decision.lane, receipt_id=decision.receipt_id,
        miner_hotkey=decision.miner_hotkey, verdict=_VERDICT_FROM_FEED[decision.verdict],
        work_units=decision.work_units, detail=decision.detail,
    )

    # (5) again, belt and braces: the window is already enforced above for the
    # kinds whose verifier reads it, and re-checking a windowed receipt here costs
    # nothing and covers a kind whose verifier does not.
    if adm.verdict == ADMIT and kind in _BLOCK_WINDOW_KINDS:
        first, last = _block_window(receipt)
        if not (first <= chain.current_block < last):
            return Admission(
                kind=kind, lane=lane, receipt_id=adm.receipt_id,
                miner_hotkey=adm.miner_hotkey, verdict=REJECT, work_units=Decimal(0),
                detail=f"finalized block {chain.current_block} outside [{first},{last})",
            )
    return adm


def _admit_eval(
    receipt: Mapping[str, Any],
    *,
    lane: str,
    key_registry: Any,
    chain: ChainContext,
    attestation_verified: bool | None,
    authorization_key_registry: Any,
    authorization_at: datetime | None,
    consumption_ledger: Any,
) -> Admission:
    receipt_id = _raw(receipt, "receipt_id")
    miner = _raw(receipt, "miner_hotkey")

    def reject(detail: str) -> Admission:
        return Admission(KIND_EVAL, lane, receipt_id, miner, REJECT, Decimal(0), detail)

    def not_proven(detail: str) -> Admission:
        return Admission(KIND_EVAL, lane, receipt_id, miner, NOT_PROVEN, Decimal(0), detail)

    # (1)+(4): receipt body — structure + receipt_id + signature, resolved against
    # the anchored key registry (never a caller-supplied key) + finalized epoch.
    try:
        doc = _eval.verify_receipt(receipt, key_registry, source_epoch=chain.source_epoch)
    except _eval.EvalReceiptError as exc:
        return reject(str(exc))
    miner = str(doc["miner_hotkey"])

    # (2) raw hardware evidence: the attestation result is the injected quote
    # verifier's, never inferred from the receipt. Absent -> not proven, not admit.
    if attestation_verified is None:
        return not_proven("no attestation verifier result supplied")
    if not _eval.creditable_as_verified_work(doc, attestation_verified=attestation_verified):
        # either the injected quote failed, or the receipt is unattested (kind=none)
        if attestation_verified is not True:
            return reject("attestation quote did not verify")
        return reject("unattested receipt is not creditable as verified work")

    # (3)+(5) signed authorization, bound to the receipt and the finalized block.
    if authorization_at is None:
        return not_proven("no authorization resolve-time supplied")
    try:
        _eval.verify_authorization(
            doc, authorization_key_registry,
            current_block=chain.current_block, at=authorization_at,
        )
    except _eval.EvalReceiptError as exc:
        return reject(str(exc))

    # (4) replay: consume the eval id exactly once, LAST, after the receipt body,
    # the injected attestation result, and the signed authorization (which carries
    # the finalized block window) have all passed, so a rejected submission never
    # burns the token the legitimate one needs.
    if consumption_ledger is not None and consumption_ledger is not NO_REPLAY_LEDGER:
        from cathedral_distill.consumption_ledger import ReplayError

        try:
            consumption_ledger.consume(
                str(doc["eval_id"]), kind="eval_id", source_epoch=chain.source_epoch
            )
        except ReplayError as exc:
            return reject(str(exc))

    work_units = Decimal(str(doc["score"]["work_units"]))
    return Admission(KIND_EVAL, lane, str(doc["receipt_id"]), miner, ADMIT, work_units, "verified")


__all__ = [
    "ADMIT", "REJECT", "NOT_PROVEN", "NO_REPLAY_LEDGER",
    "KIND_COMPUTE_CPU", "KIND_COMPUTE_GPU", "KIND_DISTILL", "KIND_CYBERGYM", "KIND_EVAL",
    "AdmissionError", "ChainContext", "Admission", "verify_admission",
]
