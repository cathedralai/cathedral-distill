"""The one fail-closed admission verifier (issue #1, P0).

Proves a single entry consumes all five inputs — raw receipt, raw hardware
evidence, signed authorization, registry state, finalized chain context — and
returns one ADMIT / REJECT / NOT_PROVEN decision that never rests on a caller
boolean: a typed receipt maps through, an unprovable GPU quote is NOT_PROVEN, a
receipt whose block window does not cover the finalized block is rejected, and an
eval run is creditable only with a verified evaluator authorization bound to it.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import admission as adm  # noqa: E402
from cathedral_distill import cybergym as cg  # noqa: E402
from cathedral_distill import cybergym_batch as cb  # noqa: E402
from cathedral_distill import cybergym_receipt as cr  # noqa: E402
from cathedral_distill import cybergym_validator as cv  # noqa: E402
from cathedral_distill import eval_receipt as er  # noqa: E402
from cathedral_distill.consumption_ledger import ConsumptionLedger  # noqa: E402
from cathedral_distill.receipt_keys import ReceiptKeyRegistry  # noqa: E402
from cathedral_distill.testing import IntegrationFixtures, digest  # noqa: E402

NOW_ISO = "2026-07-25T12:30:00.000000Z"
SOURCE_EPOCH = 11
FX = IntegrationFixtures(source_epoch=SOURCE_EPOCH)


def _chain(current_block=6_000_100, source_epoch=SOURCE_EPOCH):
    return adm.ChainContext(source_epoch=source_epoch, current_block=current_block, now_iso=NOW_ISO)


# --------------------------------------------------------------------------- #
# Dispatch + verdict mapping for the typed lanes
# --------------------------------------------------------------------------- #

def test_distill_receipt_maps_to_admit():
    a = adm.verify_admission(adm.KIND_DISTILL, FX.distill_receipt(passed=28, graded=32),
                             lane="distill", key_registry=FX.registry, chain=_chain())
    assert a.verdict == adm.ADMIT and a.work_units == Decimal(28) and a.creditable


def test_gpu_without_attestation_verifier_is_not_proven():
    a = adm.verify_admission(adm.KIND_COMPUTE_GPU, FX.gpu_receipt(),
                             lane="compute", key_registry=FX.registry, chain=_chain())
    assert a.verdict == adm.NOT_PROVEN and not a.creditable


def test_epoch_mismatch_maps_to_reject():
    a = adm.verify_admission(adm.KIND_DISTILL, FX.distill_receipt(),
                             lane="distill", key_registry=FX.registry,
                             chain=_chain(source_epoch=SOURCE_EPOCH + 1))
    assert a.verdict == adm.REJECT


# --------------------------------------------------------------------------- #
# Finalized chain context: a windowed receipt must cover the finalized block
# --------------------------------------------------------------------------- #

_CYBER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(3, 35)))
_CYBER_REG = ReceiptKeyRegistry.from_keys({"cybergym-1": _CYBER_KEY.public_key().public_bytes_raw()})
_CB_NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
_CB_CUTOFF = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


def _cybergym_receipt():
    tasks = [cb.PooledTask(task_id=f"arvo:{n}", level=cg.Level(lv),
                           binary_digest=digest(f"bin-{n}"), disclosed_at=_CB_NOW)
             for n, lv in enumerate((0, 1, 2), start=1)]
    nonce = cb.derive_batch_nonce(block=100, block_hash="0x" + "cd" * 32, network="finney",
                                  netuid=39, source_epoch=SOURCE_EPOCH, miner_hotkey="5Miner",
                                  model_commitment=digest("ckpt"))
    batch = cb.draw_batch(cb.TaskPool(tasks), size=3, nonce=nonce, as_of=_CB_NOW, cutoff=_CB_CUTOFF)
    subs = [cg.PoCSubmission(task_id=t.task_id, poc_sha256=cr.holdout_digest([t.task_id]),
                             result=cv.verify_poc(t, b"poc-" + t.task_id.encode(),
                                                  lambda tid, poc, mode: 1 if (tid in ("arvo:1", "arvo:2") and mode == "vul") else 0))
            for t in batch.tasks]
    score = cg.score_batch(batch.batch_id, list(batch.tasks), subs)
    return cr.build_receipt(score, network="finney", netuid=39, source_epoch=SOURCE_EPOCH,
                            validator_hotkey="5Validator", miner_hotkey="5Miner", nonce=nonce,
                            holdout_digest_value=cr.holdout_digest(list(batch.task_ids)),
                            valid_from_block=100, valid_until_block=460,
                            issued_at="2026-07-27T12:00:00.000000Z", private_key=_CYBER_KEY,
                            signing_key_id="cybergym-1")


def test_cybergym_admits_inside_the_block_window():
    a = adm.verify_admission(adm.KIND_CYBERGYM, _cybergym_receipt(), lane="cybergym",
                             key_registry=_CYBER_REG, chain=_chain(current_block=200))
    assert a.verdict == adm.ADMIT and a.work_units > 0


def test_cybergym_rejected_outside_the_block_window():
    a = adm.verify_admission(adm.KIND_CYBERGYM, _cybergym_receipt(), lane="cybergym",
                             key_registry=_CYBER_REG, chain=_chain(current_block=999))
    assert a.verdict == adm.REJECT and "outside" in a.detail


# --------------------------------------------------------------------------- #
# The eval lane — the signed evaluator authorization (#15)
# --------------------------------------------------------------------------- #

_AUTH_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(9, 41)))
_RECEIPT_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(41, 73)))
_EVAL_REG = ReceiptKeyRegistry.from_keys({
    "eval-authority-1": _AUTH_KEY.public_key().public_bytes_raw(),
    "eval-receipt-1": _RECEIPT_KEY.public_key().public_bytes_raw(),
})
_AUTH_AT = datetime(2026, 7, 25, 9, 0, tzinfo=UTC)


def _eval_receipt(*, attestation_kind="polaris_tdx", authorize=True, auth_over=None,
                  auth_key=_AUTH_KEY, **over):
    leaves = [er.item_leaf(i, f"item-{i}", digest(f"out-{i}"), i < 7) for i in range(10)]
    doc = {
        "schema": er.SCHEMA, "network": "finney", "netuid": 39, "source_epoch": SOURCE_EPOCH,
        "eval_id": digest("eval"), "validator_hotkey": "5Validator", "miner_hotkey": "5Miner",
        "nonce_base64": "3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "issued_at": "2026-07-25T09:00:00Z", "completed_at": "2026-07-25T09:04:00Z",
        "valid_from_block": 6_000_000, "valid_until_block": 6_000_360,
        "model": {"model_id": "cathedral/student-4b", "weights_digest": digest("w"),
                  "tokenizer_digest": digest("t")},
        "runtime": {"image_digest": digest("img"), "runner_digest": digest("run"),
                    "decode_digest": digest("dec")},
        "evalset": {"evalset_id": "frontend_v0", "sealed_digest": digest("sealed"),
                    "plaintext_digest": digest("plain"), "item_count": 10, "key_grant_id": "grant-1"},
        "grader": {"grader_id": "g_v0", "grader_digest": digest("g"), "harness_digest": digest("h")},
        "score": {"graded_items": 10, "passed_items": 7, "score": "0.7",
                  "items_root": er.items_root(leaves), "input_tokens": 4096, "output_tokens": 8192,
                  "latency_p50_ms": "812.5", "latency_p95_ms": "1904.25", "work_units": "10"},
        "eval_authorization": None,
        "attestation": {"kind": attestation_kind, "evidence_digest": digest("ev"),
                        "evidence_uri": "", "policy_digest": digest("pol"),
                        "report_data_hex": "ab" * 64},
    }
    doc.update(over)
    if attestation_kind == "none":
        doc["attestation"] = {"kind": "none", "evidence_digest": "", "evidence_uri": "",
                              "policy_digest": "", "report_data_hex": ""}
    if authorize:
        auth = er.build_authorization(dict(doc, **(auth_over or {})), auth_key,
                                      signing_key_id="eval-authority-1")
        doc["eval_authorization"] = auth
    return er.build_receipt(doc, _RECEIPT_KEY, signing_key_id="eval-receipt-1")


def _admit_eval(receipt, *, attestation_verified=True, current_block=6_000_100, at=_AUTH_AT,
                ledger=None):
    return adm.verify_admission(adm.KIND_EVAL, receipt, lane="eval", key_registry=_EVAL_REG,
                                chain=_chain(current_block=current_block),
                                attestation_verified=attestation_verified,
                                authorization_at=at, consumption_ledger=ledger)


def test_eval_admits_with_verified_authorization_and_quote():
    a = _admit_eval(_eval_receipt())
    assert a.verdict == adm.ADMIT and a.work_units == Decimal(10) and a.creditable


def test_eval_rejected_when_receipt_signature_is_forged():
    # a receipt whose own body is signed by an unanchored key — the exact
    # self-consistency forgery a receipt-only structural check could never catch.
    rogue = Ed25519PrivateKey.from_private_bytes(bytes(range(150, 182)))
    receipt = _eval_receipt()
    body = {k: v for k, v in receipt.items()
            if k not in ("receipt_id", "signing_key_id", "signature")}
    forged = er.build_receipt(body, rogue, signing_key_id="eval-receipt-1")  # claims eval-receipt-1
    a = _admit_eval(forged)
    assert a.verdict == adm.REJECT and "signature does not verify" in a.detail


def test_eval_not_proven_without_an_attestation_result():
    a = _admit_eval(_eval_receipt(), attestation_verified=None)
    assert a.verdict == adm.NOT_PROVEN


def test_eval_rejected_when_quote_did_not_verify():
    a = _admit_eval(_eval_receipt(), attestation_verified=False)
    assert a.verdict == adm.REJECT and "quote" in a.detail


def test_eval_rejected_when_unattested():
    a = _admit_eval(_eval_receipt(attestation_kind="none"))
    assert a.verdict == adm.REJECT and "unattested" in a.detail


def test_eval_rejected_without_authorization():
    a = _admit_eval(_eval_receipt(authorize=False))
    assert a.verdict == adm.REJECT and "required" in a.detail


def test_eval_rejected_when_authorization_is_for_another_miner():
    # a grant bound to a different miner cannot be reused for this receipt
    a = _admit_eval(_eval_receipt(auth_over={"miner_hotkey": "5OtherMiner"}))
    assert a.verdict == adm.REJECT and "does not match" in a.detail


def test_eval_rejected_on_forged_authorization_signature():
    # signed by a key the registry does not resolve for eval-authority-1
    rogue = Ed25519PrivateKey.from_private_bytes(bytes(range(50, 82)))
    a = _admit_eval(_eval_receipt(auth_key=rogue))
    assert a.verdict == adm.REJECT and "signature does not verify" in a.detail


def test_eval_rejected_when_finalized_block_outside_window():
    a = _admit_eval(_eval_receipt(), current_block=7_000_000)
    assert a.verdict == adm.REJECT and "block window" in a.detail


def test_eval_not_proven_without_authorization_resolve_time():
    a = _admit_eval(_eval_receipt(), at=None)
    assert a.verdict == adm.NOT_PROVEN


def test_eval_replay_is_consumed_once(tmp_path):
    ledger = ConsumptionLedger(str(tmp_path / "ledger.sqlite"))
    first = _admit_eval(_eval_receipt(), ledger=ledger)
    second = _admit_eval(_eval_receipt(), ledger=ledger)
    assert first.verdict == adm.ADMIT and second.verdict == adm.REJECT


def test_unknown_kind_fails_closed():
    with pytest.raises(adm.AdmissionError):
        adm.verify_admission("mystery", {}, lane="x", key_registry=FX.registry, chain=_chain())
