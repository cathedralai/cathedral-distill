"""CyberGym validator-side: signed receipt, chain-anchored nonce, durable score
store, and the full hardware-free epoch loop into the shared feed (issue #4).
"""
from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym as cg  # noqa: E402
from cathedral_distill import cybergym_batch as cb  # noqa: E402
from cathedral_distill import cybergym_receipt as cr  # noqa: E402
from cathedral_distill import lane_feed as lf  # noqa: E402
from cathedral_distill.cybergym_scores import CyberGymScoreStore, CyberGymScoreError  # noqa: E402
from cathedral_distill import cybergym_validator as cv  # noqa: E402
from datetime import UTC, datetime  # noqa: E402

_SEED = bytes(range(32))
KEY = Ed25519PrivateKey.from_private_bytes(_SEED)
PUB = KEY.public_key()
from cathedral_distill.receipt_keys import ReceiptKeyRegistry  # noqa: E402
KEYREG = ReceiptKeyRegistry.from_keys({"cybergym-test-1": PUB.public_bytes_raw()})

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
CUTOFF = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
BLOCK_HASH = "0x" + "cd" * 32
ISSUED = "2026-07-27T12:00:00.000000Z"
SOURCE_EPOCH = 11


def _digest(seed: str) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _pool():
    tasks = [
        cb.PooledTask(task_id=f"arvo:{n}", level=cg.Level(level), binary_digest=_digest(f"bin-{n}"),
                      disclosed_at=NOW)  # after cutoff -> private holdout
        for n, level in enumerate((0, 1, 2), start=1)
    ]
    return cb.TaskPool(tasks)


def _backend(solved_task_ids):
    """vul crashes (1) + fix clean (0) => solved; both clean otherwise."""
    def run(task_id, poc, mode):
        if task_id in solved_task_ids and mode == "vul":
            return 1
        return 0
    return run


def _batch_score(solved=("arvo:1", "arvo:2")):
    pool = _pool()
    nonce = cb.derive_batch_nonce(
        block=100, block_hash=BLOCK_HASH, network="finney", netuid=39,
        source_epoch=SOURCE_EPOCH, miner_hotkey="5Miner", model_commitment=_digest("ckpt"))
    batch = cb.draw_batch(pool, size=3, nonce=nonce, as_of=NOW, cutoff=CUTOFF)
    subs = []
    for task in batch.tasks:
        result = cv.verify_poc(task, b"poc-" + task.task_id.encode(), _backend(solved))
        subs.append(cg.PoCSubmission(task_id=task.task_id,
                                     poc_sha256=cr.holdout_digest([task.task_id]).replace(
                                         "sha256:", "sha256:"),
                                     result=result))
    return batch, nonce, cg.score_batch(batch.batch_id, list(batch.tasks), subs)


def _receipt(**over):
    batch, nonce, score = _batch_score(over.pop("solved", ("arvo:1", "arvo:2")))
    kw = dict(
        network="finney", netuid=39, source_epoch=SOURCE_EPOCH,
        validator_hotkey="5Validator", miner_hotkey="5Miner", nonce=nonce,
        holdout_digest_value=cr.holdout_digest(list(batch.task_ids)),
        valid_from_block=100, valid_until_block=460, issued_at=ISSUED,
        private_key=KEY, signing_key_id="cybergym-test-1")
    kw.update(over)
    return cr.build_receipt(score, **kw)


# --------------------------------------------------------------------------- #
# Chain-anchored nonce
# --------------------------------------------------------------------------- #

def test_nonce_is_deterministic_and_reproducible():
    args = dict(block=100, block_hash=BLOCK_HASH, network="finney", netuid=39,
                source_epoch=SOURCE_EPOCH, miner_hotkey="5Miner",
                model_commitment=_digest("ckpt"))
    assert cb.derive_batch_nonce(**args) == cb.derive_batch_nonce(**args)


def test_nonce_changes_with_block_miner_and_commitment():
    base = dict(block=100, block_hash=BLOCK_HASH, network="finney", netuid=39,
                source_epoch=SOURCE_EPOCH, miner_hotkey="5Miner",
                model_commitment=_digest("ckpt"))
    n0 = cb.derive_batch_nonce(**base)
    assert cb.derive_batch_nonce(**{**base, "block_hash": "0x" + "ab" * 32}) != n0
    assert cb.derive_batch_nonce(**{**base, "miner_hotkey": "5Other"}) != n0
    assert cb.derive_batch_nonce(**{**base, "model_commitment": _digest("other")}) != n0


def test_nonce_rejects_bad_commitment_and_block():
    good = dict(block=100, block_hash=BLOCK_HASH, network="finney", netuid=39,
                source_epoch=SOURCE_EPOCH, miner_hotkey="5Miner",
                model_commitment=_digest("ckpt"))
    with pytest.raises(cb.BatchError, match="model_commitment"):
        cb.derive_batch_nonce(**{**good, "model_commitment": "not-a-digest"})
    with pytest.raises(cb.BatchError, match="block_hash"):
        cb.derive_batch_nonce(**{**good, "block_hash": "0xzz"})


# --------------------------------------------------------------------------- #
# Signed receipt
# --------------------------------------------------------------------------- #

def test_receipt_verifies_end_to_end():
    doc = cr.verify_receipt(_receipt(), KEYREG, source_epoch=SOURCE_EPOCH)
    assert doc["score"]["work_units"] == "12"     # 8 (level0) + 4 (level1)
    assert doc["score"]["score"] == "0.857142857143"


def test_receipt_id_recomputes():
    r = _receipt()
    assert r["receipt_id"] == cr.compute_receipt_id(r)


def test_work_units_are_rederived_from_solves_and_weights():
    r = _receipt()
    # claim more earned units than the solves justify
    r["score"]["earned_units"] = "20"
    r["score"]["work_units"] = "20"
    with pytest.raises(cr.CyberGymReceiptError, match="earned_units does not match"):
        cr.verify_receipt(r, KEYREG, source_epoch=SOURCE_EPOCH)


def test_tampering_breaks_receipt_id_then_signature():
    # Tamper a field that is not internally re-derived, so the receipt_id check
    # is what catches it (a tampered score is caught earlier by the score/units
    # consistency check — see test_work_units_are_rederived_from_solves_and_weights).
    r = _receipt()
    r["validator_hotkey"] = "5Evil"
    with pytest.raises(cr.CyberGymReceiptError, match="receipt_id"):
        cr.verify_receipt(r, KEYREG, source_epoch=SOURCE_EPOCH)
    r["receipt_id"] = cr.compute_receipt_id(r)      # relabel it
    with pytest.raises(cr.CyberGymReceiptError, match="signature"):
        cr.verify_receipt(r, KEYREG, source_epoch=SOURCE_EPOCH)


def test_wrong_key_fails_signature():
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key()
    wrong = ReceiptKeyRegistry.from_keys({"cybergym-test-1": other.public_bytes_raw()})
    with pytest.raises(cr.CyberGymReceiptError, match="signature"):
        cr.verify_receipt(_receipt(), wrong, source_epoch=SOURCE_EPOCH)


def test_replay_across_epochs_is_rejected():
    with pytest.raises(cr.CyberGymReceiptError, match="source_epoch"):
        cr.verify_receipt(_receipt(), KEYREG, source_epoch=SOURCE_EPOCH + 1)


def test_unknown_field_fails_closed():
    r = _receipt()
    r["surprise"] = 1
    with pytest.raises(cr.CyberGymReceiptError, match="unknown keys"):
        cr.verify_receipt(r, KEYREG, source_epoch=SOURCE_EPOCH)


def test_floats_are_rejected():
    with pytest.raises(cr.CyberGymReceiptError, match="floats"):
        cr.canonical_bytes({"score": 0.5})


def test_solved_cannot_exceed_graded():
    r = _receipt()
    r["score"]["solved_tasks"] = 99
    with pytest.raises(cr.CyberGymReceiptError, match="exceeds graded"):
        cr.verify_receipt(r, KEYREG, source_epoch=SOURCE_EPOCH)


# --------------------------------------------------------------------------- #
# Durable score store (the adapter's source)
# --------------------------------------------------------------------------- #

def test_score_store_records_and_reads_back(tmp_path):
    store = CyberGymScoreStore(str(tmp_path / "scores.sqlite"))
    store.record(_receipt())
    assert store.epoch_scores(SOURCE_EPOCH) == {"5Miner": Decimal("12")}
    assert store.score_for("5Miner", SOURCE_EPOCH) == Decimal("12")


def test_score_store_is_idempotent_for_same_receipt(tmp_path):
    store = CyberGymScoreStore(str(tmp_path / "scores.sqlite"))
    r = _receipt()
    store.record(r)
    store.record(r)                              # no error, no double count
    assert store.epoch_scores(SOURCE_EPOCH) == {"5Miner": Decimal("12")}


def test_score_store_refuses_conflicting_rescore(tmp_path):
    store = CyberGymScoreStore(str(tmp_path / "scores.sqlite"))
    store.record(_receipt(solved=("arvo:1", "arvo:2")))     # earns 12
    with pytest.raises(CyberGymScoreError, match="conflicting"):
        store.record(_receipt(solved=("arvo:1",)))          # would earn 8 -> refused


def test_score_store_rejects_malformed_receipt(tmp_path):
    store = CyberGymScoreStore(str(tmp_path / "scores.sqlite"))
    r = _receipt()
    del r["score"]["items_root"]
    with pytest.raises(cr.CyberGymReceiptError):
        store.record(r)


# --------------------------------------------------------------------------- #
# Full epoch loop -> shared feed
# --------------------------------------------------------------------------- #

def test_full_epoch_persists_scores_and_feeds_the_vector(tmp_path):
    store = CyberGymScoreStore(str(tmp_path / "scores.sqlite"))
    chain = cv.ChainContext(block=100, block_hash=BLOCK_HASH, network="finney", netuid=39,
                            source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460)
    miners = [
        cv.MinerCommit(miner_hotkey="5Alice", model_commitment=_digest("alice"),
                       pocs={"arvo:1": b"a1", "arvo:2": b"a2"}),      # solves 2
        cv.MinerCommit(miner_hotkey="5Bob", model_commitment=_digest("bob"),
                       pocs={"arvo:1": b"b1"}),                       # solves 1
    ]
    backend = _backend({"arvo:1", "arvo:2"})
    results = cv.run_epoch(
        miners, _pool(), chain, validator_hotkey="5Validator", private_key=KEY,
        signing_key_id="cybergym-test-1", backend=backend, score_store=store,
        cutoff=CUTOFF, as_of=NOW, issued_at=ISSUED, batch_size=3, gates_required=False)

    assert {r.miner_hotkey for r in results} == {"5Alice", "5Bob"}
    # every receipt independently verifies, and each miner drew its own batch
    for r in results:
        cr.verify_receipt(r.receipt, KEYREG, source_epoch=SOURCE_EPOCH)
    assert results[0].batch.batch_id != results[1].batch.batch_id

    # verified units persisted for the adapter to read
    assert store.epoch_scores(SOURCE_EPOCH) == {"5Alice": Decimal("12"), "5Bob": Decimal("8")}

    # the contributions compose into the signed vector alongside a compute lane
    cyber = lf.Lane("cathedral_cybergym", Decimal("0.45"), [
        lf.LaneContribution(miner_hotkey=r.contribution["miner_hotkey"],
                            receipt_id=r.contribution["receipt_id"],
                            work_units=Decimal(r.contribution["work_units"]))
        for r in results
    ])
    compute = lf.Lane("cathedral_confidential_tdx", Decimal("0.45"), [
        lf.LaneContribution(miner_hotkey="5ComputeMiner",
                            receipt_id="receipt-" + _digest("c"), work_units=Decimal("3.5"))])
    feed = lf.compose_vector([cyber, compute], burn_hotkey="5Burn")
    miners_in_feed = {w["miner_hotkey"] for w in feed["weights"]}
    assert miners_in_feed == {"5Alice", "5Bob", "5ComputeMiner"}
    assert feed["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(10.0)


# --------------------------------------------------------------------------- #
# CyberGym candidate derivation (#4): gates from a verified receipt, no booleans
# --------------------------------------------------------------------------- #

def _chain():
    return cv.ChainContext(block=100, block_hash=BLOCK_HASH, network="finney", netuid=39,
                           source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460)


def _bundle_reg(model_commitment, hotkey="5Miner"):
    from cathedral_distill import bundle_registry as br
    reg = br.BundleRegistry()
    reg.register(br.BundleRegistration(miner_hotkey=hotkey, track="cybergym-v0",
                 bundle_digest=model_commitment, version="v1", registered_at=NOW, signature="s"),
                 verify_signature=False)
    return reg


def test_derived_cybergym_candidate_crowns():
    from cathedral_distill import frontier as fr
    mc = _digest("ckpt")
    cand = cv.derive_cybergym_candidate(
        _receipt(), KEYREG, source_epoch=SOURCE_EPOCH, chain=_chain(), model_commitment=mc,
        miner_coldkey="ck-miner", evaluator_coldkey="ck-val", bundle_registry=_bundle_reg(mc),
        reproduction=_receipt(validator_hotkey="5Validator2"), attestation_verified=True)
    assert cand.evidence_verified and cand.attested and not cand.contamination_detected
    policy = cv.cybergym_track_policy()
    dec = fr.Frontier([policy]).submit(policy.track, cand)
    assert dec.crowned, dec.reason


def test_cybergym_candidate_fails_attested_gate_without_tdx_evidence():
    """A valid receipt signature must NOT rubber-stamp the mandatory attested gate:
    without a real TDX attestation result, attested is False and the gate fails."""
    from cathedral_distill import frontier as fr
    mc = _digest("ckpt")
    cand = cv.derive_cybergym_candidate(
        _receipt(), KEYREG, source_epoch=SOURCE_EPOCH, chain=_chain(), model_commitment=mc,
        miner_coldkey="ck-miner", evaluator_coldkey="ck-val", bundle_registry=_bundle_reg(mc),
        reproduction=_receipt(validator_hotkey="5Validator2"))   # attestation_verified defaults False
    assert cand.evidence_verified and not cand.attested
    gates = fr.evaluate_gates(cand, cv.cybergym_track_policy())
    assert fr.GATE_ATTESTED_RECEIPT in gates.failures


def test_derived_candidate_detects_contamination_on_nonce_mismatch():
    mc = _digest("ckpt")
    bad_chain = cv.ChainContext(block=999, block_hash=BLOCK_HASH, network="finney", netuid=39,
                                source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460)
    cand = cv.derive_cybergym_candidate(_receipt(), KEYREG, source_epoch=SOURCE_EPOCH,
        chain=bad_chain, model_commitment=mc, miner_coldkey="a", evaluator_coldkey="b",
        bundle_registry=_bundle_reg(mc))
    assert cand.contamination_detected     # nonce from block 999 != the receipt's nonce


def test_self_evaluation_fails_the_independent_gate():
    from cathedral_distill import frontier as fr
    mc = _digest("ckpt")
    cand = cv.derive_cybergym_candidate(_receipt(), KEYREG, source_epoch=SOURCE_EPOCH,
        chain=_chain(), model_commitment=mc, miner_coldkey="same", evaluator_coldkey="same",
        bundle_registry=_bundle_reg(mc), reproduction=_receipt(validator_hotkey="5Validator2"),
        attestation_verified=True)
    assert not cand.independent_evaluator
    gates = fr.evaluate_gates(cand, cv.cybergym_track_policy())
    assert fr.GATE_INDEPENDENT_EVALUATOR in gates.failures


def test_cybergym_track_does_not_require_the_teacher_gate():
    from cathedral_distill import frontier as fr
    policy = cv.cybergym_track_policy()
    assert fr.GATE_TEACHER_PERMITTED not in policy.required_gates
    assert fr.GATE_ATTESTED_RECEIPT in policy.required_gates


def test_raw_candidate_is_refused_by_submit():
    from cathedral_distill import frontier as fr
    raw = fr.Candidate(miner_hotkey="5X", bundle_digest="sha256:" + "aa" * 32,
        checkpoint_digest="sha256:" + "aa" * 32, receipt_id="not-a-receipt",
        score=Decimal("0.9"), latency_p50_ms=Decimal(0), cost_usd=Decimal(0),
        submitted_at=NOW, attested=True, reproduced=True, contamination_detected=False,
        registered_bundle=True, independent_evaluator=True)  # evidence_verified defaults False
    policy = cv.cybergym_track_policy()
    dec = fr.Frontier([policy]).submit(policy.track, raw)
    assert not dec.crowned and dec.reason == "unverified_candidate"


def test_full_epoch_is_byte_identical_on_re_run(tmp_path):
    import json

    def _epoch(tag):
        store = CyberGymScoreStore(str(tmp_path / f"scores-{tag}.sqlite"))
        chain = cv.ChainContext(block=100, block_hash=BLOCK_HASH, network="finney", netuid=39,
                                source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460)
        miners = [
            cv.MinerCommit(miner_hotkey="5Alice", model_commitment=_digest("alice"),
                           pocs={"arvo:1": b"a1", "arvo:2": b"a2"}),
            cv.MinerCommit(miner_hotkey="5Bob", model_commitment=_digest("bob"),
                           pocs={"arvo:1": b"b1"}),
        ]
        results = cv.run_epoch(
            miners, _pool(), chain, validator_hotkey="5Validator", private_key=KEY,
            signing_key_id="cybergym-test-1", backend=_backend({"arvo:1", "arvo:2"}),
            score_store=store, cutoff=CUTOFF, as_of=NOW, issued_at=ISSUED, batch_size=3,
            gates_required=False)
        cyber = lf.Lane("cathedral_cybergym", Decimal("0.90"), [
            lf.LaneContribution(miner_hotkey=r.contribution["miner_hotkey"],
                                receipt_id=r.contribution["receipt_id"],
                                work_units=Decimal(r.contribution["work_units"]))
            for r in results])
        feed = lf.compose_vector([cyber], burn_hotkey="5Burn")
        return json.dumps(feed, sort_keys=True), [r.receipt["receipt_id"] for r in results]

    feed_a, ids_a = _epoch("a")
    feed_b, ids_b = _epoch("b")
    # commit -> draw -> verify -> sign -> persist -> compose is fully deterministic:
    # the same chain state + commitments reproduce byte-identical receipts and vector.
    assert feed_a == feed_b
    assert ids_a == ids_b


def test_integrated_feed_enforces_the_finalized_block_window():
    # The composition path must not be weaker than admission.verify_admission: a
    # CyberGym receipt outside its authorized block window is FAIL (its share goes
    # to burn), not a silent PASS. Back-compatible: no current_block -> unchecked.
    from cathedral_distill import integrated_feed as itf

    r = _receipt()  # valid_from_block=100, valid_until_block=460
    passes = itf.verify_lane_receipt(itf.KIND_CYBERGYM, r, lane="cathedral_cybergym",
                                     key_registry=KEYREG, source_epoch=SOURCE_EPOCH)
    assert passes.verdict == "PASS"                                   # no current_block: unchecked
    in_window = itf.verify_lane_receipt(itf.KIND_CYBERGYM, r, lane="cathedral_cybergym",
                                        key_registry=KEYREG, source_epoch=SOURCE_EPOCH, current_block=200)
    assert in_window.verdict == "PASS"
    out = itf.verify_lane_receipt(itf.KIND_CYBERGYM, r, lane="cathedral_cybergym",
                                  key_registry=KEYREG, source_epoch=SOURCE_EPOCH, current_block=999)
    assert out.verdict == "FAIL" and "outside authorized window" in out.detail
