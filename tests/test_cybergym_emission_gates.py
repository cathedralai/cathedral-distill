"""The anti-gaming gates must sit on the path that actually pays.

`frontier.evaluate_gates` has always known these gates and
`cybergym_validator.derive_cybergym_candidate` derives them from evidence, but
neither was on the emission path: reward flows `run_epoch` -> `cybergym_scores` ->
the external mechanism adapter, and `run_epoch` persisted a score after nothing
but self-verifying its own receipt. A gate that is not on that path does not stop
a payment. PR #11 put the attestation gate on it (`outcome.creditable`); these
tests pin the rest of them there, on the real
`run_epoch -> score store -> compose` path, not on a candidate object.

Every gate is fail-closed: no evidence is a failure, not a skip.
"""
from __future__ import annotations

import hashlib
import sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym_validator as cv  # noqa: E402
from cathedral_distill import frontier as fr  # noqa: E402
from cathedral_distill.bundle_registry import BundleRegistration, BundleRegistry  # noqa: E402
from cathedral_distill.cybergym import Level  # noqa: E402
from cathedral_distill.cybergym_batch import PooledTask, TaskPool  # noqa: E402
from cathedral_distill.cybergym_scores import (  # noqa: E402
    EPOCH_CLOSED,
    CyberGymScoreStore,
)
from cathedral_distill.cybergym_service import (  # noqa: E402
    compose_results_lane,
    compose_scores_lane,
)
from cathedral_distill.lane_feed import Lane, LaneContribution, compose_vector  # noqa: E402

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
CUTOFF = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
ISSUED = "2026-07-27T12:00:00.000000Z"
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PEER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(5, 37)))
SOURCE_EPOCH = 11
TRACK = "cybergym-v0"
MINER = "5Alice"


def _dg(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


COMMITMENT = _dg("alice-checkpoint")


def _pool():
    return TaskPool([
        PooledTask(task_id="arvo:1", level=Level(0), binary_digest=_dg("b1"), disclosed_at=NOW),
        PooledTask(task_id="arvo:2", level=Level(2), binary_digest=_dg("b2"), disclosed_at=NOW),
    ])


def _chain():
    return cv.ChainContext(block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
                           source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460)


def _backend(task_id, poc, mode):
    return 1 if mode == "vul" else 0


def _registry(*, hotkey=MINER, digest=COMMITMENT, registered_at=None):
    registry = BundleRegistry()
    registry.register(
        BundleRegistration(miner_hotkey=hotkey, track=TRACK, bundle_digest=digest,
                           version="v1", registered_at=registered_at or (NOW - timedelta(days=1)),
                           signature="not-checked-here"),
        verify_signature=False,
    )
    return registry


def _run(store, policy, *, miners=None, gates_required=True):
    commits = miners or [
        cv.MinerCommit(miner_hotkey=MINER, model_commitment=COMMITMENT,
                       pocs={"arvo:1": b"poc-1"}),
    ]
    return cv.run_epoch(
        commits, _pool(), _chain(), validator_hotkey="5Validator", private_key=KEY,
        signing_key_id="cybergym-1", backend=_backend, score_store=store,
        cutoff=CUTOFF, as_of=NOW, issued_at=ISSUED, batch_size=2,
        gate_policy=policy, gates_required=gates_required,
    )


def _store(tmp_path, name="scores.sqlite"):
    return CyberGymScoreStore(str(tmp_path / name))


def _compose(store, allocation=Decimal("0.90")):
    """Compose the persisted scores.

    `compose_scores_lane` refuses an epoch that is not marked closed, so a test
    that scores through `run_epoch` directly (no service) states the closure
    itself. The service does this in `score_epoch`, and only when no durable solve
    was lost.
    """
    store.mark_epoch(SOURCE_EPOCH, state=EPOCH_CLOSED, detail="scored in this test")
    return compose_scores_lane(store, SOURCE_EPOCH, allocation=allocation)


# --------------------------------------------------------------------------- #
# No gate decision is not a default
# --------------------------------------------------------------------------- #

def test_run_epoch_refuses_to_score_without_a_gate_policy(tmp_path):
    with pytest.raises(cv.EmissionGateError, match="anti-gaming gate policy"):
        _run(_store(tmp_path), None)


def test_the_dev_opt_out_warns_loudly(tmp_path):
    with pytest.warns(UserWarning, match="NO anti-gaming gates"):
        _run(_store(tmp_path), None, gates_required=False)


# --------------------------------------------------------------------------- #
# Each gate, on the persisted-score path
# --------------------------------------------------------------------------- #

def test_a_passing_epoch_persists_and_composes(tmp_path):
    store = _store(tmp_path)
    policy = cv.EmissionGatePolicy(bundle_registry=_registry())
    results = _run(store, policy)
    assert results[0].creditable and results[0].gate_failures == ()
    assert store.epoch_scores(SOURCE_EPOCH) == {MINER: Decimal("8")}
    lane = _compose(store)
    assert [c.miner_hotkey for c in lane.contributions] == [MINER]


def test_an_unanchored_model_commitment_earns_nothing(tmp_path):
    """The registry knows nothing about this commitment: it cannot be shown to be
    the miner's registered model, and it cannot be shown to pre-date the draw."""
    store = _store(tmp_path)
    results = _run(store, cv.EmissionGatePolicy(bundle_registry=BundleRegistry()))
    assert set(results[0].gate_failures) == {fr.GATE_REGISTERED_BUNDLE, fr.GATE_NO_CONTAMINATION}
    assert not results[0].creditable
    assert store.epoch_scores(SOURCE_EPOCH) == {}          # nothing persisted
    lane = _compose(store)
    assert list(lane.contributions) == []                  # so the share burns


def test_no_bundle_registry_at_all_fails_closed(tmp_path):
    store = _store(tmp_path)
    results = _run(store, cv.EmissionGatePolicy())
    assert fr.GATE_REGISTERED_BUNDLE in results[0].gate_failures
    assert store.epoch_scores(SOURCE_EPOCH) == {}


def test_a_commitment_registered_by_another_miner_earns_nothing(tmp_path):
    store = _store(tmp_path)
    stolen = _registry(hotkey="5Bob")  # Bob registered this digest first
    results = _run(store, cv.EmissionGatePolicy(bundle_registry=stolen))
    assert fr.GATE_REGISTERED_BUNDLE in results[0].gate_failures
    assert store.epoch_scores(SOURCE_EPOCH) == {}


def test_a_commitment_registered_after_the_draw_is_contaminated(tmp_path):
    """Post-commitment drawing is the whole anti-contamination argument: a model
    registered AFTER the batch was drawn cannot be proven not to have seen it."""
    store = _store(tmp_path)
    late = _registry(registered_at=NOW + timedelta(hours=1))
    results = _run(store, cv.EmissionGatePolicy(bundle_registry=late))
    assert fr.GATE_NO_CONTAMINATION in results[0].gate_failures
    assert store.epoch_scores(SOURCE_EPOCH) == {}


def test_an_explicit_commitment_deadline_is_enforced(tmp_path):
    store = _store(tmp_path)
    policy = cv.EmissionGatePolicy(
        bundle_registry=_registry(registered_at=NOW - timedelta(hours=1)),
        commitment_deadline=NOW - timedelta(days=2),  # the epoch's own commit cutoff
    )
    results = _run(store, policy)
    assert fr.GATE_NO_CONTAMINATION in results[0].gate_failures


def test_required_reproduction_is_not_satisfied_by_the_validators_own_receipt(tmp_path):
    """`reproduced` off by default is a documented owner decision, not an oversight:
    with one validator there is no peer, so requiring it zeroes every miner."""
    store = _store(tmp_path)
    policy = cv.EmissionGatePolicy(bundle_registry=_registry(), require_reproduction=True)
    results = _run(store, policy)
    assert fr.GATE_REPRODUCED in results[0].gate_failures
    assert store.epoch_scores(SOURCE_EPOCH) == {}

    # the same epoch, with a genuine peer receipt for the same batch, passes
    peer_store = _store(tmp_path, "peer.sqlite")
    peer = cv.run_epoch(
        [cv.MinerCommit(miner_hotkey=MINER, model_commitment=COMMITMENT, pocs={"arvo:1": b"poc-1"})],
        _pool(), _chain(), validator_hotkey="5PeerValidator", private_key=PEER_KEY,
        signing_key_id="cybergym-peer-1", backend=_backend, score_store=peer_store,
        cutoff=CUTOFF, as_of=NOW, issued_at=ISSUED, batch_size=2, gates_required=False,
    )[0].receipt
    from cathedral_distill.receipt_keys import ReceiptKeyRegistry
    peer_registry = ReceiptKeyRegistry.from_keys(
        {"cybergym-peer-1": PEER_KEY.public_key().public_bytes_raw()}
    )
    reproduced_store = _store(tmp_path, "reproduced.sqlite")
    results = _run(reproduced_store, cv.EmissionGatePolicy(
        bundle_registry=_registry(), require_reproduction=True,
        reproductions={MINER: peer}, reproduction_key_registry=peer_registry,
    ))
    assert results[0].gate_failures == ()
    assert reproduced_store.epoch_scores(SOURCE_EPOCH) == {MINER: Decimal("8")}


def test_required_independent_evaluator_needs_distinct_coldkeys(tmp_path):
    store = _store(tmp_path)
    same_entity = cv.EmissionGatePolicy(
        bundle_registry=_registry(), require_independent_evaluator=True,
        evaluator_coldkey="5Operator", miner_coldkeys={MINER: "5Operator"},
    )
    assert fr.GATE_INDEPENDENT_EVALUATOR in _run(store, same_entity)[0].gate_failures
    assert store.epoch_scores(SOURCE_EPOCH) == {}

    independent_store = _store(tmp_path, "independent.sqlite")
    independent = cv.EmissionGatePolicy(
        bundle_registry=_registry(), require_independent_evaluator=True,
        evaluator_coldkey="5Operator", miner_coldkeys={MINER: "5MinerColdkey"},
    )
    assert _run(independent_store, independent)[0].gate_failures == ()


def test_unknown_miner_coldkey_fails_the_independent_evaluator_gate(tmp_path):
    store = _store(tmp_path)
    policy = cv.EmissionGatePolicy(
        bundle_registry=_registry(), require_independent_evaluator=True,
        evaluator_coldkey="5Operator",  # no coldkey map at all
    )
    assert fr.GATE_INDEPENDENT_EVALUATOR in _run(store, policy)[0].gate_failures


# --------------------------------------------------------------------------- #
# A gated-out miner costs only itself
# --------------------------------------------------------------------------- #

def test_one_gated_miner_does_not_stop_the_others(tmp_path):
    store = _store(tmp_path)
    bob_commitment = _dg("bob-checkpoint")
    registry = _registry()  # only Alice's commitment is registered
    results = _run(store, cv.EmissionGatePolicy(bundle_registry=registry), miners=[
        cv.MinerCommit(miner_hotkey=MINER, model_commitment=COMMITMENT, pocs={"arvo:1": b"a"}),
        cv.MinerCommit(miner_hotkey="5Bob", model_commitment=bob_commitment, pocs={"arvo:1": b"b"}),
    ])
    by_miner = {r.miner_hotkey: r for r in results}
    assert by_miner[MINER].creditable
    assert not by_miner["5Bob"].creditable
    assert store.epoch_scores(SOURCE_EPOCH) == {MINER: Decimal("8")}
    # both receipts still exist for audit; only one was paid
    assert all(r.receipt["schema"] for r in results)


def test_a_gated_miner_earns_nothing_through_the_returned_contribution_either(tmp_path):
    """Both routes out of run_epoch have to agree about who was paid.

    Blocking the score-store write is not enough on its own: callers do compose
    `MinerResult.contribution` directly, and that dict used to carry the full
    positive work_units of a receipt whose gates had failed, so a direct composer
    credited a miner the store had refused.
    """
    store = _store(tmp_path)
    results = _run(store, cv.EmissionGatePolicy(bundle_registry=BundleRegistry()))
    result = results[0]

    assert set(result.gate_failures) == {fr.GATE_REGISTERED_BUNDLE, fr.GATE_NO_CONTAMINATION}
    assert not result.creditable
    # route 1: the durable store
    assert store.epoch_scores(SOURCE_EPOCH) == {}
    # route 2: the returned contribution
    assert result.contribution["work_units"] == "0"
    assert result.contribution["gate_failures"] == list(result.gate_failures)
    # the receipt still records what the miner scored, for audit
    assert result.receipt["score"]["earned_units"] == "8"

    # composing the results directly refuses the gated-out miner
    lane = compose_results_lane(results, allocation=Decimal("0.90"))
    assert list(lane.contributions) == []
    # and even a naive composer that ignores `creditable` cannot credit it, because
    # the units are zero
    naive = Lane("cathedral_cybergym", Decimal("0.90"), [
        LaneContribution(str(r.contribution["miner_hotkey"]),
                         str(r.contribution["receipt_id"]),
                         Decimal(str(r.contribution["work_units"])))
        for r in results
    ])
    feed = compose_vector([naive], burn_hotkey="5Burn")
    assert feed["weights"] == []
    assert feed["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(100.0)


def test_a_passing_miner_still_composes_through_both_routes(tmp_path):
    store = _store(tmp_path)
    results = _run(store, cv.EmissionGatePolicy(bundle_registry=_registry()))
    assert results[0].contribution["work_units"] == "8"
    assert "gate_failures" not in results[0].contribution
    lane = compose_results_lane(results, allocation=Decimal("0.90"))
    assert [c.miner_hotkey for c in lane.contributions] == [MINER]
    assert store.epoch_scores(SOURCE_EPOCH) == {MINER: Decimal("8")}


def test_a_repeated_dispatch_cannot_double_persist(tmp_path):
    """Scoring the same epoch twice must not pay twice: the score store refuses a
    conflicting rewrite and is idempotent for the identical receipt."""
    store = _store(tmp_path)
    policy = cv.EmissionGatePolicy(bundle_registry=_registry())
    first = _run(store, policy)[0]
    second = _run(store, policy)[0]
    assert first.receipt == second.receipt              # byte-identical re-derivation
    assert store.epoch_scores(SOURCE_EPOCH) == {MINER: Decimal("8")}
    lane = _compose(store)
    assert len(lane.contributions) == 1
