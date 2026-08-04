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

import base64
import hashlib
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym_validator as cv  # noqa: E402
from cathedral_distill import frontier as fr  # noqa: E402
from cathedral_distill.bundle_registry import (  # noqa: E402
    BundleRegistration,
    BundleRegistry,
    ed25519_registration_verifier,
    load_registry,
)
from cathedral_distill.cybergym import Level  # noqa: E402
from cathedral_distill.cybergym_batch import PooledTask, TaskPool  # noqa: E402
from cathedral_distill.cybergym_protocol import ProtocolError  # noqa: E402
from cathedral_distill.cybergym_scores import (  # noqa: E402
    EPOCH_CLOSED,
    EPOCH_INCOMPLETE,
    CyberGymScoreError,
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
        PooledTask(task_id="arvo:1", level=Level(0), binary_digest=_dg("b1"), disclosed_at=NOW, admitted=True),
        PooledTask(task_id="arvo:2", level=Level(2), binary_digest=_dg("b2"), disclosed_at=NOW, admitted=True),
    ])


def _chain():
    return cv.ChainContext(block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
                           source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460)


def _backend(task_id, poc, mode):
    return 1 if mode == "vul" else 0


def _registry(*, hotkey=MINER, digest=COMMITMENT, registered_at=None):
    # Default to a model registered BEFORE the private-disclosure window opened
    # (`cutoff`), i.e. a legitimately non-contaminated model. A registration merely
    # before the DRAW (as_of) is not enough — the contamination deadline is `cutoff`.
    at = registered_at or (CUTOFF - timedelta(days=1))
    unsigned = BundleRegistration(
        miner_hotkey=hotkey,
        track=TRACK,
        bundle_digest=digest,
        version="v1",
        registered_at=at,
    )
    registration = BundleRegistration(
        miner_hotkey=hotkey,
        track=TRACK,
        bundle_digest=digest,
        version="v1",
        registered_at=at,
        signature=base64.b64encode(KEY.sign(unsigned.signing_payload())).decode(),
    )
    verifier = ed25519_registration_verifier(
        {hotkey: KEY.public_key().public_bytes_raw()}
    )
    registry = BundleRegistry()
    registry.register(registration, signature_verifier=verifier)
    return registry


def _run(store, policy, *, miners=None, gates_required=True):
    # These tests exercise the pre-snapshot registry gates in isolation. Production
    # policy requires an observed eligibility snapshot; dedicated tests cover that
    # stronger boundary below.
    if policy is not None and policy.eligibility_snapshot is None:
        policy = replace(policy, require_observed_eligibility=False)
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


def test_unsigned_or_presence_only_registry_rows_cannot_satisfy_reward_gates(tmp_path):
    """A public timestamp is not anti-contamination evidence until its signature
    was checked against the miner's anchored key."""
    row = {
        "miner_hotkey": MINER,
        "track": TRACK,
        "bundle_digest": COMMITMENT,
        "version": "v1",
        "registered_at": (NOW - timedelta(days=1)).isoformat(),
        "parent_digest": None,
        "signature": "",
    }
    unsigned = load_registry([row])
    assert unsigned.claim_for(COMMITMENT) is None

    row["signature"] = "present-but-not-verified"
    presence_only = load_registry([row])
    assert presence_only.is_registered_by(COMMITMENT, MINER)
    assert not presence_only.is_cryptographically_verified_by(COMMITMENT, MINER)

    store = _store(tmp_path)
    result = _run(
        store, cv.EmissionGatePolicy(bundle_registry=presence_only)
    )[0]
    assert set(result.gate_failures) == {
        fr.GATE_REGISTERED_BUNDLE,
        fr.GATE_NO_CONTAMINATION,
    }
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


def test_a_model_registered_after_the_cutoff_is_contaminated_even_before_the_draw(tmp_path):
    """The contamination deadline is the private-window START (`cutoff`), not the
    draw time (`as_of`). A model registered inside `(cutoff, as_of]` postdates the
    public disclosure of holdout tasks in that window, so it can solve them by lookup
    and must NOT earn — even though it was registered before the batch was drawn.
    Under the old `as_of` boundary this exact registration wrongly passed."""
    store = _store(tmp_path)
    # 07-26: after cutoff (07-20), before the draw (as_of = NOW = 07-27).
    in_window = _registry(registered_at=NOW - timedelta(days=1))
    results = _run(store, cv.EmissionGatePolicy(bundle_registry=in_window))
    assert fr.GATE_NO_CONTAMINATION in results[0].gate_failures
    assert store.epoch_scores(SOURCE_EPOCH) == {}


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
# The gate's own evidence has to be sound, and unreadable evidence is contained
# --------------------------------------------------------------------------- #

def test_a_registry_that_raises_fails_one_miner_not_the_epoch(tmp_path):
    """One registry lookup failure used to abort the whole epoch: a total lane
    outage from a single bad row. The same containment rule receipts get."""
    class ExplodingRegistry:
        def claim_for(self, digest):
            raise RuntimeError("registry backend unavailable")

        def is_registered_by(self, digest, hotkey):
            raise RuntimeError("registry backend unavailable")

    store = _store(tmp_path)
    results = _run(store, cv.EmissionGatePolicy(bundle_registry=ExplodingRegistry()), miners=[
        cv.MinerCommit(miner_hotkey=MINER, model_commitment=COMMITMENT, pocs={"arvo:1": b"a"}),
        cv.MinerCommit(miner_hotkey="5Bob", model_commitment=_dg("bob"), pocs={"arvo:1": b"b"}),
    ])
    # the epoch completed: both miners were evaluated and both failed closed
    assert len(results) == 2
    assert all(not r.creditable for r in results)
    assert all(fr.GATE_REGISTERED_BUNDLE in r.gate_failures for r in results)
    assert store.epoch_scores(SOURCE_EPOCH) == {}


def test_a_gate_evaluation_that_raises_outright_is_contained(tmp_path):
    """Even a gate evaluator that raises somewhere unanticipated costs one miner."""
    class HostileRegistry:
        def claim_for(self, digest):
            return object()  # not a registration: attribute access will misbehave

        def is_registered_by(self, digest, hotkey):
            return True

    store = _store(tmp_path)
    results = _run(store, cv.EmissionGatePolicy(bundle_registry=HostileRegistry()))
    assert not results[0].creditable
    assert store.epoch_scores(SOURCE_EPOCH) == {}


def test_a_timezone_naive_registration_fails_that_miner_only(tmp_path):
    """`registered_at` arrives from a published row, so it can lack an offset. That
    used to raise `TypeError` mid-comparison and abort the epoch for every miner; an
    unknown offset is not evidence, so it is that miner's gate failure."""
    naive = _registry(registered_at=datetime(2026, 7, 20, 12, 0))
    store = _store(tmp_path)
    results = _run(store, cv.EmissionGatePolicy(bundle_registry=naive), miners=[
        cv.MinerCommit(miner_hotkey=MINER, model_commitment=COMMITMENT, pocs={"arvo:1": b"a"}),
        cv.MinerCommit(miner_hotkey="5Bob", model_commitment=_dg("bob"), pocs={"arvo:1": b"b"}),
    ])
    by_miner = {r.miner_hotkey: r for r in results}
    assert fr.GATE_NO_CONTAMINATION in by_miner[MINER].gate_failures
    # and the registered-bundle gate still passed for it, so only the unreadable
    # timestamp was held against it
    assert fr.GATE_REGISTERED_BUNDLE not in by_miner[MINER].gate_failures
    assert len(results) == 2
    assert store.epoch_scores(SOURCE_EPOCH) == {}


def test_backdating_a_registration_timestamp_is_a_forgery_not_an_edit():
    """`no_contamination` is derived from `registered_at`, so that field is reward
    evidence and has to be inside the signed payload. It was not: the same signature
    covered a post-draw registration and a backdated one, which defeated a gate that
    is ON by default."""
    late = BundleRegistration(
        miner_hotkey=MINER, track=TRACK, bundle_digest=COMMITMENT, version="v1",
        registered_at=NOW + timedelta(hours=1), signature="sig",
    )
    backdated = BundleRegistration(
        miner_hotkey=MINER, track=TRACK, bundle_digest=COMMITMENT, version="v1",
        registered_at=NOW - timedelta(days=1), signature="sig",
    )
    assert late.signing_payload() != backdated.signing_payload()
    assert b"registered_at" in late.signing_payload()


def test_a_backdated_registration_does_not_verify_against_its_own_signature():
    """End to end: signing the honest timestamp then editing it is caught."""
    from cathedral_distill.bundle_registry import ed25519_registration_verifier

    signer = Ed25519PrivateKey.from_private_bytes(bytes(range(9, 41)))
    honest = BundleRegistration(
        miner_hotkey=MINER, track=TRACK, bundle_digest=COMMITMENT, version="v1",
        registered_at=NOW + timedelta(hours=1),
    )
    import base64
    signature = base64.b64encode(signer.sign(honest.signing_payload())).decode()
    honest = BundleRegistration(
        miner_hotkey=MINER, track=TRACK, bundle_digest=COMMITMENT, version="v1",
        registered_at=NOW + timedelta(hours=1), signature=signature,
    )
    verifier = ed25519_registration_verifier(
        {MINER: signer.public_key().public_bytes_raw()}
    )
    BundleRegistry().register(honest, signature_verifier=verifier)  # accepted as signed

    forged = BundleRegistration(
        miner_hotkey=MINER, track=TRACK, bundle_digest=COMMITMENT, version="v1",
        registered_at=NOW - timedelta(days=1), signature=signature,
    )
    with pytest.raises(Exception, match="signature does not verify"):
        BundleRegistry().register(forged, signature_verifier=verifier)


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
    store.mark_epoch(SOURCE_EPOCH, state=EPOCH_CLOSED, detail="scored in this test")
    lane = compose_results_lane(results, score_store=store, epoch=SOURCE_EPOCH,
                                allocation=Decimal("0.90"))
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
    store.mark_epoch(SOURCE_EPOCH, state=EPOCH_CLOSED, detail="scored in this test")
    lane = compose_results_lane(results, score_store=store, epoch=SOURCE_EPOCH,
                                allocation=Decimal("0.90"))
    assert [c.miner_hotkey for c in lane.contributions] == [MINER]
    assert store.epoch_scores(SOURCE_EPOCH) == {MINER: Decimal("8")}


def test_compose_results_lane_refuses_an_epoch_that_never_closed(tmp_path):
    """`compose_results_lane` took only the results, so it structurally could not
    consult the epoch lifecycle the sibling composers gate on: it composed epochs
    the store marks `incomplete` (which `compose_scores_lane` and
    `CyberGymService.compose_lane` both refuse). It now requires the score store
    and applies the same closed-epoch gate."""
    store = _store(tmp_path)
    results = _run(store, cv.EmissionGatePolicy(bundle_registry=_registry()))
    # run_epoch alone never marks the epoch: still open, so composing must refuse
    with pytest.raises(CyberGymScoreError, match="refusing to compose"):
        compose_results_lane(results, score_store=store, epoch=SOURCE_EPOCH,
                             allocation=Decimal("0.90"))
    store.mark_epoch(SOURCE_EPOCH, state=EPOCH_INCOMPLETE, detail="state was lost")
    with pytest.raises(CyberGymScoreError, match="incomplete"):
        compose_results_lane(results, score_store=store, epoch=SOURCE_EPOCH,
                             allocation=Decimal("0.90"))


def test_compose_results_lane_refuses_the_lost_solve_epoch_not_an_empty_lane(tmp_path):
    """The restart shape: durable evidence says miners solved, this process cannot
    score them, so `score_epoch` marks the epoch incomplete and returns no
    results. Composing that `[]` used to publish the silent, empty, 100%-burn
    lane the solve store exists to prevent; it must refuse instead."""
    store = _store(tmp_path)
    store.mark_epoch(SOURCE_EPOCH, state=EPOCH_INCOMPLETE,
                     detail="1 miner(s) with durable solves could not be scored: 5Alice")
    with pytest.raises(CyberGymScoreError, match="incomplete"):
        compose_results_lane([], score_store=store, epoch=SOURCE_EPOCH,
                             allocation=Decimal("0.90"))


def test_compose_results_lane_refuses_results_from_another_epoch(tmp_path):
    """The closed-epoch marker is per epoch, so it only vouches for the epoch the
    results were actually scored under: epoch N+1 closing cleanly must not admit
    results scored under epoch N."""
    store = _store(tmp_path)
    results = _run(store, cv.EmissionGatePolicy(bundle_registry=_registry()))
    store.mark_epoch(SOURCE_EPOCH + 1, state=EPOCH_CLOSED, detail="a different epoch")
    with pytest.raises(ProtocolError, match="scored under epoch"):
        compose_results_lane(results, score_store=store, epoch=SOURCE_EPOCH + 1,
                             allocation=Decimal("0.90"))


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
