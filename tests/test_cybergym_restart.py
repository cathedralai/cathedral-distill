"""A validator restart must not turn a solved epoch into a silent 100% burn.

The crash point that matters is not "after epoch close"; that state was already
durable. It is the whole scoring window: from the first accepted submission until
`score_epoch` runs, every miner's accepted PoCs lived only in
`CyberGymService._miners`. A restart there (SIGKILL, redeploy, OOM) lost all of
them while the corpus rows survived on disk, and the next `compose_lane` composed
an empty lane, which is indistinguishable from an epoch nobody solved: the lane's
whole allocation was forcibly burned and no operator signal said why.

Two behaviours are pinned here, and they are the only two acceptable ones:

  * with a durable solve store, a restarted service recovers the accepted solves
    and scores the epoch byte-identically to the process that was killed;
  * with no durable solve store, the restarted service REFUSES to compose the
    lane, naming the miners whose durable solves it cannot account for.
"""
from __future__ import annotations

import base64
import hashlib
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.bundle_registry import (  # noqa: E402
    BundleRegistration,
    BundleRegistry,
    ed25519_registration_verifier,
)
from cathedral_distill.cybergym_holdout import load_holdout  # noqa: E402
from cathedral_distill.cybergym_protocol import (  # noqa: E402
    CyberGymCorpusStore,
    ProtocolError,
    SubmissionEnvelope,
)
from cathedral_distill.cybergym_scores import (  # noqa: E402
    EPOCH_CLOSED,
    EPOCH_INCOMPLETE,
    EPOCH_OPEN,
    CyberGymScoreError,
    CyberGymScoreStore,
    CyberGymSolveStore,
)
from cathedral_distill.cybergym_service import CyberGymService, compose_scores_lane  # noqa: E402
from cathedral_distill.cybergym_validator import (  # noqa: E402
    ChainContext,
    EmissionGatePolicy,
)
from cathedral_distill.cybergym_verifier import poc_digest  # noqa: E402

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
CUTOFF = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
ISSUED = "2026-07-27T12:00:00.000000Z"
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
MODEL = "sha256:" + hashlib.sha256(b"ckpt").hexdigest()
OTHER_MODEL = "sha256:" + hashlib.sha256(b"ckpt-2").hexdigest()
SOURCE_EPOCH = 11


def _dg(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _manifest():
    return [
        {"task_id": "arvo:1", "level": 0, "binary_digest": _dg("b1"),
         "disclosed_at": "2026-07-27T00:00:00Z"},
        {"task_id": "arvo:2", "level": 2, "binary_digest": _dg("b2"),
         "disclosed_at": "2026-07-27T00:00:00Z"},
    ]


def _chain():
    return ChainContext(block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
                        source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460)


def _backend(task_id, poc, mode):
    return 1 if (task_id == "arvo:1" and mode == "vul") else 0


def _trace(task_id, poc_sha256):
    long = ("I walk the parser and read the length field then compare it against the "
            "destination buffer size to see whether an attacker controlled value can "
            "exceed the allocation and corrupt adjacent heap metadata on the vulnerable "
            "build only")
    steps = [
        {"step": 1, "thought": f"open valid.c:1897 and read the header length; {long}", "action": "read_file"},
        {"step": 2, "thought": f"cross-check parse.c:44 for the bound; {long}", "action": "read_file"},
        {"step": 3, "thought": f"the length at valid.c:1900 is trusted so it overflows; {long}", "action": "reason"},
        {"step": 4, "thought": f"write the PoC with an oversized length header; {long}", "action": "write_poc"},
        {"step": 5, "thought": f"confirm the sanitizer fires on vul and not fix; {long}", "action": "verify"},
    ]
    return {"task_id": task_id, "poc_sha256": poc_sha256, "model_id": "cathedral/agent-v1",
            "steps": steps, "licence": "cathedral-corpus-v1", "model_seal": _dg("seal")}


def _verified_registry(*, digest=MODEL, hotkey="5Miner", registered_at=CUTOFF):
    unsigned = BundleRegistration(
        miner_hotkey=hotkey,
        track="cybergym-v0",
        bundle_digest=digest,
        version="v1",
        registered_at=registered_at,
    )
    signed = BundleRegistration(
        miner_hotkey=hotkey,
        track="cybergym-v0",
        bundle_digest=digest,
        version="v1",
        registered_at=registered_at,
        signature=base64.b64encode(KEY.sign(unsigned.signing_payload())).decode(),
    )
    registry = BundleRegistry()
    registry.register(
        signed,
        signature_verifier=ed25519_registration_verifier(
            {hotkey: KEY.public_key().public_bytes_raw()}
        ),
    )
    return registry


def _service(
    tmp_path,
    *,
    durable: bool,
    chain=None,
    batch_size: int = 2,
    gate_policy: EmissionGatePolicy | None = None,
    gates_required: bool = False,
):
    """A service over the SAME storage every time, so a new one is a restart."""
    kwargs = {}
    if durable:
        kwargs["solve_store"] = CyberGymSolveStore(str(tmp_path / "solves.sqlite"))
    else:
        kwargs["solve_durability_required"] = False
    return CyberGymService(
        load_holdout(_manifest()), chain or _chain(), backend=_backend,
        corpus_store=CyberGymCorpusStore(str(tmp_path / "corpus.sqlite")),
        score_store=CyberGymScoreStore(str(tmp_path / "scores.sqlite")),
        validator_hotkey="5Val", private_key=KEY, signing_key_id="cybergym-1",
        batch_size=batch_size, cutoff=CUTOFF, as_of=NOW, attestation_required=False,
        gate_policy=gate_policy, gates_required=gates_required, **kwargs,
    )


def _solve(service, miner="5Miner", model=MODEL):
    dispatched = service.dispatch_for(miner, model)
    poc = b"exploit-bytes-for-arvo-1"
    outcome = service.submit(SubmissionEnvelope(
        batch_id=dispatched.batch_id, task_id="arvo:1", miner_hotkey=miner,
        poc_base64=base64.b64encode(poc).decode(),
        trace=_trace("arvo:1", poc_digest(poc)),
    ))
    assert outcome.creditable, outcome.reason
    return dispatched


# --------------------------------------------------------------------------- #
# Recover
# --------------------------------------------------------------------------- #

def test_a_restart_before_epoch_close_recovers_the_accepted_solves(tmp_path):
    killed = _service(tmp_path, durable=True)
    _solve(killed)
    assert killed._corpus.size() == 1
    # the process dies here: score_epoch never ran, so nothing is in cybergym_scores
    assert killed._scores.epoch_scores(SOURCE_EPOCH) == {}
    del killed

    restarted = _service(tmp_path, durable=True)
    assert restarted.lost_durable_solvers() == set()      # nothing lost
    assert restarted.pending_solvers() == {"5Miner"}      # recovered, not yet scored
    results = restarted.score_epoch(issued_at=ISSUED)
    assert [r.miner_hotkey for r in results] == ["5Miner"]
    assert restarted._scores.epoch_scores(SOURCE_EPOCH) == {"5Miner": Decimal("8")}

    lane = restarted.compose_lane(allocation=Decimal("0.90"))
    assert [c.miner_hotkey for c in lane.contributions] == ["5Miner"]
    assert lane.contributions[0].work_units == Decimal("8")


def test_recovered_scoring_is_byte_identical_to_the_uninterrupted_run(tmp_path):
    """Recovery must reproduce the RECEIPT, not merely a similar score.

    The two runs deliberately do NOT share a chain fixture: the clean run is
    anchored by one literally-constructed ChainContext and the crashed one by
    another, so the equality is a property of equal INPUTS rather than of a shared
    object, which is what the earlier version of this test actually proved.

    `issued_at` is the epoch-close timestamp the caller supplies, and it is part of
    the receipt bytes, so both runs pass the same one, exactly as an epoch scheduler
    would derive it from the epoch. What is NOT the caller's problem is a re-score:
    once a pass has run, the timestamp is pinned and reused, which
    `test_a_rescore_reuses_the_pinned_issue_timestamp` covers.
    """
    clean_run = tmp_path / "a"
    crashed_run = tmp_path / "b"
    clean_run.mkdir()
    crashed_run.mkdir()

    clean_chain = ChainContext(
        block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
        source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460,
    )
    crashed_chain = ChainContext(
        block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
        source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460,
    )
    assert clean_chain is not crashed_chain

    uninterrupted = _service(clean_run, durable=True, chain=clean_chain)
    _solve(uninterrupted)
    expected = uninterrupted.score_epoch(issued_at=ISSUED)[0]

    killed = _service(crashed_run, durable=True, chain=crashed_chain)
    _solve(killed)
    del killed
    restarted = _service(crashed_run, durable=True, chain=crashed_chain)
    recovered = restarted.score_epoch(issued_at=ISSUED)[0]

    assert recovered.receipt == expected.receipt
    assert recovered.contribution == expected.contribution


def test_a_rescore_reuses_the_pinned_issue_timestamp(tmp_path):
    """A second scoring pass over the same epoch must not re-sign it at a new time.

    `issued_at` is inside the receipt bytes, so a retry with a fresh wall-clock
    timestamp would produce a different receipt (and a different receipt_id) for the
    same epoch's work. The first pass pins it; later passes reuse it.
    """
    service = _service(tmp_path, durable=True)
    _solve(service)
    first = service.score_epoch(issued_at=ISSUED)[0]

    later = _service(tmp_path, durable=True)
    again = later.score_epoch(issued_at="2026-07-27T18:45:00.000000Z")[0]
    assert again.receipt["issued_at"] == ISSUED
    assert again.receipt == first.receipt


def test_a_restart_under_a_different_chain_anchor_is_refused(tmp_path):
    """Recovering the PoCs is not recovering the epoch.

    The batch nonce is derived from the finalized block and block hash, so a restart
    that resumed the same `source_epoch` at a different block drew a different batch
    and signed a different receipt for that epoch, and nothing noticed: the score
    persisted and no refusal fired. The epoch's inputs are pinned, so this now
    refuses and names what changed.
    """
    killed = _service(tmp_path, durable=True)
    _solve(killed)
    del killed

    moved_on = ChainContext(
        block=512, block_hash="0x" + "ab" * 32, network="finney", netuid=39,
        source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460,
    )
    with pytest.raises(ProtocolError, match="already pinned to different scoring inputs"):
        _service(tmp_path, durable=True, chain=moved_on)


def test_a_restart_that_changes_the_batch_size_is_refused(tmp_path):
    """Any input that changes what the epoch draws or signs counts, not just the
    block: a different batch size draws a different set from the same nonce."""
    killed = _service(tmp_path, durable=True)
    _solve(killed)
    del killed
    with pytest.raises(ProtocolError, match="batch_size"):
        _service(tmp_path, durable=True, batch_size=1)


def test_the_pinned_epoch_manifest_covers_every_scoring_input(tmp_path):
    service = _service(tmp_path, durable=True)
    manifest = service.epoch_manifest()
    assert set(manifest) == {
        "schema", "source_epoch", "network", "netuid", "block", "block_hash",
        "valid_from_block", "valid_until_block", "batch_size", "cutoff", "as_of",
        "validator_hotkey", "signing_key_id", "signing_public_key_digest",
        "level_weights", "credit_synthetic_tasks", "task_source", "gates_required", "gate_policy",
    }
    assert manifest["gates_required"] is False
    assert manifest["gate_policy"] is None
    assert manifest["task_source"] is None
    pinned = service._solves.manifest_for(SOURCE_EPOCH)
    assert pinned["manifest"] == manifest
    assert pinned["digest"].startswith("sha256:")


def test_restart_that_changes_reward_gate_policy_is_refused(tmp_path):
    killed = _service(
        tmp_path,
        durable=True,
        gate_policy=EmissionGatePolicy(
            bundle_registry=_verified_registry(),
            require_reproduction=True,
            require_observed_eligibility=False,
        ),
        gates_required=True,
    )
    _solve(killed)
    del killed

    with pytest.raises(ProtocolError, match="gate_policy"):
        _service(
            tmp_path,
            durable=True,
            gate_policy=EmissionGatePolicy(
            bundle_registry=_verified_registry(),
            require_reproduction=False,
            require_observed_eligibility=False,
            ),
            gates_required=True,
        )


def test_restart_that_changes_reward_registry_identity_is_refused(tmp_path):
    killed = _service(
        tmp_path,
        durable=True,
        gate_policy=EmissionGatePolicy(
            bundle_registry=_verified_registry(), require_observed_eligibility=False
        ),
        gates_required=True,
    )
    _solve(killed)
    del killed

    with pytest.raises(ProtocolError, match="gate_policy"):
        _service(
            tmp_path,
            durable=True,
            gate_policy=EmissionGatePolicy(
                bundle_registry=_verified_registry(digest=OTHER_MODEL),
                require_observed_eligibility=False,
            ),
            gates_required=True,
        )


def test_restart_that_changes_reproduction_evidence_is_refused(tmp_path):
    killed = _service(
        tmp_path,
        durable=True,
        gate_policy=EmissionGatePolicy(
            bundle_registry=_verified_registry(),
            require_reproduction=True,
            reproductions={"5Miner": {"receipt_id": "receipt-a"}},
            require_observed_eligibility=False,
        ),
        gates_required=True,
    )
    _solve(killed)
    del killed

    with pytest.raises(ProtocolError, match="gate_policy"):
        _service(
            tmp_path,
            durable=True,
            gate_policy=EmissionGatePolicy(
                bundle_registry=_verified_registry(),
            require_reproduction=True,
            reproductions={"5Miner": {"receipt_id": "receipt-b"}},
            require_observed_eligibility=False,
            ),
            gates_required=True,
        )


# --------------------------------------------------------------------------- #
# Or refuse
# --------------------------------------------------------------------------- #

def test_a_restart_with_no_durable_solve_store_refuses_to_publish(tmp_path):
    with pytest.warns(UserWarning, match="WITHOUT a durable solve store"):
        killed = _service(tmp_path, durable=False)
    _solve(killed)
    assert killed._corpus.size() == 1
    del killed

    with pytest.warns(UserWarning, match="WITHOUT a durable solve store"):
        restarted = _service(tmp_path, durable=False)
    # the corpus proves 5Miner solved this epoch; this process cannot score it
    assert restarted.lost_durable_solvers() == {"5Miner"}
    restarted.score_epoch(issued_at=ISSUED)  # scores nothing: the solves are gone
    assert restarted._scores.epoch_scores(SOURCE_EPOCH) == {}

    # composing here would emit a vector that burns the whole lane and looks
    # exactly like an epoch nobody solved. Refuse instead.
    with pytest.raises(ProtocolError, match="refusing to compose"):
        restarted.compose_lane(allocation=Decimal("0.90"))


def test_the_store_reading_composer_also_refuses_a_lost_epoch(tmp_path):
    """The refusal has to live where the ADAPTER can see it.

    `CyberGymService.compose_lane` knows about lost solves, but the exported
    `compose_scores_lane` and the external mechanism adapter read the
    `cybergym_scores` table directly, so they could not see that knowledge and
    happily composed an empty 100%-burn lane after a restart lost the epoch. The
    epoch's state is therefore persisted in the SAME database the adapter reads.
    """
    with pytest.warns(UserWarning, match="WITHOUT a durable solve store"):
        killed = _service(tmp_path, durable=False)
    _solve(killed)
    del killed

    with pytest.warns(UserWarning, match="WITHOUT a durable solve store"):
        restarted = _service(tmp_path, durable=False)
    restarted.score_epoch(issued_at=ISSUED)

    state, detail = restarted._scores.epoch_state(SOURCE_EPOCH)
    assert state == EPOCH_INCOMPLETE and "5Miner" in detail
    # the store-reading composer refuses on the marker alone, with no access to the
    # service object that noticed the loss
    with pytest.raises(CyberGymScoreError, match="refusing to compose"):
        compose_scores_lane(restarted._scores, SOURCE_EPOCH, allocation=Decimal("0.90"))


def test_the_store_reading_composer_refuses_an_epoch_that_never_closed(tmp_path):
    """An unmarked epoch is not composable either: "no scoring pass ran" and
    "nobody solved anything" produce the same empty vector, so they must not be
    treated the same."""
    service = _service(tmp_path, durable=True)
    _solve(service)
    assert service._scores.epoch_state(SOURCE_EPOCH)[0] == EPOCH_OPEN
    with pytest.raises(CyberGymScoreError, match="refusing to compose"):
        compose_scores_lane(service._scores, SOURCE_EPOCH, allocation=Decimal("0.90"))

    service.score_epoch(issued_at=ISSUED)
    assert service._scores.epoch_state(SOURCE_EPOCH)[0] == EPOCH_CLOSED
    lane = compose_scores_lane(service._scores, SOURCE_EPOCH, allocation=Decimal("0.90"))
    assert [c.miner_hotkey for c in lane.contributions] == ["5Miner"]


@pytest.mark.parametrize("path", ["", ":memory:", "file:x?mode=memory&cache=shared"])
def test_a_non_durable_solve_store_is_refused(path):
    """`CyberGymSolveStore(":memory:")` used to satisfy the service's "durable store
    required" check while forgetting every solve on restart."""
    with pytest.raises(CyberGymScoreError):
        CyberGymSolveStore(path)


@pytest.mark.parametrize("path", ["", "  ", ":memory:", "file:x?mode=memory&cache=shared"])
def test_a_non_durable_score_store_is_refused(path):
    """The score store is the table the external mechanism adapter reads, as a
    FILE, from another process. An in-memory score store could be marked closed
    and composed in-process while the adapter saw an empty database and published
    100% burn: the same durability rule the solve store applies, on the store
    whose whole purpose is to be read externally."""
    with pytest.raises(CyberGymScoreError, match="durable"):
        CyberGymScoreStore(path)


def test_the_score_store_durability_check_has_a_named_opt_out():
    # Test-only: the opt-out has to be typed in full, so a production wiring
    # cannot end up in memory by forgetting an argument.
    store = CyberGymScoreStore(":memory:", durability_required=False)
    store.mark_epoch(3, state=EPOCH_CLOSED, detail="in-memory, explicitly opted out")
    assert store.epoch_state(3)[0] == EPOCH_CLOSED
    store.close()


def test_a_running_service_requires_a_durable_solve_store_by_default(tmp_path):
    with pytest.raises(ProtocolError, match="durable solve store"):
        CyberGymService(
            load_holdout(_manifest()), _chain(), backend=_backend,
            corpus_store=CyberGymCorpusStore(str(tmp_path / "corpus.sqlite")),
            score_store=CyberGymScoreStore(str(tmp_path / "scores.sqlite")),
            validator_hotkey="5Val", private_key=KEY, signing_key_id="cybergym-1",
            batch_size=2, cutoff=CUTOFF, as_of=NOW, attestation_required=False,
            gates_required=False,
        )


# --------------------------------------------------------------------------- #
# Repeated dispatch must not destroy or resurrect solves
# --------------------------------------------------------------------------- #

def test_redispatch_with_the_same_commitment_keeps_accepted_solves(tmp_path):
    service = _service(tmp_path, durable=True)
    _solve(service)
    service.dispatch_for("5Miner", MODEL)  # same commitment -> same nonce, same batch
    assert service.score_epoch(issued_at=ISSUED)[0].contribution["work_units"] == "8"


def test_a_self_recommit_is_refused_and_the_solves_survive(tmp_path):
    """#34: a miner may NOT re-commit mid-epoch, even authenticated as itself.

    This previously succeeded and abandoned the miner's own solves -- documented
    as self-harm. It was not only self-harm: `model_commitment` feeds
    derive_batch_nonce, so re-committing RE-DRAWS the sealed batch. A miner could
    commit, inspect the batch, discard it and commit again until the draw landed
    on tasks it already held PoCs for.
    """
    service = _service(tmp_path, durable=True)
    _solve(service)
    with pytest.raises(ProtocolError, match="pinned for source_epoch"):
        service.dispatch_for("5Miner", OTHER_MODEL, authenticated_caller="5Miner")

    # The refusal is before any state change: the solve is intact and still scores.
    assert [r.miner_hotkey for r in service.score_epoch(issued_at=ISSUED)] == ["5Miner"]
    restarted = _service(tmp_path, durable=True)
    assert "5Miner" in restarted._miners


def test_the_same_commitment_may_be_redispatched(tmp_path):
    """The pin must not break legitimate retry: a miner that loses its dispatch
    message and asks again with the SAME commitment gets the same batch."""
    service = _service(tmp_path, durable=True)
    first = service.dispatch_for("5Miner", MODEL, authenticated_caller="5Miner")
    again = service.dispatch_for("5Miner", MODEL, authenticated_caller="5Miner")
    assert again.batch_id == first.batch_id
    assert [t.task_id for t in again.tasks] == [t.task_id for t in first.tasks]


def test_an_unauthenticated_recommit_cannot_zero_a_victims_accepted_solves(tmp_path):
    """CRITICAL regression: dispatch is caller-bound. An attacker cannot POST a
    different commitment for a victim's PUBLIC hotkey to delete the victim's verified
    solves — the solve-dropping re-commit is refused unless proven to be the miner."""
    service = _service(tmp_path, durable=True)
    _solve(service, miner="5Victim")

    # an unauthenticated re-commit that would drop the victim's solves -> refused
    with pytest.raises(ProtocolError, match="pinned for source_epoch"):
        service.dispatch_for("5Victim", OTHER_MODEL)
    # a wrong authenticated caller -> refused before any state change
    with pytest.raises(ProtocolError, match="may not dispatch for"):
        service.dispatch_for("5Victim", OTHER_MODEL, authenticated_caller="5Attacker")

    # the victim's solve is untouched: not lost, not unscorable, and still scores
    assert service.lost_durable_solvers() == set()
    assert "5Victim" not in service._unscorable
    assert [r.miner_hotkey for r in service.score_epoch(issued_at=ISSUED)] == ["5Victim"]
    # nothing was durably deleted: a restart still rehydrates the victim's solve
    restarted = _service(tmp_path, durable=True)
    assert "5Victim" in restarted._miners


# --------------------------------------------------------------------------- #
# A miner's own re-commit costs that miner, never the lane
# --------------------------------------------------------------------------- #

def test_a_recommit_cannot_be_used_to_grind_the_sealed_batch(tmp_path):
    """The acceptance test from #34: grinding must not beat the honest draw.

    The reported break was a miner holding PoCs for a small subset going from
    earning NOTHING on its honest batch to full marks after 1771 accepted
    re-dispatches. Here the loop is refused from the second attempt on, so the
    miner is stuck with the batch it was sealed to.
    """
    service = _service(tmp_path, durable=True)
    honest = service.dispatch_for("5Grinder", MODEL, authenticated_caller="5Grinder")

    accepted_regrinds = 0
    for i in range(25):
        try:
            service.dispatch_for(
                "5Grinder", f"sha256:{i:064x}", authenticated_caller="5Grinder")
            accepted_regrinds += 1
        except ProtocolError:
            pass
    assert accepted_regrinds == 0, "the sealed batch was re-drawable"

    # and the batch it is held to is the one it was originally sealed to
    still = service.dispatch_for("5Grinder", MODEL, authenticated_caller="5Grinder")
    assert still.batch_id == honest.batch_id


def test_the_commitment_pin_survives_a_restart(tmp_path):
    """Acceptance item 2: a restart must not reset the pin, or the grind is
    simply 'restart the validator' -- and a miner cannot force that anyway, but
    an ordinary crash must not hand out a fresh draw."""
    service = _service(tmp_path, durable=True)
    _solve(service, miner="5Miner")
    original = service._miners["5Miner"].model_commitment
    del service

    restarted = _service(tmp_path, durable=True)
    assert restarted._miners["5Miner"].model_commitment == original
    with pytest.raises(ProtocolError, match="pinned for source_epoch"):
        restarted.dispatch_for("5Miner", OTHER_MODEL, authenticated_caller="5Miner")


def test_an_operator_can_clear_a_genuine_loss_without_losing_data(tmp_path):
    """The one refusal that remains has to be clearable, or it is still an outage."""
    with pytest.warns(UserWarning, match="WITHOUT a durable solve store"):
        killed = _service(tmp_path, durable=False)
    _solve(killed)
    del killed

    with pytest.warns(UserWarning, match="WITHOUT a durable solve store"):
        restarted = _service(tmp_path, durable=False)
    restarted.score_epoch(issued_at=ISSUED)
    assert restarted.lost_durable_solvers() == {"5Miner"}
    with pytest.raises(ProtocolError, match="acknowledge_unscorable_solves"):
        restarted.compose_lane(allocation=Decimal("0.90"))

    with pytest.raises(ProtocolError, match="must carry a reason"):
        restarted.acknowledge_unscorable_solves(reason="  ")

    acknowledged = restarted.acknowledge_unscorable_solves(
        reason="solve store was not configured before the restart; state is gone"
    )
    assert acknowledged == {"5Miner"}
    # the durable evidence is untouched: nothing was deleted to clear the refusal
    assert restarted._corpus.size() == 1
    # and the lane composes again, with the acknowledgement in the epoch's record
    lane = restarted.compose_lane(allocation=Decimal("0.90"))
    assert list(lane.contributions) == []
    state, detail = restarted._scores.epoch_state(SOURCE_EPOCH)
    assert state == EPOCH_CLOSED and "operator acknowledged" in detail


def test_an_acknowledged_loss_stays_acknowledged_across_a_restart(tmp_path):
    killed = _service(tmp_path, durable=True)
    _solve(killed)
    del killed

    # the solve store file is lost, but the corpus survives: genuinely unrecoverable
    (tmp_path / "solves.sqlite").unlink()
    restarted = _service(tmp_path, durable=True)
    restarted.score_epoch(issued_at=ISSUED)
    assert restarted.lost_durable_solvers() == {"5Miner"}
    restarted.acknowledge_unscorable_solves(reason="solve store file lost")

    again = _service(tmp_path, durable=True)
    assert again.lost_durable_solvers() == set()
    again.score_epoch(issued_at=ISSUED)
    again.compose_lane(allocation=Decimal("0.90"))
