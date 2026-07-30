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
from cathedral_distill.cybergym_validator import ChainContext  # noqa: E402
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


def _service(tmp_path, *, durable: bool):
    """A service over the SAME storage every time, so a new one is a restart."""
    kwargs = {}
    if durable:
        kwargs["solve_store"] = CyberGymSolveStore(str(tmp_path / "solves.sqlite"))
    else:
        kwargs["solve_durability_required"] = False
    return CyberGymService(
        load_holdout(_manifest()), _chain(), backend=_backend,
        corpus_store=CyberGymCorpusStore(str(tmp_path / "corpus.sqlite")),
        score_store=CyberGymScoreStore(str(tmp_path / "scores.sqlite")),
        validator_hotkey="5Val", private_key=KEY, signing_key_id="cybergym-1",
        batch_size=2, cutoff=CUTOFF, as_of=NOW, attestation_required=False,
        gates_required=False, **kwargs,
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
    """Recovery must reproduce the receipt, not merely a similar score."""
    clean_run = tmp_path / "a"
    crashed_run = tmp_path / "b"
    clean_run.mkdir()
    crashed_run.mkdir()

    uninterrupted = _service(clean_run, durable=True)
    _solve(uninterrupted)
    expected = uninterrupted.score_epoch(issued_at=ISSUED)[0]

    killed = _service(crashed_run, durable=True)
    _solve(killed)
    del killed
    recovered = _service(crashed_run, durable=True).score_epoch(issued_at=ISSUED)[0]

    assert recovered.receipt == expected.receipt
    assert recovered.contribution == expected.contribution


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


def test_redispatch_with_a_new_commitment_drops_the_old_solves_durably(tmp_path):
    service = _service(tmp_path, durable=True)
    _solve(service)
    service.dispatch_for("5Miner", OTHER_MODEL)  # a different batch entirely
    assert service.score_epoch(issued_at=ISSUED) == []
    # and a restart must not resurrect the abandoned solves
    restarted = _service(tmp_path, durable=True)
    assert restarted._miners == {}
