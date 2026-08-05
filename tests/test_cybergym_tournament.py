"""Top-5 rank-tournament scoring — base-100, 5-epoch rolling, deterministic."""
from __future__ import annotations

import hashlib
import json
import sys
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.cybergym_tournament import (  # noqa: E402
    BASE,
    ROLLING_WEIGHTS,
    TOURNAMENT_SHARES,
    WINDOW,
    WINNER_SLOTS,
    Scoreboard,
    TournamentError,
    build_scoreboard,
    epoch_score_base100,
    lane_contributions,
    rolling_total,
)

# The epoch's chain-anchored nonce that keys the ungrindable tie-break.
NONCE = b"cgnonce-sha256:" + b"ab" * 16


def test_the_two_weight_vectors_are_normalised():
    assert sum(ROLLING_WEIGHTS) == Decimal("1")
    assert sum(TOURNAMENT_SHARES) == Decimal("1")
    assert WINDOW == 5 and WINNER_SLOTS == 5


# --------------------------------------------------------------------------- #
# Per-epoch base-100 score: absolute difficulty-weighted completion
# --------------------------------------------------------------------------- #

def test_absolute_base_100_score():
    assert epoch_score_base100(0, 0) == Decimal("0")     # nothing dispatched
    assert epoch_score_base100(0, 10) == Decimal("0")    # solved nothing
    assert epoch_score_base100(10, 10) == Decimal("100")  # solved everything
    assert epoch_score_base100(5, 10) == Decimal("50")   # half the weighted set
    # weighted, not count-based: 2 units of 8 dispatched = 25.
    assert epoch_score_base100(Decimal("2"), Decimal("8")) == Decimal("25")


def test_base_100_is_absolute_not_relative_to_the_field():
    # A strong field does not deflate anyone: everyone who solves all gets 100.
    assert epoch_score_base100(10, 10) == Decimal("100")
    # A non-terminating ratio is quantised to fixed precision (determinism).
    assert epoch_score_base100(1, 3) == Decimal("33.333333")


def test_score_fails_closed_on_incoherent_units():
    with pytest.raises(TournamentError):
        epoch_score_base100(11, 10)      # solved more than dispatched
    with pytest.raises(TournamentError):
        epoch_score_base100(-1, 10)      # negative


# --------------------------------------------------------------------------- #
# Rolling 5-epoch recency total
# --------------------------------------------------------------------------- #

def test_rolling_total_applies_the_recency_weights():
    # 0.03·80 + 0.07·85 + 0.15·90 + 0.25·95 + 0.50·100
    assert rolling_total([80, 85, 90, 95, 100]) == Decimal("95.6")
    # a flat 60 collapses to 60 (weights sum to 1)
    assert rolling_total([60, 60, 60, 60, 60]) == Decimal("60")


def test_newcomer_latest_epoch_carries_half_the_weight():
    # Only the latest epoch present -> right-aligned, gets the 0.50 weight.
    assert rolling_total([95]) == Decimal("47.5")
    assert rolling_total([50, 80, 90]) == Decimal(  # 0.15·50 + 0.25·80 + 0.50·90
        "72.5"
    )


def test_rolling_total_keeps_only_the_last_five_epochs():
    # A 6th (older) epoch is dropped; result equals the last-5 computation.
    assert rolling_total([100, 80, 85, 90, 95, 100]) == rolling_total(
        [80, 85, 90, 95, 100]
    )


def test_rolling_total_rejects_out_of_range():
    with pytest.raises(TournamentError):
        rolling_total([101])
    with pytest.raises(TournamentError):
        rolling_total([-1])


# --------------------------------------------------------------------------- #
# The worked example (the table in the design doc), end to end
# --------------------------------------------------------------------------- #

WORKED = {
    "M1": [80, 85, 90, 95, 100],   # T = 95.6  rank 1
    "M2": [100, 90, 80, 70, 60],   # T = 68.8  rank 3
    "M3": [0, 0, 50, 80, 90],      # T = 72.5  rank 2
    "M4": [60, 60, 60, 60, 60],    # T = 60.0  rank 4
    "M5": [95],                    # T = 47.5  rank 5 (newcomer)
    "M6": [50, 50, 50, 40, 30],    # T = 37.5  rank 6 (out)
}


def test_worked_example_totals_ranking_and_payout():
    sb = build_scoreboard(21, WORKED, nonce=NONCE)
    got = {s.miner_hotkey: s.total for s in sb.standings}
    assert got == {
        "M1": Decimal("95.6"), "M3": Decimal("72.5"), "M2": Decimal("68.8"),
        "M4": Decimal("60"), "M5": Decimal("47.5"), "M6": Decimal("37.5"),
    }
    # ranking order
    assert [s.miner_hotkey for s in sb.standings] == ["M1", "M3", "M2", "M4", "M5", "M6"]
    assert [s.rank for s in sb.standings] == [1, 2, 3, 4, 5, 6]
    # top-5 winners in rank order, with the fixed shares; M6 earns nothing
    assert sb.winners == ("M1", "M3", "M2", "M4", "M5")
    shares = {s.miner_hotkey: s.lane_share for s in sb.standings}
    assert shares == {
        "M1": Decimal("0.65"), "M3": Decimal("0.14"), "M2": Decimal("0.10"),
        "M4": Decimal("0.07"), "M5": Decimal("0.04"), "M6": Decimal("0"),
    }
    assert sb.lane_burn == Decimal("0")  # 5 winners -> full lane pays out


def test_effective_emission_is_share_times_the_lane():
    # v3 CyberGym lane = 0.30 of total emission.
    sb = build_scoreboard(21, WORKED, nonce=NONCE)
    lane = Decimal("0.30")
    top = next(s for s in sb.standings if s.rank == 1)
    assert top.lane_share * lane == Decimal("0.1950")


# --------------------------------------------------------------------------- #
# Determinism: same inputs -> byte-identical scoreboard (consensus depends on it)
# --------------------------------------------------------------------------- #

def test_scoreboard_is_deterministic():
    a = build_scoreboard(21, WORKED, nonce=NONCE).to_dict()
    b = build_scoreboard(21, dict(reversed(list(WORKED.items()))), nonce=NONCE).to_dict()
    assert a == b  # input order must not matter


def test_ties_break_by_the_nonce_digest_not_hotkey_order():
    # All tied at T=50: order is the nonce-keyed digest — deterministic for a fixed
    # nonce, but NOT plain hotkey-ascending (that was the grindable default), and it
    # reshuffles when the epoch nonce changes.
    hks = ["5Kf", "5Zz", "5Mn", "5Qp", "5Rt", "5Bc", "5Aa"]
    scores = {h: [50] for h in hks}
    order1 = [s.miner_hotkey for s in build_scoreboard(1, scores, nonce=b"nonce-one").standings]
    again = [s.miner_hotkey for s in build_scoreboard(1, scores, nonce=b"nonce-one").standings]
    order2 = [s.miner_hotkey for s in build_scoreboard(1, scores, nonce=b"nonce-two").standings]
    assert order1 == again              # deterministic for a fixed nonce (consensus)
    assert order1 != sorted(hks)        # NOT hotkey-ascending (the grindable behaviour)
    assert order1 != order2             # a different epoch nonce reshuffles the tie


def test_grinding_an_early_hotkey_earns_no_permanent_advantage():
    # wallscaler's exploit: register a lexicographically-early hotkey to win ties for
    # free, forever. With a nonce-keyed tie-break its rank is not a property of the
    # address — the epoch nonce moves it, so there is no permanent edge.
    hks = ["5Aaaaa", "5m1", "5m2", "5m3", "5m4", "5m5"]  # all tied at 100
    scores = {h: [100] for h in hks}

    def rank_of(target: str, nonce: bytes) -> int:
        sb = build_scoreboard(1, scores, nonce=nonce)
        return next(s.rank for s in sb.standings if s.miner_hotkey == target)

    ranks = {n: rank_of("5Aaaaa", n) for n in (b"e1", b"e2", b"e3", b"e4", b"e5")}
    assert len(set(ranks.values())) > 1  # the early address does not hold a fixed rank


def test_source_epoch_also_rotates_the_tiebreak():
    # The digest keys on source_epoch too, so even a (hypothetically) repeated nonce
    # cannot freeze the tie order across epochs.
    hks = ["5Kf", "5Zz", "5Mn", "5Qp", "5Rt", "5Bc", "5Aa"]
    scores = {h: [50] for h in hks}
    o21 = [s.miner_hotkey for s in build_scoreboard(21, scores, nonce=b"same").standings]
    o22 = [s.miner_hotkey for s in build_scoreboard(22, scores, nonce=b"same").standings]
    assert o21 != o22


def test_a_non_string_or_bytes_nonce_is_refused_not_coerced():
    # HIGH: str(None)=='None' is truthy, so coercing would freeze the tie-break to a
    # grindable public constant. None / int / bool must all fail closed.
    for bad in (None, 0, 1, False, True, 3.14, ["x"]):
        with pytest.raises(TournamentError):
            build_scoreboard(1, {"5a": [50]}, nonce=bad)
    # empty bytes/str are non-empty-guarded too
    for empty in (b"", ""):
        with pytest.raises(TournamentError):
            build_scoreboard(1, {"5a": [50]}, nonce=empty)


def test_there_is_no_hidden_tiebreak_override():
    # The ranking is a pure function of scores + nonce + source_epoch (all in the board),
    # so build_scoreboard accepts no caller tie-break a peer could not see.
    with pytest.raises(TypeError):
        build_scoreboard(1, {"5a": [50]}, nonce=NONCE, tiebreak={"5a": 0})  # type: ignore[call-arg]


def _canonical(doc: dict) -> bytes:
    # Same sort_keys/compact contract the signed reports use.
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("ascii")


def test_scoreboard_dict_is_canonical_json():
    doc = build_scoreboard(21, WORKED, nonce=NONCE).to_dict()
    body = _canonical(doc)
    # canonical: re-serialising the parsed body is byte-identical, and it digests.
    assert _canonical(json.loads(body)) == body
    assert hashlib.sha256(body).hexdigest()


# --------------------------------------------------------------------------- #
# Fewer than five qualified miners: renormalise (onboarding) vs burn (mature)
# --------------------------------------------------------------------------- #

def test_zero_score_miners_never_win():
    sb = build_scoreboard(1, {"5solver": [40], "5idle": [0], "5absent": []}, nonce=NONCE)
    assert sb.winners == ("5solver",)
    assert {s.miner_hotkey: s.lane_share for s in sb.standings}["5idle"] == Decimal("0")


def test_short_field_renormalises_and_lane_burn_matches_compose_vector():
    # <5 winners: renormalise present ranks to sum to 1 (full lane pays out, burn 0) —
    # and shares summing to 1 is exactly what compose_vector applies, so the signed
    # lane_burn=0 is not a false claim. (The mature-field *partial burn* is deferred to
    # the composer-integration PR; announcing it here would sign a burn the composer
    # renormalises away.)
    sb = build_scoreboard(1, {"5a": [90], "5b": [80]}, nonce=NONCE)
    shares = {s.miner_hotkey: s.lane_share for s in sb.standings}
    assert shares["5a"] == Decimal("0.822785")   # 0.65 / 0.79
    assert shares["5b"] == Decimal("0.177215")   # 0.14 / 0.79
    assert sum(shares.values()) == Decimal("1")
    assert sb.lane_burn == Decimal("0")


def test_no_qualified_miners_burns_the_whole_lane():
    # An EMPTY lane is the one burn compose_vector honours (its allocation -> burn), so
    # lane_burn=1 here is enforceable and honest.
    sb = build_scoreboard(1, {"5idle": [0]}, nonce=NONCE)
    assert sb.winners == ()
    assert sb.lane_burn == Decimal("1")


def test_lane_contributions_map_shares_to_work_units():
    sb = build_scoreboard(21, WORKED, nonce=NONCE)
    contribs = {c["miner_hotkey"]: Decimal(c["work_units"]) for c in lane_contributions(sb)}
    assert contribs == {
        "M1": Decimal("0.65"), "M3": Decimal("0.14"), "M2": Decimal("0.10"),
        "M4": Decimal("0.07"), "M5": Decimal("0.04"),
    }
    assert "M6" not in contribs  # non-winners carry no contribution
