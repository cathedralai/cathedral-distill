"""Top-5 rank-tournament scoring for the CyberGym lane.

The mechanism (see ``CYBERGYM_DISPATCH_SCORING_DESIGN``):

1. **Per-epoch, base 100.** Each miner's epoch score is *absolute* difficulty-weighted
   completion: ``100 × solved_units / dispatched_units`` over the epoch's common batch.
   Solving everything = 100; half the weighted set = 50. It means the same every epoch.
2. **Rolling total, 5-epoch recency window.** ``T = 0.03·a + 0.07·b + 0.15·c + 0.25·d +
   0.50·e`` over the last five epochs (``e`` latest; weights sum to 1). Missing older
   epochs count as 0, so a newcomer's only epoch is the latest (weight 0.50) and can
   reach the top-5 in a few epochs.
3. **Top-5 rank tournament.** Miners are ranked by ``T`` (ties broken deterministically);
   the top five earn fixed shares of the CyberGym lane — ``0.65, 0.14, 0.10, 0.07, 0.04``.

Because the payout is by *rank* with a hard top-5 cutoff, a tiny scoring disagreement
becomes a whole payout slot — so this is only consensus-safe if every validator derives
the **identical** ranking. Everything here is therefore a pure, fixed-precision function
of the disclosed, verified solve set, with a canonical tie-break, so all validators
produce byte-identical standings. ``build_scoreboard`` returns the announced, signable
document.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Any

SCOREBOARD_SCHEMA = "cathedral_cybergym_tournament_scoreboard_v1"

# Recency weights, oldest → latest; sum == 1.
ROLLING_WEIGHTS: tuple[Decimal, ...] = (
    Decimal("0.03"), Decimal("0.07"), Decimal("0.15"), Decimal("0.25"), Decimal("0.50"),
)
WINDOW = len(ROLLING_WEIGHTS)  # 5

# Top-5 lane shares, rank 1..5; sum == 1.
TOURNAMENT_SHARES: tuple[Decimal, ...] = (
    Decimal("0.65"), Decimal("0.14"), Decimal("0.10"), Decimal("0.07"), Decimal("0.04"),
)
WINNER_SLOTS = len(TOURNAMENT_SHARES)  # 5

BASE = Decimal("100")
# Fixed precision so every validator quantizes identically (float drift would let two
# honest validators disagree on a rank boundary — the one thing this mechanism cannot
# tolerate). Scores/totals to 1e-6; shares are already exact.
QUANT = Decimal("0.000001")


class TournamentError(ValueError):
    """Raised on an incoherent scoring input. Fails closed — never silently rounds."""


def _q(value: Decimal) -> Decimal:
    return value.quantize(QUANT, rounding=ROUND_HALF_EVEN)


def epoch_score_base100(solved_units: Decimal | int | str,
                        dispatched_units: Decimal | int | str) -> Decimal:
    """Absolute base-100 score for one epoch: ``100 × solved / dispatched``.

    ``dispatched_units`` is the total difficulty-weight of the epoch's common batch;
    ``solved_units`` is the weight this miner solved (attested + trainable + deduped).
    Returns 0 when nothing was dispatched. Fails closed on negative or > dispatched.
    """
    solved = Decimal(solved_units)
    dispatched = Decimal(dispatched_units)
    if solved < 0 or dispatched < 0:
        raise TournamentError("units must be non-negative")
    if solved > dispatched:
        raise TournamentError(
            f"solved units ({solved}) exceed dispatched units ({dispatched})")
    if dispatched == 0:
        return Decimal(0)
    return _q(BASE * solved / dispatched)


def rolling_total(epoch_scores: Sequence[Decimal | int | str]) -> Decimal:
    """Recency-weighted total over the last ``WINDOW`` epochs (oldest → latest).

    Fewer than ``WINDOW`` scores are right-aligned — missing **older** epochs count as
    0, so the latest score always carries the 0.50 weight. More than ``WINDOW`` keeps
    only the most recent five. Each score must be in ``[0, 100]``.
    """
    last = [Decimal(s) for s in epoch_scores[-WINDOW:]]
    for s in last:
        if s < 0 or s > BASE:
            raise TournamentError(f"epoch score {s} is outside [0, 100]")
    padded = [Decimal(0)] * (WINDOW - len(last)) + last
    return _q(sum((w * s for w, s in zip(ROLLING_WEIGHTS, padded)), Decimal(0)))


@dataclass(frozen=True)
class Standing:
    """One miner's place in an epoch's tournament."""

    miner_hotkey: str
    epoch_scores: tuple[Decimal, ...]  # the contributing per-epoch scores, oldest → latest
    total: Decimal                     # T(m), in [0, 100]
    rank: int                          # 1-based over ALL miners (dense over T desc)
    lane_share: Decimal                # share of the CyberGym lane; 0 unless a top-5 winner


@dataclass(frozen=True)
class Scoreboard:
    """The announced, signable result of one epoch's tournament."""

    source_epoch: int
    standings: tuple[Standing, ...]    # every miner, ranked best → worst
    winners: tuple[str, ...]           # top-5 hotkeys, rank order
    lane_burn: Decimal                 # lane fraction forfeited to burn (unfilled slots)
    tiebreak_nonce: str                # the epoch nonce that keyed the tie-break (auditable)

    def to_dict(self) -> dict[str, Any]:
        """Canonical announcement — deterministic across validators.

        Sign/digest with ``cybergym_score_report.canonical_report_bytes`` /
        ``report_digest`` (same sort_keys/compact contract).
        """
        return {
            "schema": SCOREBOARD_SCHEMA,
            "source_epoch": int(self.source_epoch),
            "rolling_weights": [str(w) for w in ROLLING_WEIGHTS],
            "tournament_shares": [str(s) for s in TOURNAMENT_SHARES],
            "tiebreak_nonce": self.tiebreak_nonce,
            "lane_burn": str(self.lane_burn),
            "winners": list(self.winners),
            "standings": [
                {
                    "miner_hotkey": s.miner_hotkey,
                    "rank": s.rank,
                    "total": str(s.total),
                    "epoch_scores": [str(x) for x in s.epoch_scores],
                    "lane_share": str(s.lane_share),
                }
                for s in self.standings
            ],
        }


def _nonce_digest(nonce: bytes, hotkey: str) -> str:
    """The ungrindable per-epoch ordering value for ``hotkey``.

    ``sha256(nonce ‖ hotkey)`` — deterministic (every validator computes the same) but
    keyed on the chain-anchored epoch **nonce**, which no miner controls and which
    changes each epoch. So a miner cannot pre-register a hotkey that sorts early: which
    of a set of tied hotkeys wins is pseudo-random per epoch, not a permanent property
    of the address. Same pattern as ``cybergym_mix.apportion``. (This does not by itself
    resist Sybil — registering many hotkeys still costs registration + a UID slot each,
    and each must independently earn the tying score; it removes the *free, permanent,
    zero-work* advantage of a lexicographically-early address.)
    """
    return hashlib.sha256(nonce + b"\x00" + hotkey.encode("utf-8")).hexdigest()


def build_scoreboard(
    source_epoch: int,
    per_miner_scores: Mapping[str, Sequence[Decimal | int | str]],
    *,
    nonce: bytes | str,
    tiebreak: Mapping[str, int] | None = None,
    renormalize_when_short: bool = True,
) -> Scoreboard:
    """Rank every miner by their rolling total and award the top-5 lane shares.

    ``per_miner_scores`` maps hotkey → that miner's last-≤5 base-100 epoch scores
    (oldest → latest). A **winner** is a top-5 miner with ``T > 0`` (no zero-solve
    earners).

    ``nonce`` is the epoch's chain-anchored nonce (required). Because the top-5 cutoff
    is payout-decisive and level-weighted scores tie often (a fully-solved batch ties at
    ``T=100``), ties MUST break in a way no miner can grind. Ties break by the
    ``nonce``-keyed digest (see ``_nonce_digest``), then hotkey — never by hotkey alone.

    ``tiebreak`` optionally supplies a **typed merit** key per miner (``int``; a *smaller*
    value ranks first, e.g. earliest-solve sequence). It takes precedence over the nonce
    digest when present, is validated as ``int`` (compared numerically — not string-
    coerced, so ``9 < 10 < 100``), and misses fall to the nonce digest. Omit it for the
    pure ungrindable default.

    ``renormalize_when_short`` controls the < 5-winner case:
      * ``True`` (onboarding): renormalize the present ranks' shares to sum to 1 so the
        whole 0.30 lane pays out to the miners that exist — no burning 84% of the lane
        with two miners;
      * ``False`` (mature field): keep the fixed shares; the unfilled slots' share
        (``lane_burn``) is forfeited to burn.
    When 5+ miners qualify the two are identical (shares already sum to 1, burn 0).
    """
    nonce_bytes = bytes(nonce) if isinstance(nonce, (bytes, bytearray)) else str(nonce).encode("utf-8")
    if not nonce_bytes:
        raise TournamentError(
            "build_scoreboard requires a non-empty epoch nonce: the top-5 cutoff is "
            "payout-decisive and ties are common, so the tie-break must be ungrindable")
    if tiebreak is not None:
        for hk, value in tiebreak.items():
            if isinstance(value, bool) or not isinstance(value, int):
                raise TournamentError(
                    f"tiebreak[{hk!r}] must be an int (e.g. solve-time seconds; smaller "
                    "ranks first) — string values would compare lexicographically")

    totals: dict[str, Decimal] = {}
    scores: dict[str, tuple[Decimal, ...]] = {}
    for hotkey, epoch_scores in per_miner_scores.items():
        window = tuple(_q(Decimal(s)) for s in epoch_scores[-WINDOW:])
        scores[hotkey] = window
        totals[hotkey] = rolling_total(epoch_scores)

    # Deterministic AND ungrindable ranking: T desc, then the typed merit key (missing =
    # +inf so it defers to the shuffle), then the nonce-keyed digest, then hotkey.
    def _order_key(hk: str) -> tuple[Decimal, float, str, str]:
        merit: float = 0.0 if tiebreak is None else float(tiebreak.get(hk, float("inf")))
        return (-totals[hk], merit, _nonce_digest(nonce_bytes, hk), hk)

    ordered = sorted(totals, key=_order_key)

    winners = [h for h in ordered if totals[h] > 0][:WINNER_SLOTS]
    shares = _award_shares(len(winners), renormalize_when_short=renormalize_when_short)
    lane_burn = _q(Decimal(1) - sum(shares, Decimal(0)))
    share_by_hotkey = dict(zip(winners, shares))

    standings = tuple(
        Standing(
            miner_hotkey=h,
            epoch_scores=scores[h],
            total=totals[h],
            rank=i + 1,
            lane_share=share_by_hotkey.get(h, Decimal(0)),
        )
        for i, h in enumerate(ordered)
    )
    return Scoreboard(
        source_epoch=int(source_epoch),
        standings=standings,
        winners=tuple(winners),
        lane_burn=lane_burn,
        tiebreak_nonce=nonce if isinstance(nonce, str) else nonce_bytes.hex(),
    )


def _award_shares(n_winners: int, *, renormalize_when_short: bool) -> list[Decimal]:
    """The lane shares for ``n_winners`` (0..5), in rank order."""
    if n_winners <= 0:
        return []
    if n_winners > WINNER_SLOTS:  # pragma: no cover - winners is sliced to WINNER_SLOTS
        raise TournamentError("more winners than tournament slots")
    fixed = list(TOURNAMENT_SHARES[:n_winners])
    if n_winners == WINNER_SLOTS or not renormalize_when_short:
        return fixed
    total = sum(fixed, Decimal(0))
    return [_q(s / total) for s in fixed]


def lane_contributions(scoreboard: Scoreboard) -> list[dict[str, str]]:
    """The winners as CyberGym-lane contributions for ``lane_feed.compose_vector``.

    ``work_units`` is set to the lane share, so ``compose_vector``'s in-lane
    proportional split reproduces the tournament shares exactly *when they sum to 1*
    (the ≥5-winner or renormalized case). In the mature < 5-winner **burn** case the
    lane must forfeit ``scoreboard.lane_burn`` — that needs the lane composer to honour
    an explicit intra-lane burn rather than renormalizing; wire ``lane_burn`` through
    at integration. ``receipt_id`` is filled by the caller from the epoch receipt.
    """
    return [
        {"miner_hotkey": s.miner_hotkey, "work_units": str(s.lane_share)}
        for s in scoreboard.standings
        if s.lane_share > 0
    ]


__all__ = [
    "SCOREBOARD_SCHEMA",
    "ROLLING_WEIGHTS",
    "TOURNAMENT_SHARES",
    "WINDOW",
    "WINNER_SLOTS",
    "BASE",
    "TournamentError",
    "epoch_score_base100",
    "rolling_total",
    "Standing",
    "Scoreboard",
    "build_scoreboard",
    "lane_contributions",
]
