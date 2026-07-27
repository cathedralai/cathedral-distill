"""Tests for the reward mechanism: teacher allowlist, maintainer registry, frontier.

These target the attacks the mechanism exists to stop: self-declared licences,
lineage hijacking, digest squatting, plagiarism of the champion's checkpoint, and
sandbagging a real gain into several small payouts.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import frontier as fr  # noqa: E402
from cathedral_distill import bundle_registry as br  # noqa: E402
from cathedral_distill import teacher_registry as tr  # noqa: E402

NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
LICENCE = b"Modified MIT. Training competing models permitted."


# --------------------------------------------------------------------------- #
# Teacher registry
# --------------------------------------------------------------------------- #

def _record(**kw):
    base = dict(
        teacher_id="moonshot/kimi/k3",
        licence_digest=tr.licence_digest(LICENCE),
        licence_uri="https://example/licence.txt",
        reviewed_at=NOW - timedelta(days=1),
        review_expires_at=NOW + timedelta(days=90),
        reviewer="cathedral-policy",
        permitted_purposes=frozenset({tr.PURPOSE_DISTILLATION}),
        competing_model_training=True,
    )
    base.update(kw)
    return tr.TeacherRecord(**base)


def test_permitted_teacher_passes_with_licence_check():
    reg = tr.TeacherRegistry({"moonshot/kimi/k3": _record()})
    got = reg.assert_permitted(
        "moonshot/kimi/k3",
        purpose=tr.PURPOSE_DISTILLATION,
        at=NOW,
        published_licence=LICENCE,
    )
    assert got.reviewer == "cathedral-policy"


def test_unknown_teacher_is_refused():
    reg = tr.TeacherRegistry()
    with pytest.raises(tr.TeacherNotPermitted) as exc:
        reg.assert_permitted("openai/gpt/5.6", purpose=tr.PURPOSE_DISTILLATION, at=NOW)
    assert exc.value.reason == "teacher_not_in_registry"


def test_licence_change_since_review_is_refused():
    # A vendor tightening terms must not silently keep the old permission.
    reg = tr.TeacherRegistry({"moonshot/kimi/k3": _record()})
    with pytest.raises(tr.TeacherNotPermitted) as exc:
        reg.assert_permitted(
            "moonshot/kimi/k3",
            purpose=tr.PURPOSE_DISTILLATION,
            at=NOW,
            published_licence=b"All rights reserved. No distillation.",
        )
    assert exc.value.reason == "licence_text_changed_since_review"


def test_expired_review_is_refused():
    reg = tr.TeacherRegistry({"moonshot/kimi/k3": _record()})
    with pytest.raises(tr.TeacherNotPermitted) as exc:
        reg.assert_permitted(
            "moonshot/kimi/k3",
            purpose=tr.PURPOSE_DISTILLATION,
            at=NOW + timedelta(days=365),
        )
    assert exc.value.reason == "review_expired"


def test_inference_permission_does_not_grant_distillation():
    reg = tr.TeacherRegistry({
        "moonshot/kimi/k3": _record(
            permitted_purposes=frozenset({tr.PURPOSE_INFERENCE})
        )
    })
    with pytest.raises(tr.TeacherNotPermitted, match="purpose_not_permitted"):
        reg.assert_permitted(
            "moonshot/kimi/k3", purpose=tr.PURPOSE_DISTILLATION, at=NOW
        )


def test_competing_model_clause_blocks_distillation():
    reg = tr.TeacherRegistry({
        "moonshot/kimi/k3": _record(competing_model_training=False)
    })
    with pytest.raises(tr.TeacherNotPermitted) as exc:
        reg.assert_permitted(
            "moonshot/kimi/k3", purpose=tr.PURPOSE_DISTILLATION, at=NOW
        )
    assert exc.value.reason == "competing_model_training_forbidden"


def test_teacher_id_must_pin_a_version():
    # A review of kimi/k2 says nothing about kimi/k3.
    with pytest.raises(ValueError, match="provider/model/version"):
        _record(teacher_id="moonshot/kimi")


def test_policy_document_carries_no_secrets():
    reg = tr.TeacherRegistry({"moonshot/kimi/k3": _record()})
    policy = reg.as_policy()
    assert policy["schema"] == tr.REGISTRY_SCHEMA
    assert policy["teachers"][0]["reviewer"] == "cathedral-policy"


# --------------------------------------------------------------------------- #
# Maintainer registry
# --------------------------------------------------------------------------- #

def _reg(hotkey="5Alice", digest=None, parent=None, version="1.0.0", at=None):
    return br.BundleRegistration(
        miner_hotkey=hotkey,
        track="hermes-extract-v0",
        bundle_digest=digest or br.bundle_digest(b"recipe-a"),
        version=version,
        registered_at=at or NOW,
        parent_digest=parent,
        signature="sig",
    )


def test_first_registration_wins():
    registry = br.BundleRegistry()
    registry.register(_reg())
    assert registry.is_registered_by(br.bundle_digest(b"recipe-a"), "5Alice")


def test_second_maintainer_cannot_squat_the_same_digest():
    registry = br.BundleRegistry()
    registry.register(_reg(hotkey="5Alice"))
    with pytest.raises(br.RegistrationError, match="already claimed by another"):
        registry.register(_reg(hotkey="5Bob"))


def test_unsigned_registration_is_refused():
    registry = br.BundleRegistry()
    unsigned = br.BundleRegistration(
        miner_hotkey="5Alice",
        track="t",
        bundle_digest=br.bundle_digest(b"x"),
        version="1",
        registered_at=NOW,
    )
    with pytest.raises(br.RegistrationError, match="must be signed"):
        registry.register(unsigned)


def test_lineage_hijacking_is_refused():
    # Bob must not graft his bundle onto Alice's history.
    registry = br.BundleRegistry()
    root = br.bundle_digest(b"alice-v1")
    registry.register(_reg(hotkey="5Alice", digest=root))
    with pytest.raises(br.RegistrationError, match="different maintainer"):
        registry.register(
            _reg(hotkey="5Bob", digest=br.bundle_digest(b"bob-v1"), parent=root)
        )


def test_version_chain_builds_and_reads_back():
    registry = br.BundleRegistry()
    v1 = br.bundle_digest(b"v1")
    v2 = br.bundle_digest(b"v2")
    registry.register(_reg(digest=v1, version="1.0.0"))
    registry.register(_reg(digest=v2, version="2.0.0", parent=v1,
                           at=NOW + timedelta(hours=1)))
    chain = registry.lineage(v2)
    assert [c.version for c in chain] == ["2.0.0", "1.0.0"]


def test_chain_cannot_change_track():
    registry = br.BundleRegistry()
    v1 = br.bundle_digest(b"v1")
    registry.register(_reg(digest=v1))
    child = br.BundleRegistration(
        miner_hotkey="5Alice",
        track="a-different-track",
        bundle_digest=br.bundle_digest(b"v2"),
        version="2.0.0",
        registered_at=NOW,
        parent_digest=v1,
        signature="sig",
    )
    with pytest.raises(br.RegistrationError, match="cannot change track"):
        registry.register(child)


def test_unknown_parent_is_refused():
    registry = br.BundleRegistry()
    with pytest.raises(br.RegistrationError, match="not a registered bundle"):
        registry.register(_reg(parent=br.bundle_digest(b"nonexistent")))


def test_self_parenting_is_refused():
    digest = br.bundle_digest(b"loop")
    with pytest.raises(br.RegistrationError, match="own parent"):
        _reg(digest=digest, parent=digest)


def test_bundle_digest_is_boundary_safe():
    # Length-prefixing means these two component lists cannot collide.
    assert br.bundle_digest(b"ab", b"c") != br.bundle_digest(b"a", b"bc")


def test_signing_payload_is_domain_separated_and_stable():
    payload = _reg().signing_payload()
    assert payload.startswith(br.REGISTRATION_DOMAIN)
    assert payload == _reg().signing_payload()


def test_replay_from_published_rows_preserves_first_wins():
    registry = br.BundleRegistry()
    digest = br.bundle_digest(b"contested")
    registry.register(_reg(hotkey="5Alice", digest=digest, at=NOW))
    rows = registry.as_public_index()
    # A hostile feed appends a later claim on the same digest.
    rows.append({
        "miner_hotkey": "5Bob", "track": "hermes-extract-v0",
        "bundle_digest": digest, "version": "9.9.9",
        "registered_at": (NOW + timedelta(days=1)).isoformat(),
        "parent_digest": None, "signature": "sig",
    })
    rebuilt = br.load_registry(rows)
    assert rebuilt.is_registered_by(digest, "5Alice")


# --------------------------------------------------------------------------- #
# Frontier / king-of-the-hill
# --------------------------------------------------------------------------- #

POLICY = fr.TrackPolicy(
    track="hermes-extract-v0",
    min_margin=Decimal("0.005"),
    max_cost_usd=Decimal("100"),
    max_latency_p50_ms=Decimal("5000"),
)


def _cand(score="0.70", **kw):
    base = dict(
        miner_hotkey="5Alice",
        bundle_digest=br.bundle_digest(b"a"),
        checkpoint_digest="sha256:" + "aa" * 32,
        receipt_id="sha256:" + "bb" * 32,
        score=Decimal(score),
        latency_p50_ms=Decimal("900"),
        cost_usd=Decimal("55"),
        submitted_at=NOW,
        attested=True,
        teacher_permitted=True,
        reproduced=True,
        contamination_detected=False,
        registered_bundle=True,
        independent_evaluator=True,
    )
    base.update(kw)
    return fr.Candidate(**base)


def test_first_eligible_candidate_is_crowned():
    f = fr.Frontier([POLICY])
    decision = f.submit(POLICY.track, _cand())
    assert decision.crowned
    assert f.champion(POLICY.track).score == Decimal("0.70")


def test_any_failed_gate_blocks_the_crown_regardless_of_score():
    f = fr.Frontier([POLICY])
    decision = f.submit(POLICY.track, _cand(score="0.99", attested=False))
    assert not decision.crowned
    assert fr.GATE_ATTESTED_RECEIPT in decision.gates.failures
    assert f.champion(POLICY.track) is None


def test_all_gates_are_reported_not_just_the_first():
    f = fr.Frontier([POLICY])
    decision = f.submit(
        POLICY.track,
        _cand(attested=False, reproduced=False, contamination_detected=True),
    )
    assert set(decision.gates.failures) >= {
        fr.GATE_ATTESTED_RECEIPT, fr.GATE_REPRODUCED, fr.GATE_NO_CONTAMINATION,
    }


def test_contamination_blocks_even_a_perfect_score():
    f = fr.Frontier([POLICY])
    assert not f.submit(
        POLICY.track, _cand(score="1", contamination_detected=True)
    ).crowned


def test_latency_over_cpu_budget_blocks_the_crown():
    # A student that cannot serve inside the TDX CPU envelope is worthless here.
    f = fr.Frontier([POLICY])
    decision = f.submit(POLICY.track, _cand(score="0.95", latency_p50_ms=Decimal("9000")))
    assert not decision.crowned
    assert fr.GATE_WITHIN_LATENCY in decision.gates.failures


def test_cost_ceiling_blocks_the_crown():
    f = fr.Frontier([POLICY])
    decision = f.submit(POLICY.track, _cand(cost_usd=Decimal("5000")))
    assert fr.GATE_WITHIN_COST in decision.gates.failures


def test_unregistered_bundle_blocks_the_crown():
    f = fr.Frontier([POLICY])
    decision = f.submit(POLICY.track, _cand(registered_bundle=False))
    assert fr.GATE_REGISTERED_BUNDLE in decision.gates.failures


def test_tie_keeps_the_incumbent():
    # This is the anti-plagiarism rule: resubmitting the champion's own
    # checkpoint scores identically and must gain nothing.
    f = fr.Frontier([POLICY])
    f.submit(POLICY.track, _cand(score="0.70", miner_hotkey="5Alice"))
    decision = f.submit(POLICY.track, _cand(score="0.70", miner_hotkey="5Bob"))
    assert not decision.crowned
    assert decision.reason == "did_not_beat_frontier"
    assert f.champion(POLICY.track).miner_hotkey == "5Alice"


def test_margin_must_be_cleared_not_merely_matched():
    f = fr.Frontier([POLICY])
    f.submit(POLICY.track, _cand(score="0.70"))
    # +0.004 is inside the noise margin.
    assert not f.submit(
        POLICY.track, _cand(score="0.704", miner_hotkey="5Bob")
    ).crowned
    # +0.005 clears it.
    assert f.submit(
        POLICY.track, _cand(score="0.705", miner_hotkey="5Bob")
    ).crowned


def test_sandbagging_gains_nothing():
    """The core economic property: slicing a gain does not multiply payouts.

    Under improvement-over-baseline, submitting 0.72 then 0.75 then 0.80 pays
    three times. Under frontier ownership the maintainer simply holds one crown,
    so the slices earn no more than going straight to the best result.
    """
    sliced = fr.Frontier([POLICY])
    for step in ("0.72", "0.75", "0.80"):
        sliced.submit(POLICY.track, _cand(score=step))

    direct = fr.Frontier([POLICY])
    direct.submit(POLICY.track, _cand(score="0.80"))

    assert sliced.champion(POLICY.track).score == direct.champion(POLICY.track).score
    assert (
        sliced.emission_shares()[f"champion:{POLICY.track}"]
        == direct.emission_shares()[f"champion:{POLICY.track}"]
    )


def test_worse_candidate_never_unseats_the_champion():
    f = fr.Frontier([POLICY])
    f.submit(POLICY.track, _cand(score="0.80"))
    f.submit(POLICY.track, _cand(score="0.10", miner_hotkey="5Bob"))
    assert f.champion(POLICY.track).score == Decimal("0.80")


def test_below_track_floor_is_not_crowned():
    policy = fr.TrackPolicy(track="t", min_score_to_crown=Decimal("0.5"))
    f = fr.Frontier([policy])
    decision = f.submit("t", _cand(score="0.2"))
    assert not decision.crowned
    assert decision.reason == "below_track_floor"


def test_empty_frontier_pays_everything_to_burn():
    # Same stance the existing mechanism takes for an empty verified set.
    f = fr.Frontier([POLICY])
    shares = f.emission_shares()
    assert shares["burn"] == Decimal("1")


def test_burn_fraction_defaults_to_the_contractual_ten_percent():
    f = fr.Frontier([POLICY])
    f.submit(POLICY.track, _cand())
    shares = f.emission_shares()
    assert shares["burn"] == Decimal("0.10")
    assert shares[f"champion:{POLICY.track}"] == Decimal("0.90")


def test_shares_sum_to_one_with_serving_split():
    f = fr.Frontier([POLICY])
    f.submit(POLICY.track, _cand())
    shares = f.emission_shares(
        burn_fraction=Decimal("0.10"), serving_fraction=Decimal("0.30")
    )
    assert sum(shares.values()) == Decimal("1")
    assert shares["serving"] == Decimal("0.30")


def test_multiple_tracks_split_the_champion_pool():
    a = fr.TrackPolicy(track="a")
    b = fr.TrackPolicy(track="b")
    f = fr.Frontier([a, b])
    f.submit("a", _cand())
    f.submit("b", _cand(bundle_digest=br.bundle_digest(b"b")))
    shares = f.emission_shares()
    assert shares["champion:a"] == shares["champion:b"] == Decimal("0.45")


def test_unknown_track_is_rejected():
    f = fr.Frontier([POLICY])
    with pytest.raises(fr.FrontierError, match="unknown track"):
        f.submit("not-a-track", _cand())


def test_champion_manifest_mirrors_sat_king_shape():
    f = fr.Frontier([POLICY])
    f.submit(POLICY.track, _cand())
    manifest = f.champion(POLICY.track).as_manifest()
    assert manifest["schema"] == fr.FRONTIER_SCHEMA
    assert manifest["checkpoint_digest"].startswith("sha256:")


def test_self_evaluation_blocks_the_crown():
    """A maintainer must not evaluate its own submission.

    TDX keeps the sealed set unreadable even from the host, but an operator who
    controls the machine can re-run the eval and submit only its best result.
    """
    f = fr.Frontier([POLICY])
    decision = f.submit(POLICY.track, _cand(score="0.99", independent_evaluator=False))
    assert not decision.crowned
    assert fr.GATE_INDEPENDENT_EVALUATOR in decision.gates.failures


# --------------------------------------------------------------------------- #
# Paired evaluation — a champion must be scored on the challenger's batch
# --------------------------------------------------------------------------- #

def test_unbatched_comparison_still_works():
    # Default empty batch_id preserves the old behaviour for a static set.
    f = fr.Frontier([POLICY])
    f.submit(POLICY.track, _cand(score="0.70"))
    assert f.submit(POLICY.track, _cand(score="0.80", miner_hotkey="5Bob")).crowned


def test_cross_batch_challenge_is_refused_without_rescore():
    f = fr.Frontier([POLICY])
    f.submit(POLICY.track, _cand(score="0.70", batch_id="epoch-1"))
    # A challenger on a different batch cannot be judged against the stale score.
    decision = f.submit(
        POLICY.track, _cand(score="0.99", batch_id="epoch-2", miner_hotkey="5Bob"))
    assert not decision.crowned
    assert decision.reason == "champion_not_scored_on_this_batch"
    assert f.champion(POLICY.track).miner_hotkey == "5Alice"


def test_rescore_enables_a_fair_paired_comparison():
    f = fr.Frontier([POLICY])
    f.submit(POLICY.track, _cand(score="0.70", batch_id="epoch-1"))
    # epoch-2 rotates in. Re-score the incumbent on epoch-2 (it does worse there),
    # then the challenger — genuinely better on the SAME batch — wins.
    decision = f.submit(
        POLICY.track,
        _cand(score="0.75", batch_id="epoch-2", miner_hotkey="5Bob"),
        champion_rescore=fr.ChampionRescore(
            score=Decimal("0.60"), batch_id="epoch-2",
            receipt_id="sha256:" + "re" * 32))
    assert decision.crowned
    assert f.champion(POLICY.track).miner_hotkey == "5Bob"


def test_easy_batch_attack_is_blocked():
    """The bug this fixes: a champion crowned on an easy batch must not survive
    a challenger who is genuinely better on a hard one — nor win by comparison
    against its own inflated old score."""
    f = fr.Frontier([POLICY])
    # Alice crowned at 0.90 on an easy batch.
    f.submit(POLICY.track, _cand(score="0.90", batch_id="easy"))
    # Bob scores 0.80 on a hard batch. Against Alice's stale 0.90 he would lose —
    # but that comparison is invalid, so it is refused until Alice is re-scored.
    refused = f.submit(
        POLICY.track, _cand(score="0.80", batch_id="hard", miner_hotkey="5Bob"))
    assert not refused.crowned and refused.reason == "champion_not_scored_on_this_batch"
    # Re-scored on the hard batch Alice only manages 0.50, so Bob's 0.80 wins.
    decision = f.submit(
        POLICY.track, _cand(score="0.80", batch_id="hard", miner_hotkey="5Bob"),
        champion_rescore=fr.ChampionRescore(
            score=Decimal("0.50"), batch_id="hard", receipt_id="sha256:" + "aa" * 32))
    assert decision.crowned
    assert f.champion(POLICY.track).miner_hotkey == "5Bob"


def test_incumbent_survives_when_it_still_wins_on_the_new_batch():
    f = fr.Frontier([POLICY])
    f.submit(POLICY.track, _cand(score="0.90", batch_id="epoch-1"))
    decision = f.submit(
        POLICY.track,
        _cand(score="0.70", batch_id="epoch-2", miner_hotkey="5Bob"),
        champion_rescore=fr.ChampionRescore(
            score=Decimal("0.85"), batch_id="epoch-2", receipt_id="sha256:" + "bb" * 32))
    assert not decision.crowned
    assert decision.reason == "did_not_beat_frontier"
    # The incumbent's stored score is now the fresh epoch-2 number, not the stale one.
    champ = f.champion(POLICY.track)
    assert champ.miner_hotkey == "5Alice" and champ.batch_id == "epoch-2"
    assert champ.score == Decimal("0.85")


def test_rescore_for_the_wrong_batch_is_ignored_and_refused():
    f = fr.Frontier([POLICY])
    f.submit(POLICY.track, _cand(score="0.70", batch_id="epoch-1"))
    # A rescore measured on epoch-3 does not license an epoch-2 comparison.
    decision = f.submit(
        POLICY.track, _cand(score="0.99", batch_id="epoch-2", miner_hotkey="5Bob"),
        champion_rescore=fr.ChampionRescore(
            score=Decimal("0.10"), batch_id="epoch-3", receipt_id="sha256:" + "cc" * 32))
    assert not decision.crowned
    assert decision.reason == "champion_not_scored_on_this_batch"


def test_rescore_requires_a_batch_id():
    with pytest.raises(fr.FrontierError, match="name the batch"):
        fr.ChampionRescore(score=Decimal("0.5"), batch_id="", receipt_id="x")


def test_first_champion_on_a_batch_needs_no_rescore():
    f = fr.Frontier([POLICY])
    decision = f.submit(POLICY.track, _cand(score="0.70", batch_id="epoch-1"))
    assert decision.crowned
    assert f.champion(POLICY.track).batch_id == "epoch-1"


def test_champion_manifest_carries_batch_id():
    f = fr.Frontier([POLICY])
    f.submit(POLICY.track, _cand(score="0.70", batch_id="epoch-1"))
    assert f.champion(POLICY.track).as_manifest()["batch_id"] == "epoch-1"
