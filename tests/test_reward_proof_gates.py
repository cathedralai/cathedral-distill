"""The reward-proof harness must be honest: it may only say PROVEN when all five hold.

This is the owner's go/no-go for activating CyberGym rewards (#41), so its failure
mode that matters is a FALSE pass. The gate logic is tested with the network calls
mocked; the live behaviour is exercised by running it against the real feed/box.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "reward_proof_gates", Path(__file__).resolve().parents[1] / "scripts" / "reward_proof_gates.py")
rpg = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(rpg)


def _args(**over):
    base = dict(miner="5CyberMiner", miner_uid=7, publisher="http://pub",
                verifier="http://ver", network="finney", netuid=39, out=None)
    base.update(over)
    return SimpleNamespace(**base)


def test_the_verdict_is_not_proven_unless_all_five_pass(monkeypatch):
    # A v2 feed and a missing release: the real world today. Must be NOT PROVEN.
    def fake_get(url, timeout=30):
        if "status" in url:
            return 200, {"lane": {"lane_id": "cathedral_cybergym"},
                         "participation": {"available": True, "scored": 1},
                         "leaderboard": {"scored_miners": 1},
                         "epoch": {"source_epoch": 21}}
        if "weights/next" in url:
            return 200, {"policy_metadata": {"validated_supply": {"contract_version": "v2"}}}
        if "release.json" in url:
            return 404, None
        return 0, {}

    monkeypatch.setattr(rpg, "_get", fake_get)
    # gate2 fails on v2 -> overall NOT PROVEN
    g1 = rpg.gate1_score_backed_by_tdx(_args())
    g2 = rpg.gate2_feed_has_miner_and_burn(_args())
    assert g1.status == rpg.PASS
    assert g2.status == rpg.FAIL and "not v3" in g2.detail


def test_gate2_passes_only_with_v3_miner_present(monkeypatch):
    def fake_get(url, timeout=30):
        return 200, {"policy_metadata": {
            "validated_supply": {"contract_version": "v3", "fixed_burn_allocation": 0.0},
            "cybergym_lane": {"fraction": 0.30, "weights": {"7": 0.30}}}}

    monkeypatch.setattr(rpg, "_get", fake_get)
    g = rpg.gate2_feed_has_miner_and_burn(_args(miner_uid=7))
    assert g.status == rpg.PASS

    # same feed, a miner NOT in the lane -> fail
    g_absent = rpg.gate2_feed_has_miner_and_burn(_args(miner_uid=999))
    assert g_absent.status == rpg.FAIL


def test_gate5_is_blocked_on_the_owner_until_the_release_exists(monkeypatch):
    monkeypatch.setattr(rpg, "_get", lambda url, timeout=30: (404, None))
    g = rpg.gate5_external_miner(_args())
    assert g.status == rpg.BLOCKED
    assert "not published" in g.detail and "release.json" in g.detail


def test_a_published_release_still_needs_a_real_external_operator(monkeypatch):
    monkeypatch.setattr(rpg, "_get", lambda url, timeout=30: (200, {}))
    g = rpg.gate5_external_miner(_args())
    # Even with the release up, gate 5 cannot be self-certified.
    assert g.status == rpg.BLOCKED
    assert "external operator" in g.detail


def test_gate1_fails_without_a_scored_attested_solve(monkeypatch):
    monkeypatch.setattr(rpg, "_get", lambda url, timeout=30: (200, {
        "lane": {"lane_id": "cathedral_cybergym"},
        "participation": {"available": True, "scored": 0},
        "leaderboard": {"scored_miners": 0}}))
    g = rpg.gate1_score_backed_by_tdx(_args())
    assert g.status == rpg.FAIL and "nothing to back a reward" in g.detail
