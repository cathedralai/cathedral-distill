"""The reward-proof harness must be honest: PROVEN only when all five hold, with
independently verifiable evidence, and never a false pass (review of #59).

Tests the gate logic with network calls and receipt verification mocked; the live
behaviour is exercised by running it against the real feed/box.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

from cathedral_distill.cybergym_cathedral_attest import commitment_sha256

_SPEC = importlib.util.spec_from_file_location(
    "reward_proof_gates", Path(__file__).resolve().parents[1] / "scripts" / "reward_proof_gates.py")
rpg = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(rpg)

REAL_TASK = "arvo:12345"
POC = "sha256:" + "ab" * 32
TRACE = "sha256:" + "cd" * 32


def _args(**over):
    base = dict(miner="5CyberMiner", miner_uid=42, publisher="http://pub",
                expect_key_id="cathedral-weight-policy", network="finney", netuid=39,
                now="2026-07-30T12:00:00Z", attested_receipt=None, receipt_task=None,
                receipt_poc_sha256=None, receipt_trace_id=None, validator_acceptance=None,
                validator_wrote_block=None, external_miner_transcript=None, out=None)
    base.update(over)
    return SimpleNamespace(**base)


def _tdx_receipt():
    sha = commitment_sha256(task_id=REAL_TASK, poc_sha256=POC, trace_id=TRACE)
    return {
        "receipt_id": "352e0bb4-2f92-4d18", "receipt_status": "ready", "exit_code": 0,
        "started_at": "2026-07-30T11:59:00Z", "miner_hotkey": "5CyberMiner",
        "task_policy": {"reuse": "forbidden", "egress": "none", "hardware_class": "tdx_cpu"},
        "verification": {"intel_verified": True, "report_data_match": True},
        "artifacts": [{"path": "result.txt", "sha256": sha}],
        "tee_attestation": {"kind": "tdx-1.5"},
    }


# --- gate 1: no false pass, real attestation required ------------------------- #
def test_gate1_blocked_without_a_receipt():
    assert rpg.gate1_score_backed_by_tdx(_args()).status == rpg.BLOCKED


def test_gate1_refuses_a_synthetic_task(monkeypatch, tmp_path):
    r = tmp_path / "r.json"; r.write_text("{}")
    g = rpg.gate1_score_backed_by_tdx(_args(
        attested_receipt=str(r), receipt_task="synthvuln:abc:0",
        receipt_poc_sha256=POC, receipt_trace_id=TRACE))
    assert g.status == rpg.FAIL and "synthetic" in g.detail


def test_gate1_blocks_a_trusted_issuer_receipt_until_the_raw_quote_is_verified(tmp_path):
    import json as _json
    r = tmp_path / "r.json"; r.write_text(_json.dumps(_tdx_receipt()))
    g = rpg.gate1_score_backed_by_tdx(_args(
        attested_receipt=str(r), receipt_task=REAL_TASK,
        receipt_poc_sha256=POC, receipt_trace_id=TRACE))
    assert g.status == rpg.BLOCKED and "trusted-issuer" in g.detail


def test_gate1_fails_a_receipt_for_a_different_miner(tmp_path):
    import json as _json
    rec = _tdx_receipt(); rec["miner_hotkey"] = "5SomeoneElse"
    r = tmp_path / "r.json"; r.write_text(_json.dumps(rec))
    g = rpg.gate1_score_backed_by_tdx(_args(
        attested_receipt=str(r), receipt_task=REAL_TASK,
        receipt_poc_sha256=POC, receipt_trace_id=TRACE))
    assert g.status == rpg.FAIL and "not the intended miner" in g.detail


# --- gate 2: v3 + miner + expected key --------------------------------------- #
def test_gate2_requires_v3(monkeypatch):
    monkeypatch.setattr(rpg, "_get", lambda u, timeout=30: (200, {
        "key_id": "cathedral-weight-policy", "signature": "x",
        "policy_metadata": {"validated_supply": {"contract_version": "v2"}}}))
    assert rpg.gate2_feed_has_miner_and_burn(_args()).status == rpg.FAIL


def test_gate2_rejects_the_wrong_signer(monkeypatch):
    monkeypatch.setattr(rpg, "_get", lambda u, timeout=30: (200, {
        "key_id": "attacker-key", "signature": "x",
        "policy_metadata": {"validated_supply": {"contract_version": "v3"}}}))
    g = rpg.gate2_feed_has_miner_and_burn(_args())
    assert g.status == rpg.FAIL and "wrong or unpinned signer" in g.detail


def test_gate2_passes_with_v3_miner_present_and_key(monkeypatch):
    monkeypatch.setattr(rpg, "_get", lambda u, timeout=30: (200, {
        "key_id": "cathedral-weight-policy", "signature": "x",
        "policy_metadata": {
            "validated_supply": {"contract_version": "v3", "fixed_burn_allocation": 0.0},
            "cybergym_lane": {"fraction": 0.30, "weights": {"42": 0.30}}}}))
    assert rpg.gate2_feed_has_miner_and_burn(_args(miner_uid=42)).status == rpg.PASS
    assert rpg.gate2_feed_has_miner_and_burn(_args(miner_uid=999)).status == rpg.FAIL


# --- gate 3: acceptance evidence --------------------------------------------- #
def test_gate3_blocked_without_acceptance():
    assert rpg.gate3_validator_accepts_and_submits(_args()).status == rpg.BLOCKED


def test_gate3_fails_a_rejection_transcript(tmp_path):
    import json as _json
    a = tmp_path / "a.json"; a.write_text(_json.dumps({"ok": False, "error": "still v2"}))
    g = rpg.gate3_validator_accepts_and_submits(_args(validator_acceptance=str(a)))
    assert g.status == rpg.FAIL and "did NOT accept" in g.detail


def test_gate3_blocks_acceptance_without_a_finalized_write_proof(tmp_path):
    import json as _json
    a = tmp_path / "a.json"
    a.write_text(_json.dumps({"ok": True, "accepted_by": "validated_supply_v3",
                              "uids_weighted": 4, "weight_sum": 1.0}))
    g = rpg.gate3_validator_accepts_and_submits(_args(validator_acceptance=str(a)))
    assert g.status == rpg.BLOCKED and "finalized-chain" in g.detail


def test_gate3_blocks_a_caller_supplied_write_block(tmp_path):
    import json as _json
    a = tmp_path / "a.json"
    a.write_text(_json.dumps({"ok": True, "accepted_by": "validated_supply_v3",
                              "uids_weighted": 4, "weight_sum": 1.0}))
    g = rpg.gate3_validator_accepts_and_submits(
        _args(validator_acceptance=str(a), validator_wrote_block=8801234))
    assert g.status == rpg.BLOCKED and "caller-supplied" in g.detail


# --- gate 4: finalized-chain reward state ------------------------------------ #
def _install_chain(monkeypatch, *, hotkey="5CyberMiner", incentive=0.5, emission=0.7):
    class _MG:
        hotkeys = ["x"] * 42 + [hotkey]
        I = [0.0] * 42 + [incentive]
        E = [0.0] * 42 + [emission]

    class _ST:
        def __init__(self, network):
            self.network = network

        def metagraph(self, netuid, lite):
            return _MG()

    monkeypatch.setitem(__import__("sys").modules, "bittensor.core.subtensor",
                        SimpleNamespace(Subtensor=_ST))


def test_gate4_fails_when_the_finalized_row_has_zero_emission(monkeypatch):
    _install_chain(monkeypatch, emission=0.0)
    g = rpg.gate4_chain_shows_emission(_args())
    assert g.status == rpg.FAIL and "not yet paid" in g.detail


def test_gate4_fails_when_uid_no_longer_belongs_to_miner(monkeypatch):
    _install_chain(monkeypatch, hotkey="5DifferentMiner")
    g = rpg.gate4_chain_shows_emission(_args())
    assert g.status == rpg.FAIL and "binding is stale" in g.detail


# --- gate 5: cannot self-certify --------------------------------------------- #
def test_gate5_blocked_without_release(monkeypatch):
    monkeypatch.setattr(rpg, "_get", lambda u, timeout=30: (404, None))
    g = rpg.gate5_external_miner(_args())
    assert g.status == rpg.BLOCKED and "release.json" in g.detail


def test_gate5_still_blocked_when_release_up_but_no_transcript(monkeypatch):
    monkeypatch.setattr(rpg, "_get", lambda u, timeout=30: (200, {}))
    g = rpg.gate5_external_miner(_args())
    assert g.status == rpg.BLOCKED and "REAL external operator" in g.detail


def test_gate5_rejects_our_own_hotkey_as_external(tmp_path):
    import json as _json
    e = tmp_path / "e.json"
    e.write_text(_json.dumps({"miner_hotkey": "5CyberMiner",  # us, not external
                              "installed_signed_release": True,
                              "completed_without_bypass": True}))
    g = rpg.gate5_external_miner(_args(external_miner_transcript=str(e)))
    assert g.status == rpg.FAIL and "DIFFERENT operator" in g.detail


def test_gate5_blocks_an_unsigned_external_transcript(tmp_path):
    import json as _json
    e = tmp_path / "e.json"
    e.write_text(_json.dumps({"miner_hotkey": "5ExternalParty",
                              "installed_signed_release": True,
                              "completed_without_bypass": True}))
    g = rpg.gate5_external_miner(_args(external_miner_transcript=str(e)))
    assert g.status == rpg.BLOCKED and "unsigned" in g.detail


# --- the whole run: proof stays blocked without independent verifiers ---------- #
def test_all_five_proven_is_blocked_without_independent_verifiers(monkeypatch, tmp_path):
    import json as _json
    rec = tmp_path / "r.json"; rec.write_text(_json.dumps(_tdx_receipt()))
    acc = tmp_path / "a.json"; acc.write_text(_json.dumps(
        {"ok": True, "accepted_by": "validated_supply_v3", "uids_weighted": 4, "weight_sum": 1.0}))
    ext = tmp_path / "e.json"; ext.write_text(_json.dumps(
        {"miner_hotkey": "5ExternalParty", "installed_signed_release": True,
         "completed_without_bypass": True}))
    out = tmp_path / "t.json"

    monkeypatch.setattr(rpg, "_get", lambda u, timeout=30: (200, {
        "key_id": "cathedral-weight-policy", "signature": "x",
        "policy_metadata": {
            "validated_supply": {"contract_version": "v3", "fixed_burn_allocation": 0.0},
            "cybergym_lane": {"fraction": 0.30, "weights": {"42": 0.30}}}}))

    class _MG:
        hotkeys = ["x"] * 42 + ["5CyberMiner"]
        I = [0.0] * 42 + [0.5]
        E = [0.0] * 42 + [0.7]

    class _ST:
        def __init__(self, network): pass
        def metagraph(self, netuid, lite): return _MG()

    monkeypatch.setitem(__import__("sys").modules, "bittensor.core.subtensor",
                        SimpleNamespace(Subtensor=_ST))

    rc = rpg.main([
        "--miner", "5CyberMiner", "--miner-uid", "42", "--publisher", "http://pub",
        "--expect-key-id", "cathedral-weight-policy",
        "--attested-receipt", str(rec), "--receipt-task", REAL_TASK,
        "--receipt-poc-sha256", POC, "--receipt-trace-id", TRACE,
        "--validator-acceptance", str(acc), "--validator-wrote-block", "8801234",
        "--external-miner-transcript", str(ext),
        "--now", "2026-07-30T12:00:00Z", "--out", str(out),
    ])
    assert rc == 1
    t = _json.loads(out.read_text())
    assert t["proven"] is False
    assert t["bound"]["miner_hotkey"] == "5CyberMiner" and t["bound"]["miner_uid"] == 42
    assert [g["status"] for g in t["gates"]] == [
        rpg.BLOCKED, rpg.PASS, rpg.BLOCKED, rpg.PASS, rpg.BLOCKED]


def test_todays_reality_is_not_proven(monkeypatch):
    # v2 feed, no evidence files: must be NOT PROVEN.
    monkeypatch.setattr(rpg, "_get", lambda u, timeout=30: (
        (200, {"key_id": "cathedral-weight-policy", "signature": "x",
               "policy_metadata": {"validated_supply": {"contract_version": "v2"}}})
        if "weights/next" in u else (404, None)))
    rc = rpg.main(["--miner", "5CyberMiner", "--miner-uid", "42", "--publisher", "http://pub",
                   "--expect-key-id", "cathedral-weight-policy"])
    assert rc == 1
