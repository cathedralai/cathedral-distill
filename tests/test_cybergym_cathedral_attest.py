"""The Cathedral attest.v1 → CyberGym submission adapter, proven without hardware.

A fixture receipt mirrors the real `attest.v1 · tdx_cpu` worker receipt shape (kind
`tdx-1.5`, `verification.intel_verified` + `report_data_match`, sealed policy, a
`result.txt` artifact = the commitment). The tests prove the adapter binds an
attestation to exactly one `(task_id, poc, trace)` and fails closed on a wrong TEE,
an unverified quote, a replay/lift to another submission, an unsealed worker, and a
stale receipt — the properties that make an attested solve un-forgeable.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.cybergym_cathedral_attest import (  # noqa: E402
    commitment_sha256,
    tee_kind,
    verify_cathedral_attestation,
)

TASK = "arvo:368"
POC_SHA = "sha256:" + "ab" * 32
TRACE_ID = "sha256:" + "cd" * 32
NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def _receipt(*, task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID, kind="tdx-1.5",
             intel_verified=True, report_data_match=True, reuse="forbidden",
             egress="none", hardware="tdx_cpu", exit_code=0, status="ready",
             started="2026-07-30T11:59:00Z", artifact_sha=None):
    """A well-formed receipt whose result.txt artifact commits to (task,poc,trace)."""
    sha = artifact_sha if artifact_sha is not None else commitment_sha256(
        task_id=task_id, poc_sha256=poc_sha256, trace_id=trace_id)
    return {
        "receipt_id": "352e0bb4-2f92-4d18-b468-f65a93a46d77",
        "receipt_status": status, "exit_code": exit_code, "started_at": started,
        "files_sha256": "72" * 16, "artifacts_sha256": "58" * 16, "policy_sha256": "02" * 16,
        "task_policy": {"reuse": reuse, "egress": egress, "hardware_class": hardware},
        "verification": {"intel_verified": intel_verified, "report_data_match": report_data_match},
        "artifacts": [{"path": "result.txt", "sha256": sha, "size_bytes": 209}],
        "tee_attestation": {"kind": kind, "quote_b64": "BAACAIEA…",
                            "bound_digest": "sha256:57cd", "result_sha256": "3a39"},
    }


def _ok(receipt):
    return verify_cathedral_attestation(receipt, task_id=TASK, poc_sha256=POC_SHA,
                                        trace_id=TRACE_ID, now=NOW)


# --------------------------------------------------------------------------- #
# the happy path + tee mapping
# --------------------------------------------------------------------------- #
def test_a_genuine_sealed_tdx_receipt_binds_the_submission():
    r = _ok(_receipt())
    assert r.attested and r.tee == "intel_tdx" and r.reason == "attested_intel_tdx"
    assert r.artifact_sha256 == commitment_sha256(task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID)


def test_tee_kind_maps_tdx_and_refuses_sev():
    assert tee_kind({"tee_attestation": {"kind": "tdx-1.5"}}) == "intel_tdx"
    assert tee_kind({"tee_attestation": {"kind": "sev-snp-1"}}) == "amd_sev_snp"


# --------------------------------------------------------------------------- #
# fail-closed: wrong TEE / unverified / unsealed
# --------------------------------------------------------------------------- #
def test_an_amd_sev_quote_is_refused():
    r = _ok(_receipt(kind="sev-snp-1"))
    assert not r.attested and "Intel TDX" in r.reason


def test_unverified_quote_is_refused():
    assert not _ok(_receipt(intel_verified=False)).attested
    assert not _ok(_receipt(report_data_match=False)).attested


def test_unsealed_worker_is_refused():
    assert not _ok(_receipt(reuse="allowed")).attested       # replayable worker
    assert not _ok(_receipt(egress="allow:*")).attested      # can phone home
    assert not _ok(_receipt(hardware="cpu")).attested        # not a TEE
    assert not _ok(_receipt(exit_code=1)).attested
    assert not _ok(_receipt(status="pending")).attested


# --------------------------------------------------------------------------- #
# fail-closed: the binding — replay / lift / tamper
# --------------------------------------------------------------------------- #
def test_attestation_cannot_be_replayed_for_another_task():
    # a receipt attesting task arvo:1065 can't credit an arvo:368 submission
    other = _receipt(task_id="arvo:1065")
    r = verify_cathedral_attestation(other, task_id="arvo:368", poc_sha256=POC_SHA,
                                     trace_id=TRACE_ID, now=NOW)
    assert not r.attested and "does not bind" in r.reason


def test_attestation_cannot_be_paired_with_a_different_poc_or_trace():
    r = _receipt()
    assert not verify_cathedral_attestation(
        r, task_id=TASK, poc_sha256="sha256:" + "99" * 32, trace_id=TRACE_ID, now=NOW).attested
    assert not verify_cathedral_attestation(
        r, task_id=TASK, poc_sha256=POC_SHA, trace_id="sha256:" + "99" * 32, now=NOW).attested


def test_missing_result_artifact_is_refused():
    r = _receipt()
    r["artifacts"] = []
    assert not _ok(r).attested


def test_stale_attestation_is_refused():
    old = _receipt(started="2026-07-01T00:00:00Z")
    assert not _ok(old).attested


def test_a_malformed_receipt_fails_closed_without_raising():
    assert not verify_cathedral_attestation({}, task_id=TASK, poc_sha256=POC_SHA,
                                            trace_id=TRACE_ID, now=NOW).attested


# --------------------------------------------------------------------------- #
# trustless mode: an injected raw-quote verifier
# --------------------------------------------------------------------------- #
def test_trustless_mode_verifies_the_raw_quote_and_ignores_the_issuer_flag():
    seen = {}

    def verifier(quote_b64, expected_rd_hex):
        seen["quote"] = quote_b64
        seen["rd"] = expected_rd_hex
        return True

    # even with Cathedral's own flags false, a passing raw-quote verify credits it
    r = verify_cathedral_attestation(_receipt(intel_verified=False, report_data_match=False),
                                     task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID,
                                     now=NOW, quote_verifier=verifier)
    assert r.attested and r.trustless and r.reason == "attested_intel_tdx_trustless"
    assert seen["quote"].startswith("BAAC") and len(seen["rd"]) == 64


def test_trustless_mode_fails_closed_when_the_quote_is_rejected():
    r = verify_cathedral_attestation(_receipt(), task_id=TASK, poc_sha256=POC_SHA,
                                     trace_id=TRACE_ID, now=NOW,
                                     quote_verifier=lambda q, rd: False)
    assert not r.attested and "raw TDX quote" in r.reason
