"""Compute receipt credit requires independently replayable SAT evidence."""
from __future__ import annotations

from cathedral_distill import integrated_feed as itf
from cathedral_distill.testing import IntegrationFixtures

NOW = "2026-07-25T12:30:00.000000Z"


def _fixture():
    fixtures = IntegrationFixtures()
    receipt = fixtures.cpu_receipt()
    return fixtures, receipt, dict(receipt.work_evidence)


def _verify(fixtures, receipt, evidence):
    return itf.verify_lane_receipt(
        itf.KIND_COMPUTE_CPU,
        receipt,
        lane="cathedral_confidential_tdx",
        key_registry=fixtures.registry,
        now_iso=NOW,
        source_epoch=fixtures.source_epoch,
        work_evidence=evidence,
        consumption_ledger=itf.NO_REPLAY_LEDGER,
    )


def test_valid_compute_evidence_replays_before_a_receipt_is_creditable():
    fixtures, receipt, evidence = _fixture()
    decision = _verify(fixtures, receipt, evidence)
    assert decision.verdict == itf.PASS
    assert decision.receipt_id == receipt["receipt_id"]


def test_compute_receipt_without_the_sidecar_is_refused():
    fixtures, receipt, _evidence = _fixture()
    # A parsed wire receipt is a plain mapping, so it cannot carry an in-memory
    # sidecar attachment.  The explicit transport field is mandatory there.
    decision = _verify(fixtures, dict(receipt), None)
    assert decision.verdict == itf.FAIL
    assert "work evidence must be an object" in decision.detail


def test_result_bytes_cannot_be_substituted_after_the_receipt_is_signed():
    fixtures, receipt, evidence = _fixture()
    evidence["result_base64"] = "e30="  # canonical JSON object, wrong signed digest
    decision = _verify(fixtures, receipt, evidence)
    assert decision.verdict == itf.FAIL
    assert "result does not match" in decision.detail


def test_sidecar_is_bound_to_one_receipt_id():
    fixtures, _receipt, evidence = _fixture()
    other = fixtures.cpu_receipt(subject="5DifferentMiner")
    decision = _verify(fixtures, other, evidence)
    assert decision.verdict == itf.FAIL
    assert "different receipt" in decision.detail
