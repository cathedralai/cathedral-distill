"""Atomic once-only replay-token consumption (issue #1 gate #16).

Proves a token is consumed exactly once and a replay fails closed — both the
primitive and its use in the admission pipeline (a resubmitted receipt becomes
FAIL, not a second credit).
"""
from __future__ import annotations

import base64
import hashlib
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill.consumption_ledger import ConsumptionLedger, ReplayError  # noqa: E402
from cathedral_distill.testing import IntegrationFixtures  # noqa: E402

NOW_ISO = "2026-07-25T12:30:00.000000Z"
SOURCE_EPOCH = 11
LANE_CPU = "cathedral_confidential_tdx"


def test_token_consumed_exactly_once():
    ledger = ConsumptionLedger()
    ledger.consume("receipt-sha256:" + "aa" * 32)
    assert ledger.is_consumed("receipt-sha256:" + "aa" * 32)
    with pytest.raises(ReplayError, match="already consumed"):
        ledger.consume("receipt-sha256:" + "aa" * 32)  # replay fails closed
    ledger.consume("receipt-sha256:" + "bb" * 32)  # a different token is fine
    assert ledger.size() == 2


def test_empty_token_is_refused():
    with pytest.raises(ReplayError, match="non-empty"):
        ConsumptionLedger().consume("")


def test_ledger_persists_across_reopen(tmp_path):
    path = str(tmp_path / "ledger.sqlite")
    ledger = ConsumptionLedger(path)
    ledger.consume("t1")
    ledger.close()
    reopened = ConsumptionLedger(path)  # a restart does not forget a consumed token
    with pytest.raises(ReplayError):
        reopened.consume("t1")


def test_replayed_receipt_becomes_fail_in_the_pipeline():
    fx = IntegrationFixtures()
    ledger = ConsumptionLedger()
    first = itf.verify_lane_receipt(
        itf.KIND_COMPUTE_CPU, fx.cpu_receipt(), lane=LANE_CPU, key_registry=fx.registry,
        source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO, consumption_ledger=ledger)
    assert first.verdict == "PASS"
    # the SAME receipt resubmitted is refused as a replay, not credited again
    replay = itf.verify_lane_receipt(
        itf.KIND_COMPUTE_CPU, fx.cpu_receipt(), lane=LANE_CPU, key_registry=fx.registry,
        source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO, consumption_ledger=ledger)
    assert replay.verdict == "FAIL" and "already consumed" in replay.detail
    assert replay.work_units == Decimal(0)


def test_without_a_ledger_behaviour_is_unchanged():
    fx = IntegrationFixtures()
    for _ in range(2):
        d = itf.verify_lane_receipt(
            itf.KIND_COMPUTE_CPU, fx.cpu_receipt(), lane=LANE_CPU, key_registry=fx.registry,
            source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO)
        assert d.verdict == "PASS"  # no ledger -> no replay gate (opt-in)
