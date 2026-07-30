"""Atomic once-only replay-token consumption (issue #1 gate #16).

Proves a token is consumed exactly once and a replay fails closed — both the
primitive and its use in the admission pipeline (a resubmitted receipt becomes
FAIL, not a second credit), including under real concurrency, where the pre-fix
shared-connection ledger handed "success" to 5-13 of 24 racing threads for one
token while inserting a single row.
"""
from __future__ import annotations

import base64
import hashlib
import sys
import threading
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


def _ledger(tmp_path, name: str = "ledger.sqlite") -> ConsumptionLedger:
    return ConsumptionLedger(str(tmp_path / name))


def test_token_consumed_exactly_once(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.consume("receipt-sha256:" + "aa" * 32)
    assert ledger.is_consumed("receipt-sha256:" + "aa" * 32)
    with pytest.raises(ReplayError, match="already consumed"):
        ledger.consume("receipt-sha256:" + "aa" * 32)  # replay fails closed
    ledger.consume("receipt-sha256:" + "bb" * 32)  # a different token is fine
    assert ledger.size() == 2


def test_empty_token_is_refused(tmp_path):
    with pytest.raises(ReplayError, match="non-empty"):
        _ledger(tmp_path).consume("")


def test_a_ledger_with_no_path_is_refused():
    # No default path: a non-durable ledger forgets consumed tokens on restart,
    # which fails OPEN (an already-credited receipt becomes creditable again).
    with pytest.raises(ReplayError, match="durable database path"):
        ConsumptionLedger()


@pytest.mark.parametrize("path", [":memory:", "file:x?mode=memory&cache=shared"])
def test_an_in_memory_ledger_is_refused(path):
    with pytest.raises(ReplayError, match="not durable"):
        ConsumptionLedger(path)


def test_concurrent_consumption_of_one_token_succeeds_exactly_once(tmp_path):
    """The once-only guarantee has to hold across ledger OBJECTS, not just threads.

    24 consumers, spread over two separate `ConsumptionLedger` instances on one
    database file, release off a barrier and consume the SAME token. That is the
    case that matters: replay protection has to survive two validator components
    (or two processes) holding their own ledger over shared storage, which is
    exactly what one shared in-process connection cannot give you. Exactly one
    consumer may succeed, 23 must fail closed with ReplayError, the table must
    hold one row, and no SQLite operational error may surface at all.

    Pre-fix (one connection with check_same_thread=False and an implicit deferred
    transaction) this reported 5-13 successes for one inserted row, plus
    "cannot start a transaction within a transaction" and a bare SystemError.

    Structure note: every ledger is constructed here, in the main thread, and the
    barrier surrounds `consume()` alone. A barrier wait must never be gated on a
    constructor succeeding, or a constructor failure leaves the other threads
    waiting forever and a real failure looks like a hang.
    """
    threads_count = 24
    ledgers = [_ledger(tmp_path), _ledger(tmp_path)]  # two instances, one file
    barrier = threading.Barrier(threads_count)
    lock = threading.Lock()
    successes: list[str] = []
    replays: list[str] = []
    unexpected: list[str] = []

    def worker(ledger: ConsumptionLedger) -> None:
        try:
            barrier.wait(timeout=30)
        except threading.BrokenBarrierError:
            with lock:
                unexpected.append("BrokenBarrierError")
            return
        try:
            ledger.consume("receipt-sha256:" + "cc" * 32)
        except ReplayError:
            with lock:
                replays.append("replay")
            return
        except BaseException as exc:  # noqa: BLE001 - classify, never swallow
            barrier.abort()
            with lock:
                unexpected.append(f"{type(exc).__name__}: {exc}")
            return
        with lock:
            successes.append("ok")

    threads = [
        threading.Thread(target=worker, args=(ledgers[i % len(ledgers)],), daemon=True)
        for i in range(threads_count)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert not any(thread.is_alive() for thread in threads), "a consumer never finished"
    assert unexpected == []
    assert len(successes) == 1, f"{len(successes)} consumers credited one token"
    assert len(replays) == threads_count - 1
    assert ledgers[0].size() == 1 and ledgers[1].size() == 1


def test_ledger_persists_across_reopen(tmp_path):
    path = str(tmp_path / "ledger.sqlite")
    ledger = ConsumptionLedger(path)
    ledger.consume("t1")
    ledger.close()
    reopened = ConsumptionLedger(path)  # a restart does not forget a consumed token
    with pytest.raises(ReplayError):
        reopened.consume("t1")


def test_replayed_receipt_becomes_fail_in_the_pipeline(tmp_path):
    fx = IntegrationFixtures()
    ledger = _ledger(tmp_path)
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
