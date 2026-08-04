"""Pure regression coverage for the loopback CyberGym E2E harness."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "cybergym_mock_miner.py"
SPEC = importlib.util.spec_from_file_location("cybergym_mock_miner", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


def _attempt(hotkey: str, task_id: str, *, creditable: bool = True):
    return HARNESS.Attempt(
        miner_label=hotkey,
        hotkey=hotkey,
        task_id=task_id,
        http_status=200,
        solved=creditable,
        creditable=creditable,
        artifact_contract_ok=True,
    )


def _run(hotkey: str, *attempts):
    return HARNESS.MinerRun(hotkey, hotkey, tuple(attempts))


def test_duplicate_task_assignments_are_not_collapsed_by_task_id():
    report = HARNESS.E2EReport(
        advertised_task_ids=frozenset({"arvo:1", "arvo:2"}),
        capable_runs=(
            _run("miner-a", _attempt("miner-a", "arvo:1")),
            _run("miner-b", _attempt("miner-b", "arvo:1")),
        ),
        cheater_runs=(_run("cheater", _attempt("cheater", "arvo:1", creditable=False)),),
        expected_capable_runs=2,
        grinder_redraws_accepted=0,
    )

    assert len(report.capable_attempts) == 2
    assert {attempt.hotkey for attempt in report.capable_attempts} == {"miner-a", "miner-b"}
    assert report.covered_task_ids == {"arvo:1"}
    assert report.missing_task_ids == {"arvo:2"}
    assert not report.passed
    assert any("never attempted" in failure for failure in report.failures)


def test_full_coverage_requires_every_advertised_task_and_capable_credit():
    report = HARNESS.E2EReport(
        advertised_task_ids=frozenset({"arvo:1", "arvo:2"}),
        capable_runs=(
            _run("miner-a", _attempt("miner-a", "arvo:1")),
            _run("miner-b", _attempt("miner-b", "arvo:2")),
        ),
        cheater_runs=(_run("cheater", _attempt("cheater", "arvo:1", creditable=False)),),
        expected_capable_runs=2,
        grinder_redraws_accepted=0,
    )

    assert report.passed
    assert report.failures == ()


def test_noncreditable_capable_attempt_and_grinder_redraw_fail_closed():
    report = HARNESS.E2EReport(
        advertised_task_ids=frozenset({"arvo:1"}),
        capable_runs=(_run("miner-a", _attempt("miner-a", "arvo:1", creditable=False)),),
        cheater_runs=(_run("cheater", _attempt("cheater", "arvo:1", creditable=False)),),
        expected_capable_runs=1,
        grinder_redraws_accepted=1,
    )

    assert not report.passed
    assert any("not creditable" in failure for failure in report.failures)
    assert any("re-drew" in failure for failure in report.failures)
