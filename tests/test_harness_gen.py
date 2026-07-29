"""Harness-generation scoring — objective, validator-re-derivable, never judged.

Proves the 4-gate score: a harness that doesn't build or crashes on trivial input
earns 0; otherwise units are the normalized coverage GAIN over the validator-held
baseline (so a no-op harness ~0, full target coverage → the weight), plus a bug
bonus when the fuzz budget finds a crash. The score is a pure function of
(task, result), so any validator re-derives it.
"""
from __future__ import annotations

from decimal import Decimal

from cathedral_distill.harness_gen import (
    HarnessResult,
    HarnessTask,
    derived_harness_units,
    harness_backend_from_env,
    stub_harness_backend,
)

TASK = HarnessTask(task_id="libpng:png_read_info", target="libpng:png_read_info",
                   baseline_edges=40, target_edges=140, seed=1, run_budget=4000,
                   weight=Decimal("8"), bug_bonus=Decimal("16"))


def _res(**kw):
    base = dict(build_ok=True, sanity_ok=True, coverage_edges=40,
                coverage_features=0, bug_found=False)
    base.update(kw)
    return HarnessResult(**base)


def test_build_or_sanity_failure_earns_zero():
    assert derived_harness_units(TASK, _res(build_ok=False, coverage_edges=140)) == Decimal(0)
    assert derived_harness_units(TASK, _res(sanity_ok=False, coverage_edges=140)) == Decimal(0)
    assert derived_harness_units(TASK, None) == Decimal(0)


def test_no_coverage_gain_over_baseline_earns_zero():
    # a harness that reaches only the baseline (a no-op) earns nothing
    assert derived_harness_units(TASK, _res(coverage_edges=40)) == Decimal(0)
    assert derived_harness_units(TASK, _res(coverage_edges=30)) == Decimal(0)  # below baseline


def test_coverage_gain_is_normalized_to_weight():
    # halfway to full target coverage: (90-40)/(140-40) = 0.5 -> 0.5*8 = 4
    assert derived_harness_units(TASK, _res(coverage_edges=90)) == Decimal("4.0000")
    # full target coverage -> the whole weight
    assert derived_harness_units(TASK, _res(coverage_edges=140)) == Decimal("8.0000")
    # over-covering is capped at the weight (no runaway)
    assert derived_harness_units(TASK, _res(coverage_edges=500)) == Decimal("8.0000")


def test_bug_found_adds_the_bonus_on_top():
    # full coverage + a real crash = weight + bonus
    assert derived_harness_units(TASK, _res(coverage_edges=140, bug_found=True)) == Decimal("24.0000")
    # even a modest-coverage harness that finds a bug is well rewarded
    assert derived_harness_units(TASK, _res(coverage_edges=65, bug_found=True)) == Decimal("2.0000") + Decimal("16")


def test_score_is_deterministic():
    r = _res(coverage_edges=90, bug_found=True)
    assert derived_harness_units(TASK, r) == derived_harness_units(TASK, r)


def test_stub_backend_gates_empty_harness_and_serves_results():
    backend = stub_harness_backend({
        TASK.task_id: _res(coverage_edges=110, bug_found=False),
    })
    empty = backend("   ", TASK)
    assert not empty.build_ok and not empty.sanity_ok
    assert derived_harness_units(TASK, empty) == Decimal(0)

    good = backend("LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){ png_read(d,n); }", TASK)
    assert good.build_ok and good.coverage_edges == 110
    # (110-40)/100 = 0.7 -> 5.6 units
    assert derived_harness_units(TASK, good) == Decimal("5.6000")


def test_backend_from_env_requires_hw_or_injected_stub():
    import pytest
    with pytest.raises(RuntimeError):
        harness_backend_from_env()                          # no CYBERGYM_RUN_HW, no default
    stub = stub_harness_backend({})
    assert harness_backend_from_env(stub) is stub            # injected default used
