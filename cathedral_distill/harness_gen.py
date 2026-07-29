"""Fuzz-harness generation — the second CyberGym-adjacent miner task.

Where the differential task asks a miner to *reproduce a bug* (a PoC that crashes
the vulnerable build, not the patched one), this task asks a miner to *write a
fuzz harness* (an ``LLVMFuzzerTestOneInput`` driver) for a target — the
oss-fuzz-gen problem. It reuses the whole existing spine (dispatch → submit →
verify → score → compose → attest → corpus); only the verify is new, and it is
built to be **objective and validator-re-derivable**, never judged:

    gate 1  BUILD     the harness compiles + links against the pinned target
                      (ASan + libFuzzer). Fails → 0.
    gate 2  SANITY    it runs on trivial inputs without crashing and is not a
                      no-op (it must actually reach the target).
    gate 3  COVERAGE  fuzzed with a PINNED seed + fixed run budget, the coverage
                      it reaches is DETERMINISTIC — every validator re-derives the
                      same number. Proven on a real ARVO target (freetype
                      ftfuzzer): two runs at seed=1/runs=4000 both reach
                      cov=310 / ft=540. The score is coverage GAIN over a
                      validator-held baseline harness, so a trivial no-op harness
                      scores ~0.
    gate 4  BUG       if the budget finds a crash, that crash input is a PoC and
                      flows straight into the EXISTING differential verify
                      (crash-vuln / clean-patch) — the strongest, binary signal.

Work units are validator-derived: ``(build ∧ sanity) × normalized coverage gain +
bug bonus`` — the same "never miner-claimed" discipline as ``cybergym.score_batch``.
The fuzz run is behind an injected backend (a hardware-free stub for tests; the
real libFuzzer run gated by ``CYBERGYM_RUN_HW``), exactly like
``cybergym_verifier.backend_from_env``. The harness source rides the existing
``SubmissionEnvelope`` (in place of the PoC), and the result composes into its own
``harness_gen_v0`` lane under the same signed allocation config.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from decimal import Decimal
from typing import Callable, Mapping


@dataclass(frozen=True)
class HarnessTask:
    """One harness-generation challenge, drawn nonce-sealed like a CyberGym task.

    `baseline_edges` is the coverage of the **existing human-written OSS-Fuzz
    target** for this project (validator-held) — matching oss-fuzz-gen's headline
    metric, "line coverage diff against existing human-written fuzz targets". A
    miner is paid only for coverage it adds *over the human harness*, so matching
    the human earns ~0 and only a genuinely better harness earns. `target_edges`
    is the reachable-edge budget used to normalise the gain into [0, weight].
    `seed` + `run_budget` pin the fuzz run so every validator re-derives the same
    coverage (determinism proven on the ARVO ftfuzzer target)."""

    task_id: str
    target: str                 # e.g. "libpng:png_read_info"
    baseline_edges: int         # coverage of the empty/reference harness
    target_edges: int           # reachable-edge budget of the target (normaliser)
    seed: int = 1
    run_budget: int = 100_000
    weight: Decimal = Decimal("8")   # max coverage units for fully covering the target
    bug_bonus: Decimal = Decimal("16")  # a real crash is worth more than any coverage


@dataclass(frozen=True)
class HarnessResult:
    """The validator-derived outcome of running one submitted harness."""

    build_ok: bool
    sanity_ok: bool
    coverage_edges: int         # target edges reached under the pinned seed+budget
    coverage_features: int
    bug_found: bool             # libFuzzer hit a crash within the budget
    crash_input: bytes | None = None   # -> feeds the differential verify (gate 4)


def derived_harness_units(task: HarnessTask, result: HarnessResult | None) -> Decimal:
    """The score, re-derivable by any validator from the SAME harness + seed + budget.

    Zero unless the harness both builds and passes sanity (a harness that crashes
    on empty input, or does not compile, is not a harness). Otherwise: normalized
    coverage GAIN over the baseline, capped at `weight`, plus the bug bonus if the
    fuzz run found a crash. Never trusts a miner-claimed number.
    """
    if result is None or not result.build_ok or not result.sanity_ok:
        return Decimal(0)
    gain = max(0, result.coverage_edges - task.baseline_edges)
    denom = max(1, task.target_edges - task.baseline_edges)
    frac = Decimal(min(gain, denom)) / Decimal(denom)      # [0, 1]
    cov_units = (task.weight * frac).quantize(Decimal("0.0001"))
    return cov_units + (task.bug_bonus if result.bug_found else Decimal(0))


# --------------------------------------------------------------------------- #
# Verify seam — hardware-free stub for tests; real libFuzzer under CYBERGYM_RUN_HW.
# Signature mirrors cybergym_verifier: (harness_source, task) -> HarnessResult.
# --------------------------------------------------------------------------- #
HarnessBackend = Callable[[str, HarnessTask], HarnessResult]


def stub_harness_backend(results: Mapping[str, HarnessResult]) -> HarnessBackend:
    """A `HarnessBackend` over a fixed result table, keyed by task_id — the
    hardware-free path the tests inject (the real one runs libFuzzer)."""

    def run(harness_source: str, task: HarnessTask) -> HarnessResult:
        if not harness_source.strip():
            return HarnessResult(build_ok=False, sanity_ok=False, coverage_edges=0,
                                 coverage_features=0, bug_found=False)
        return results.get(task.task_id,
                           HarnessResult(True, True, task.baseline_edges, 0, False))

    return run


def libfuzzer_backend():
    """The real backend. Rather than reinvent coverage measurement, this **reuses
    google/oss-fuzz-gen's own evaluation runner** — build the submitted harness on
    the OSS-Fuzz platform, run it, and diff its line coverage against the existing
    human-written target (their four metrics: compilability, runtime crashes,
    runtime coverage, coverage diff) — returning a HarnessResult. The determinism
    the score relies on was proven live on the ARVO ftfuzzer target
    (~/cgverify/harness_verify.sh). Provisioned into the attested verify worker;
    not importable in the hardware-free env."""
    raise NotImplementedError(
        "libfuzzer_backend wraps oss-fuzz-gen's evaluator on the OSS-Fuzz build "
        "image + a fuzz budget, on the attested worker (CYBERGYM_RUN_HW); see "
        "~/cgverify/harness_verify.sh for the proven mechanism. The hardware-free "
        "path uses stub_harness_backend."
    )


def harness_backend_from_env(default: HarnessBackend | None = None) -> HarnessBackend:
    """Return the real libFuzzer backend when CYBERGYM_RUN_HW=1, else the injected
    default (a stub). Mirrors cybergym_verifier.backend_from_env."""
    if os.environ.get("CYBERGYM_RUN_HW") == "1":
        return libfuzzer_backend()
    if default is None:
        raise RuntimeError("no harness backend: set CYBERGYM_RUN_HW=1 or inject a stub")
    return default


HARNESS_GEN_LANE = "cathedral_harness_gen"


__all__ = [
    "HarnessTask", "HarnessResult", "derived_harness_units",
    "HarnessBackend", "stub_harness_backend", "libfuzzer_backend",
    "harness_backend_from_env", "HARNESS_GEN_LANE",
]
