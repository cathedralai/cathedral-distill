"""Every documented test count must match the suite, or CI says so.

The claim "N tests" appears in the README, two docs and two site pages. Nothing
checked it, and it drifted into **three different values describing one suite** —
670 in `docs/LAUNCH_COPY.md` and `docs/POSITIONING.md`, 678 in `README.md`, 721 on
the site — each written at a different moment and then left. A number that nobody
verifies is worse than no number: it is a specific, checkable claim about the
project that happens to be false, in the files a newcomer reads first.

So the number is pinned here. Adding a test now fails this, and the failure names
the value to write. That is the intended cost: the claim is load-bearing marketing
copy, so keeping it true is part of adding a test.

**Collected, not passing.** `tests/test_cybergym_hw.py` skips without
`CYBERGYM_RUN_HW=1` and the real vul/fix dataset, so the number that *pass* depends
on the environment — which is exactly the kind of number that cannot be maintained
in a document. The collected count is the same everywhere, so that is what is
claimed and what is checked.

Collection runs in a subprocess so the answer does not depend on how this test was
invoked: running one file must not report a smaller suite and fail.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Every file that states a count, and the pattern that finds it. Add a file here
# when it starts making the claim; the test then holds it to the same number.
CLAIM = re.compile(r"(\d[\d,]*)\s*(?:passing\s+)?tests\b", re.IGNORECASE)
DOCUMENTED = (
    "README.md",
    "docs/LAUNCH_COPY.md",
    "docs/POSITIONING.md",
    "site/index.html",
    "site/research.html",
)


def _collected() -> int:
    """How many tests the suite collects, asked of pytest itself.

    `-o addopts=` clears the `-q` in pyproject: quiet collection prints per-file
    counts and no total, so the total has to be re-enabled to be parsed.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-o", "addopts=",
         "-p", "no:cacheprovider", "tests"],
        capture_output=True, text=True, cwd=ROOT, timeout=300,
    )
    match = re.search(r"(\d+) tests? collected", result.stdout)
    if match is None:
        pytest.fail(
            "could not read a collected-test count from pytest:\n"
            f"exit={result.returncode}\n{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
        )
    return int(match.group(1))


def _claims(relative: str) -> list[tuple[int, int, str]]:
    """`(line_number, count, line)` for every stated count in one file."""
    path = ROOT / relative
    found: list[tuple[int, int, str]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for match in CLAIM.finditer(line):
            # Skip ordinals and code identifiers: only a bare integer is a claim.
            digits = match.group(1).replace(",", "")
            if digits.isdigit():
                found.append((number, int(digits), line.strip()))
    return found


def test_the_suite_still_collects_what_the_docs_claim():
    collected = _collected()
    wrong: list[str] = []
    seen = 0
    for relative in DOCUMENTED:
        for line_number, claimed, text in _claims(relative):
            seen += 1
            if claimed != collected:
                wrong.append(f"  {relative}:{line_number} says {claimed} — {text[:90]}")
    assert seen, "no file states a test count any more; drop this test or fix DOCUMENTED"
    assert not wrong, (
        f"the suite collects {collected} tests, but these disagree:\n"
        + "\n".join(wrong)
        + f"\n\nUpdate them to {collected}."
    )


def test_every_listed_file_exists_and_states_a_count():
    """A renamed or reworded file must not silently stop being checked."""
    for relative in DOCUMENTED:
        path = ROOT / relative
        assert path.is_file(), f"{relative} is listed in DOCUMENTED but does not exist"
        assert _claims(relative), (
            f"{relative} no longer states a test count; remove it from DOCUMENTED "
            "rather than leaving a check that silently passes"
        )


def test_the_count_is_collected_rather_than_passing():
    """The documented number must be the environment-independent one.

    A `passing` count would be a different number here than on a machine with the
    CyberGym dataset, so it cannot be stated in a document that is true everywhere.
    This asserts the gap exists, so if the hardware skip ever goes away the choice
    can be revisited deliberately.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-o", "addopts=",
         "-p", "no:cacheprovider", "-m", "", "tests/test_cybergym_hw.py"],
        capture_output=True, text=True, cwd=ROOT, timeout=300,
    )
    assert "collected" in result.stdout, result.stdout[-500:]
    source = (ROOT / "tests" / "test_cybergym_hw.py").read_text(encoding="utf-8")
    assert "CYBERGYM_RUN_HW" in source, (
        "the hardware suite no longer gates on CYBERGYM_RUN_HW; if nothing skips by "
        "default, a `passing` count is now stable and this module's choice of "
        "`collected` can be reconsidered"
    )
