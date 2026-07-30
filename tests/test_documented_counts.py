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
# Two claim shapes are recognised: "N tests" (checked against collected) and
# "N passed" (checked against a real run's actual passed count) — issue #31: a
# stale "678 passed" survived in README's "Run the tests" block because the
# original pattern only matched the "tests" phrasing, so this file's own
# collected-vs-passing distinction (see test_the_count_is_collected_rather_than_passing)
# left an opening for exactly the kind of claim it says cannot be maintained.
CLAIM = re.compile(r"(\d[\d,]*)\s*(?:passing\s+)?(tests|passed)\b", re.IGNORECASE)
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


def _claims(relative: str) -> list[tuple[int, int, str, str]]:
    """`(line_number, count, kind, line)` for every stated count in one file.

    `kind` is `"tests"` or `"passed"` — they are checked against different
    ground truths (collected vs. an actual run's passed count).
    """
    path = ROOT / relative
    found: list[tuple[int, int, str, str]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for match in CLAIM.finditer(line):
            # Skip ordinals and code identifiers: only a bare integer is a claim.
            digits = match.group(1).replace(",", "")
            if digits.isdigit():
                found.append((number, int(digits), match.group(2).lower(), line.strip()))
    return found


_THIS_FILE = "tests/test_documented_counts.py"


def _passed() -> int:
    """How many tests an actual run reports as passed, asked of pytest itself.

    Not derived from `collected - known_skip_count`: the skip is a runtime
    `pytest.skip()` inside `test_cybergym_hw.py`, invisible to `--collect-only`,
    and hardcoding "1" would silently go stale the moment a second skip is
    added anywhere in the suite — exactly the drift this module exists to
    catch. A real run is the only source that cannot lie about this.

    MUST exclude `_THIS_FILE` from the subprocess: this function is called from
    a test IN that file, so a subprocess run over the unrestricted "tests"
    directory recurses into itself — this function calling itself, inside a
    child process, unboundedly. Not hypothetical: the first version of this
    fix did exactly that and forked well over a hundred live pytest processes
    before it was caught. `--ignore` makes the recursion structurally
    impossible rather than merely avoided, so the excluded file's own (fixed,
    never-skipped — asserted below) test count is added back separately.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-o", "addopts=", "-p", "no:cacheprovider",
         "-p", "no:warnings", f"--ignore={_THIS_FILE}", "tests"],
        capture_output=True, text=True, cwd=ROOT, timeout=600,
    )
    match = re.search(r"(\d+) passed", result.stdout)
    if match is None:
        pytest.fail(
            "could not read a passed-test count from a real pytest run:\n"
            f"exit={result.returncode}\n{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
        )
    this_file_count = _collected_in(_THIS_FILE)
    return int(match.group(1)) + this_file_count


def _collected_in(relative: str) -> int:
    """How many tests a single file collects — used only to add this module's
    own (excluded-from-the-recursive-run) tests back into `_passed()`'s total.
    Safe to treat as always-passing: `test_this_files_own_tests_never_skip`
    below asserts nothing here ever carries a skip marker or calls `pytest.skip`.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-o", "addopts=",
         "-p", "no:cacheprovider", relative],
        capture_output=True, text=True, cwd=ROOT, timeout=60,
    )
    match = re.search(r"(\d+) tests? collected", result.stdout)
    if match is None:
        pytest.fail(f"could not collect {relative}:\n{result.stdout[-1000:]}")
    return int(match.group(1))


def test_the_suite_still_collects_what_the_docs_claim():
    collected = _collected()
    passed = _passed()
    ground_truth = {"tests": collected, "passed": passed}
    wrong: list[str] = []
    seen = 0
    for relative in DOCUMENTED:
        for line_number, claimed, kind, text in _claims(relative):
            seen += 1
            if claimed != ground_truth[kind]:
                wrong.append(
                    f"  {relative}:{line_number} says {claimed} {kind} — {text[:90]}"
                )
    assert seen, "no file states a test count any more; drop this test or fix DOCUMENTED"
    assert not wrong, (
        f"the suite collects {collected} tests and {passed} pass, but these disagree:\n"
        + "\n".join(wrong)
        + f"\n\nUpdate 'N tests' claims to {collected} and 'N passed' claims to {passed}."
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


def test_this_files_own_tests_never_skip():
    """`_passed()` adds this file's own test count back in as a flat, assumed-
    passing number (see `_collected_in`) rather than running it — so nothing
    in this file may ever carry a skip marker or call the skip function, or
    that add-back becomes wrong instead of merely excluded.

    Checked structurally (AST), not by searching the file's own text for the
    words that name a skip: this module's source necessarily CONTAINS those
    words — this very check has to write them down to name what it is looking
    for — so a plain substring search always finds itself and the check can
    never fail. A decorator list and a call's callee are syntax positions, not
    prose; unparsing only those specific AST nodes cannot be confused by a
    docstring, an error message, or this paragraph.
    """
    import ast

    tree = ast.parse((ROOT / _THIS_FILE).read_text(encoding="utf-8"), filename=_THIS_FILE)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if "skipif" in ast.unparse(dec).lower():
                    offenders.append(f"{node.name} carries {ast.unparse(dec)}")
        if isinstance(node, ast.Call):
            callee = node.func
            if (isinstance(callee, ast.Attribute) and callee.attr == "skip"
                    and isinstance(callee.value, ast.Name) and callee.value.id == "pytest"):
                offenders.append(f"line {node.lineno} calls pytest.{callee.attr}(...)")
    assert not offenders, (
        f"{_THIS_FILE} now has a skip ({'; '.join(offenders)}) — _passed()'s flat "
        "add-back of this file's collected count is no longer valid; it must run "
        "this file for real (still excluded from the outer subprocess to avoid "
        "the recursion) and add its actual passed count instead"
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
