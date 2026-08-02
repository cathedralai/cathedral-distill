"""The CYBERGYM_RUN_HW gate (issue #4): the real-binary differential path is kept
out of the hardware-free suite and runs only when explicitly enabled.

The env-gate wiring itself is unit-tested here (no dataset needed); the real
differential run is a skipif-guarded test that executes only on a host with
CYBERGYM_RUN_HW set and the ~130 GB dataset present.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym_verifier as cv  # noqa: E402


def test_backend_from_env_is_none_without_the_flag(monkeypatch):
    monkeypatch.delenv("CYBERGYM_RUN_HW", raising=False)
    assert cv.backend_from_env() is None  # nothing hardware-bound runs by accident


def test_backend_from_env_returns_a_backend_when_enabled(monkeypatch):
    monkeypatch.setenv("CYBERGYM_RUN_HW", "1")
    monkeypatch.setenv("CYBERGYM_REPRODUCE_CMD", "true {mode} {task_id}")
    backend = cv.backend_from_env()
    assert callable(backend)  # constructed, not yet run — no binaries touched here


@pytest.mark.parametrize(
    "sandbox_value",
    [None, "", " ", " 0", "0 ", "false", "no", "unknown"],
)
def test_backend_from_env_sandbox_setting_fails_closed(monkeypatch, sandbox_value):
    monkeypatch.setenv("CYBERGYM_RUN_HW", "1")
    monkeypatch.setenv("CYBERGYM_REPRODUCE_CMD", "true {mode} {task_id}")
    if sandbox_value is None:
        monkeypatch.delenv("CYBERGYM_SANDBOX", raising=False)
    else:
        monkeypatch.setenv("CYBERGYM_SANDBOX", sandbox_value)

    hardened = object()
    raw = object()
    monkeypatch.setattr(
        cv, "sandboxed_subprocess_backend", lambda *args, **kwargs: hardened
    )
    monkeypatch.setattr(cv, "subprocess_backend", lambda *args, **kwargs: raw)

    assert cv.backend_from_env() is hardened


def test_backend_from_env_allows_only_explicit_zero_opt_out(monkeypatch):
    monkeypatch.setenv("CYBERGYM_RUN_HW", "1")
    monkeypatch.setenv("CYBERGYM_REPRODUCE_CMD", "true {mode} {task_id}")
    monkeypatch.setenv("CYBERGYM_SANDBOX", "0")

    hardened = object()
    raw = object()
    monkeypatch.setattr(
        cv, "sandboxed_subprocess_backend", lambda *args, **kwargs: hardened
    )
    monkeypatch.setattr(cv, "subprocess_backend", lambda *args, **kwargs: raw)

    assert cv.backend_from_env() is raw


def test_enabled_without_a_command_fails_closed(monkeypatch):
    monkeypatch.setenv("CYBERGYM_RUN_HW", "1")
    monkeypatch.delenv("CYBERGYM_REPRODUCE_CMD", raising=False)
    with pytest.raises(cv.VerifierError, match="CYBERGYM_REPRODUCE_CMD"):
        cv.backend_from_env()


@pytest.mark.skipif(
    not os.environ.get("CYBERGYM_RUN_HW"),
    reason="needs CYBERGYM_RUN_HW=1 and the CyberGym vul/fix dataset",
)
def test_real_differential_backend_runs():  # pragma: no cover - hardware path
    from cathedral_distill.cybergym import Level, Task

    backend = cv.backend_from_env()
    assert backend is not None
    task = Task(task_id=os.environ["CYBERGYM_HW_TASK_ID"], level=Level(0),
                binary_digest="sha256:" + "0" * 64)
    result = cv.verify_poc(task, os.environ["CYBERGYM_HW_POC"].encode(), backend)
    # a known-solving PoC crashes the vul build (non-clean) and not the fix build
    assert result.solved
