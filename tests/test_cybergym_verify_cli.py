"""`cybergym_verify_cli` — the workload `Dockerfile.cybergym-verify` entrypoints.

Proves the module the Dockerfile names actually exists and behaves as its own
contract comment promises: reads task.json + poc.bin, prints EXACTLY the
canonical DifferentialResult JSON to stdout (no trailing newline, sorted keys),
and fails closed (nonzero exit, stderr only) on any malformed input or missing
backend — nothing on the workload path may write an unbounded stdout.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym_verify_cli as cli  # noqa: E402
from cathedral_distill.cybergym import DifferentialResult  # noqa: E402

TASK_ID = "arvo:7"
DIGEST = "sha256:" + "ab" * 32


def _write(tmp_path, name, content):
    path = tmp_path / name
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content)
    return str(path)


def _task_json(tmp_path, **over):
    body = {"task_id": TASK_ID, "level": 0, "binary_digest": DIGEST}
    body.update(over)
    return _write(tmp_path, "task.json", json.dumps(body))


def _solving_backend(task_id, poc, mode):
    return 1 if mode == "vul" else 0  # crashes vul, clean on fix -> solved


def test_canonical_result_bytes_has_no_trailing_newline_and_sorted_keys():
    result = DifferentialResult(task_id=TASK_ID, vul_exit_code=1, fix_exit_code=0)
    raw = cli.canonical_result_bytes(result)
    assert not raw.endswith(b"\n")
    decoded = json.loads(raw)
    assert decoded == {
        "task_id": TASK_ID, "vul_exit_code": 1, "fix_exit_code": 0,
        "stable": True, "solved": True, "outcome": "solved",
    }
    # deterministic across calls -> the quote's stdout binding is reproducible
    assert raw == cli.canonical_result_bytes(result)


def test_run_verifies_against_the_injected_backend(tmp_path, monkeypatch):
    task_path = _task_json(tmp_path)
    poc_path = _write(tmp_path, "poc.bin", b"\x90" * 16)
    monkeypatch.setattr(cli, "backend_from_env", lambda: _solving_backend)
    result = cli.run(task_path, poc_path)
    assert result.solved is True


def test_run_without_a_configured_backend_fails_closed(tmp_path, monkeypatch):
    task_path = _task_json(tmp_path)
    poc_path = _write(tmp_path, "poc.bin", b"")
    monkeypatch.setattr(cli, "backend_from_env", lambda: None)
    with pytest.raises(cli.CliError, match="no differential backend configured"):
        cli.run(task_path, poc_path)


def test_malformed_task_id_fails_closed(tmp_path, monkeypatch):
    task_path = _task_json(tmp_path, task_id="not-a-real-task-id")
    poc_path = _write(tmp_path, "poc.bin", b"")
    monkeypatch.setattr(cli, "backend_from_env", lambda: _solving_backend)
    with pytest.raises(cli.CliError, match="malformed"):
        cli.run(task_path, poc_path)


def test_missing_poc_file_fails_closed(tmp_path, monkeypatch):
    task_path = _task_json(tmp_path)
    monkeypatch.setattr(cli, "backend_from_env", lambda: _solving_backend)
    with pytest.raises(cli.CliError, match="could not read poc file"):
        cli.run(task_path, str(tmp_path / "missing.bin"))


def test_main_prints_only_the_canonical_result_to_stdout(tmp_path, monkeypatch, capsys):
    task_path = _task_json(tmp_path)
    poc_path = _write(tmp_path, "poc.bin", b"\x90" * 16)
    monkeypatch.setattr(cli, "backend_from_env", lambda: _solving_backend)
    code = cli.main(["--task", task_path, "--poc", poc_path])
    out, err = capsys.readouterr()
    assert code == 0
    assert err == ""
    assert json.loads(out) == {
        "task_id": TASK_ID, "vul_exit_code": 1, "fix_exit_code": 0,
        "stable": True, "solved": True, "outcome": "solved",
    }


def test_main_exits_nonzero_and_writes_only_stderr_on_failure(tmp_path, monkeypatch, capsys):
    task_path = _task_json(tmp_path)
    poc_path = _write(tmp_path, "poc.bin", b"")
    monkeypatch.setattr(cli, "backend_from_env", lambda: None)
    code = cli.main(["--task", task_path, "--poc", poc_path])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert "no differential backend configured" in err
