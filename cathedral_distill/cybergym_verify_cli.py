"""The differential-crash verify workload — what `Dockerfile.cybergym-verify` runs.

Runs as the admitted workload inside the TDX worker (see the Dockerfile's own
header comment): reads a task and a PoC from `/input`, runs the PoC against the
prebuilt vulnerable and patched binaries via the injected verifier backend, and
prints EXACTLY the canonical `DifferentialResult` JSON to stdout — nothing else.
The quote binds `sha256(image_digest || sha256hex(stdout))`, so stdout is the
binding surface: sorted keys, compact separators, no trailing newline, matching
every other canonical-JSON surface in this codebase (`eval_receipt.canonical_json`,
`polaris_attest.polaris_stdout`). Logs and errors go to stderr, never stdout.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cathedral_distill.cybergym import DifferentialResult, Level, Task
from cathedral_distill.cybergym_verifier import VerifierError, backend_from_env, verify_poc


class CliError(RuntimeError):
    """The verify CLI could not complete. Fails closed — never a silent pass."""


def canonical_result_bytes(result: DifferentialResult) -> bytes:
    """The exact stdout bytes the quote binds. No trailing newline."""
    return json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _read_task(path: str) -> Task:
    try:
        raw = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise CliError(f"could not read task file {path!r}: {exc}") from exc
    if not isinstance(raw, dict):
        raise CliError(f"task file {path!r} must be a JSON object")
    try:
        return Task(
            task_id=str(raw["task_id"]),
            level=Level(int(raw["level"])),
            binary_digest=str(raw["binary_digest"]),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise CliError(f"task file {path!r} is malformed: {exc}") from exc


def _read_poc(path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise CliError(f"could not read poc file {path!r}: {exc}") from exc


def run(task_path: str, poc_path: str) -> DifferentialResult:
    """Verify one PoC against one task's vul/fix binaries. Fails closed.

    The backend is `cybergym_verifier.backend_from_env()` — gated by
    `CYBERGYM_RUN_HW` (set in this image) and configured by
    `CYBERGYM_REPRODUCE_CMD` (+ optional `CYBERGYM_REPRODUCE_TIMEOUT_S` /
    `CYBERGYM_SANDBOX`). No backend configured is an operator/deployment error,
    not a verification outcome, so it raises rather than reporting a result.
    """
    task = _read_task(task_path)
    poc = _read_poc(poc_path)
    backend = backend_from_env()
    if backend is None:
        raise CliError(
            "no differential backend configured — CYBERGYM_RUN_HW and "
            "CYBERGYM_REPRODUCE_CMD must both be set inside the verify image"
        )
    try:
        return verify_poc(task, poc, backend)
    except VerifierError as exc:
        raise CliError(f"differential verification failed: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cathedral-cybergym-verify")
    parser.add_argument("--task", required=True, help="path to task.json")
    parser.add_argument("--poc", required=True, help="path to poc.bin")
    args = parser.parse_args(argv)
    try:
        result = run(args.task, args.poc)
    except CliError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_result_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
