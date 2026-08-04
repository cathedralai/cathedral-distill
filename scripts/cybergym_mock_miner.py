#!/usr/bin/env python3
"""Drive a loopback CyberGym repro server through its public HTTP surface.

This is an E2E *test harness*, not a production miner.  It deliberately talks
only to an explicit loopback URL, and its known ARVO fixtures are for proving
that the verifier discriminates between a real differential crash and garbage.
It must never be used against a reward-bearing public endpoint.

The harness verifies all three mutation routes:

* capable miners submit known local test fixtures;
* a cheater submits plausible garbage and must receive no credit; and
* a grinder cannot replace a sealed model commitment.

Every (miner, task) result is retained.  A run fails if a capable dispatch
fails, any capable task is not creditable, a task advertised by ``/healthz`` is
not covered, the artifact response violates its declared contract, a cheater
earns credit, or commitment re-draws are accepted.

For a private corpus, replace ``fixture_poc`` with an actual miner that obtains
the authorised build from the deployment's authenticated artifact channel.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


DEFAULT_BASE_URL = "http://127.0.0.1:8666"
DEFAULT_COMMITMENT = "sha256:" + "a1" * 32
DEFAULT_TIMEOUT = 600
OUT_OF_BAND_ARTIFACT_ERROR = (
    "no inline artifact for this task; fetch the build out of band by binary_digest"
)
LONG_REASONING = (
    "I read the parser's length field and compare it against the destination "
    "buffer size to determine whether an attacker controlled value can exceed "
    "the allocation and corrupt adjacent heap metadata on the vulnerable build only"
)


@dataclass(frozen=True)
class Attempt:
    """One submission, never collapsed by task id."""

    miner_label: str
    hotkey: str
    task_id: str
    http_status: int
    solved: bool
    creditable: bool
    artifact_contract_ok: bool
    error: str | None = None


@dataclass(frozen=True)
class MinerRun:
    """All attempts produced by one dispatch."""

    miner_label: str
    hotkey: str
    attempts: tuple[Attempt, ...]
    dispatch_error: str | None = None


@dataclass(frozen=True)
class E2EReport:
    """Fail-closed result of a complete mock-miner drive."""

    advertised_task_ids: frozenset[str]
    capable_runs: tuple[MinerRun, ...]
    cheater_runs: tuple[MinerRun, ...]
    expected_capable_runs: int
    grinder_redraws_accepted: int
    grinder_error: str | None = None

    @property
    def capable_attempts(self) -> tuple[Attempt, ...]:
        return tuple(attempt for run in self.capable_runs for attempt in run.attempts)

    @property
    def cheater_attempts(self) -> tuple[Attempt, ...]:
        return tuple(attempt for run in self.cheater_runs for attempt in run.attempts)

    @property
    def covered_task_ids(self) -> frozenset[str]:
        return frozenset(attempt.task_id for attempt in self.capable_attempts)

    @property
    def missing_task_ids(self) -> frozenset[str]:
        return self.advertised_task_ids - self.covered_task_ids

    @property
    def failures(self) -> tuple[str, ...]:
        failures: list[str] = []
        if not self.advertised_task_ids:
            failures.append("/healthz advertised no tasks")
        if len(self.capable_runs) != self.expected_capable_runs:
            failures.append(
                "capable dispatch count is "
                f"{len(self.capable_runs)}/{self.expected_capable_runs}"
            )
        for run in (*self.capable_runs, *self.cheater_runs):
            if run.dispatch_error:
                failures.append(f"{run.miner_label} dispatch failed: {run.dispatch_error}")
        if len(self.capable_attempts) < len(self.advertised_task_ids):
            failures.append(
                "too few capable attempts for advertised task coverage: "
                f"{len(self.capable_attempts)}/{len(self.advertised_task_ids)}"
            )
        if self.missing_task_ids:
            failures.append(
                "advertised task(s) were never attempted: "
                + ", ".join(sorted(self.missing_task_ids))
            )
        unexpected = self.covered_task_ids - self.advertised_task_ids
        if unexpected:
            failures.append("attempted unadvertised task(s): " + ", ".join(sorted(unexpected)))
        for attempt in self.capable_attempts:
            if not attempt.artifact_contract_ok:
                failures.append(
                    f"{attempt.miner_label}/{attempt.task_id}: artifact route violated its contract"
                )
            if attempt.error:
                failures.append(f"{attempt.miner_label}/{attempt.task_id}: {attempt.error}")
            elif not attempt.creditable:
                failures.append(
                    f"{attempt.miner_label}/{attempt.task_id}: capable submission was not creditable"
                )
        for attempt in self.cheater_attempts:
            if not attempt.artifact_contract_ok:
                failures.append(
                    f"{attempt.miner_label}/{attempt.task_id}: artifact route violated its contract"
                )
            if attempt.error:
                failures.append(f"{attempt.miner_label}/{attempt.task_id}: {attempt.error}")
            elif attempt.creditable:
                failures.append(
                    f"{attempt.miner_label}/{attempt.task_id}: cheater submission earned credit"
                )
        if not self.cheater_attempts:
            failures.append("cheater produced no submission; discrimination was not tested")
        if self.grinder_error:
            failures.append(f"grinder dispatch failed: {self.grinder_error}")
        if self.grinder_redraws_accepted:
            failures.append(
                f"grinder re-drew a sealed batch {self.grinder_redraws_accepted} time(s)"
            )
        return tuple(failures)

    @property
    def passed(self) -> bool:
        return not self.failures


def _loopback_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "http" or not parsed.hostname or parsed.path not in {"", "/"}:
        raise argparse.ArgumentTypeError("base URL must be an http:// loopback host with no path")
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname.lower() in {"localhost", "localhost.localdomain"}
    if not loopback:
        raise argparse.ArgumentTypeError("mock E2E harness only permits an explicit loopback base URL")
    return value.rstrip("/")


def _request(base_url: str, method: str, path: str, payload: Mapping[str, Any] | None,
             *, timeout: int) -> tuple[int, dict[str, Any]]:
    body = json.dumps(dict(payload)).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        base_url + path, data=body, method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, _json_object(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _json_object(exc.read())


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(raw)
    except ValueError:
        return {"raw": raw[:200].decode("utf-8", "replace")}
    return dict(decoded) if isinstance(decoded, Mapping) else {"raw": decoded}


def fixture_poc(task_id: str, *, docker: str) -> bytes:
    """Read an ARVO test fixture from a local image.

    This is intentionally narrow: it refuses non-ARVO tasks instead of guessing
    a registry/image convention for a private corpus.
    """
    kind, separator, number = task_id.partition(":")
    if kind != "arvo" or not separator or not number.isdecimal():
        raise ValueError(f"no local mock fixture is defined for task {task_id!r}")
    image = f"n132/arvo:{number}-vul"
    result = subprocess.run(
        [docker, "run", "--rm", "--entrypoint", "cat", image, "/tmp/poc"],
        capture_output=True, check=True,
    )
    if not result.stdout:
        raise ValueError(f"mock fixture is empty for {task_id!r}")
    return result.stdout


def _trace(task_id: str, poc: bytes) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "poc_sha256": "sha256:" + hashlib.sha256(poc).hexdigest(),
        "model_id": "cathedral/mock-miner-e2e-v2",
        "licence": "cathedral-corpus-v1",
        "model_seal": hashlib.sha256(b"mock-miner-e2e-v2").hexdigest(),
        "steps": [
            {"step": 1, "thought": f"Read the parser input path. {LONG_REASONING}", "action": "read_file"},
            {"step": 2, "thought": f"Check the allocation bound. {LONG_REASONING}", "action": "read_file"},
            {"step": 3, "thought": f"Derive the trigger condition. {LONG_REASONING}", "action": "reason"},
            {"step": 4, "thought": f"Write a bounded reproducer. {LONG_REASONING}", "action": "write_poc"},
            {"step": 5, "thought": f"Check vulnerable versus fixed. {LONG_REASONING}", "action": "verify"},
        ],
    }


def _artifact_contract_ok(status: int, payload: Mapping[str, Any]) -> bool:
    if status == 200 and isinstance(payload.get("program"), str):
        return True
    return status == 400 and payload.get("error") == OUT_OF_BAND_ARTIFACT_ERROR


def _submit(base_url: str, *, batch_id: str, task_id: str, hotkey: str, poc: bytes,
            timeout: int) -> tuple[int, dict[str, Any]]:
    return _request(base_url, "POST", "/cybergym/submit", {
        "schema": "cathedral_cybergym_submission_envelope_v1",
        "batch_id": batch_id,
        "task_id": task_id,
        "miner_hotkey": hotkey,
        "poc_base64": base64.b64encode(poc).decode("ascii"),
        "trace": _trace(task_id, poc),
    }, timeout=timeout)


def run_miner(base_url: str, label: str, hotkey: str, *, cheat: bool, commitment: str,
              timeout: int, docker: str) -> MinerRun:
    """Dispatch and submit every task, retaining all attempts."""
    status, batch = _request(base_url, "POST", "/cybergym/dispatch", {
        "miner_hotkey": hotkey, "model_commitment": commitment,
    }, timeout=timeout)
    if status != 200:
        return MinerRun(label, hotkey, (), f"HTTP {status}: {batch.get('error', batch)}")
    batch_id = batch.get("batch_id")
    raw_tasks = batch.get("tasks")
    if not isinstance(batch_id, str) or not isinstance(raw_tasks, list):
        return MinerRun(label, hotkey, (), "dispatch response lacks batch_id or tasks")

    attempts: list[Attempt] = []
    for raw_task in raw_tasks:
        task_id = raw_task.get("task_id") if isinstance(raw_task, Mapping) else None
        if not isinstance(task_id, str) or not task_id:
            attempts.append(Attempt(label, hotkey, "<invalid>", 0, False, False, False,
                                    "dispatch returned an invalid task"))
            continue
        artifact_status, artifact = _request(
            base_url, "POST", "/cybergym/artifact", {"task_id": task_id}, timeout=timeout)
        try:
            poc = b"NOT-A-REAL-CRASH-INPUT" * 64 if cheat else fixture_poc(task_id, docker=docker)
            submit_status, outcome = _submit(
                base_url, batch_id=batch_id, task_id=task_id, hotkey=hotkey, poc=poc, timeout=timeout)
            attempts.append(Attempt(
                label, hotkey, task_id, submit_status, bool(outcome.get("solved")),
                bool(outcome.get("creditable")), _artifact_contract_ok(artifact_status, artifact),
                None if submit_status == 200 else str(outcome.get("error", outcome)),
            ))
        except (OSError, ValueError, subprocess.SubprocessError, urllib.error.URLError) as exc:
            attempts.append(Attempt(
                label, hotkey, task_id, 0, False, False,
                _artifact_contract_ok(artifact_status, artifact), f"submission setup failed: {exc}",
            ))
    return MinerRun(label, hotkey, tuple(attempts))


def run_grinder(base_url: str, hotkey: str, *, timeout: int) -> tuple[int, str | None]:
    status, first = _request(base_url, "POST", "/cybergym/dispatch", {
        "miner_hotkey": hotkey, "model_commitment": DEFAULT_COMMITMENT,
    }, timeout=timeout)
    if status != 200:
        return 0, f"initial dispatch HTTP {status}: {first.get('error', first)}"
    accepted = 0
    for index in range(5):
        status, _response = _request(base_url, "POST", "/cybergym/dispatch", {
            "miner_hotkey": hotkey, "model_commitment": f"sha256:{index:064x}",
        }, timeout=timeout)
        accepted += status == 200
    return accepted, None


def _print_report(report: E2EReport) -> None:
    print("CyberGym mock-miner E2E result")
    print(f"  advertised tasks       : {', '.join(sorted(report.advertised_task_ids)) or '<none>'}")
    print(f"  capable attempts       : {len(report.capable_attempts)}")
    print(f"  capable coverage       : {', '.join(sorted(report.covered_task_ids)) or '<none>'}")
    print(f"  missing advertised     : {', '.join(sorted(report.missing_task_ids)) or '<none>'}")
    print(f"  cheater attempts       : {len(report.cheater_attempts)}")
    print(f"  grinder re-draws       : {report.grinder_redraws_accepted}")
    for attempt in (*report.capable_attempts, *report.cheater_attempts):
        print(
            f"  {attempt.miner_label}/{attempt.task_id}: http={attempt.http_status} "
            f"solved={attempt.solved} creditable={attempt.creditable} "
            f"artifact_contract={'ok' if attempt.artifact_contract_ok else 'BAD'}"
            + (f" error={attempt.error}" if attempt.error else "")
        )
    for failure in report.failures:
        print(f"  FAIL: {failure}")
    if report.passed:
        print("  PASS: full capable coverage, rejection of garbage, and sealed commitments.")


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", type=_loopback_url, default=DEFAULT_BASE_URL)
    parser.add_argument("--hotkey", action="append", dest="hotkeys", default=[],
                        help="registered capable-miner hotkey; repeat once per capable dispatch")
    parser.add_argument("--cheater-hotkey", default="5CheatingMiner")
    parser.add_argument("--grinder-hotkey", default="5GrindingMiner")
    parser.add_argument(
        "--model-commitment", default=DEFAULT_COMMITMENT,
        help="existing sealed commitment for a registered capable hotkey",
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--docker", default="docker")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if not args.hotkeys:
        args.hotkeys = [f"5Capable{number}" for number in range(1, 7)]
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        health_status, health = _request(args.base_url, "GET", "/healthz", None, timeout=15)
    except urllib.error.URLError as exc:
        print(f"FAIL: /healthz is unreachable: {exc}", file=sys.stderr)
        return 1
    raw_advertised = health.get("tasks") if health_status == 200 else None
    advertised = frozenset(item for item in raw_advertised if isinstance(item, str)) if isinstance(raw_advertised, list) else frozenset()

    capable_runs = tuple(
        run_miner(
            args.base_url, f"capable-{number}", hotkey, cheat=False,
            commitment=args.model_commitment, timeout=args.timeout, docker=args.docker,
        )
        for number, hotkey in enumerate(args.hotkeys, start=1)
    )
    cheater_runs = (
        run_miner(
            args.base_url, "cheater", args.cheater_hotkey, cheat=True,
            commitment=DEFAULT_COMMITMENT, timeout=args.timeout, docker=args.docker,
        ),
    )
    redraws, grinder_error = run_grinder(
        args.base_url, args.grinder_hotkey, timeout=args.timeout)
    report = E2EReport(
        advertised, capable_runs, cheater_runs, len(args.hotkeys), redraws, grinder_error)
    _print_report(report)
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
