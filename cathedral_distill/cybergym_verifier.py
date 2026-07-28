"""The CyberGym verifier runner — the differential crash test as executable work.

`cybergym.py` scores a `DifferentialResult`. This module *produces* one: it runs a
PoC against the vulnerable and patched builds and reads the two exit codes. It is
the piece that runs inside the attested worker (the `WorkloadExecutionAdapter`
input), and its output is the verified fact everything else is derived from.

The backend is injected. `subprocess_backend` shells out to CyberGym's own
`reproduce` runner over the prebuilt binaries — no compiler, milliseconds per run;
tests inject a deterministic function. The runner does not know or trust the model
that produced the PoC — it only observes what the bytes do to the binaries, which
is the whole point of fail-closed verification.

Safety posture: the PoC is adversarial input to a deliberately-crashing binary, so
production runs this inside the TDX sandbox (confidentiality + attestation) with
the binary/sanitiser environment pinned by digest. A bounded timeout maps to
CyberGym's clean code 300, so a hung target is "did not crash", never a pass.
"""
from __future__ import annotations

import hashlib
import subprocess
from typing import Callable

from cathedral_distill.cybergym import (
    CRASH_CLEAN_CODES,
    DifferentialResult,
    Task,
)

# (task_id, poc_bytes, mode) -> exit_code, where mode is "vul" | "fix".
VerifierBackend = Callable[[str, bytes, str], int]

TIMEOUT_CLEAN_CODE = 300  # CyberGym's "timed out, did not crash" — must be in CRASH_CLEAN


class VerifierError(RuntimeError):
    """Raised when verification cannot be performed (not when a PoC merely fails)."""


def poc_digest(poc_bytes: bytes) -> str:
    return "sha256:" + hashlib.sha256(poc_bytes).hexdigest()


def verify_poc(
    task: Task, poc_bytes: bytes, backend: VerifierBackend
) -> DifferentialResult:
    """Run one PoC against both builds and return the differential result.

    Runs the vulnerable build first; the patched build only matters when the vuln
    build actually crashed, but both are always run so the receipt records both
    exit codes and a validator can re-derive `solved` without re-running.
    """
    if not isinstance(poc_bytes, (bytes, bytearray)):
        raise VerifierError("poc must be raw bytes")
    vul = int(backend(task.task_id, bytes(poc_bytes), "vul"))
    fix = int(backend(task.task_id, bytes(poc_bytes), "fix"))
    return DifferentialResult(
        task_id=task.task_id, vul_exit_code=vul, fix_exit_code=fix
    )


def subprocess_backend(
    reproduce_cmd: str, *, timeout_s: float = 120.0
) -> VerifierBackend:
    """Backend that drives CyberGym's `reproduce` over the prebuilt binaries.

    `reproduce_cmd` is a template with `{mode}` (vul|fix); the PoC arrives on
    stdin. A timeout is reported as the clean timeout code, never as a crash — a
    target that hangs must not be scored as a solve.

    Not exercised in the hardware-free suite (it needs the CyberGym binaries);
    the injected backend covers the runner logic. This is the production seam.
    """
    import shlex

    def run(task_id: str, poc_bytes: bytes, mode: str) -> int:  # pragma: no cover
        if mode not in ("vul", "fix"):
            raise VerifierError(f"unknown mode {mode!r}")
        argv = shlex.split(reproduce_cmd.format(mode=mode, task_id=task_id))
        try:
            proc = subprocess.run(
                argv, input=poc_bytes, capture_output=True, timeout=timeout_s
            )
        except subprocess.TimeoutExpired:
            return TIMEOUT_CLEAN_CODE
        return proc.returncode

    return run


def sandboxed_subprocess_backend(
    reproduce_cmd: str,
    *,
    timeout_s: float = 120.0,
    cpu_seconds: int = 60,
    memory_bytes: int = 2 * 1024 * 1024 * 1024,
) -> VerifierBackend:
    """`subprocess_backend` hardened for running adversarial PoCs against a
    deliberately-crashing binary. The PoC is attacker input, so the child runs:

      * with a **scrubbed environment** — only a minimal PATH and the CUDA/TRITON
        vars a toolchain needs, never the validator's secrets (SparkProof SEC-4:
        untrusted candidate code must not read `os.environ`);
      * under **resource limits** — CPU time, address space, and no core dumps, so
        a runaway or memory-bomb PoC cannot exhaust the host;
      * with a **wall-clock timeout** mapped to the clean timeout code.

    Network isolation (no egress) is the remaining control and is enforced at the
    container/namespace layer around this process (run it inside `--network none`
    / a seccomp-net-denied sandbox); it is documented here as required, not
    something a bare subprocess can guarantee.
    """
    import os
    import resource
    import shlex

    safe_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    for keep in ("LANG", "LC_ALL"):
        if keep in os.environ:
            safe_env[keep] = os.environ[keep]
    for prefix in ("CUDA_", "TRITON_"):
        for k, v in os.environ.items():
            if k.startswith(prefix):
                safe_env[k] = v

    def _limits() -> None:  # pragma: no cover - runs in the child, before exec
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.setsid()  # own session/process group so a timeout kills the whole tree

    def run(task_id: str, poc_bytes: bytes, mode: str) -> int:  # pragma: no cover
        if mode not in ("vul", "fix"):
            raise VerifierError(f"unknown mode {mode!r}")
        argv = shlex.split(reproduce_cmd.format(mode=mode, task_id=task_id))
        try:
            proc = subprocess.run(
                argv, input=poc_bytes, capture_output=True, timeout=timeout_s,
                env=safe_env, preexec_fn=_limits, close_fds=True,
            )
        except subprocess.TimeoutExpired:
            return TIMEOUT_CLEAN_CODE
        return proc.returncode

    return run


def backend_from_env() -> VerifierBackend | None:
    """Select the real differential backend, gated by `CYBERGYM_RUN_HW`.

    The hardware path (the ~130 GB dataset + prebuilt vul/fix binaries) is kept
    out of the hardware-free suite: it runs only when `CYBERGYM_RUN_HW` is set.
    Then this reads `CYBERGYM_REPRODUCE_CMD` (the `{mode}`/`{task_id}` template)
    and optional `CYBERGYM_REPRODUCE_TIMEOUT_S`, and returns `subprocess_backend`.
    Returns `None` when `CYBERGYM_RUN_HW` is unset, so callers keep their injected
    (test/stub) backend and nothing hardware-bound runs by accident.
    """
    import os

    if not os.environ.get("CYBERGYM_RUN_HW"):
        return None
    cmd = os.environ.get("CYBERGYM_REPRODUCE_CMD")
    if not cmd:
        raise VerifierError(
            "CYBERGYM_RUN_HW is set but CYBERGYM_REPRODUCE_CMD (the reproduce "
            "command template) is not"
        )
    timeout = float(os.environ.get("CYBERGYM_REPRODUCE_TIMEOUT_S", "120"))
    # Default to the hardened sandbox for the real adversarial path; an operator
    # can opt out with CYBERGYM_SANDBOX=0 (e.g. when an outer container already
    # provides isolation).
    if os.environ.get("CYBERGYM_SANDBOX", "1") not in ("0", "false", "no", ""):
        return sandboxed_subprocess_backend(cmd, timeout_s=timeout)
    return subprocess_backend(cmd, timeout_s=timeout)


def crash_summary(result: DifferentialResult) -> str:
    """One line for an operator log. Never used for scoring — that is `solved`."""
    vul_crash = result.vul_exit_code not in CRASH_CLEAN_CODES
    fix_crash = result.fix_exit_code not in CRASH_CLEAN_CODES
    return (
        f"{result.task_id}: vul={'crash' if vul_crash else 'clean'} "
        f"fix={'crash' if fix_crash else 'clean'} -> {result.outcome}"
    )
