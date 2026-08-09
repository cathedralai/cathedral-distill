"""Stage 1 of the Cathedral Security Agent pipeline: harness-capability competition.

Miners submit a GENERAL security-agent harness (committed by digest), NOT a solution. We
draw a batch of FRESH SEALED tasks AFTER the harness commitment, run the harness on each
under an attested, no-egress runner, and score the harness by how many tasks it GENUINELY
solves — the same differential the reward path uses (crash the vul build, spare the fix).
No reasoning traces are collected in Stage 1; this stage discovers which agent architectures
actually solve. The trace-manufacturing dataset is Stage 2.

WHY A HIGH STAGE-1 SCORE MEANS "GENUINE CAPABILITY" — three requirements, each stated where
it is enforced or, honestly, only required:

1. **COMMIT-THEN-DRAW (enforced here).** The harness digest IS the dispatch commitment that
   freezes the batch draw, so a harness cannot be tuned to the exact tasks it is graded on.
   `evaluate_harness` refuses a dispatch whose `model_commitment` is not this harness's digest.

2. **NO EGRESS (required of the runner, not enforceable here).** The runner MUST execute the
   harness with network isolation. A general harness with open egress fetches the public
   OSS-Fuzz/CVE reproducer at runtime and "solves" everything — TDX would attest it happily.
   The runner is an injected seam whose production implementation is the TDX-attested,
   no-egress enclave; this module cannot enforce isolation and does not pretend to.

3. **FRESH, NON-PUBLIC TASKS (the corpus's job, not this module's).** Even with no network
   egress, the answer can be reached through the harness model's own weights or a baked-in
   corpus (KNOWN_FLAWS answer-provenance channels 2/3). The batch MUST come from an admitted
   sealed corpus of bugs outside the harness model's memorization; the supply guarantee lives
   in the corpus, and no score here is meaningful without it.

The harness receives only the dispatched CHALLENGE ARTIFACT per task (never the held reference
PoC), produces an exploit, and `cybergym_verifier.verify_poc` decides solved / not.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Callable

from cathedral_distill.cybergym import Level, Task
from cathedral_distill.cybergym_protocol import DispatchedTask, DispatchMessage
from cathedral_distill.cybergym_verifier import VerifierBackend, poc_digest, verify_poc

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class HarnessError(ValueError):
    """A Stage-1 harness submission or evaluation is malformed. Fails closed."""


@dataclass(frozen=True)
class HarnessSubmission:
    """A miner's Stage-1 entry: a committed general harness, not a solution.

    `harness_digest` is the sha256 of the exact harness bundle/image the miner submits;
    it doubles as the dispatch commitment that freezes the batch draw (commit-then-draw).
    """

    miner_hotkey: str
    harness_digest: str
    version: str

    def __post_init__(self) -> None:
        if not self.miner_hotkey:
            raise HarnessError("miner_hotkey is required")
        if not _DIGEST_RE.match(self.harness_digest):
            raise HarnessError("harness_digest must be sha256:<64 hex>")
        if not self.version or len(self.version) > 32:
            raise HarnessError("version must be 1..32 chars")


@dataclass(frozen=True)
class HarnessResult:
    """The outcome of running the harness on one task."""

    task_id: str
    solved: bool
    exploit_sha256: str | None  # None when the harness produced no output
    reason: str  # the differential outcome, or why no solve


@dataclass(frozen=True)
class HarnessScore:
    """A harness's capability on one fresh batch: solve count over what was dispatched."""

    miner_hotkey: str
    harness_digest: str
    dispatched: int
    results: tuple[HarnessResult, ...] = field(default_factory=tuple)

    @property
    def solved(self) -> int:
        return sum(1 for r in self.results if r.solved)

    @property
    def solve_rate(self) -> Decimal:
        """Fraction of the fresh batch the harness genuinely solved (0 on an empty batch)."""
        if self.dispatched <= 0:
            return Decimal(0)
        return Decimal(self.solved) / Decimal(self.dispatched)


# (submission, task, challenge_artifact) -> exploit bytes the harness produced, or None.
# The PRODUCTION implementation runs the committed harness inside a TDX-attested enclave
# with NO network egress; a local subprocess runner (below) covers the dev/test path.
HarnessRunner = Callable[[HarnessSubmission, DispatchedTask, bytes], bytes | None]

# (task_id) -> the bounded challenge artifact the harness is allowed to see. NEVER the
# held reference PoC — that is the answer.
ArtifactProvider = Callable[[str], bytes]


def evaluate_harness(
    submission: HarnessSubmission,
    dispatch: DispatchMessage,
    *,
    runner: HarnessRunner,
    backend: VerifierBackend,
    artifact_provider: ArtifactProvider | None = None,
) -> HarnessScore:
    """Run the committed harness on a FRESH dispatched batch and score it by solve count.

    Fails closed on commit-then-draw: the dispatch's `model_commitment` MUST equal this
    harness's digest, i.e. the batch was frozen to this harness before it was drawn, so the
    harness cannot have been tuned to the tasks it is graded on. Each task's exploit is
    checked by the same differential verifier the reward path uses; a harness that produces
    no output, or one whose output does not crash the vul build and spare the fix, does not
    score for that task.
    """
    if getattr(dispatch, "model_commitment", None) != submission.harness_digest:
        raise HarnessError(
            "dispatch was not committed to this harness (commit-then-draw): the batch must be "
            "drawn under the harness digest, or the harness could be tuned to its own graded set"
        )
    results: list[HarnessResult] = []
    for dt in dispatch.tasks:
        artifact = artifact_provider(dt.task_id) if artifact_provider is not None else b""
        exploit = runner(submission, dt, artifact)
        if not isinstance(exploit, (bytes, bytearray)) or not exploit:
            results.append(HarnessResult(dt.task_id, False, None, "harness_produced_no_exploit"))
            continue
        task = Task(task_id=dt.task_id, level=Level(dt.level), binary_digest=dt.binary_digest)
        diff = verify_poc(task, bytes(exploit), backend)
        results.append(
            HarnessResult(dt.task_id, diff.solved, poc_digest(bytes(exploit)), diff.outcome)
        )
    return HarnessScore(
        miner_hotkey=submission.miner_hotkey,
        harness_digest=submission.harness_digest,
        dispatched=len(dispatch.tasks),
        results=tuple(results),
    )


def rank_harnesses(scores: list[HarnessScore]) -> list[HarnessScore]:
    """Order harnesses for the Stage-1 competition: most genuine solves first.

    Primary key is solve COUNT on the shared fresh batch (not rate — a harness graded on a
    bigger batch is not penalised for it); ties break on the harness digest so the order is
    deterministic and ungrindable by resubmitting under a fresh hotkey.
    """
    return sorted(scores, key=lambda s: (-s.solved, s.harness_digest))


def local_harness_runner(
    harness_cmd: str, *, timeout_s: float = 300.0
) -> HarnessRunner:
    """A DEV/TEST runner: run a local harness command on a task, return its exploit on stdout.

    `harness_cmd` is a shell template with `{task_id}`; the challenge artifact arrives on
    stdin, the produced exploit is read from stdout. This is NOT the production seam and does
    NOT provide attestation. It runs with a fresh empty environment and no shell, but it
    CANNOT enforce network isolation from Python — the production runner is the TDX-attested,
    no-egress enclave, and a harness with egress must never be scored through this.
    """
    import shlex

    def run(submission: HarnessSubmission, task: DispatchedTask, artifact: bytes) -> bytes | None:  # pragma: no cover
        argv = shlex.split(harness_cmd.format(task_id=task.task_id))
        try:
            proc = subprocess.run(
                argv, input=artifact, capture_output=True, timeout=timeout_s, env={}
            )
        except (subprocess.SubprocessError, OSError):
            return None
        return proc.stdout or None

    return run


__all__ = [
    "HarnessError",
    "HarnessSubmission",
    "HarnessResult",
    "HarnessScore",
    "HarnessRunner",
    "ArtifactProvider",
    "evaluate_harness",
    "rank_harnesses",
    "local_harness_runner",
]
