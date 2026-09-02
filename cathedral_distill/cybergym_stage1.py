"""Stage 1 of the Cathedral Security Agent pipeline: harness-capability competition.

Miners submit a GENERAL security-agent harness (committed by digest), NOT a solution. We
draw a batch of FRESH SEALED tasks AFTER the harness commitment, run the harness on each
under an attested, no-egress runner, and score the harness by how many tasks it GENUINELY
solves — the same differential the reward path uses (crash the vul build, spare the fix).
No reasoning traces are collected in Stage 1; this stage discovers which agent architectures
actually solve. The trace-manufacturing dataset is Stage 2.

WHY A HIGH STAGE-1 SCORE MEANS "GENUINE CAPABILITY" — three requirements, each stated where
it is enforced or, honestly, only required:

1. **COMMIT-THEN-DRAW (enforced here ONLY when the caller supplies the anchor block).**
   `evaluate_harness` refuses a dispatch whose `model_commitment` is not this harness's
   digest — but that equality alone is IDENTITY CONSISTENCY, not freshness (issue #136). It
   proves the dispatch is labelled with this harness; it does not prove the batch was drawn
   after the harness was committed. It cannot: the shared epoch draw uses
   `derive_epoch_batch_nonce`, which deliberately excludes the commitment so every miner
   receives the SAME batch — a common frontier and a per-miner commitment cannot both bind
   one nonce.

   The property that actually rules out tuning is an ORDERING: the harness was committed at
   a block that PRECEDES the anchor block the batch was drawn from, so the tasks did not
   exist as a known set when the harness was frozen. That is what `commitment_block` and
   `anchor_block` enforce here. When the caller supplies both, the ordering is checked and
   `HarnessScore.commitment_verified` is True. When it does not, the score is still produced
   but carries `commitment_verified=False`, because a freshness claim that was never checked
   must not be indistinguishable from one that was — **a consumer that moves weight MUST
   refuse an unverified score.** For the fresh corpus the stronger guarantee is
   `oss_fuzz_supply.eligible_for` (the bug was not public when the harness committed), which
   subsumes this one; block ordering is what covers everything else.

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

import hashlib
import json
import re
import subprocess
import time
from dataclasses import dataclass, field, replace
from decimal import Decimal
from typing import Any, Callable, Mapping, Sequence

# Per-observation-field caps so a log is an execution record, not a padding surface: stdout/stderr
# and the serialised args are bounded, and there is no free-text reasoning field at all.
_MAX_FIELD_BYTES = 64 * 1024
_MAX_ARGS_BYTES = 16 * 1024
_MAX_MODEL_LEN = 128  # a model id is short; cap it like every other field so it can't be padded


def _cap(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + f"...<+{len(s) - n}B truncated>"

from cathedral_distill.cybergym import Level, Task
from cathedral_distill.cybergym_protocol import DispatchedTask, DispatchMessage
from cathedral_distill.cybergym_verifier import VerifierBackend, poc_digest, verify_poc

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: The Stage-1 execution-log schema. See ``build_execution_log`` for the contract. This is an
#: EXECUTION RECORD produced by grading a harness we ran ourselves — actions, observations,
#: file effects, and a terminal reason — NOT a model-authored "thought"/reasoning narrative
#: (which is what made padding gameable in the miner-submitted trace path). It is collected as a
#: by-product of grading (distill#142): no new incentive, no miner-supplied trace, nothing to trust.
EXECUTION_LOG_SCHEMA = "cathedral_stage1_execution_log_v1"

#: Terminal reasons a run can end with. `solved`/`no_output` come from grading; `timeout`/`crash`
#: are the runner's own outcome. Retaining the non-solve reasons is the point of the log: a harness
#: that flailed for the full timeout is as much data as one that solved (distill#142, #143).
EXIT_SOLVED, EXIT_NO_OUTPUT, EXIT_TIMEOUT, EXIT_CRASH = "solved", "no_output", "timeout", "crash"


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
    #: Block height at which this harness digest was committed on-chain. Paired with the
    #: draw's anchor block it is what makes commit-then-draw REAL rather than decorative
    #: (issue #136): a harness committed before the anchor cannot have been tuned to the
    #: batch that anchor drew. Optional only so existing callers keep working — a
    #: submission without it can never be `commitment_verified`, so it cannot be paid by a
    #: consumer that checks.
    commitment_block: int | None = None

    def __post_init__(self) -> None:
        if not self.miner_hotkey:
            raise HarnessError("miner_hotkey is required")
        if not _DIGEST_RE.match(self.harness_digest):
            raise HarnessError("harness_digest must be sha256:<64 hex>")
        if not self.version or len(self.version) > 32:
            raise HarnessError("version must be 1..32 chars")
        _check_block(self.commitment_block, "commitment_block")


def _check_block(value: object, name: str) -> None:
    """A block height is a non-negative int, or absent. Never a bool, never negative."""
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HarnessError(f"{name} must be a non-negative integer or None")


def _verify_commitment_ordering(commitment_block: int | None, anchor_block: int | None) -> bool:
    """Whether commit-then-draw is PROVEN for this pair. Never silently 'probably'.

    Both heights are needed: without the commitment there is nothing to order, and without
    the anchor there is nothing to order it against. Missing either returns False — the
    property is unproven, which is a different thing from disproven and a very different
    thing from proven.

    Strictly less-than. A harness committed IN the anchor block is not provably ignorant of
    what that block drew, and an anti-tuning rule whose boundary is loose is not a rule.
    """
    if commitment_block is None or anchor_block is None:
        return False
    if commitment_block >= anchor_block:
        raise HarnessError(
            f"harness was committed at block {commitment_block}, which does not precede the "
            f"batch anchor block {anchor_block}: the batch was drawable when the harness was "
            "frozen, so the score would not be evidence of untuned capability (#136)"
        )
    return True


@dataclass(frozen=True)
class HarnessResult:
    """The outcome of running the harness on one task.

    ``log_sha256`` is a CONTENT-ADDRESSED reference to the execution log (persisted separately via
    the ``log_sink``), not the log bytes — so ``HarnessScore`` stays small and comparable. It is
    ``None`` only when the runner returned no log (a legacy ``bytes|None`` runner, or an
    enclave runner whose log egress has not landed yet). ``exit_reason`` is the terminal reason
    (see ``EXIT_*``); ``duration_ms`` is the runner's own wall time when it reports one.
    """

    task_id: str
    solved: bool
    exploit_sha256: str | None  # None when the harness produced no output
    reason: str  # the differential outcome, or why no solve
    log_sha256: str | None = None
    exit_reason: str = ""
    duration_ms: int | None = None


@dataclass(frozen=True)
class HarnessRun:
    """What one harness run PRODUCED on one task: the exploit AND the execution log.

    Widens the old ``bytes | None`` runner return so grading can retain the trajectory it already
    paid to produce (distill#142). ``log`` is the canonical ``EXECUTION_LOG_SCHEMA`` bytes (build it
    with ``build_execution_log``); ``exit_reason`` is one of ``EXIT_*``; ``duration_ms`` the run's
    wall time. A runner that still returns bare ``bytes | None`` is normalised to this shape with
    ``log=None`` for one release, so existing runners and tests keep working.
    """

    exploit: bytes | None
    log: bytes | None = None
    duration_ms: int | None = None
    exit_reason: str = ""


def _as_run(returned: "bytes | bytearray | None | HarnessRun") -> HarnessRun:
    """Normalise a runner's return into a ``HarnessRun``. Accepts the legacy ``bytes | None`` shape
    (one release of backward compatibility) and the new ``HarnessRun``. Anything else fails closed."""
    if isinstance(returned, HarnessRun):
        return returned
    if returned is None:
        return HarnessRun(exploit=None)
    if isinstance(returned, (bytes, bytearray)):
        return HarnessRun(exploit=bytes(returned))
    raise HarnessError("runner must return bytes | None | HarnessRun")


def task_family(task_id: str) -> str:
    """The task's domain label (the id prefix before ':', e.g. ``arvo`` / ``freshvuln``), so logs
    can be grouped per domain. Empty ids and ids without a prefix fall back to the whole id."""
    head = str(task_id).split(":", 1)[0].strip()
    return head or str(task_id)


def build_execution_log(
    *, task_id: str, terminal_reason: str, steps: Sequence[Mapping[str, Any]],
    duration_ms: int | None = None, model: str = "",
) -> bytes:
    """Canonical bytes for one Stage-1 run's EXECUTION LOG (``EXECUTION_LOG_SCHEMA``).

    An execution RECORD, deliberately NOT a model-authored reasoning narrative: each step carries
    the ACTION taken and its ARGS, the observed RESULT (``stdout``/``stderr``/``exit_code``), and
    any FILE effects (``{path, op, sha256}``) — what the harness did and saw, not what it "thought".
    There is intentionally NO free-text reasoning field, and the observation fields are SIZE-CAPPED
    (``stdout``/``stderr`` at ``_MAX_FIELD_BYTES``, the serialised ``args`` at ``_MAX_ARGS_BYTES``):
    the miner-submitted trace path was gameable because it accepted an unbounded self-reported
    thought; a bounded record of graded execution we ran ourselves is not the same surface. Carries a
    ``task_family`` label and a ``terminal_reason`` (one of ``EXIT_*``) so a training corpus can group
    by domain and compute failure-mode frequencies (#143).

    Serialisation is sorted-key compact JSON so the bytes are content-addressable (its sha256 is the
    ``HarnessResult.log_sha256`` reference). Steps are normalised to the fixed shape below; unknown
    keys — at the step top level AND inside ``args`` — are dropped/bounded, so a runner cannot
    smuggle an unbounded narrative field back in.
    """
    norm_steps: list[dict[str, Any]] = []
    for i, s in enumerate(steps):
        result = s.get("result") or {}
        files = []
        for f in s.get("files") or ():
            files.append({
                "path": _cap(str(f.get("path", "")), _MAX_ARGS_BYTES),
                "op": str(f.get("op", ""))[:32],
                "sha256": str(f.get("sha256", ""))[:80],
            })
        raw_args = s.get("args")
        if isinstance(raw_args, (dict, list)):
            enc = json.dumps(raw_args, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, default=str)
            # bound the serialised args: legit tool arguments are small; anything padded to bloat the
            # log (or bury a narrative) is replaced by a marker rather than stored verbatim. Keep the
            # value by round-tripping through the SAME default=str encoding, so it is JSON-native and
            # the final document dump (which has no default=) can never raise on a str-coercible-but-
            # not-JSON-native arg (bytes/Decimal/set/datetime) that slipped past this size gate.
            args: Any = json.loads(enc) if len(enc) <= _MAX_ARGS_BYTES else {"_truncated_bytes": len(enc)}
        else:
            args = _cap(str(raw_args if raw_args is not None else ""), _MAX_ARGS_BYTES)
        norm_steps.append({
            "seq": int(s.get("seq", i)),
            "action": str(s.get("action", ""))[:256],
            "args": args,
            "result": {
                "stdout": _cap(str(result.get("stdout", "")), _MAX_FIELD_BYTES),
                "stderr": _cap(str(result.get("stderr", "")), _MAX_FIELD_BYTES),
                "exit_code": (int(result["exit_code"]) if result.get("exit_code") is not None else None),
            },
            "files": files,
            "ts_ms": (int(s["ts_ms"]) if s.get("ts_ms") is not None else None),
        })
    doc = {
        "schema": EXECUTION_LOG_SCHEMA,
        "task_id": str(task_id),
        "task_family": task_family(task_id),
        "terminal_reason": str(terminal_reason),
        "duration_ms": (int(duration_ms) if duration_ms is not None else None),
        # the DECLARED model the caller supplies (from the backend's registration provenance); "" if
        # absent. Capped like every other field so it can't be a padding vector; NOT validated or
        # attested here — attribution is the backend's job, this builder only records what it is given.
        "model": str(model)[:_MAX_MODEL_LEN],
        "steps": norm_steps,
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


@dataclass(frozen=True)
class HarnessScore:
    """A harness's capability on one fresh batch: solve count over what was dispatched."""

    miner_hotkey: str
    harness_digest: str
    dispatched: int
    results: tuple[HarnessResult, ...] = field(default_factory=tuple)
    #: Commit-then-draw was PROVEN for this score: the harness's commitment block precedes
    #: the batch's anchor block (#136). False means the ordering was never checked — the
    #: caller supplied no anchor, or the submission carries no commitment block — NOT that
    #: it failed, which raises. Defaults False so a score is never presumed verified, and it
    #: rides in `consensus_digest` so a verified score cannot tie with an unverified one.
    #: **A consumer that moves weight must refuse a score with this False.**
    commitment_verified: bool = False
    #: The submission's commitment block, carried so the attested record is built from the
    #: SAME height this score was judged on. It lives here rather than being passed to
    #: `execution_from_score` separately because a free-typed block could name an earlier
    #: height than the submission actually had, and a re-grader would then "verify" a
    #: commitment that never happened.
    commitment_block: int | None = None

    @property
    def solved(self) -> int:
        return sum(1 for r in self.results if r.solved)

    @property
    def solve_rate(self) -> Decimal:
        """Fraction of the fresh batch the harness genuinely solved (0 on an empty batch)."""
        if self.dispatched <= 0:
            return Decimal(0)
        return Decimal(self.solved) / Decimal(self.dispatched)


# (submission, task, challenge_artifact) -> the harness's exploit AND execution log. Returns a
# ``HarnessRun`` (exploit + log + reason), or the legacy bare ``bytes | None`` exploit for one
# release. The PRODUCTION implementation runs the committed harness inside a TDX-attested enclave
# with NO network egress; a local subprocess runner (below) covers the dev/test path.
HarnessRunner = Callable[[HarnessSubmission, DispatchedTask, bytes], "bytes | None | HarnessRun"]

# (task_id) -> the bounded challenge artifact the harness is allowed to see. NEVER the
# held reference PoC — that is the answer.
ArtifactProvider = Callable[[str], bytes]

# (task_id, execution_log_bytes) -> None. Persists ONE log per DISPATCHED task, called by
# ``evaluate_harness`` BEFORE the solve/no-solve branch, so a harness that produced nothing is
# retained exactly like one that solved (distill#142 / backend#3). The backend binds this to
# ``AgentStore.store_log(round, miner, task, ...)``; failures are the most useful rows and must
# never be silently dropped.
#
# CONTRACT: the sink MUST fail SOFT — it must not raise. It is called outside the per-task crash
# isolation, so a raise aborts the whole batch (loudly, never silently). That is intentional for a
# genuine storage failure (e.g. the disk is full: continuing to grade while unable to persist is
# pointless), NOT something a size/format issue should ever trigger — ``store_log`` truncates-and-marks
# rather than raising, exactly so one oversize log never aborts a grading run.
LogSink = Callable[[str, bytes], None]


def _grade_task(
    submission: HarnessSubmission, dt: DispatchedTask, *,
    runner: HarnessRunner, backend: VerifierBackend,
    artifact_provider: ArtifactProvider | None,
) -> tuple[HarnessResult, bytes | None]:
    """Grade ONE dispatched task. Returns ``(result, log_bytes)`` (``log_bytes`` is ``None`` only for
    a legacy ``bytes|None`` runner). Isolates per-task failure: if the runner, the differential
    verifier, or the task data RAISES, a ``crash`` log is synthesised and returned so the task is
    still recorded and the caller can keep grading the rest of the batch — one bad task must never
    abort the whole grading run (that would drop every later task's log)."""
    try:
        artifact = artifact_provider(dt.task_id) if artifact_provider is not None else b""
        raw = runner(submission, dt, artifact)
        run = _as_run(raw)
        # A MODERN runner that omitted the log on a failure path would silently drop the highest-
        # value row (a timeout/no-output that produced nothing); synthesise a minimal log from its
        # terminal reason. A LEGACY bytes|None runner carries no log for one release — documented.
        log_bytes = run.log
        if log_bytes is None and isinstance(raw, HarnessRun):
            log_bytes = build_execution_log(
                task_id=dt.task_id, terminal_reason=(run.exit_reason or "unknown"), steps=[])
        exploit = run.exploit
        if not isinstance(exploit, (bytes, bytearray)) or not exploit:
            return (HarnessResult(dt.task_id, False, None, "harness_produced_no_exploit",
                                  exit_reason=(run.exit_reason or EXIT_NO_OUTPUT),
                                  duration_ms=run.duration_ms), log_bytes)
        task = Task(task_id=dt.task_id, level=Level(dt.level), binary_digest=dt.binary_digest)
        diff = verify_poc(task, bytes(exploit), backend)
        return (HarnessResult(dt.task_id, diff.solved, poc_digest(bytes(exploit)), diff.outcome,
                              exit_reason=(EXIT_SOLVED if diff.solved else run.exit_reason),
                              duration_ms=run.duration_ms), log_bytes)
    except Exception as exc:  # noqa: BLE001 — the runner/verifier/task data is untrusted to not raise
        log_bytes = build_execution_log(
            task_id=dt.task_id, terminal_reason=EXIT_CRASH,
            steps=[{"seq": 0, "action": "run_harness",
                    "result": {"stderr": f"{type(exc).__name__}: {exc}"}}])
        return (HarnessResult(dt.task_id, False, None, f"harness_run_crashed:{type(exc).__name__}",
                              exit_reason=EXIT_CRASH), log_bytes)


def evaluate_harness(
    submission: HarnessSubmission,
    dispatch: DispatchMessage,
    *,
    runner: HarnessRunner,
    backend: VerifierBackend,
    artifact_provider: ArtifactProvider | None = None,
    log_sink: LogSink | None = None,
    anchor_block: int | None = None,
) -> HarnessScore:
    """Run the committed harness on a FRESH dispatched batch and score it by solve count.

    Fails closed on identity: the dispatch's `model_commitment` MUST equal this harness's
    digest. Pass ``anchor_block`` — the block the batch was drawn from — to also prove
    commit-then-draw: with the submission's `commitment_block` it establishes that the
    harness was frozen before the batch existed, and sets `commitment_verified`. Without it
    the score is produced but marked unverified, never silently presumed fresh (#136). Each task's exploit is
    checked by the same differential verifier the reward path uses; a harness that produces
    no output, or one whose output does not crash the vul build and spare the fix, does not
    score for that task.

    When ``log_sink`` is given, the run's execution log is persisted for EVERY dispatched task —
    the sink is invoked before the solve/no-solve branch, so the no-exploit and timeout/crash
    cases are retained exactly like a solve (distill#142; failures are the corpus rows most likely
    to be silently dropped and the most useful for skill distillation, #143). The log is a
    content-addressed reference on ``HarnessResult.log_sha256``; the bytes live wherever the sink
    put them.
    """
    if getattr(dispatch, "model_commitment", None) != submission.harness_digest:
        raise HarnessError(
            "dispatch was not committed to this harness (commit-then-draw): the batch must be "
            "drawn under the harness digest, or the harness could be tuned to its own graded set"
        )
    _check_block(anchor_block, "anchor_block")
    verified = _verify_commitment_ordering(submission.commitment_block, anchor_block)
    results: list[HarnessResult] = []
    for dt in dispatch.tasks:
        # Per-task, exception-isolated: a raising runner/verifier yields a synthesised crash log,
        # never an aborted batch. This is where the "every dispatched task" guarantee is enforced.
        result, log_bytes = _grade_task(
            submission, dt, runner=runner, backend=backend, artifact_provider=artifact_provider)
        # Persist ONE log per DISPATCHED task, before the solve/no-solve outcome matters, so the
        # no-exploit / timeout / crash rows are retained exactly like a solve. The content-addressed
        # ``log_sha256`` is recorded only when the sink actually stored the bytes, so the reference is
        # never dangling.
        if log_bytes is not None and log_sink is not None:
            log_sink(dt.task_id, log_bytes)
            result = replace(result, log_sha256="sha256:" + hashlib.sha256(log_bytes).hexdigest())
        results.append(result)
    return HarnessScore(
        miner_hotkey=submission.miner_hotkey,
        harness_digest=submission.harness_digest,
        dispatched=len(dispatch.tasks),
        results=tuple(results),
        commitment_verified=verified,
        commitment_block=submission.commitment_block,
    )


# -- consensus: one authoritative run, deterministic re-grading (#137) ------------------- #
#
# ``evaluate_harness`` EXECUTES the harness, and nothing can make that execution reproducible:
# the harness is a reasoning agent, so the production runner reaches a model
# (``cybergym_attest._verify_agent_egress`` restricts agent-enclave egress to the model hosts
# rather than denying it, precisely because "a reasoning agent MUST reach the model"), and LLM
# sampling is not bit-identical across independent runs. So the issue's second option — an
# enforced reproducibility contract for per-validator re-execution — is not merely expensive,
# it is unachievable for the workload Stage 1 grades. Two honest validators re-running the same
# harness WILL disagree, and that disagreement would land straight on weights.
#
# The half that IS deterministic is the differential: given the same exploit bytes, every
# validator observes the same vul/fix outcome, and #153/#166 made that a guarantee rather than
# a hope (a candidate solve is confirmed by repetition, and a flaky crash scores
# `nondeterministic_crash` instead of crediting on luck).
#
# So the decision this encodes is the issue's FIRST option, along the seam that already exists:
# the harness runs ONCE in the attested enclave and its per-task output is COMMITTED by digest
# (`HarnessResult.exploit_sha256`, the `PoCSubmission`/`poc_sha256` pattern); every validator
# then grades those committed bytes with :func:`grade_committed_execution`, which takes no
# runner and therefore cannot introduce the divergence. Byte-identical ranking across validators
# is a precondition for weight consumption, and it is reachable only on this side of the seam.


@dataclass(frozen=True)
class CommittedRun:
    """One task's output from the single authoritative harness execution, by digest.

    ``exploit_sha256`` is ``None`` when the harness produced no exploit — committed as such,
    so "produced nothing" is an attested outcome rather than a gap a re-grader has to guess at.
    """

    task_id: str
    exploit_sha256: str | None
    log_sha256: str | None = None
    exit_reason: str = ""
    duration_ms: int | None = None

    def __post_init__(self) -> None:
        if not str(self.task_id):
            raise HarnessError("a committed run needs a task_id")
        for field_name in ("exploit_sha256", "log_sha256"):
            value = getattr(self, field_name)
            if value is not None and not _DIGEST_RE.match(str(value)):
                raise HarnessError(f"{field_name} must be sha256:<64 hex> or None")


@dataclass(frozen=True)
class HarnessExecution:
    """The attested record of the ONE authoritative execution of a harness on one batch.

    This is what leaves the enclave and what every validator grades from. It binds the run to
    the harness and the batch it was drawn for, so a record cannot be replayed against a
    different batch or credited to a different harness.
    """

    miner_hotkey: str
    harness_digest: str
    batch_id: str
    runs: tuple[CommittedRun, ...] = field(default_factory=tuple)
    #: The submission's commitment block, carried into the attested record so a validator
    #: can re-check commit-then-draw against the anchor without holding the submission
    #: (#136). It is inside `digest()`, so the enclave attests it like everything else.
    commitment_block: int | None = None

    def __post_init__(self) -> None:
        _check_block(self.commitment_block, "commitment_block")
        if not _DIGEST_RE.match(str(self.harness_digest)):
            raise HarnessError("harness_digest must be sha256:<64 hex>")
        seen = [r.task_id for r in self.runs]
        if len(seen) != len(set(seen)):
            raise HarnessError("a committed execution carries one run per task; ids repeat")

    def run_for(self, task_id: str) -> CommittedRun | None:
        for r in self.runs:
            if r.task_id == task_id:
                return r
        return None

    def digest(self) -> str:
        """Canonical digest of the whole record — what an enclave binds into its quote.

        "Run once with ATTESTED committed bytes" needs one value to attest; this is it. The
        enclave puts this in the quote's report_data, so a validator can check that the
        execution it is grading is the one the hardware signed, rather than trusting whoever
        handed it the record. Field order is canonical so the digest does not depend on how
        the record happened to be serialised.
        """
        body = json.dumps(
            {
                "miner_hotkey": self.miner_hotkey,
                "harness_digest": self.harness_digest,
                "batch_id": self.batch_id,
                "commitment_block": self.commitment_block,
                "runs": sorted(
                    (
                        {
                            "task_id": r.task_id,
                            "exploit_sha256": r.exploit_sha256,
                            "log_sha256": r.log_sha256,
                            "exit_reason": r.exit_reason,
                            "duration_ms": r.duration_ms,
                        }
                        for r in self.runs
                    ),
                    key=lambda row: row["task_id"],
                ),
            },
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return "sha256:" + hashlib.sha256(body).hexdigest()


def execution_from_score(score: HarnessScore, dispatch: DispatchMessage) -> HarnessExecution:
    """The committable record of a producer-side ``evaluate_harness`` run.

    The enclave grades and commits in one pass; this is the projection of that pass onto the
    bytes a validator is allowed to re-derive a rank from.

    Takes the DISPATCH rather than a bare ``batch_id`` so the record cannot be mis-bound at the
    point it is created: a record built against the wrong batch is refused at grading time
    anyway, but a producer that silently emits one is a bug worth failing on here, where the
    batch it was actually graded against is still in hand.
    """
    if score.miner_hotkey != dispatch.miner_hotkey:
        raise HarnessError("score and dispatch name different miners; refusing to commit it")
    if score.commitment_verified and score.commitment_block is None:
        # Cannot happen through `evaluate_harness` (verification requires the block), so this
        # catches a hand-built score claiming a proof it carries no basis for.
        raise HarnessError(
            "score is commitment_verified but carries no commitment_block: the attested "
            "record would drop the proof it was verified under (#136)"
        )
    return HarnessExecution(
        miner_hotkey=score.miner_hotkey,
        harness_digest=score.harness_digest,
        batch_id=dispatch.batch_id,
        # From the SCORE, never a caller-supplied height: a free-typed block could name an
        # earlier commitment than the submission had, and a re-grader would then verify a
        # commitment that never happened.
        commitment_block=score.commitment_block,
        runs=tuple(
            CommittedRun(
                task_id=r.task_id, exploit_sha256=r.exploit_sha256, log_sha256=r.log_sha256,
                exit_reason=r.exit_reason, duration_ms=r.duration_ms,
            )
            for r in score.results
        ),
    )


# (task_id) -> the committed exploit bytes for that task, or None when unavailable.
ExploitProvider = Callable[[str], "bytes | None"]

#: Reasons a committed run cannot be credited. Never a differential outcome — these mean the
#: COMMITMENT failed, so the task scores unsolved and says which way it failed.
REASON_NO_EXPLOIT = "harness_produced_no_exploit"
REASON_EXPLOIT_MISSING = "committed_exploit_unavailable"
REASON_DIGEST_MISMATCH = "committed_exploit_digest_mismatch"
REASON_NOT_IN_EXECUTION = "task_absent_from_committed_execution"


def grade_committed_execution(
    execution: HarnessExecution,
    dispatch: DispatchMessage,
    *,
    backend: VerifierBackend,
    exploit_provider: ExploitProvider,
    anchor_block: int | None = None,
) -> HarnessScore:
    """Re-derive a harness's score from its COMMITTED execution — no runner, no divergence.

    The validator-side entry point. The harness does not run here, so its sampling — the
    unbounded divergence #137 is about — is gone: two honest validators handed the same
    execution and the same dispatch grade the same bytes and produce the same rank
    (:func:`consensus_digest` is the cheap comparison).

    What remains is bounded, and worth naming rather than glossing: the DIFFERENTIAL can still
    disagree if a task's crash is itself flaky, so one validator could observe ``solved`` where
    another observes ``nondeterministic_crash``. Two things hold that down and neither is this
    function's doing — ``verify_poc`` confirms a candidate solve by repetition (#153/#166), and
    admission is supposed to keep non-deterministic tasks out of the corpus in the first place.
    Raising ``DEFAULT_CONFIRMATIONS`` shrinks the residual further. This function removes the
    dominant source of divergence; it does not turn a flaky corpus into a reproducible one.

    Fails closed on the bindings before grading anything: the execution must be for THIS batch,
    THIS miner, and a harness the batch was committed to (commit-then-draw, the same contract
    ``evaluate_harness`` enforces). A record that satisfies none of these is not a low score, it
    is not evidence at all.

    **CALLER'S PRECONDITION — this function does NOT check provenance.** It grades the record it
    is handed, so the caller MUST first verify that :meth:`HarnessExecution.digest` matches the
    value the producing enclave bound into its attestation quote. The bindings checked here
    prove the record is internally consistent and drawn for this batch; they cannot prove it came
    from the enclave rather than from whoever passed it in. Grading an unattested record ranks
    miners on unverified data, which is the failure this whole path exists to prevent — verify
    the quote, then call this.

    Per task, the refusal directions are deliberately asymmetric. A task the execution never
    covered, an exploit the provider cannot supply, or bytes whose digest disagrees with the
    commitment all score UNSOLVED with the reason naming which — a digest mismatch in particular
    means the bytes being graded are not the bytes that were attested, which is exactly the
    substitution the commitment exists to prevent, so it must never be able to earn. Grading
    continues for the remaining tasks: one bad row must not discard the honest rest.
    """
    if execution.harness_digest != getattr(dispatch, "model_commitment", None):
        raise HarnessError(
            "committed execution is for a harness this batch was not drawn under "
            "(commit-then-draw): refusing to grade it"
        )
    if execution.batch_id != dispatch.batch_id:
        raise HarnessError(
            f"committed execution is for batch {execution.batch_id!r}, not {dispatch.batch_id!r}"
        )
    if execution.miner_hotkey != dispatch.miner_hotkey:
        raise HarnessError("committed execution names a different miner than the dispatch")
    _check_block(anchor_block, "anchor_block")
    verified = _verify_commitment_ordering(execution.commitment_block, anchor_block)

    results: list[HarnessResult] = []
    for dt in dispatch.tasks:
        run = execution.run_for(dt.task_id)
        if run is None:
            results.append(HarnessResult(dt.task_id, False, None, REASON_NOT_IN_EXECUTION))
            continue
        base = dict(log_sha256=run.log_sha256, exit_reason=run.exit_reason,
                    duration_ms=run.duration_ms)
        if run.exploit_sha256 is None:
            results.append(HarnessResult(dt.task_id, False, None, REASON_NO_EXPLOIT, **base))
            continue
        exploit = exploit_provider(dt.task_id)
        if not isinstance(exploit, (bytes, bytearray)) or not exploit:
            results.append(HarnessResult(
                dt.task_id, False, run.exploit_sha256, REASON_EXPLOIT_MISSING, **base))
            continue
        exploit = bytes(exploit)
        if poc_digest(exploit) != run.exploit_sha256:
            results.append(HarnessResult(
                dt.task_id, False, run.exploit_sha256, REASON_DIGEST_MISMATCH, **base))
            continue
        task = Task(task_id=dt.task_id, level=Level(dt.level), binary_digest=dt.binary_digest)
        diff = verify_poc(task, exploit, backend)
        results.append(HarnessResult(
            dt.task_id, diff.solved, run.exploit_sha256, diff.outcome, **base))
    return HarnessScore(
        miner_hotkey=execution.miner_hotkey,
        harness_digest=execution.harness_digest,
        dispatched=len(dispatch.tasks),
        results=tuple(results),
        commitment_verified=verified,
        commitment_block=execution.commitment_block,
    )


def consensus_digest(score: HarnessScore) -> str:
    """A canonical digest of everything a rank depends on, so divergence is one comparison.

    Covers only the fields that MUST agree between validators: the identity being ranked, the
    batch size, and per task the solve bit, the committed exploit digest, and the differential
    outcome. Deliberately EXCLUDES ``duration_ms``, ``log_sha256`` and ``exit_reason`` — wall
    time is validator-local, and the other two describe how the run went rather than what it
    scored, so folding them in would report divergence where the rank does not actually differ.

    Tasks are sorted by id: the score's row order follows the dispatch, and two validators
    handed the same dispatch see the same order anyway, but sorting means a re-ordered-but-
    equivalent score is not reported as a disagreement.
    """
    body = json.dumps(
        {
            "miner_hotkey": score.miner_hotkey,
            "harness_digest": score.harness_digest,
            "dispatched": int(score.dispatched),
            "commitment_verified": bool(score.commitment_verified),
            "results": sorted(
                (
                    {
                        "task_id": r.task_id,
                        "solved": bool(r.solved),
                        "exploit_sha256": r.exploit_sha256,
                        "reason": r.reason,
                    }
                    for r in score.results
                ),
                key=lambda row: row["task_id"],
            ),
        },
        sort_keys=True, separators=(",", ":"),
    ).encode()
    return "sha256:" + hashlib.sha256(body).hexdigest()


def rank_harnesses(scores: list[HarnessScore]) -> list[HarnessScore]:
    """Order harnesses for the Stage-1 competition: most genuine solves first.

    Primary key is solve COUNT on the shared fresh batch (not rate — a harness graded on a
    bigger batch is not penalised for it); ties break on the harness digest so the order is
    deterministic and ungrindable by resubmitting under a fresh hotkey.

    The ORDER is deterministic given the scores; whether the SCORES agree between validators is
    decided upstream. Rank from :func:`grade_committed_execution` when the result will touch
    weights — ranking scores that came from independent ``evaluate_harness`` re-execution
    reproduces #137, because the harness itself is not reproducible.
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

    It emits the SAME ``EXECUTION_LOG_SCHEMA`` shape as the production enclave runner is expected
    to (distill#142 acceptance): one step recording the harness invocation — the command as the
    action, the challenge-artifact digest as an input observation, the captured stdout/stderr and
    exit code, and a terminal reason (``no_output``/``timeout``/``crash``/produced-output). The
    reward/grade decision is NOT in the log — ``evaluate_harness`` sets ``solved`` from the
    differential — so the local and enclave runners produce identical logs for the same run.
    """
    import shlex

    def run(submission: HarnessSubmission, task: DispatchedTask, artifact: bytes) -> HarnessRun:
        argv = shlex.split(harness_cmd.format(task_id=task.task_id))
        art_digest = "sha256:" + hashlib.sha256(artifact or b"").hexdigest()
        started = time.monotonic()
        stdout: bytes = b""
        stderr = ""
        exit_code: int | None = None
        reason = ""
        try:
            proc = subprocess.run(
                argv, input=artifact, capture_output=True, timeout=timeout_s, env={}
            )
            stdout, exit_code = proc.stdout or b"", proc.returncode
            stderr = (proc.stderr or b"")[:8192].decode("utf-8", "replace")
            reason = "" if stdout else EXIT_NO_OUTPUT
        except subprocess.TimeoutExpired:
            reason = EXIT_TIMEOUT
        except (subprocess.SubprocessError, OSError) as exc:
            reason, stderr = EXIT_CRASH, str(exc)[:8192]
        duration_ms = int((time.monotonic() - started) * 1000)
        log = build_execution_log(
            task_id=task.task_id, terminal_reason=reason or "produced_output",
            duration_ms=duration_ms,
            steps=[{
                "seq": 0, "action": "run_harness", "args": {"argv": argv},
                "result": {
                    "stdout": stdout[:8192].decode("utf-8", "replace"),
                    "stderr": stderr, "exit_code": exit_code,
                },
                "files": [{"path": "<stdin:challenge_artifact>", "op": "read", "sha256": art_digest}],
                "ts_ms": duration_ms,
            }],
        )
        return HarnessRun(exploit=(bytes(stdout) or None), log=log,
                          duration_ms=duration_ms, exit_reason=reason)

    return run


__all__ = [
    "HarnessError",
    "HarnessSubmission",
    "HarnessResult",
    "HarnessRun",
    "HarnessScore",
    "HarnessRunner",
    "ArtifactProvider",
    "LogSink",
    "EXECUTION_LOG_SCHEMA",
    "EXIT_SOLVED",
    "EXIT_NO_OUTPUT",
    "EXIT_TIMEOUT",
    "EXIT_CRASH",
    "build_execution_log",
    "task_family",
    "evaluate_harness",
    "rank_harnesses",
    "local_harness_runner",
]
