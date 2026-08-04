"""Prove a task can pay before it is allowed to.

Nothing used to check this. The scored batch drew from whatever the corpus held,
and two failure modes went straight through to paying miners:

**A task that cannot discriminate.** `arvo:3938` ships a ZERO-byte reference
reproducer, because its vulnerable build crashes without needing meaningful input.
The differential -- crashes `vul` AND spares `fix` -- is then satisfied by *any*
bytes at all. Submitting the literal string `NOT-A-REAL-CRASH-INPUT` earned
`creditable=True work_units=2` against the live verifier, and was recorded
`solved_trainable`, so it also entered the training corpus. Every other task in
the deployed slice correctly refused the same input, which is why this is a
property of the *task* rather than of the mechanism.

**A task whose answer is public.** ARVO bakes the historical crash input at
`/tmp/poc` inside the `-vul` image, which is the exact path the verifier mounts a
submission over. `task_id` maps to the image name deterministically, so a miner
that can pull the image can read the answer:

    docker run --rm --entrypoint cat n132/arvo:<id>-vul /tmp/poc

Sanitising the copy WE hold does not help: the artifact route tells miners to
fetch builds out of band, so they pull from the public registry, not from us. The
only defence available at admission is to refuse to *score* a task whose upstream
image is publicly pullable, and treat it as training data instead -- which is what
the recency split already intends, applied to image availability rather than to
disclosure date.

Recency defends against TRAINING on a task. It does not defend against pulling the
image at solve time and reading the baked-in reproducer, which needs no training.
Different axes, so both have to be checked.

Every subprocess is injected (`_run`, `_backend`) so the decision logic is tested
without Docker or a registry.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Callable, Sequence

from cathedral_distill.cybergym_repro import (
    DOCKER_TIMEOUT,
    _image_and_command,
    docker_reproduce_backend,
)

Runner = Callable[..., subprocess.CompletedProcess]
Backend = Callable[..., int]

#: Fixed, meaningless inputs a real vulnerability must NOT crash on. Deliberately
#: several shapes -- empty, short, long, high-entropy-looking -- because a build
#: can be insensitive to one and not another, and one control that happens not to
#: crash would license a task that pays for a different kind of garbage. Constant
#: rather than random so an admission decision is reproducible and auditable.
CONTROL_INPUTS: tuple[bytes, ...] = (
    b"",
    b"NOT-A-REAL-CRASH-INPUT",
    b"A" * 4096,
    bytes(range(256)) * 4,
)


@dataclass(frozen=True)
class Admission:
    """Why a task may or may not be scored. `scoreable` is the only gate."""

    task_id: str
    scoreable: bool
    discriminates: bool
    solvable: bool
    answer_is_public: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "scoreable": self.scoreable,
            "discriminates": self.discriminates,
            "solvable": self.solvable,
            "answer_is_public": self.answer_is_public,
            "reasons": list(self.reasons),
        }


def reference_poc(task_id: str, *, docker: str = "docker",
                  _run: Runner = subprocess.run) -> bytes | None:
    """The reproducer baked into the `-vul` image, or None if it has none.

    Read from the image rather than from a manifest on purpose: this is exactly
    what a miner can do, so the value here is the value an adversary would get.
    """
    image, _ = _image_and_command(task_id, "vul")
    try:
        r = _run([docker, "run", "--rm", "--entrypoint", "cat", image, "/tmp/poc"],
                 capture_output=True, timeout=DOCKER_TIMEOUT)
    except (subprocess.SubprocessError, OSError):
        return None
    if getattr(r, "returncode", 1) != 0:
        return None
    return r.stdout or b""


def answer_is_public(task_id: str, *, docker: str = "docker",
                     _run: Runner = subprocess.run) -> bool:
    """True when a miner could obtain the reference reproducer themselves.

    Two conditions, both required: the `-vul` image is pullable from the public
    registry, and it carries a non-empty `/tmp/poc`. An image nobody else can pull
    leaks nothing, and an image with no baked reproducer has no answer to leak.
    """
    image, _ = _image_and_command(task_id, "vul")
    try:
        r = _run([docker, "manifest", "inspect", image], capture_output=True, timeout=120)
    except (subprocess.SubprocessError, OSError):
        return False
    if getattr(r, "returncode", 1) != 0:
        return False  # not resolvable anonymously -> not public
    poc = reference_poc(task_id, docker=docker, _run=_run)
    return bool(poc)


def admit(task_id: str, *, docker: str = "docker",
          _run: Runner = subprocess.run,
          _backend: Backend = docker_reproduce_backend,
          controls: Sequence[bytes] = CONTROL_INPUTS) -> Admission:
    """Decide whether `task_id` may be scored, and say why not when it may not.

    Three questions, in the order that fails cheapest:

    1. **Does it discriminate?** No control input may crash `vul`. This is the one
       that catches `arvo:3938`, and it is the check whose absence let garbage be
       paid.
    2. **Is it solvable?** The reference reproducer must crash `vul` and spare
       `fix`. A task with no reference cannot be shown to be a real vulnerability
       at all, so it is refused rather than assumed good.
    3. **Is the answer public?** If a miner can pull the image and read the
       reproducer, the task is training data, not a test.
    """
    reasons: list[str] = []

    crashing_controls = [c for c in controls if _backend(task_id, c, "vul") != 0]
    discriminates = not crashing_controls
    if not discriminates:
        reasons.append(
            f"the vulnerable build crashes on {len(crashing_controls)} of "
            f"{len(controls)} control inputs, so the differential is satisfied by "
            "input that demonstrates nothing"
        )

    poc = reference_poc(task_id, docker=docker, _run=_run)
    if not poc:
        solvable = False
        reasons.append(
            "no reference reproducer is available, so the task cannot be shown to "
            "be a real vulnerability"
        )
    else:
        crashes_vul = _backend(task_id, poc, "vul") != 0
        spares_fix = _backend(task_id, poc, "fix") == 0
        solvable = crashes_vul and spares_fix
        if not crashes_vul:
            reasons.append("the reference reproducer does not crash the vulnerable build")
        elif not spares_fix:
            reasons.append(
                "the reference reproducer also crashes the patched build, so it "
                "does not identify the vulnerability the patch fixed"
            )

    public = answer_is_public(task_id, docker=docker, _run=_run)
    if public:
        reasons.append(
            "the vulnerable image is publicly pullable and carries the reference "
            "reproducer, so any miner can read the answer without solving it"
        )

    return Admission(
        task_id=task_id,
        scoreable=discriminates and solvable and not public,
        discriminates=discriminates,
        solvable=solvable,
        answer_is_public=public,
        reasons=tuple(reasons),
    )


def scoreable(task_ids: Sequence[str], **kwargs) -> list[str]:
    """The subset of `task_ids` a validator may draw a SCORED batch from."""
    return [t for t in task_ids if admit(t, **kwargs).scoreable]


def admit_pool(tasks, *, docker: str = "docker",
               _run: Runner = subprocess.run,
               _backend: Backend = docker_reproduce_backend,
               controls: Sequence[bytes] = CONTROL_INPUTS,
               on_refused=None):
    """Run the admission gate over `PooledTask`s and stamp `admitted` on each.

    This is the ingest-time bridge between the Docker-running gate and the
    Docker-free draw: it runs `admit` once per task here, so `draw_batch` never
    has to. Returns new `PooledTask`s (the type is frozen) with `admitted` set to
    the gate's verdict; everything else is preserved.

    `on_refused(task_id, admission)` is called for each refused task, so an
    operator ingesting a corpus sees WHY a task will never be scored rather than
    it silently vanishing from the holdout. Pass `log`/`print` or collect them.
    """
    import dataclasses

    admitted = []
    for task in tasks:
        verdict = admit(task.task_id, docker=docker, _run=_run,
                        _backend=_backend, controls=controls)
        if not verdict.scoreable and on_refused is not None:
            on_refused(task.task_id, verdict)
        admitted.append(dataclasses.replace(task, admitted=verdict.scoreable))
    return admitted


__all__ = [
    "CONTROL_INPUTS",
    "Admission",
    "admit",
    "admit_pool",
    "answer_is_public",
    "reference_poc",
    "scoreable",
]
