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

The public-answer probe itself must fail CLOSED (issue #78). A registry lookup has
three outcomes, not two: the registry says the image does not resolve (no leak),
the image is pullable and carries the answer (leak), or the probe never got an
answer -- timeout, no egress, DNS failure, rate limit. The last is precisely the
normal state of a locked-down validator host, and treating it as "not public"
would admit every publicly-pullable ARVO task the moment Docker Hub throttles the
box. An unanswered probe is therefore its own refusal, distinct from a detected
leak, and never a default in either direction.

Every subprocess is injected (`_run`, `_backend`) so the decision logic is tested
without Docker or a registry.
"""
from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Sequence

from cathedral_distill.cybergym_repro import (
    DOCKER_TIMEOUT,
    _image_and_command,
    docker_reproduce_backend,
)
from cathedral_distill.cybergym_repro_manifest import (
    PinnedReproTask,
    PrivateReproManifest,
    ReproManifestError,
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
    """Why a task may or may not be scored. `scoreable` is the only gate.

    `answer_is_public` and `answer_probe_errored` are deliberately separate
    fields: "we saw the leak" and "we could not ask" both refuse admission, but
    an operator triaging a refused corpus must be able to tell a task that is
    genuinely burned from one whose verdict is retryable once the registry is
    reachable again. Folding them into one boolean would rebuild issue #78 with
    the polarity flipped.
    """

    task_id: str
    scoreable: bool
    discriminates: bool
    solvable: bool
    answer_is_public: bool
    answer_probe_errored: bool = False
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "scoreable": self.scoreable,
            "discriminates": self.discriminates,
            "solvable": self.solvable,
            "answer_is_public": self.answer_is_public,
            "answer_probe_errored": self.answer_probe_errored,
            "reasons": list(self.reasons),
        }


def reference_poc_image(image: str, *, docker: str = "docker",
                        _run: Runner = subprocess.run) -> bytes | None:
    """The reproducer baked into one exact vulnerable image, or None if absent.

    The caller supplies the image rather than a task id so a private manifest is
    checked against its immutable image bytes instead of the mutable public-tag
    fallback used by the legacy task-id helper.
    """
    try:
        r = _run([docker, "run", "--rm", "--entrypoint", "cat", image, "/tmp/poc"],
                 capture_output=True, timeout=DOCKER_TIMEOUT)
    except (subprocess.SubprocessError, OSError):
        return None
    if getattr(r, "returncode", 1) != 0:
        return None
    return r.stdout or b""


def reference_poc(task_id: str, *, docker: str = "docker",
                  _run: Runner = subprocess.run) -> bytes | None:
    """The reproducer baked into the tag-derived `-vul` image, or None if absent.

    This compatibility helper is for the standalone admission probe. A validator
    must call :func:`admit_private_manifest`, which binds every check to the
    digest-pinned image pair held in its private manifest.
    """
    image, _ = _image_and_command(task_id, "vul")
    return reference_poc_image(image, docker=docker, _run=_run)


#: Registry messages that mean the image authoritatively does NOT resolve for an
#: anonymous client. ``docker manifest inspect`` exits non-zero both for "no such
#: image" and for "the network ate the request", so the exit code alone cannot
#: separate absent from errored -- only a recognised not-found/denied message may
#: be read as absent. "denied" belongs here because the probe is anonymous: an
#: image the registry refuses to show an anonymous client leaks nothing to a
#: miner, whatever the refusal's underlying cause. Lower-case substrings, matched
#: against the probe's lower-cased combined output; anything non-zero that
#: matches none of them is a probe ERROR, never an absence.
MANIFEST_ABSENT_SIGNATURES: tuple[str, ...] = (
    "manifest unknown",
    "no such manifest",
    "not found",
    "name unknown",
    "denied",
    "repository does not exist",
)


@dataclass(frozen=True)
class PublicAnswerProbe:
    """One registry probe's outcome: not-public, public, or unanswered.

    A boolean cannot carry this decision. `public=False, errored=False` is the
    registry authoritatively saying no anonymous client resolves the image;
    `public=True` is a confirmed leak; `errored=True` is "the probe never got an
    answer", which refuses admission on its own (see the module docstring) and
    carries `detail` so the refusal names what actually went wrong.
    """

    public: bool
    errored: bool
    detail: str = ""


class PublicAnswerProbeError(RuntimeError):
    """The boolean public-answer helpers cannot answer either way.

    `answer_is_public*` return a bool, and a probe error fits neither value:
    False admits a leaking task (issue #78), True brands a possibly-private task
    as burned. So the helpers raise instead of guessing; callers that want the
    three-way verdict use :func:`probe_public_answer_image` directly, as the
    admission pipeline does.
    """


def probe_public_answer_image(image: str, *, poc: bytes | None = None,
                              docker: str = "docker",
                              _run: Runner = subprocess.run,
                              attempts: int = 2) -> PublicAnswerProbe:
    """Ask the registry, anonymously, whether `image` leaks its answer.

    ``docker manifest inspect`` normally uses the validator host's credentials,
    which cannot distinguish a public image from a private one the validator is
    allowed to pull.  A fresh empty Docker config makes this an anonymous
    registry lookup.

    Three outcomes, and the third fails closed (issue #78): a resolvable image
    carrying a reproducer is `public`; a not-found/denied message from the
    registry (see :data:`MANIFEST_ABSENT_SIGNATURES`) is authoritatively not
    public; everything else -- an exception, a timeout, a rate limit, any
    non-zero exit whose message is not a recognised absence -- is `errored`.
    An errored attempt is retried (`attempts` total, transient faults are the
    common case) and then reported as an error, never defaulted to "not public".

    Fixture extraction on a resolvable image does not get its own error arm:
    when `poc` is not supplied it falls back to :func:`reference_poc_image`,
    whose failure reads as "no reproducer" here -- but the composed admission
    always extracts the reproducer first and passes it in, and an extraction
    failure already refuses the task on the solvability axis.
    """
    detail = ""
    for _ in range(max(1, attempts)):
        try:
            with tempfile.TemporaryDirectory(prefix="cybergym-anon-docker-") as config:
                r = _run(
                    [docker, "--config", config, "manifest", "inspect", image],
                    capture_output=True, timeout=120,
                )
        except (subprocess.SubprocessError, OSError) as exc:
            detail = f"{type(exc).__name__}: {exc}"
            continue
        if getattr(r, "returncode", 1) == 0:
            if poc is None:
                poc = reference_poc_image(image, docker=docker, _run=_run)
            return PublicAnswerProbe(public=bool(poc), errored=False)
        output = _decoded_output(r)
        if any(signature in output.lower() for signature in MANIFEST_ABSENT_SIGNATURES):
            return PublicAnswerProbe(public=False, errored=False)
        detail = output.strip()[:300] or f"exit {getattr(r, 'returncode', 1)} with no output"
    return PublicAnswerProbe(public=False, errored=True, detail=detail)


def _decoded_output(r: subprocess.CompletedProcess) -> str:
    """Stderr then stdout of one probe attempt, as text, for signature matching."""
    parts = []
    for stream in (getattr(r, "stderr", b""), getattr(r, "stdout", b"")):
        if isinstance(stream, bytes):
            stream = stream.decode("utf-8", errors="replace")
        parts.append(stream or "")
    return "\n".join(part for part in parts if part)


def answer_is_public_image(image: str, *, poc: bytes | None = None,
                           docker: str = "docker",
                           _run: Runner = subprocess.run) -> bool:
    """True only when an anonymous Docker client can resolve the image and read a PoC.

    Boolean convenience over :func:`probe_public_answer_image`. When the probe
    errors this raises :class:`PublicAnswerProbeError` rather than returning
    either value: the previous behaviour returned False, which read as "not
    public, admissible" and admitted every publicly-pullable task on a host the
    registry happened not to answer (issue #78).
    """
    probe = probe_public_answer_image(image, poc=poc, docker=docker, _run=_run)
    if probe.errored:
        raise PublicAnswerProbeError(
            f"the public-registry probe for {image} errored rather than "
            f"answering: {probe.detail or 'no detail captured'}"
        )
    return probe.public


def answer_is_public(task_id: str, *, docker: str = "docker",
                     _run: Runner = subprocess.run) -> bool:
    """True when a miner could obtain the reference reproducer themselves.

    Two conditions, both required: the `-vul` image is pullable from the public
    registry, and it carries a non-empty `/tmp/poc`. An image nobody else can pull
    leaks nothing, and an image with no baked reproducer has no answer to leak.
    Raises :class:`PublicAnswerProbeError` when the registry probe errors, like
    the image-addressed helper it delegates to.
    """
    image, _ = _image_and_command(task_id, "vul")
    return answer_is_public_image(image, docker=docker, _run=_run)


def _admit(task_id: str, *, reference: Callable[[], bytes | None],
           public_answer: Callable[[bytes | None], PublicAnswerProbe],
           backend: Backend,
           controls: Sequence[bytes]) -> Admission:
    """Evaluate the three scoreability properties for one fixed task/image pair."""
    reasons: list[str] = []

    crashing_controls = [control for control in controls if backend(task_id, control, "vul") != 0]
    discriminates = not crashing_controls
    if not discriminates:
        reasons.append(
            f"the vulnerable build crashes on {len(crashing_controls)} of "
            f"{len(controls)} control inputs, so the differential is satisfied by "
            "input that demonstrates nothing"
        )

    poc = reference()
    if not poc:
        solvable = False
        reasons.append(
            "no reference reproducer is available, so the task cannot be shown to "
            "be a real vulnerability"
        )
    else:
        crashes_vul = backend(task_id, poc, "vul") != 0
        spares_fix = backend(task_id, poc, "fix") == 0
        solvable = crashes_vul and spares_fix
        if not crashes_vul:
            reasons.append("the reference reproducer does not crash the vulnerable build")
        elif not spares_fix:
            reasons.append(
                "the reference reproducer also crashes the patched build, so it "
                "does not identify the vulnerability the patch fixed"
            )

    probe = public_answer(poc)
    if probe.errored:
        reasons.append(
            "probe_error: the public-registry probe errored rather than answering "
            f"({probe.detail or 'no detail captured'}); an unanswered probe is not "
            "evidence the answer is private, so the task is refused instead of "
            "being labelled public or not"
        )
    elif probe.public:
        reasons.append(
            "the vulnerable image is publicly pullable and carries the reference "
            "reproducer, so any miner can read the answer without solving it"
        )

    return Admission(
        task_id=task_id,
        scoreable=discriminates and solvable and not probe.public and not probe.errored,
        discriminates=discriminates,
        solvable=solvable,
        answer_is_public=probe.public,
        answer_probe_errored=probe.errored,
        reasons=tuple(reasons),
    )


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
       reproducer, the task is training data, not a test. And if the registry
       cannot be asked -- timeout, no egress, rate limit -- the task is refused
       with `probe_error` rather than assumed private (issue #78).
    """
    return _admit(
        task_id,
        reference=lambda: reference_poc(task_id, docker=docker, _run=_run),
        public_answer=lambda poc: probe_public_answer_image(
            _image_and_command(task_id, "vul")[0], poc=poc, docker=docker, _run=_run),
        backend=_backend,
        controls=controls,
    )


def admit_private_manifest(manifest: PrivateReproManifest, *, docker: str = "docker",
                           _run: Runner = subprocess.run,
                           _backend: Backend = docker_reproduce_backend,
                           controls: Sequence[bytes] = CONTROL_INPUTS) -> tuple[Admission, ...]:
    """Run admission over the validator's exact, digest-pinned manifest images.

    This is the production entrypoint.  Unlike :func:`admit`, its Docker
    differential receives the same ``PrivateReproManifest`` that
    ``ReproTaskSource`` will later dispatch, so a tag-derived probe cannot approve
    different bytes from the ones the verifier scores.
    """
    if not isinstance(manifest, PrivateReproManifest):
        raise ReproManifestError("manifest admission requires a PrivateReproManifest")

    admissions: list[Admission] = []
    for task in manifest.tasks:
        def backend(task_id: str, poc: bytes, mode: str, *, _task: PinnedReproTask = task) -> int:
            if task_id != _task.task_id:
                raise ReproManifestError("admission backend received a task outside its manifest entry")
            return _backend(
                task_id, poc, mode, manifest=manifest, docker=docker, _run=_run)

        admissions.append(_admit(
            task.task_id,
            reference=lambda task=task: reference_poc_image(
                task.vulnerable_image, docker=docker, _run=_run),
            public_answer=lambda poc, task=task: probe_public_answer_image(
                task.vulnerable_image, poc=poc, docker=docker, _run=_run),
            backend=backend,
            controls=controls,
        ))
    return tuple(admissions)


def require_admitted_private_manifest(manifest: PrivateReproManifest, **kwargs) -> tuple[Admission, ...]:
    """Return manifest admissions or refuse startup before any task is advertised."""
    admissions = admit_private_manifest(manifest, **kwargs)
    refused = [admission for admission in admissions if not admission.scoreable]
    if refused:
        detail = "; ".join(
            f"{admission.task_id}: {', '.join(admission.reasons)}" for admission in refused
        )
        raise ReproManifestError(f"corpus admission refused manifest task(s): {detail}")
    return admissions


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
    "MANIFEST_ABSENT_SIGNATURES",
    "Admission",
    "PublicAnswerProbe",
    "PublicAnswerProbeError",
    "admit",
    "admit_private_manifest",
    "admit_pool",
    "answer_is_public",
    "answer_is_public_image",
    "probe_public_answer_image",
    "reference_poc",
    "reference_poc_image",
    "require_admitted_private_manifest",
    "scoreable",
]
