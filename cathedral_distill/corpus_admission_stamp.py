"""Stamp a holdout manifest with admission verdicts the loader can hold it to.

`corpus_admission.admit_pool` runs the gate and returns stamped in-memory
objects; `cybergym_holdout.load_holdout` reads `admitted` back off disk. Nothing
connected the two (issue #78, second half): `admitted: true` in a manifest was a
human-typed claim, with no record of WHEN it was decided or against WHICH image.
That is two distinct holes:

**The honor system.** The gate exists, but the artifact a validator actually
loads never proves the gate ran. An operator who types `"admitted": true` — or
edits a refusal into an approval — produces a manifest indistinguishable from
one the gate blessed.

**The TOCTOU.** ARVO images are tag-addressed (`n132/arvo:<id>-vul`), and a tag
is mutable upstream. Admission can honestly decide "the answer is not public"
against today's bytes, and tomorrow's push under the same tag can bake the
reproducer back in — the boolean survives the mutation it was supposed to rule
out. The only closure is to record the content digest of the image the decision
actually inspected, so a runtime that later pulls the tag can refuse bytes the
gate never saw.

So every stamped entry carries an `admission` object: the verdict, the gate's
reasons, the three-way probe outcome (`not_public` / `public` / `probe_error` —
a probe error is stamped `admitted: false` with its reason, never dropped, per
the fail-closed contract the probe itself now honors), an `admitted_at` UTC
timestamp, and the `image_digest` the decision was made against.

**Where the digest comes from.** Not from the anonymous registry probe: an
ADMISSIBLE task's image is precisely the one an anonymous client cannot resolve,
so the probe that approves a task has no manifest bytes to hash. Instead the
digest is read with the validator's own credentials from the local image store —
``docker image inspect --format '{{index .RepoDigests 0}}'`` — immediately after
the gate's own ``docker run`` used the image, the same injected-runner shape as
`corpus_images._repo_digest`. That yields the `repo@sha256:...` reference a
later ``docker pull`` reports for the same bytes, so pull-time enforcement is a
string comparison (:func:`digest_matches`), not a second registry protocol. An
approval whose digest cannot be resolved is refused, not stamped unbound: an
unbindable "yes" is exactly the honor-system claim this tool exists to retire.

**Re-stamping re-decides from scratch.** A prior `admission` object in the input
is evidence of nothing here — trusting it would rebuild the honor system one
level up — so it is discarded before the gate runs, and every `admitted: true`
this tool emits was affirmed by the gate in THIS run.

Every subprocess is injected (`_run`, `_backend`), as everywhere else in the
admission stack, so the stamping logic is tested without Docker.
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Mapping, Sequence

from cathedral_distill.corpus_admission import CONTROL_INPUTS, Admission, admit
from cathedral_distill.cybergym_holdout import (
    IMAGE_DIGEST_RE,
    HoldoutError,
    load_holdout,
)
from cathedral_distill.cybergym_repro import _image_and_command, docker_reproduce_backend

Runner = Callable[..., subprocess.CompletedProcess]
Backend = Callable[..., int]
Clock = Callable[[], datetime]


def probe_outcome(admission: Admission) -> str:
    """Collapse the gate's two probe fields into the manifest's one enum.

    The `Admission` dataclass keeps `answer_is_public` and
    `answer_probe_errored` separate so triage can tell a burned task from a
    retryable one; a manifest entry wants the same distinction as one value.
    `probe_error` wins over `public` because an errored probe asserted nothing —
    including not the leak.
    """
    if admission.answer_probe_errored:
        return "probe_error"
    if admission.answer_is_public:
        return "public"
    return "not_public"


def resolve_image_digest(task_id: str, *, docker: str = "docker",
                         _run: Runner = subprocess.run) -> str:
    """The `repo@sha256:...` content digest of the task's vulnerable image, or ''.

    Read from the LOCAL image store, with the validator's own credentials — the
    gate's differential just ran this image, so the local bytes are the bytes
    the decision inspected, and their registry digest is what a later pull of
    the mutable tag must be compared against. '' means "could not bind": no
    local image, no RepoDigest (e.g. a locally-built image that never touched a
    registry), or output that is not a digest. The caller treats '' as a
    refusal, never as an approval with a blank.
    """
    image, _ = _image_and_command(task_id, "vul")
    try:
        r = _run([docker, "image", "inspect", "--format",
                  "{{index .RepoDigests 0}}", image],
                 capture_output=True, timeout=60)
    except (subprocess.SubprocessError, OSError):
        return ""
    if getattr(r, "returncode", 1) != 0:
        return ""
    digest = (r.stdout or b"").decode("utf-8", "replace").strip()
    return digest if IMAGE_DIGEST_RE.match(digest) else ""


def digest_matches(stamped: str | None, observed: str | None) -> bool:
    """True only when both values name the same image content.

    The stamp records what ``docker`` reports (`repo@sha256:...`); a runtime
    comparing after a pull may hold either that form or a bare `sha256:...`.
    Only the digest part decides — the repository name is addressing, not
    content. Absence on either side is False, never a benign pass: a missing
    digest is exactly the unbound state enforcement exists to refuse.
    """
    def _norm(value: str | None) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        digest = value.strip().lower().rsplit("@", 1)[-1]
        return digest if IMAGE_DIGEST_RE.match(digest) else None

    stamped_norm, observed_norm = _norm(stamped), _norm(observed)
    return stamped_norm is not None and stamped_norm == observed_norm


def stamp_admissions(entries: Sequence[Mapping], *, docker: str = "docker",
                     _run: Runner = subprocess.run,
                     _backend: Backend = docker_reproduce_backend,
                     controls: Sequence[bytes] = CONTROL_INPUTS,
                     now: Clock = lambda: datetime.now(UTC)) -> list[dict]:
    """Re-decide admission for every entry and return a newly stamped manifest.

    The order of operations is the fail-closed contract:

    1. The WHOLE manifest is schema-validated (via `load_holdout`, with any
       prior `admitted`/`admission` stripped — they are about to be re-derived
       and must neither be trusted nor allowed to block re-derivation) before a
       single container runs. A malformed manifest is refused outright.
    2. Each task gets a fresh `admit` verdict through the injected seams. A
       probe error, a public answer, a degenerate task: all stamped
       `admitted: false` with the gate's reasons — never dropped, so the refusal
       is auditable in the artifact itself.
    3. An affirmed task must also bind: its image digest is resolved
       (:func:`resolve_image_digest`), and failure to resolve flips the verdict
       to refused with its own reason. No entry leaves here `admitted: true`
       unless the gate said yes AND the decision names the bytes it saw.
    4. The finished manifest is round-tripped through `load_holdout` before it
       is returned, so this tool cannot emit a manifest its own loader would
       refuse.
    """
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        raise HoldoutError("holdout manifest must be a list of task entries")
    base: list[dict] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise HoldoutError("each holdout entry must be an object")
        base.append({k: v for k, v in entry.items()
                     if k not in ("admitted", "admission")})
    load_holdout(base)  # full schema validation before any Docker work

    stamped: list[dict] = []
    for clean in base:
        task_id = str(clean["task_id"])
        verdict = admit(task_id, docker=docker, _run=_run,
                        _backend=_backend, controls=controls)
        decided_at = now()
        decided_at = (decided_at.replace(tzinfo=UTC) if decided_at.tzinfo is None
                      else decided_at.astimezone(UTC))
        reasons = list(verdict.reasons)
        digest = ""
        admitted = False
        if verdict.scoreable:
            digest = resolve_image_digest(task_id, docker=docker, _run=_run)
            admitted = bool(digest)
            if not admitted:
                reasons.append(
                    "the vulnerable image's content digest could not be resolved "
                    "after the gate ran, so this approval cannot be bound to the "
                    "bytes it inspected; refused rather than stamped unbound"
                )
        out = dict(clean)
        out["admitted"] = admitted
        out["admission"] = {
            "admitted": admitted,
            "probe": probe_outcome(verdict),
            "reasons": reasons,
            "admitted_at": decided_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "image_digest": digest or None,
        }
        stamped.append(out)

    load_holdout(stamped)  # prove the loader affirms every stamp we just wrote
    return stamped


def stamp_holdout_file(path: str | Path, out: str | Path, **kwargs) -> list[dict]:
    """Read a holdout manifest, re-stamp it, and write a NEW manifest to `out`.

    The input's document shape survives: a bare list stays a bare list, an
    object keeps its other top-level keys with only `tasks` replaced. Writing
    over the input is refused — the pre-stamp manifest is the evidence of what
    an operator claimed before the gate spoke, and a tool whose job is making
    claims auditable must not destroy the claim it audited.
    """
    in_path, out_path = Path(path), Path(out)
    if in_path.resolve() == out_path.resolve():
        raise HoldoutError(
            "refusing to overwrite the input manifest; write the stamped copy "
            "to a new path so the pre-stamp manifest survives as evidence"
        )
    try:
        raw = in_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise HoldoutError(f"cannot read holdout manifest: {exc}") from exc
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise HoldoutError("holdout manifest is not valid JSON") from exc
    if isinstance(doc, Mapping):
        entries = doc.get("tasks")
    else:
        entries = doc
    if not isinstance(entries, list):
        raise HoldoutError("holdout manifest must be a list, or an object with a 'tasks' list")

    stamped = stamp_admissions(entries, **kwargs)
    output = {**doc, "tasks": stamped} if isinstance(doc, Mapping) else stamped
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, sort_keys=True)
        f.write("\n")
    return stamped


def main(argv: Sequence[str] | None = None) -> int:
    """CLI: `cathedral-cybergym-admit <manifest> [--out PATH]`.

    Exit 0 when every task was admitted, 1 when the stamped manifest records
    refusals (a valid artifact — the refusals are IN it, with reasons), 2 when
    the manifest itself was refused and nothing was written.
    """
    import argparse

    p = argparse.ArgumentParser(
        description="Re-run corpus admission over a holdout manifest and write a "
                    "digest-bound, stamped copy.")
    p.add_argument("manifest",
                   help="holdout manifest JSON (a list of entries, or an object "
                        "with a 'tasks' list)")
    p.add_argument("--out",
                   help="stamped manifest output path "
                        "(default: <manifest>.stamped.json; never the input)")
    p.add_argument("--docker", default="docker", help="docker binary to invoke")
    args = p.parse_args(argv)

    out = args.out or f"{args.manifest}.stamped.json"
    try:
        stamped = stamp_holdout_file(args.manifest, out, docker=args.docker)
    except HoldoutError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    admitted = sum(1 for e in stamped if e["admitted"])
    print(f"admitted {admitted}/{len(stamped)} tasks -> {out}")
    for e in stamped:
        if not e["admitted"]:
            reasons = e["admission"]["reasons"]
            print(f"REFUSED {e['task_id']}: {reasons[0] if reasons else 'refused'}")
    return 0 if admitted == len(stamped) else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "digest_matches",
    "main",
    "probe_outcome",
    "resolve_image_digest",
    "stamp_admissions",
    "stamp_holdout_file",
]
