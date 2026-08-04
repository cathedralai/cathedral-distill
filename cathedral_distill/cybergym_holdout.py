"""Ingest disclosed-vulnerability metadata into a CyberGym `TaskPool`.

`cybergym_batch.TaskPool` / `draw_batch` are the consumer side of the sealed-batch
mechanism; this is the missing producer side — the loader that turns a manifest of
disclosed vulnerabilities into the pool a validator draws batches from, plus the
per-task context a level-gated `dispatch` reveals.

A manifest entry is one vulnerability:

    {
      "task_id": "arvo:12345",
      "level": 0,                                  # 0..3 difficulty
      "binary_digest": "sha256:<64 hex>",          # the vulnerable build
      "disclosed_at": "2026-07-20T00:00:00Z",      # OSS-Fuzz disclosure time
      "admitted": true,                            # corpus_admission verdict; absent/false => never drawn
      "admission": {                               # optional stamp; written by corpus_admission_stamp
        "admitted": true,                          # must agree with the entry's own flag
        "probe": "not_public",                     # not_public | public | probe_error
        "reasons": [],                             # the gate's refusal reasons, verbatim
        "admitted_at": "2026-08-04T12:00:00Z",     # when the gate decided (UTC)
        "image_digest": "n132/arvo@sha256:<64 hex>" # the vul image the decision inspected
      },
      "context": {                                 # optional; level-gated on dispatch
        "description": "heap overflow in the length parser",
        "sanitizer_trace": "AddressSanitizer: heap-buffer-overflow valid.c:1900",
        "patch": "--- a/valid.c\n+++ b/valid.c\n@@ bound the length @@"
      }
    }

The `admission` object is the difference between a claim and a record: without
it, `admitted: true` is whatever an operator typed (issue #78). When present it
is VALIDATED here, on the one ingest path every holdout passes through, so a
manifest whose stamp contradicts its own flag — or whose "yes" carries no image
digest to enforce, or records a probe that never answered — is refused at load,
not discovered at payout. Entries without the object still load (the stamp is
how the field is earned going forward, not a retroactive invalidation of every
existing manifest), and the field itself still fails closed to False.

The vulnerability *corpus* (the ~130 GB of real vul/fix builds) is infrastructure;
this loader only ingests the metadata that seals a batch and gates its context. The
binary bytes plug in behind the injected crash backend, exactly as in the tests.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from cathedral_distill.cybergym import Level
from cathedral_distill.cybergym_batch import BatchError, PooledTask, TaskPool

# The full context fields a task may carry; dispatch reveals only the
# level-appropriate subset (LEVEL_CONTEXT_FIELDS).
_CONTEXT_FIELDS = ("description", "sanitizer_trace", "patch")

#: The three outcomes a stamped admission may record for the public-answer
#: probe. Mirrors `corpus_admission`'s three-way verdict (issue #78): only
#: `not_public` may accompany `admitted: true` — `public` is a confirmed leak
#: and `probe_error` asserted nothing, so an admitted entry recording either is
#: internally contradictory and refused.
PROBE_OUTCOMES = ("not_public", "public", "probe_error")

#: Grammar for the image digest an admission was decided against: the full
#: `repo@sha256:<64 hex>` reference `docker` reports, or a bare digest. This is
#: the TOCTOU binding — the mutable tag is addressing, the digest is content.
IMAGE_DIGEST_RE = re.compile(r"\A(?:[^\s@]+@)?sha256:[0-9a-f]{64}\Z")


class HoldoutError(ValueError):
    """Raised when a holdout manifest is malformed. Fails closed."""


def _parse_timestamp(value: Any, *, name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise HoldoutError(f"{name} must be an ISO-8601 timestamp string")
    text = value.strip()
    # Accept a trailing 'Z' (common in manifests) as UTC.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise HoldoutError(f"{name} is not a valid timestamp: {value!r}") from exc
    # Normalise to an aware UTC datetime so pool comparisons are unambiguous.
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _parse_disclosed_at(value: Any) -> datetime:
    return _parse_timestamp(value, name="disclosed_at")


def _parse_admission(task_id: str, raw: Any, admitted: bool) -> str | None:
    """Validate one entry's `admission` stamp; return its image digest, if any.

    The stamp is the only evidence that `admitted: true` was earned rather than
    typed, so a stamp that contradicts the entry carrying it is refused — the
    loader never picks a side in an inconsistency, because either side could be
    the tampered one. The rules an ADMITTED entry's stamp must satisfy are
    exactly the invariants `corpus_admission_stamp` writes: the stamp itself
    says admitted, the probe answered `not_public`, and an image digest binds
    the decision to content (without it the TOCTOU issue #78 describes is
    back — the tag mutates upstream and the boolean survives).
    """
    if not isinstance(raw, Mapping):
        raise HoldoutError(f"admission for {task_id!r} must be an object")
    stamp_admitted = raw.get("admitted")
    if not isinstance(stamp_admitted, bool):
        raise HoldoutError(f"admission.admitted for {task_id!r} must be a boolean")
    if stamp_admitted != admitted:
        raise HoldoutError(
            f"{task_id!r} says admitted={admitted} but its admission stamp says "
            f"{stamp_admitted}; an entry that contradicts its own stamp has been "
            "edited after the gate spoke, so neither value is believed"
        )
    probe = raw.get("probe")
    if probe not in PROBE_OUTCOMES:
        raise HoldoutError(
            f"admission.probe for {task_id!r} must be one of "
            f"{', '.join(PROBE_OUTCOMES)}, got {probe!r}"
        )
    reasons = raw.get("reasons", [])
    if (not isinstance(reasons, Sequence) or isinstance(reasons, (str, bytes))
            or not all(isinstance(reason, str) for reason in reasons)):
        raise HoldoutError(f"admission.reasons for {task_id!r} must be a list of strings")
    _parse_timestamp(raw.get("admitted_at"), name=f"admission.admitted_at for {task_id!r}")
    digest = raw.get("image_digest")
    if digest is not None and (
            not isinstance(digest, str) or IMAGE_DIGEST_RE.match(digest) is None):
        raise HoldoutError(
            f"admission.image_digest for {task_id!r} must be a "
            f"[repo@]sha256:<64 hex> digest, got {digest!r}"
        )
    if admitted:
        if probe != "not_public":
            raise HoldoutError(
                f"{task_id!r} is stamped admitted but its probe outcome is "
                f"{probe!r}; the gate never admits on an unanswered or leaking "
                "probe, so this stamp was not written by the gate"
            )
        if digest is None:
            raise HoldoutError(
                f"{task_id!r} is stamped admitted but carries no image_digest; "
                "an approval that names no content cannot be enforced against "
                "the mutable upstream tag (issue #78)"
            )
    return digest


@dataclass(frozen=True)
class Holdout:
    """A drawable task pool plus the per-task context a dispatch may reveal."""

    pool: TaskPool
    _context: Mapping[str, Mapping[str, str]]
    _admission_digests: Mapping[str, str] = field(default_factory=dict)

    def image_digest(self, task_id: str) -> str | None:
        """The vul-image content digest this task's admission was decided against.

        None for a task with no stamp (legacy manifests, synthetic sources).
        This accessor is the pull-time enforcement seam: a runtime that pulls a
        tag-addressed image before serving the task must compare what it pulled
        against this value (`corpus_admission_stamp.digest_matches`) and refuse
        a mismatch — the tag is mutable upstream, the stamp names the exact
        bytes the admission gate inspected (issue #78).
        """
        return self._admission_digests.get(task_id)

    def context_provider(self, task_id: str) -> Mapping[str, str]:
        """Full context for a task; `dispatch` reveals only its level's fields.

        Delegates to the pool's own `context_provider` when it has one — the
        synthetic source (`cybergym_synthetic.SyntheticTaskSource`) generates
        context per draw rather than from a fixed manifest, so there is no
        static dict to read here for it. A plain `TaskPool` has no such
        method, so the fixed `_context` this holdout was loaded with is used
        unchanged for the real-corpus path.
        """
        provider = getattr(self.pool, "context_provider", None)
        if provider is not None:
            return dict(provider(task_id))
        return dict(self._context.get(task_id, {}))


def load_holdout(entries: Sequence[Mapping[str, Any]]) -> Holdout:
    """Build a `Holdout` from a sequence of manifest entries. Fails closed."""
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        raise HoldoutError("holdout manifest must be a list of task entries")
    pooled: list[PooledTask] = []
    context: dict[str, dict[str, str]] = {}
    digests: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise HoldoutError("each holdout entry must be an object")
        missing = {"task_id", "level", "binary_digest", "disclosed_at"} - set(entry)
        if missing:
            raise HoldoutError(f"holdout entry missing keys: {', '.join(sorted(missing))}")
        level_raw = entry["level"]
        if isinstance(level_raw, bool) or not isinstance(level_raw, int) or not 0 <= level_raw <= 3:
            raise HoldoutError(f"level must be an integer 0..3, got {level_raw!r}")
        # Admission is read from the manifest, not defaulted. A task is scoreable
        # only if the entry explicitly records that admission ran and passed
        # (`corpus_admission.admit_pool` writes this). An entry without the field is
        # treated as not-yet-admitted and fails closed: it loads, but a scored draw
        # will not select it. This is the seam a degenerate task (arvo:3938) slipped
        # through when the field defaulted True — the invariant is enforced HERE, on
        # the real ingest path, not only in the isolated gate.
        admitted_raw = entry.get("admitted", False)
        if not isinstance(admitted_raw, bool):
            raise HoldoutError(
                f"admitted for {entry.get('task_id')!r} must be a boolean, got "
                f"{admitted_raw!r}"
            )
        try:
            # PooledTask.to_task() validates the task_id and binary_digest grammar.
            task = PooledTask(
                task_id=str(entry["task_id"]),
                level=Level(level_raw),
                binary_digest=str(entry["binary_digest"]),
                disclosed_at=_parse_disclosed_at(entry["disclosed_at"]),
                admitted=admitted_raw,
            )
            task.to_task()
        except (BatchError, ValueError) as exc:
            raise HoldoutError(f"invalid holdout entry {entry.get('task_id')!r}: {exc}") from exc
        pooled.append(task)

        if "admission" in entry:
            digest = _parse_admission(task.task_id, entry["admission"], admitted_raw)
            if digest is not None:
                digests[task.task_id] = digest

        ctx = entry.get("context") or {}
        if not isinstance(ctx, Mapping):
            raise HoldoutError(f"context for {task.task_id!r} must be an object")
        unknown = set(ctx) - set(_CONTEXT_FIELDS)
        if unknown:
            raise HoldoutError(f"unknown context fields for {task.task_id!r}: {', '.join(sorted(unknown))}")
        revealed = {k: str(ctx[k]) for k in _CONTEXT_FIELDS if k in ctx}
        if revealed:
            context[task.task_id] = revealed

    try:
        pool = TaskPool(pooled)  # rejects an empty pool / duplicate task ids
    except BatchError as exc:
        raise HoldoutError(str(exc)) from exc
    return Holdout(pool=pool, _context=context, _admission_digests=digests)


def load_holdout_file(path: str | Path) -> Holdout:
    """Load a holdout from a JSON file: either a bare list of entries, or an
    object with a top-level ``"tasks"`` list."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise HoldoutError(f"cannot read holdout manifest: {exc}") from exc
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise HoldoutError("holdout manifest is not valid JSON") from exc
    if isinstance(doc, Mapping):
        doc = doc.get("tasks")
    if not isinstance(doc, list):
        raise HoldoutError("holdout manifest must be a list, or an object with a 'tasks' list")
    return load_holdout(doc)


__all__ = [
    "IMAGE_DIGEST_RE",
    "PROBE_OUTCOMES",
    "Holdout",
    "HoldoutError",
    "load_holdout",
    "load_holdout_file",
]
