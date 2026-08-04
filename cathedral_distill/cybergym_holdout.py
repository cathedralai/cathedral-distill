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
      "context": {                                 # optional; level-gated on dispatch
        "description": "heap overflow in the length parser",
        "sanitizer_trace": "AddressSanitizer: heap-buffer-overflow valid.c:1900",
        "patch": "--- a/valid.c\n+++ b/valid.c\n@@ bound the length @@"
      }
    }

The vulnerability *corpus* (the ~130 GB of real vul/fix builds) is infrastructure;
this loader only ingests the metadata that seals a batch and gates its context. The
binary bytes plug in behind the injected crash backend, exactly as in the tests.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from cathedral_distill.cybergym import Level
from cathedral_distill.cybergym_batch import BatchError, PooledTask, TaskPool

# The full context fields a task may carry; dispatch reveals only the
# level-appropriate subset (LEVEL_CONTEXT_FIELDS).
_CONTEXT_FIELDS = ("description", "sanitizer_trace", "patch")


class HoldoutError(ValueError):
    """Raised when a holdout manifest is malformed. Fails closed."""


def _parse_disclosed_at(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise HoldoutError("disclosed_at must be an ISO-8601 timestamp string")
    text = value.strip()
    # Accept a trailing 'Z' (common in manifests) as UTC.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise HoldoutError(f"disclosed_at is not a valid timestamp: {value!r}") from exc
    # Normalise to an aware UTC datetime so pool comparisons are unambiguous.
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


@dataclass(frozen=True)
class Holdout:
    """A drawable task pool plus the per-task context a dispatch may reveal."""

    pool: TaskPool
    _context: Mapping[str, Mapping[str, str]]

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
    return Holdout(pool=pool, _context=context)


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


__all__ = ["Holdout", "HoldoutError", "load_holdout", "load_holdout_file"]
