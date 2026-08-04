"""Immutable, private task manifests for the real CyberGym reproduction lane.

A Docker tag is an instruction to look up mutable bytes.  It is not task identity
and it cannot be reward evidence.  This module accepts only complete per-epoch
manifests whose vulnerable and fixed images are ``repository@sha256:...`` values.
The manifest remains on the validator; a dispatched batch reveals only its selected
tasks.  The batch evidence digest commits to the exact pair, task metadata, and
private-manifest digest that selected those tasks.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping, Sequence

from cathedral_distill.cybergym import Level, Task

MANIFEST_SCHEMA = "cathedral_cybergym_private_repro_manifest_v1"
BATCH_EVIDENCE_SCHEMA = "cathedral_cybergym_pinned_batch_evidence_v1"
MANIFEST_DOMAIN = b"cathedral-cybergym-private-repro-manifest-v1\x00"
TASK_DOMAIN = b"cathedral-cybergym-repro-image-pair-v1\x00"
BATCH_DOMAIN = b"cathedral-cybergym-pinned-batch-evidence-v1\x00"
_PINNED_IMAGE_RE = re.compile(r"\A[^\s@]+@sha256:[0-9a-f]{64}\Z")
_CONTEXT_FIELDS = frozenset({"description", "sanitizer_trace", "patch"})


class ReproManifestError(ValueError):
    """A private task manifest is malformed or unsafe to dispatch."""


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value), sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(domain + _canonical_bytes(value)).hexdigest()


def _timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ReproManifestError(f"{field} must be an ISO-8601 timestamp")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ReproManifestError(f"{field} is not a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReproManifestError(f"{field} must include a UTC offset")
    return parsed.astimezone(UTC)


def _nonnegative_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReproManifestError(f"{field} must be a non-negative integer")
    return value


def _pinned_image(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _PINNED_IMAGE_RE.fullmatch(value) is None:
        raise ReproManifestError(
            f"{field} must be an immutable repository@sha256:<64 hex> reference"
        )
    return value


@dataclass(frozen=True)
class PinnedReproTask:
    """One undisclosed task plus its exact vulnerable and fixed images."""

    task_id: str
    level: Level
    disclosed_at: datetime
    vulnerable_image: str
    fixed_image: str
    context: Mapping[str, str]

    @property
    def binary_digest(self) -> str:
        return _digest(
            TASK_DOMAIN,
            {
                "task_id": self.task_id,
                "vulnerable_image": self.vulnerable_image,
                "fixed_image": self.fixed_image,
            },
        )

    def to_task(self) -> Task:
        return Task(
            task_id=self.task_id,
            level=self.level,
            binary_digest=self.binary_digest,
        )

    def evidence(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "level": int(self.level),
            "disclosed_at": self.disclosed_at.isoformat(),
            "binary_digest": self.binary_digest,
            "vulnerable_image": self.vulnerable_image,
            "fixed_image": self.fixed_image,
        }


@dataclass(frozen=True)
class PrivateReproManifest:
    """A validator-held, digest-pinned task set for exactly one source epoch."""

    source_epoch: int
    tasks: tuple[PinnedReproTask, ...]
    digest: str

    def task(self, task_id: str) -> PinnedReproTask:
        for task in self.tasks:
            if task.task_id == task_id:
                return task
        raise ReproManifestError(f"task {task_id!r} is absent from the private manifest")

    def select(self, task_ids: Sequence[str]) -> tuple[PinnedReproTask, ...]:
        selected = tuple(self.task(task_id) for task_id in task_ids)
        if len({task.task_id for task in selected}) != len(selected):
            raise ReproManifestError("batch contains a duplicate task")
        return selected

    def batch_evidence(self, task_ids: Sequence[str]) -> dict[str, Any]:
        selected = self.select(task_ids)
        return {
            "schema": BATCH_EVIDENCE_SCHEMA,
            "manifest_digest": self.digest,
            "source_epoch": self.source_epoch,
            "tasks": [task.evidence() for task in sorted(selected, key=lambda item: item.task_id)],
        }

    def batch_evidence_digest(self, task_ids: Sequence[str]) -> str:
        return _digest(BATCH_DOMAIN, self.batch_evidence(task_ids))


def _parse_task(value: Any) -> PinnedReproTask:
    if not isinstance(value, Mapping):
        raise ReproManifestError("each manifest task must be an object")
    expected = {
        "task_id", "level", "disclosed_at", "vulnerable_image", "fixed_image", "context",
    }
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unknown = sorted(set(value) - expected)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if unknown:
            detail.append("unknown " + ", ".join(unknown))
        raise ReproManifestError("manifest task has " + "; ".join(detail))
    raw_level = value["level"]
    if isinstance(raw_level, bool) or not isinstance(raw_level, int) or raw_level not in range(4):
        raise ReproManifestError("task level must be an integer 0..3")
    raw_context = value["context"]
    if not isinstance(raw_context, Mapping) or set(raw_context) - _CONTEXT_FIELDS:
        raise ReproManifestError("task context has unsupported fields")
    task = PinnedReproTask(
        task_id=str(value["task_id"]),
        level=Level(raw_level),
        disclosed_at=_timestamp(value["disclosed_at"], field="task disclosed_at"),
        vulnerable_image=_pinned_image(value["vulnerable_image"], field="vulnerable_image"),
        fixed_image=_pinned_image(value["fixed_image"], field="fixed_image"),
        context={key: str(raw_context[key]) for key in sorted(raw_context)},
    )
    try:
        task.to_task()
    except ValueError as exc:
        raise ReproManifestError(f"invalid task {task.task_id!r}: {exc}") from exc
    if task.vulnerable_image == task.fixed_image:
        raise ReproManifestError("vulnerable and fixed images must differ")
    return task


def load_private_repro_manifest(document: Any) -> PrivateReproManifest:
    """Parse a complete immutable manifest.  Tag-only images fail before startup."""
    if not isinstance(document, Mapping):
        raise ReproManifestError("private repro manifest must be an object")
    expected = {"schema", "source_epoch", "tasks"}
    if set(document) != expected:
        raise ReproManifestError("private repro manifest has unknown or missing fields")
    if document["schema"] != MANIFEST_SCHEMA:
        raise ReproManifestError("unsupported private repro manifest schema")
    source_epoch = _nonnegative_int(document["source_epoch"], field="source_epoch")
    raw_tasks = document["tasks"]
    if not isinstance(raw_tasks, list) or not raw_tasks:
        raise ReproManifestError("private repro manifest tasks must be a non-empty list")
    tasks = tuple(sorted(
        (_parse_task(value) for value in raw_tasks), key=lambda task: task.task_id
    ))
    if len({task.task_id for task in tasks}) != len(tasks):
        raise ReproManifestError("private repro manifest has duplicate task ids")
    canonical_tasks = [task.evidence() | {"context": dict(task.context)} for task in sorted(tasks, key=lambda item: item.task_id)]
    digest = _digest(
        MANIFEST_DOMAIN,
        {"schema": MANIFEST_SCHEMA, "source_epoch": source_epoch, "tasks": canonical_tasks},
    )
    return PrivateReproManifest(source_epoch=source_epoch, tasks=tasks, digest=digest)


def load_private_repro_manifest_file(path: str) -> PrivateReproManifest:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ReproManifestError(f"cannot load private repro manifest: {exc}") from exc
    return load_private_repro_manifest(document)


def build_private_repro_manifest(
    images: Mapping[str, Mapping[str, Mapping[str, str]]],
    *,
    source_epoch: int,
    disclosed_at: datetime,
    metadata: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Build a manifest after image pull/inspection, for an explicit private epoch."""
    if disclosed_at.tzinfo is None or disclosed_at.utcoffset() is None:
        raise ReproManifestError("disclosed_at must include a UTC offset")
    rows = []
    for task_id in sorted(images):
        pair = images[task_id]
        meta = metadata.get(task_id)
        if not isinstance(meta, Mapping):
            raise ReproManifestError(f"task {task_id!r} has no metadata")
        try:
            vulnerable_image = str(pair["vul"]["digest"])
            fixed_image = str(pair["fix"]["digest"])
        except (KeyError, TypeError) as exc:
            raise ReproManifestError(f"task {task_id!r} has no complete image pair") from exc
        rows.append(
            {
                "task_id": task_id,
                "level": int(meta["level"]),
                "disclosed_at": disclosed_at.astimezone(UTC).isoformat(),
                "vulnerable_image": vulnerable_image,
                "fixed_image": fixed_image,
                "context": {
                    key: str(meta[key])
                    for key in ("description", "sanitizer_trace", "patch")
                    if key in meta
                },
            }
        )
    document = {"schema": MANIFEST_SCHEMA, "source_epoch": source_epoch, "tasks": rows}
    # Validate the generated document before an operator writes it.
    load_private_repro_manifest(document)
    return document


__all__ = [
    "MANIFEST_SCHEMA",
    "BATCH_EVIDENCE_SCHEMA",
    "PinnedReproTask",
    "PrivateReproManifest",
    "ReproManifestError",
    "build_private_repro_manifest",
    "load_private_repro_manifest",
    "load_private_repro_manifest_file",
]
