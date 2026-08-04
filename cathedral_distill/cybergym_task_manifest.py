"""Immutable, per-epoch CyberGym task manifests.

The verifier must never identify a challenge by a mutable container tag.  A task
manifest pins the exact vulnerable and fixed image bytes as ``repo@sha256`` refs,
the disclosure metadata that defines its holdout status, and a source-epoch scoped
digest that the service and signed receipt retain as evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from cathedral_distill.cybergym import Level
from cathedral_distill.cybergym_batch import BatchError, PooledTask, TaskPool
from cathedral_distill.cybergym_holdout import HoldoutError, _parse_disclosed_at


TASK_MANIFEST_SCHEMA = "cathedral_cybergym_task_manifest_v1"
TASK_MANIFEST_DOMAIN = b"cathedral-cybergym-task-manifest-v1\x00"
IMAGE_PAIR_DOMAIN = b"cathedral-cybergym-image-pair-v1\x00"
_PINNED_IMAGE_RE = re.compile(r"\A[^@\s]+@sha256:[0-9a-f]{64}\Z")
_TASK_KEYS = frozenset({
    "task_id", "level", "disclosed_at", "vulnerable_image", "fixed_image", "context",
})
_MANIFEST_KEYS = frozenset({
    "schema", "source_epoch", "created_at", "commitment_cutoff", "private_until", "tasks",
})


class TaskManifestError(ValueError):
    """A task manifest cannot safely be used for dispatch or verification."""


def _utc_timestamp(value: Any, *, field: str) -> datetime:
    try:
        result = _parse_disclosed_at(value)
    except HoldoutError as exc:
        raise TaskManifestError(f"{field}: {exc}") from exc
    if result.tzinfo is None:
        raise TaskManifestError(f"{field} must include a UTC offset")
    return result.astimezone(UTC)


def _pinned_image(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _PINNED_IMAGE_RE.fullmatch(value) is None:
        raise TaskManifestError(
            f"{field} must be an immutable repo@sha256:<64 lowercase hex> reference"
        )
    return value


def image_pair_digest(*, vulnerable_image: str, fixed_image: str) -> str:
    """Digest both exact images with unambiguous role labels and boundaries."""
    vulnerable = _pinned_image(vulnerable_image, field="vulnerable_image")
    fixed = _pinned_image(fixed_image, field="fixed_image")
    material = json.dumps(
        {"fixed_image": fixed, "vulnerable_image": vulnerable},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(IMAGE_PAIR_DOMAIN + material).hexdigest()


@dataclass(frozen=True)
class ManifestTask:
    task_id: str
    level: Level
    disclosed_at: datetime
    vulnerable_image: str
    fixed_image: str
    context: Mapping[str, str]

    def __post_init__(self) -> None:
        try:
            PooledTask(
                task_id=self.task_id,
                level=self.level,
                binary_digest=image_pair_digest(
                    vulnerable_image=self.vulnerable_image,
                    fixed_image=self.fixed_image,
                ),
                disclosed_at=self.disclosed_at,
            ).to_task()
        except (BatchError, ValueError) as exc:
            raise TaskManifestError(f"invalid task {self.task_id!r}: {exc}") from exc
        _utc_timestamp(self.disclosed_at.isoformat(), field="task disclosed_at")
        allowed_context = {"description", "sanitizer_trace", "patch"}
        unknown = set(self.context) - allowed_context
        if unknown:
            raise TaskManifestError(
                f"task {self.task_id!r} has unknown context fields: {', '.join(sorted(unknown))}"
            )

    @property
    def binary_digest(self) -> str:
        return image_pair_digest(
            vulnerable_image=self.vulnerable_image, fixed_image=self.fixed_image
        )

    def to_pooled_task(self) -> PooledTask:
        return PooledTask(
            task_id=self.task_id,
            level=self.level,
            binary_digest=self.binary_digest,
            disclosed_at=self.disclosed_at,
        )

    def as_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "task_id": self.task_id,
            "level": int(self.level),
            "disclosed_at": self.disclosed_at.isoformat(),
            "vulnerable_image": self.vulnerable_image,
            "fixed_image": self.fixed_image,
        }
        if self.context:
            document["context"] = dict(self.context)
        return document


@dataclass(frozen=True)
class ImmutableTaskManifest:
    source_epoch: int
    created_at: datetime
    commitment_cutoff: datetime
    private_until: datetime
    tasks: tuple[ManifestTask, ...]

    def __post_init__(self) -> None:
        if isinstance(self.source_epoch, bool) or not isinstance(self.source_epoch, int) or self.source_epoch < 0:
            raise TaskManifestError("source_epoch must be a non-negative integer")
        _utc_timestamp(self.created_at.isoformat(), field="created_at")
        _utc_timestamp(self.commitment_cutoff.isoformat(), field="commitment_cutoff")
        _utc_timestamp(self.private_until.isoformat(), field="private_until")
        if self.commitment_cutoff > self.created_at:
            raise TaskManifestError("commitment_cutoff cannot be after created_at")
        if self.private_until <= self.created_at:
            raise TaskManifestError("private_until must be after created_at")
        if not self.tasks:
            raise TaskManifestError("task manifest must contain at least one task")
        seen: set[str] = set()
        for task in self.tasks:
            if task.task_id in seen:
                raise TaskManifestError(f"duplicate task_id {task.task_id!r}")
            seen.add(task.task_id)
            if task.disclosed_at <= self.commitment_cutoff:
                raise TaskManifestError(
                    f"task {task.task_id!r} is not private after commitment_cutoff"
                )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": TASK_MANIFEST_SCHEMA,
            "source_epoch": self.source_epoch,
            "created_at": self.created_at.isoformat(),
            "commitment_cutoff": self.commitment_cutoff.isoformat(),
            "private_until": self.private_until.isoformat(),
            "tasks": [task.as_dict() for task in sorted(self.tasks, key=lambda item: item.task_id)],
        }

    @property
    def digest(self) -> str:
        body = json.dumps(
            self.unsigned_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return "sha256:" + hashlib.sha256(TASK_MANIFEST_DOMAIN + body).hexdigest()

    def assert_private_at(self, as_of: datetime) -> None:
        instant = _utc_timestamp(as_of.isoformat(), field="as_of")
        if instant >= self.private_until:
            raise TaskManifestError(
                "task manifest is no longer private for this epoch; refuse reward dispatch"
            )

    def task(self, task_id: str) -> ManifestTask:
        for task in self.tasks:
            if task.task_id == task_id:
                return task
        raise TaskManifestError(f"task {task_id!r} is absent from the manifest")

    def task_pool(self) -> TaskPool:
        return TaskPool([task.to_pooled_task() for task in self.tasks])

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "ImmutableTaskManifest":
        if not isinstance(document, Mapping):
            raise TaskManifestError("task manifest must be an object")
        missing = sorted(_MANIFEST_KEYS - set(document))
        unknown = sorted(set(document) - _MANIFEST_KEYS)
        if missing or unknown:
            detail = []
            if missing:
                detail.append(f"missing keys: {', '.join(missing)}")
            if unknown:
                detail.append(f"unknown keys: {', '.join(unknown)}")
            raise TaskManifestError("task manifest " + "; ".join(detail))
        if document["schema"] != TASK_MANIFEST_SCHEMA:
            raise TaskManifestError("unsupported task manifest schema")
        raw_tasks = document["tasks"]
        if not isinstance(raw_tasks, list):
            raise TaskManifestError("task manifest tasks must be an array")
        tasks: list[ManifestTask] = []
        for raw in raw_tasks:
            if not isinstance(raw, Mapping):
                raise TaskManifestError("each task must be an object")
            missing = sorted(_TASK_KEYS - set(raw))
            unknown = sorted(set(raw) - _TASK_KEYS)
            # context is optional, unlike the other five task fields.
            if missing == ["context"]:
                missing = []
            if missing or unknown:
                detail = []
                if missing:
                    detail.append(f"missing keys: {', '.join(missing)}")
                if unknown:
                    detail.append(f"unknown keys: {', '.join(unknown)}")
                raise TaskManifestError("task manifest task " + "; ".join(detail))
            level = raw["level"]
            if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 3:
                raise TaskManifestError("task level must be an integer 0..3")
            context = raw.get("context") or {}
            if not isinstance(context, Mapping):
                raise TaskManifestError("task context must be an object")
            tasks.append(ManifestTask(
                task_id=str(raw["task_id"]),
                level=Level(level),
                disclosed_at=_utc_timestamp(raw["disclosed_at"], field="task disclosed_at"),
                vulnerable_image=_pinned_image(raw["vulnerable_image"], field="vulnerable_image"),
                fixed_image=_pinned_image(raw["fixed_image"], field="fixed_image"),
                context={str(key): str(value) for key, value in context.items()},
            ))
        return cls(
            source_epoch=document["source_epoch"],
            created_at=_utc_timestamp(document["created_at"], field="created_at"),
            commitment_cutoff=_utc_timestamp(
                document["commitment_cutoff"], field="commitment_cutoff"
            ),
            private_until=_utc_timestamp(document["private_until"], field="private_until"),
            tasks=tuple(tasks),
        )


def load_task_manifest(path: str | Path) -> ImmutableTaskManifest:
    try:
        raw = Path(path).read_text(encoding="utf-8")
        document = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise TaskManifestError(f"cannot read task manifest: {exc}") from exc
    return ImmutableTaskManifest.from_document(document)


__all__ = [
    "IMAGE_PAIR_DOMAIN", "TASK_MANIFEST_DOMAIN", "TASK_MANIFEST_SCHEMA",
    "ImmutableTaskManifest", "ManifestTask", "TaskManifestError",
    "image_pair_digest", "load_task_manifest",
]
