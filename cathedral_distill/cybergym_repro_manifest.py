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

# v1 pins only the validator's vulnerable/fixed image pair. It remains readable
# for historical/dev manifests but cannot be a reward-bearing task source because
# it has no separately delivered miner artifact or validator-held PoC commitment.
MANIFEST_SCHEMA = "cathedral_cybergym_private_repro_manifest_v1"
# v2 adds the two independent blobs a reward-bearing task needs: the bounded
# miner artifact and the validator-only reference PoC. Neither blob is embedded
# in the manifest; only its immutable digest is committed here.
REWARD_MANIFEST_SCHEMA = "cathedral_cybergym_private_repro_manifest_v2"
BATCH_EVIDENCE_SCHEMA = "cathedral_cybergym_pinned_batch_evidence_v1"
MANIFEST_DOMAIN = b"cathedral-cybergym-private-repro-manifest-v1\x00"
TASK_DOMAIN = b"cathedral-cybergym-repro-image-pair-v1\x00"
BATCH_DOMAIN = b"cathedral-cybergym-pinned-batch-evidence-v1\x00"
_PINNED_IMAGE_RE = re.compile(r"\A[^\s@]+@sha256:[0-9a-f]{64}\Z")
_SHA256_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_CONTEXT_FIELDS = frozenset({"description", "sanitizer_trace", "patch"})
_CRASH_EVIDENCE_FIELDS = frozenset({"sanitizer", "exit_codes", "signals"})
_SANITIZERS = frozenset({
    "AddressSanitizer", "MemorySanitizer", "ThreadSanitizer", "LeakSanitizer",
    "UndefinedBehaviorSanitizer", "HWAddressSanitizer",
})


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


def _sha256_digest(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256_DIGEST_RE.fullmatch(value) is None:
        raise ReproManifestError(f"{field} must be sha256:<64 lowercase hex>")
    return value


def _crash_evidence(value: Any) -> Mapping[str, Any]:
    """Validate the immutable execution rule for a non-legacy private task."""
    if not isinstance(value, Mapping) or set(value) != _CRASH_EVIDENCE_FIELDS:
        raise ReproManifestError(
            "crash_evidence must contain exactly sanitizer, exit_codes, and signals"
        )
    sanitizer = value["sanitizer"]
    exit_codes = value["exit_codes"]
    signals = value["signals"]
    if not isinstance(sanitizer, str) or sanitizer not in _SANITIZERS:
        raise ReproManifestError("crash_evidence sanitizer is unsupported")
    for field, values, upper in (
        ("exit_codes", exit_codes, 255),
        ("signals", signals, 64),
    ):
        if (
            not isinstance(values, list) or not values
            or any(isinstance(item, bool) or not isinstance(item, int) or not 1 <= item <= upper for item in values)
            or len(set(values)) != len(values)
        ):
            raise ReproManifestError(
                f"crash_evidence {field} must be a unique non-empty integer list"
            )
    return {
        "sanitizer": sanitizer,
        "exit_codes": list(exit_codes),
        "signals": list(signals),
    }


def _origin_terms(value: Any) -> tuple[str, ...]:
    """The PRIVATE stripped-origin identifiers (absent/empty is fine). A tuple of
    unique, non-empty, non-whitespace strings; anything else is a manifest error."""
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise ReproManifestError("origin_terms must be a list of strings")
    terms = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ReproManifestError("origin_terms entries must be non-empty strings")
        terms.append(item)
    if len(set(terms)) != len(terms):
        raise ReproManifestError("origin_terms must be unique")
    return tuple(terms)


@dataclass(frozen=True)
class PinnedReproTask:
    """One undisclosed task plus its exact vulnerable and fixed images."""

    task_id: str
    level: Level
    disclosed_at: datetime
    vulnerable_image: str
    fixed_image: str
    context: Mapping[str, str]
    crash_evidence: Mapping[str, Any] | None = None
    challenge_artifact_digest: str | None = None
    reference_poc_digest: str | None = None
    #: The exact PUBLIC-origin identifiers the sealer stripped (source basenames, the
    #: crashing symbol, the project name, an upstream id). PRIVATE — never disclosed to a
    #: miner (not in `context`, so not in any dispatched field), but bound into the
    #: manifest digest via `evidence()` so tampering is evident. Admission asserts none of
    #: them reappear in the disclosed context (`corpus_admission` forbidden_terms), turning
    #: the fingerprint check from operator-must-remember into enforced-by-construction.
    origin_terms: tuple[str, ...] = ()

    @property
    def reward_ready(self) -> bool:
        """Whether this task commits both blobs needed on the reward path."""
        return (
            self.challenge_artifact_digest is not None
            and self.reference_poc_digest is not None
        )

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
        evidence = {
            "task_id": self.task_id,
            "level": int(self.level),
            "disclosed_at": self.disclosed_at.isoformat(),
            "binary_digest": self.binary_digest,
            "vulnerable_image": self.vulnerable_image,
            "fixed_image": self.fixed_image,
        }
        if self.crash_evidence is not None:
            evidence["crash_evidence"] = dict(self.crash_evidence)
        if self.challenge_artifact_digest is not None:
            evidence["challenge_artifact_digest"] = self.challenge_artifact_digest
        if self.reference_poc_digest is not None:
            evidence["reference_poc_digest"] = self.reference_poc_digest
        if self.origin_terms:
            # Bound into the manifest digest (tamper-evidence), never disclosed. Absent
            # when empty so it does not change the digest of a manifest that has none.
            evidence["origin_terms"] = list(self.origin_terms)
        return evidence


@dataclass(frozen=True)
class PrivateReproManifest:
    """A validator-held, digest-pinned task set for exactly one source epoch."""

    source_epoch: int
    tasks: tuple[PinnedReproTask, ...]
    digest: str
    schema: str = MANIFEST_SCHEMA

    @property
    def reward_ready(self) -> bool:
        """Whether every task has the v2 private-artifact commitments."""
        return self.schema == REWARD_MANIFEST_SCHEMA and all(
            task.reward_ready for task in self.tasks
        )

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


def _parse_task(value: Any, *, reward_manifest: bool) -> PinnedReproTask:
    if not isinstance(value, Mapping):
        raise ReproManifestError("each manifest task must be an object")
    expected = {
        "task_id", "level", "disclosed_at", "vulnerable_image", "fixed_image", "context",
    }
    if reward_manifest:
        expected |= {"challenge_artifact_digest", "reference_poc_digest"}
    allowed = expected | {"crash_evidence", "origin_terms"}
    if set(value) - allowed or expected - set(value):
        missing = sorted(expected - set(value))
        unknown = sorted(set(value) - allowed)
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
        crash_evidence=(
            _crash_evidence(value["crash_evidence"])
            if "crash_evidence" in value else None
        ),
        challenge_artifact_digest=(
            _sha256_digest(
                value["challenge_artifact_digest"], field="challenge_artifact_digest"
            )
            if reward_manifest else None
        ),
        reference_poc_digest=(
            _sha256_digest(value["reference_poc_digest"], field="reference_poc_digest")
            if reward_manifest else None
        ),
        origin_terms=_origin_terms(value.get("origin_terms")),
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
    schema = document["schema"]
    if schema not in (MANIFEST_SCHEMA, REWARD_MANIFEST_SCHEMA):
        raise ReproManifestError("unsupported private repro manifest schema")
    source_epoch = _nonnegative_int(document["source_epoch"], field="source_epoch")
    raw_tasks = document["tasks"]
    if not isinstance(raw_tasks, list) or not raw_tasks:
        raise ReproManifestError("private repro manifest tasks must be a non-empty list")
    tasks = tuple(sorted(
        (
            _parse_task(value, reward_manifest=(schema == REWARD_MANIFEST_SCHEMA))
            for value in raw_tasks
        ),
        key=lambda task: task.task_id,
    ))
    if len({task.task_id for task in tasks}) != len(tasks):
        raise ReproManifestError("private repro manifest has duplicate task ids")
    canonical_tasks = [task.evidence() | {"context": dict(task.context)} for task in sorted(tasks, key=lambda item: item.task_id)]
    digest = _digest(
        MANIFEST_DOMAIN,
        {"schema": schema, "source_epoch": source_epoch, "tasks": canonical_tasks},
    )
    return PrivateReproManifest(
        source_epoch=source_epoch, tasks=tasks, digest=digest, schema=schema
    )


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
    challenge_artifacts: Mapping[str, bytes] | None = None,
    reference_pocs: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    """Build a private manifest after image pull/inspection.

    Supplying both blob maps creates a v2 reward manifest. The caller writes the
    exact bytes to validator-controlled artifact/PoC storage; only their digests
    enter the manifest. Supplying neither preserves the v1 dry-run format.
    """
    if disclosed_at.tzinfo is None or disclosed_at.utcoffset() is None:
        raise ReproManifestError("disclosed_at must include a UTC offset")
    if (challenge_artifacts is None) != (reference_pocs is None):
        raise ReproManifestError(
            "challenge_artifacts and reference_pocs must be supplied together"
        )
    reward_manifest = challenge_artifacts is not None
    if reward_manifest:
        assert reference_pocs is not None
        expected = set(images)
        if set(challenge_artifacts) != expected or set(reference_pocs) != expected:
            raise ReproManifestError(
                "challenge_artifacts and reference_pocs must cover exactly the image task ids"
            )
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
        row = {
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
        if "crash_evidence" in meta:
            row["crash_evidence"] = dict(meta["crash_evidence"])
        if meta.get("origin_terms"):
            # PRIVATE stripped-origin identifiers; validated by the loader below.
            row["origin_terms"] = list(meta["origin_terms"])
        if reward_manifest:
            assert challenge_artifacts is not None and reference_pocs is not None
            artifact = challenge_artifacts[task_id]
            reference = reference_pocs[task_id]
            if not isinstance(artifact, bytes) or not artifact:
                raise ReproManifestError(
                    f"challenge artifact for {task_id!r} must be non-empty bytes"
                )
            if not isinstance(reference, bytes):
                raise ReproManifestError(
                    f"reference PoC for {task_id!r} must be bytes"
                )
            row["challenge_artifact_digest"] = "sha256:" + hashlib.sha256(artifact).hexdigest()
            row["reference_poc_digest"] = "sha256:" + hashlib.sha256(reference).hexdigest()
        rows.append(row)
    document = {
        "schema": REWARD_MANIFEST_SCHEMA if reward_manifest else MANIFEST_SCHEMA,
        "source_epoch": source_epoch,
        "tasks": rows,
    }
    # Validate the generated document before an operator writes it.
    load_private_repro_manifest(document)
    return document


__all__ = [
    "MANIFEST_SCHEMA",
    "REWARD_MANIFEST_SCHEMA",
    "BATCH_EVIDENCE_SCHEMA",
    "PinnedReproTask",
    "PrivateReproManifest",
    "ReproManifestError",
    "build_private_repro_manifest",
    "load_private_repro_manifest",
    "load_private_repro_manifest_file",
]
