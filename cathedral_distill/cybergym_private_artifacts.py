"""Validator-held blobs for private CyberGym reproduction tasks.

The verifier image pair and the miner's analyzable artifact have different
audiences.  This module keeps both the miner artifact and the reference PoC in
validator-controlled storage, verifies each against the v2 private manifest,
and exposes only the artifact to the dispatch service.  Files are addressed by
their lower-case SHA-256 hex value (without the ``sha256:`` prefix), never by an
untrusted task id.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Mapping

from cathedral_distill.cybergym_repro_manifest import (
    PrivateReproManifest,
    ReproManifestError,
)

MAX_CHALLENGE_ARTIFACT_BYTES = 8 * 1024 * 1024
# A reference larger than a miner is permitted to submit could never be solved
# through the protocol. Bounding it also keeps corpus admission from mounting an
# accidental multi-gigabyte file into the verifier.
MAX_REFERENCE_POC_BYTES = 1024 * 1024


class PrivateArtifactError(ReproManifestError):
    """A validator-held challenge artifact or reference PoC is unsafe to use."""


def _digest(blob: bytes) -> str:
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _validated_blobs(
    manifest: PrivateReproManifest,
    blobs: Mapping[str, bytes],
    *,
    digest_field: str,
    label: str,
    require_nonempty: bool,
    max_bytes: int,
) -> dict[str, bytes]:
    if not isinstance(manifest, PrivateReproManifest) or not manifest.reward_ready:
        raise PrivateArtifactError(
            f"{label} storage requires a v2 private repro manifest with pinned blobs"
        )
    if not isinstance(blobs, Mapping):
        raise PrivateArtifactError(f"{label} storage must map task ids to bytes")
    expected = {task.task_id for task in manifest.tasks}
    supplied = set(blobs)
    missing = sorted(expected - supplied)
    unknown = sorted(supplied - expected)
    if missing or unknown:
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if unknown:
            detail.append("unknown " + ", ".join(unknown))
        raise PrivateArtifactError(f"{label} storage has " + "; ".join(detail))

    validated: dict[str, bytes] = {}
    for task in manifest.tasks:
        blob = blobs[task.task_id]
        if not isinstance(blob, bytes):
            raise PrivateArtifactError(f"{label} for {task.task_id!r} must be bytes")
        if require_nonempty and not blob:
            raise PrivateArtifactError(f"{label} for {task.task_id!r} is empty")
        if len(blob) > max_bytes:
            raise PrivateArtifactError(
                f"{label} for {task.task_id!r} exceeds {max_bytes} bytes"
            )
        expected_digest = getattr(task, digest_field)
        if not isinstance(expected_digest, str):
            raise PrivateArtifactError(
                f"{label} for {task.task_id!r} is not pinned in the private manifest"
            )
        if _digest(blob) != expected_digest:
            raise PrivateArtifactError(
                f"{label} digest for {task.task_id!r} does not match the private manifest"
            )
        validated[task.task_id] = bytes(blob)
    return validated


def _load_directory(
    manifest: PrivateReproManifest,
    directory: str,
    *,
    digest_field: str,
    label: str,
) -> dict[str, bytes]:
    root = Path(directory)
    if not root.is_dir():
        raise PrivateArtifactError(f"{label} directory is not readable: {root}")
    blobs: dict[str, bytes] = {}
    for task in manifest.tasks:
        digest = getattr(task, digest_field)
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise PrivateArtifactError(
                f"{label} for {task.task_id!r} is not pinned in the private manifest"
            )
        try:
            blobs[task.task_id] = (root / digest.removeprefix("sha256:")).read_bytes()
        except OSError as exc:
            raise PrivateArtifactError(
                f"cannot read {label} for {task.task_id!r}: {exc}"
            ) from exc
    return blobs


class PrivateChallengeArtifactStore:
    """Bounded miner artifacts, held locally until an authenticated batch read."""

    def __init__(self, manifest: PrivateReproManifest, blobs: Mapping[str, bytes]) -> None:
        self._manifest_digest = manifest.digest
        self._blobs = _validated_blobs(
            manifest,
            blobs,
            digest_field="challenge_artifact_digest",
            label="challenge artifact",
            require_nonempty=True,
            max_bytes=MAX_CHALLENGE_ARTIFACT_BYTES,
        )

    @classmethod
    def from_directory(
        cls, manifest: PrivateReproManifest, directory: str
    ) -> "PrivateChallengeArtifactStore":
        return cls(
            manifest,
            _load_directory(
                manifest,
                directory,
                digest_field="challenge_artifact_digest",
                label="challenge artifact",
            ),
        )

    @property
    def manifest_digest(self) -> str:
        return self._manifest_digest

    def artifact(self, task_id: str) -> bytes:
        try:
            return self._blobs[task_id]
        except KeyError as exc:
            raise PrivateArtifactError(
                f"challenge artifact is unavailable for task {task_id!r}"
            ) from exc


class PrivateReferencePoCStore:
    """Validator-only reference PoCs, never exposed through the artifact route."""

    def __init__(self, manifest: PrivateReproManifest, blobs: Mapping[str, bytes]) -> None:
        self._manifest_digest = manifest.digest
        self._blobs = _validated_blobs(
            manifest,
            blobs,
            digest_field="reference_poc_digest",
            label="reference PoC",
            require_nonempty=False,
            max_bytes=MAX_REFERENCE_POC_BYTES,
        )

    @classmethod
    def from_directory(
        cls, manifest: PrivateReproManifest, directory: str
    ) -> "PrivateReferencePoCStore":
        return cls(
            manifest,
            _load_directory(
                manifest,
                directory,
                digest_field="reference_poc_digest",
                label="reference PoC",
            ),
        )

    @property
    def manifest_digest(self) -> str:
        return self._manifest_digest

    def reference_poc(self, task_id: str) -> bytes:
        try:
            return self._blobs[task_id]
        except KeyError as exc:
            raise PrivateArtifactError(
                f"reference PoC is unavailable for task {task_id!r}"
            ) from exc


__all__ = [
    "PrivateArtifactError",
    "PrivateChallengeArtifactStore",
    "PrivateReferencePoCStore",
    "MAX_CHALLENGE_ARTIFACT_BYTES",
    "MAX_REFERENCE_POC_BYTES",
]
