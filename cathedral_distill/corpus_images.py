"""Pull + digest-pin the CyberGym vul/fix images for a real-data deployment.

`cybergym_repro`'s verify backend runs prebuilt Docker images; a real-corpus
validator must (a) pull the vul+fix pair for every task it will serve and (b) pin
each by content digest, so a later re-pull (or a compromised registry) cannot swap
the image under a running validator and change a crash verdict (launch runbook
Phase 1.4: a digest-pinned, read-only image set). This module does both and writes a
manifest a deployment can verify against.

The subprocess runner is injected (`_run`) so the pull/inspect/manifest logic is
unit-tested without Docker; on a real box it shells out to `docker`.
"""
from __future__ import annotations

import json
import subprocess
from datetime import datetime
from typing import Callable, Mapping, Sequence

from cathedral_distill.cybergym_repro import REPRO_SUBSET, _image_and_command
from cathedral_distill.cybergym_repro_manifest import (
    MANIFEST_SCHEMA,
    build_private_repro_manifest,
)

Runner = Callable[..., subprocess.CompletedProcess]
PULL_TIMEOUT = 1800  # a cold arvo image is a few GB


def image_pairs(task_ids: Sequence[str]) -> list[tuple[str, str, str]]:
    """`[(task_id, vul_image, fix_image)]` — the vul+fix pair the differential needs."""
    return [(t, _image_and_command(t, "vul")[0], _image_and_command(t, "fix")[0]) for t in task_ids]


def _pull(image: str, *, docker: str, _run: Runner) -> None:
    _run([docker, "pull", image], capture_output=True, timeout=PULL_TIMEOUT)


def _repo_digest(image: str, *, docker: str, _run: Runner) -> str:
    """The image's content digest (`repo@sha256:...`), or '' if not present locally."""
    try:
        r = _run([docker, "inspect", "--format", "{{index .RepoDigests 0}}", image],
                 capture_output=True, timeout=60)
    except (subprocess.SubprocessError, OSError):
        return ""
    return (r.stdout or b"").decode("utf-8", "replace").strip()


def pull_and_pin(task_ids: Sequence[str], *, docker: str = "docker",
                 _run: Runner = subprocess.run) -> dict[str, dict]:
    """Pull each task's vul+fix images and record their content digests.

    Returns `{task_id: {"vul": {"ref", "digest"}, "fix": {...}}}`. A digest of ''
    means the image did not pull (registry miss / offline) — surfaced, never hidden,
    so a deployment can refuse to serve an unpinned task.
    """
    manifest: dict[str, dict] = {}
    for task_id, vul, fix in image_pairs(task_ids):
        entry: dict[str, dict] = {}
        for role, image in (("vul", vul), ("fix", fix)):
            _pull(image, docker=docker, _run=_run)
            entry[role] = {"ref": image, "digest": _repo_digest(image, docker=docker, _run=_run)}
        manifest[task_id] = entry
    return manifest


def unpinned(manifest: Mapping[str, dict]) -> list[str]:
    """Task ids whose vul or fix image has no digest — not safe to serve."""
    return sorted(t for t, e in manifest.items()
                  if not e.get("vul", {}).get("digest") or not e.get("fix", {}).get("digest"))


def write_manifest(
    manifest: Mapping[str, dict],
    path: str,
    *,
    source_epoch: int,
    disclosed_at: datetime,
) -> dict:
    """Write the private, immutable repro manifest a validator can dispatch.

    ``pull_and_pin`` intentionally returns raw inspection data so callers can
    reject failed pulls.  This conversion makes a reward-bearing artifact: every
    task gets an explicit disclosure timestamp and immutable image pair, and the
    generated document is re-validated before it reaches disk.
    """
    doc = build_private_repro_manifest(
        manifest,
        source_epoch=source_epoch,
        disclosed_at=disclosed_at,
        metadata=REPRO_SUBSET,
    )
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write("\n")
    return doc


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="Pull + digest-pin the CyberGym vul/fix corpus images.")
    p.add_argument("--tasks", nargs="*", help="task ids (default: the REPRO_SUBSET)")
    p.add_argument("--out", default="corpus_images.json", help="manifest output path")
    p.add_argument("--source-epoch", type=int, required=True,
                   help="epoch that owns this private holdout manifest")
    p.add_argument("--disclosed-at", required=True,
                   help="UTC disclosure time for this private holdout (ISO-8601)")
    args = p.parse_args(argv)

    ids = args.tasks or list(REPRO_SUBSET)
    manifest = pull_and_pin(ids)
    try:
        disclosed_at = datetime.fromisoformat(args.disclosed_at.replace("Z", "+00:00"))
    except ValueError:
        p.error("--disclosed-at must be an ISO-8601 timestamp")
    write_manifest(
        manifest,
        args.out,
        source_epoch=args.source_epoch,
        disclosed_at=disclosed_at,
    )
    missing = unpinned(manifest)
    print(f"pinned {len(manifest) - len(missing)}/{len(manifest)} tasks → {args.out}")
    if missing:
        print(f"WARNING: {len(missing)} task(s) have no image digest and must not be served: "
              f"{', '.join(missing)}")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["MANIFEST_SCHEMA", "image_pairs", "pull_and_pin", "unpinned", "write_manifest", "main"]
