"""Pull + digest-pin the corpus images, proven without Docker.

The subprocess runner is injected with a fake `docker` that acknowledges `pull` and
returns a synthetic `repo@sha256:` digest for `inspect`, so the pair enumeration,
manifest shape, digest capture, and the unpinned-task guard are all exercised in CI.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.corpus_images import (  # noqa: E402
    MANIFEST_SCHEMA,
    image_pairs,
    pull_and_pin,
    unpinned,
    write_manifest,
)


class FakeDocker:
    """`pull` succeeds; `inspect` returns a synthetic content digest per image. A
    `missing` set forces an empty digest, standing in for an image that never pulled."""

    def __init__(self, missing=()):
        self.missing = set(missing)
        self.pulled: list[str] = []

    def __call__(self, argv, capture_output=False, timeout=None):
        assert argv[0] == "docker"
        if argv[1] == "pull":
            self.pulled.append(argv[2])
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if argv[1] == "inspect":
            image = argv[-1]
            digest = b"" if image in self.missing else f"{image}@sha256:{'ab' * 32}".encode()
            return subprocess.CompletedProcess(argv, 0, digest, b"")
        raise AssertionError(f"unexpected docker call: {argv}")


def test_image_pairs_are_the_vul_and_fix_builds():
    assert image_pairs(["arvo:368"]) == [("arvo:368", "n132/arvo:368-vul", "n132/arvo:368-fix")]
    assert image_pairs(["oss-fuzz:42535201"])[0][1:] == (
        "cybergym/oss-fuzz:42535201-vul", "cybergym/oss-fuzz:42535201-fix")


def test_pull_and_pin_records_both_builds_with_digests():
    fake = FakeDocker()
    manifest = pull_and_pin(["arvo:368", "arvo:10400"], _run=fake)
    assert set(manifest) == {"arvo:368", "arvo:10400"}
    assert manifest["arvo:368"]["vul"]["ref"] == "n132/arvo:368-vul"
    assert manifest["arvo:368"]["vul"]["digest"] == "n132/arvo:368-vul@sha256:" + "ab" * 32
    assert manifest["arvo:368"]["fix"]["digest"].startswith("n132/arvo:368-fix@sha256:")
    # both builds of both tasks were actually pulled
    assert set(fake.pulled) == {
        "n132/arvo:368-vul", "n132/arvo:368-fix", "n132/arvo:10400-vul", "n132/arvo:10400-fix"}
    assert unpinned(manifest) == []


def test_unpinned_flags_a_task_missing_an_image():
    fake = FakeDocker(missing={"n132/arvo:368-fix"})  # the patched build never pulled
    manifest = pull_and_pin(["arvo:368", "arvo:10400"], _run=fake)
    assert unpinned(manifest) == ["arvo:368"]          # can't serve a half-pinned task


def test_write_manifest_is_schema_tagged_and_stable(tmp_path):
    fake = FakeDocker()
    manifest = pull_and_pin(["arvo:368"], _run=fake)
    out = tmp_path / "corpus_images.json"
    write_manifest(manifest, str(out))
    doc = json.loads(out.read_text())
    assert doc["schema"] == MANIFEST_SCHEMA
    assert doc["images"]["arvo:368"]["vul"]["digest"].startswith("n132/arvo:368-vul@sha256:")
