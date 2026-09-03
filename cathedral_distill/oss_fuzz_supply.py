"""Fresh supply: turn newly-disclosed OSS-Fuzz findings into sealable candidates.

The corpus this candidate lane could pay on has to be FRESH, and the obvious source is
not. ARVO's published dataset is a frozen snapshot -- its newest bug was filed
2024-05-02, and its monthly counts taper to nothing across early 2024 (60, 30, 21, 17,
2), which is an ingestion that stopped rather than a discovery rate that fell. So the
ingest is ours.

The feed is ``google/oss-fuzz-vulns``: a public git repository of OSV records, still
committing daily, where 93% of records carry BOTH an ``introduced`` and a ``fixed``
commit. That pair, with the repo, IS the vul/fix input a re-seal needs, so ingestion
never has to scrape Google's issue tracker.

**The boundary is a Git graph snapshot, not a timestamp.** A harness commitment binds an
independently observed feed head. Intake binds a later independently approved head,
requires the committed head to be its ancestor, and derives the exact commit delta. An OSV
identity is eligible only when every historical path-add commit for that identity is in
the post-commit delta. A future-looking ``%cI`` cannot make an old record fresh, and an
old-looking ``%cI`` cannot hide a genuinely post-snapshot record. Commit times and the
record's ``published:`` field remain descriptive evidence only.

**EVERY identity appearance, never just the latest path.** A record that was added,
removed, re-added, duplicated, or moved retains every add commit across every path. Keying
by path is unsafe: the live feed has retained old and migrated paths for the same OSV id,
and the newer path can be years younger than the first public appearance. Running this
pipeline buys reproducible feed-relative freshness, never secrecy or independent proof of
real-world disclosure time.

Layering follows the rest of this package: parsing and eligibility are pure and fully
tested, while the Git execution seam is injected. Exact bytes are verified before one
fixed safe document loader sees them. That keeps ``pyyaml`` out of the package's base
dependencies; the loader imports it lazily for non-JSON YAML and says so if it is missing.

What this module does NOT do: reproduce anything. Turning a candidate into an admitted
task means rebuilding both sides and checking the reference PoC crashes vul and spares
fix (ARVO's own tooling, ~81% success), then running ``corpus_admission`` and sealing the
id with ``cybergym_sealed``. That needs Docker, gcloud credentials and real build compute.
This module produces the worklist that stage consumes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence

#: The upstream catalog a candidate is named for. OSV records reference the OSS-Fuzz
#: issue, so candidates are ``oss-fuzz:<n>`` — the form ``cybergym_sealed.parse_origin``
#: accepts and ``corpus_admission`` refuses if it ever reached a task id unsealed.
CATALOG = "oss-fuzz"

#: The OSS-Fuzz issue id inside a report URL. Both tracker generations appear in the feed
#: (3-5 digit ids from the old tracker, 8-9 digit from the new one); both are "the
#: OSS-Fuzz issue id" and both are what ARVO keys a rebuild on.
_REPORT_ID_RE = re.compile(r"detail\?id=(\d+)")

#: NUL-delimited ``git log`` field marker; paths can legally contain newlines.
_COMMIT_MARKER = "COMMIT"

#: Root of the public ``google/oss-fuzz-vulns`` history. A deliberate upstream history
#: replacement requires an explicit reviewed update instead of silently resetting the
#: eligibility boundary. This root identifies a history family; it does NOT authenticate a
#: tip, because an attacker can make a fork that shares the root. Reward use must also pin
#: an independently verified feed head.
CANONICAL_FEED_ROOT = "fe983844fa12a389973e9addcfbac672229f2fef"

_GIT_OBJECT_RE = re.compile(r"\A[0-9a-f]{40,64}\Z")
_OSV_FILENAME_RE = re.compile(r"\A(OSV-[0-9]{4}-[0-9]+)\.ya?ml\Z")


class SupplyError(ValueError):
    """The feed could not be read or parsed. Fails closed — never a silent empty batch."""


def _osv_id_from_path(path: str) -> str | None:
    """Return the stable OSV identity encoded by a feed path, if it is a record."""
    match = _OSV_FILENAME_RE.fullmatch(PurePosixPath(path).name)
    return match.group(1) if match else None


def _git_blob_oid(record_bytes: bytes) -> str:
    """The SHA-1 object id Git assigns to these exact canonical feed bytes.

    The pinned upstream repository uses Git's SHA-1 object format. SHA-1 here reproduces
    an existing Git identifier rather than making a new collision-resistance claim; the
    candidate also carries a SHA-256 content digest.
    """
    header = f"blob {len(record_bytes)}\0".encode()
    return hashlib.sha1(  # noqa: S324 - reproducing the pinned Git object format
        header + record_bytes, usedforsecurity=False
    ).hexdigest()


@dataclass(frozen=True, order=True)
class DisclosureAppearance:
    """One path-add event; its committer time is descriptive, not eligibility authority."""

    path: str
    add_commit: str
    commit_time: datetime

    def __post_init__(self) -> None:
        if not _GIT_OBJECT_RE.fullmatch(self.add_commit):
            raise SupplyError("add_commit must be a full git object id")
        if self.commit_time.tzinfo is None or self.commit_time.utcoffset() is None:
            raise SupplyError("commit_time must be timezone-aware (UTC)")


@dataclass(frozen=True)
class DisclosureEvidence:
    """Graph- and content-bound provenance for one current OSV identity.

    ``appearances`` contains every historical path-add event with the same stable
    filename identity. ``post_commit_adds`` is the subset Git proves is reachable from
    ``feed_head`` but not from ``committed_feed_head``. An identity is fresh only when
    every one of its add events is in that post-commit set. Git timestamps remain attached
    for audit display, but never decide eligibility.

    ``record_blobs`` binds each path present at ``feed_head`` to exact bytes. Both heads
    must be independently observed/policy-bound: the canonical root identifies a history
    family but cannot authenticate a fork that shares that root.
    """

    osv_id: str
    committed_feed_head: str
    feed_head: str
    appearances: tuple[DisclosureAppearance, ...]
    post_commit_adds: tuple[str, ...]
    record_blobs: tuple[tuple[str, str], ...]
    feed_root: str = CANONICAL_FEED_ROOT

    def __post_init__(self) -> None:
        if not _OSV_FILENAME_RE.fullmatch(f"{self.osv_id}.yaml"):
            raise SupplyError(f"invalid stable OSV id {self.osv_id!r}")
        if not _GIT_OBJECT_RE.fullmatch(self.committed_feed_head):
            raise SupplyError("committed_feed_head must be a full git object id")
        if not _GIT_OBJECT_RE.fullmatch(self.feed_head):
            raise SupplyError("feed_head must be a full git object id")
        if self.feed_root != CANONICAL_FEED_ROOT:
            raise SupplyError(
                "feed_root does not match the pinned canonical feed history"
            )
        if (
            not self.appearances
            or tuple(sorted(set(self.appearances))) != self.appearances
        ):
            raise SupplyError("appearances must be a non-empty sorted unique tuple")
        if any(
            _osv_id_from_path(appearance.path) != self.osv_id
            for appearance in self.appearances
        ):
            raise SupplyError("every appearance path must name the same stable OSV id")
        if tuple(sorted(set(self.post_commit_adds))) != self.post_commit_adds:
            raise SupplyError("post_commit_adds must be a sorted unique tuple")
        appearance_commits = {appearance.add_commit for appearance in self.appearances}
        if any(
            not _GIT_OBJECT_RE.fullmatch(commit) for commit in self.post_commit_adds
        ):
            raise SupplyError("post-commit add must be a full git object id")
        if not set(self.post_commit_adds).issubset(appearance_commits):
            raise SupplyError("post_commit_adds contains a commit with no appearance")
        if (
            not self.record_blobs
            or tuple(sorted(set(self.record_blobs))) != self.record_blobs
        ):
            raise SupplyError(
                "current record blobs must be a non-empty sorted unique tuple"
            )
        blob_paths = tuple(path for path, _ in self.record_blobs)
        if len(set(blob_paths)) != len(blob_paths):
            raise SupplyError("a current record path may bind only one blob")
        historical_paths = set(self.paths)
        for path, blob in self.record_blobs:
            if path not in historical_paths or _osv_id_from_path(path) != self.osv_id:
                raise SupplyError(
                    "every current record blob must cover a historical path for the same OSV id"
                )
            if not _GIT_OBJECT_RE.fullmatch(blob):
                raise SupplyError("record blob must be a full git object id")

    @property
    def paths(self) -> tuple[str, ...]:
        """Every historical path for this stable identity, in canonical order."""
        return tuple(sorted({appearance.path for appearance in self.appearances}))

    @property
    def descriptive_first_add(self) -> DisclosureAppearance:
        """Earliest committer timestamp for display only; never use it for eligibility."""
        return min(
            self.appearances,
            key=lambda appearance: (
                appearance.commit_time,
                appearance.add_commit,
                appearance.path,
            ),
        )

    @property
    def all_adds_after_commitment(self) -> bool:
        """Whether graph reachability places every identity appearance after the snapshot."""
        return {appearance.add_commit for appearance in self.appearances} == set(
            self.post_commit_adds
        )

    def blob_for(self, record_path: str) -> str | None:
        """Return the blob pinned for a path present at ``feed_head``."""
        return dict(self.record_blobs).get(record_path)


@dataclass(frozen=True)
class FreshCandidate:
    """One newly-disclosed upstream bug, with everything a re-seal needs to rebuild it.

    Commit timestamps are descriptive metadata only. Eligibility comes from whether every
    add event for the stable identity is outside the harness's committed feed snapshot.

    **Every field here is PRIVATE to the pipeline.** This is a worklist entry, not
    dispatchable context. Three of them fingerprint the public origin outright and must be
    genericised before anything reaches a miner:

    * ``crash_type`` is OSV's ``summary``, which names the CRASHING SYMBOL
      ("Stack-buffer-overflow in log4cxx::helpers::Transcoder::decode"). Passing it
      through as a task ``description`` hands over the upstream bug.
    * ``project`` and ``repo`` name the codebase directly.

    ``scripts/reseal_task.py`` genericises disclosure against exactly these identifiers and
    records them as private ``origin_terms``; ``origin_id`` additionally has to be sealed
    (``cybergym_sealed``) because a public-catalog task id is refused at admission on its own.
    """

    osv_id: str
    origin_id: str  # oss-fuzz:<n>. A stable NAME for the bug — not a claim that
    # ARVO has an entry for it (ARVO's dataset is frozen at 2024-05).
    project: str
    repo: str
    introduced: str  # commit the bug entered at
    fixed: str  # commit that patched it — the other half of the pair
    crash_type: str  # OSV's summary; CARRIES THE CRASHING SYMBOL, never disclose raw
    severity: str
    record_path: str
    record_sha256: str
    disclosure: DisclosureEvidence

    def __post_init__(self) -> None:
        if self.osv_id != self.disclosure.osv_id:
            raise SupplyError("candidate OSV id does not match its disclosure evidence")
        if self.record_path not in self.disclosure.paths:
            raise SupplyError(
                "candidate record path is absent from its disclosure evidence"
            )
        if self.disclosure.blob_for(self.record_path) is None:
            raise SupplyError(
                "candidate record path is absent from the pinned feed head"
            )
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.record_sha256):
            raise SupplyError("candidate record_sha256 must be a full SHA-256 digest")

    @property
    def descriptive_first_add_at(self) -> datetime:
        """Earliest attached committer time for audit display, never eligibility."""
        return self.disclosure.descriptive_first_add.commit_time


@dataclass(frozen=True)
class IngestOutcome:
    """A parsed record, or the reason it cannot become a task.

    Skips are RETURNED rather than raised or dropped: ~7% of records carry no ``fixed``
    commit and are simply not pairable, and a pipeline that silently swallowed them would
    hide a supply problem behind an empty worklist. The reason is the funnel's telemetry.
    """

    candidate: FreshCandidate | None
    reason: str = ""

    @property
    def usable(self) -> bool:
        return self.candidate is not None


def _report_id(document: Mapping[str, Any]) -> str | None:
    """The OSS-Fuzz issue id, from the references or the details prose."""
    for ref in document.get("references") or ():
        if isinstance(ref, Mapping):
            match = _REPORT_ID_RE.search(str(ref.get("url", "")))
            if match:
                return match.group(1)
    match = _REPORT_ID_RE.search(str(document.get("details", "")))
    return match.group(1) if match else None


def _git_range(
    document: Mapping[str, Any],
) -> tuple[Mapping[str, Any], str, str, str] | None:
    """The first GIT range carrying both ends, as ``(its affected entry, repo, introduced, fixed)``.

    The affected entry is returned alongside so the project name and severity are read from
    the SAME entry the commits came from. A record with several affected entries would
    otherwise label a candidate with entry 0's project while rebuilding entry 1's commits.
    """
    for affected in document.get("affected") or ():
        if not isinstance(affected, Mapping):
            continue
        for rng in affected.get("ranges") or ():
            if not isinstance(rng, Mapping) or rng.get("type") != "GIT":
                continue
            introduced = fixed = ""
            for event in rng.get("events") or ():
                if not isinstance(event, Mapping):
                    continue
                # `introduced: "0"`/unknown is a placeholder, not a commit we can build.
                value = str(event.get("introduced", "") or "")
                if value and value not in ("0", "unknown"):
                    introduced = value
                if event.get("fixed"):
                    fixed = str(event["fixed"])
            if introduced and fixed:
                return affected, str(rng.get("repo", "")), introduced, fixed
    return None


def parse_osv_record(
    record_bytes: bytes,
    *,
    disclosure: DisclosureEvidence,
    record_path: str,
) -> IngestOutcome:
    """One exact feed blob plus bound disclosure evidence -> a candidate, or why not.

    The document's own ``published`` field is not the clock this pipeline trusts. The
    supplied bytes must hash to the blob at the independently pinned ``feed_head`` before
    the module's fixed safe loader may parse them. Accepting an injected or pre-parsed
    document with a matching id/path would leave provenance cosmetic: a caller could
    substitute different repository, range, or issue data after its provenance was
    derived.
    """
    if not isinstance(record_bytes, bytes):
        raise SupplyError("an OSV record must be supplied as exact bytes")
    if not isinstance(disclosure, DisclosureEvidence):
        raise SupplyError("an OSV record requires DisclosureEvidence")
    expected_blob = disclosure.blob_for(record_path)
    if expected_blob is None:
        raise SupplyError(
            f"record path {record_path!r} is not present at pinned feed head "
            f"{disclosure.feed_head}"
        )
    actual_blob = _git_blob_oid(record_bytes)
    if actual_blob != expected_blob:
        raise SupplyError(
            f"record bytes do not match pinned blob for {record_path!r}: "
            f"expected {expected_blob}, got {actual_blob}"
        )
    document = load_osv_document(record_bytes)
    if not isinstance(document, Mapping):
        raise SupplyError("an OSV record must parse to a mapping")
    osv_id = str(document.get("id", "") or "")
    if not osv_id:
        return IngestOutcome(None, "record has no id")
    if osv_id != disclosure.osv_id:
        raise SupplyError(
            f"record id {osv_id!r} does not match disclosure identity {disclosure.osv_id!r}"
        )
    if record_path not in disclosure.paths:
        raise SupplyError(
            f"record path {record_path!r} is not covered by disclosure evidence for {osv_id}"
        )

    report_id = _report_id(document)
    if not report_id:
        return IngestOutcome(
            None, f"{osv_id}: no OSS-Fuzz report id, cannot name the origin"
        )

    git = _git_range(document)
    if git is None:
        # ~7% of the feed. Without both ends there is no vul/fix pair to rebuild.
        return IngestOutcome(
            None, f"{osv_id}: no GIT range with both introduced and fixed"
        )
    affected, repo, introduced, fixed = git
    if not repo:
        return IngestOutcome(None, f"{osv_id}: GIT range names no repo")

    package = affected.get("package") or {}
    ecosystem_specific = affected.get("ecosystem_specific") or {}

    return IngestOutcome(
        FreshCandidate(
            osv_id=osv_id,
            origin_id=f"{CATALOG}:{report_id}",
            project=str((package or {}).get("name", "") or ""),
            repo=repo,
            introduced=introduced,
            fixed=fixed,
            crash_type=str(document.get("summary", "") or ""),
            severity=str(ecosystem_specific.get("severity", "") or ""),
            record_path=record_path,
            record_sha256="sha256:" + hashlib.sha256(record_bytes).hexdigest(),
            disclosure=disclosure,
        )
    )


# (argv) -> the command's stdout as text. Injected so the git seam is testable.
GitRunner = Callable[[Sequence[str]], str]


def parse_record_blobs(tree_text: str) -> dict[str, str]:
    """Parse ``git ls-tree -rz`` into exact current OSV path -> blob bindings."""
    records: dict[str, str] = {}
    for raw_entry in tree_text.split("\0"):
        if not raw_entry:
            continue
        metadata, separator, path = raw_entry.partition("\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise SupplyError(f"malformed git tree entry {raw_entry!r}")
        mode, object_type, object_id = fields
        osv_id = _osv_id_from_path(path)
        if osv_id is None:
            continue
        if mode not in {"100644", "100755"} or object_type != "blob":
            raise SupplyError(f"OSV record path {path!r} is not a regular git blob")
        if not _GIT_OBJECT_RE.fullmatch(object_id):
            raise SupplyError(f"OSV record path {path!r} has an invalid blob id")
        if path in records:
            raise SupplyError(f"duplicate OSV record path in git tree: {path!r}")
        records[path] = object_id
    return records


def _reject_local_history_overrides(repo_path: str, *, git: GitRunner) -> None:
    """Refuse grafts and replacement refs that can rewrite reachability locally."""
    graft_path_text = git(
        [
            "git",
            "--no-replace-objects",
            "-C",
            repo_path,
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "info/grafts",
        ]
    ).strip()
    graft_path = Path(graft_path_text)
    if not graft_path_text or not graft_path.is_absolute():
        raise SupplyError("could not resolve the repository graft file path")
    try:
        if os.path.lexists(graft_path):
            raise SupplyError(
                f"local Git graft file is forbidden for disclosure history: {graft_path}"
            )
    except OSError as exc:
        raise SupplyError("could not safely inspect the repository graft file") from exc

    replacements = tuple(
        line.strip()
        for line in git(
            [
                "git",
                "--no-replace-objects",
                "-C",
                repo_path,
                "replace",
                "-l",
            ]
        ).splitlines()
        if line.strip()
    )
    if replacements:
        raise SupplyError(
            "local Git replacement refs are forbidden for disclosure history: "
            f"{replacements!r}"
        )


def parse_disclosure_index(
    log_text: str,
    *,
    record_blobs: Mapping[str, str],
    committed_feed_head: str,
    post_commit_ids: Iterable[str],
    feed_head: str,
    feed_root: str = CANONICAL_FEED_ROOT,
) -> dict[str, DisclosureEvidence]:
    """Map current OSV ids to all add events and their graph-snapshot classification.

    Expects a NUL-framed ``COMMIT, object id, %cI, paths...`` stream. Newlines and control
    bytes are legal inside Git paths, so a line parser could hide an older identity path
    and reset its apparent age. ``post_commit_ids`` must come from the verified
    ``feed_head ^ committed_feed_head`` graph delta; timestamps are descriptive only.
    """
    if not _GIT_OBJECT_RE.fullmatch(committed_feed_head):
        raise SupplyError("committed_feed_head must be a full git object id")
    if not _GIT_OBJECT_RE.fullmatch(feed_head):
        raise SupplyError("feed_head must be a full git object id")
    if feed_root != CANONICAL_FEED_ROOT:
        raise SupplyError("feed_root does not match the pinned canonical feed history")
    post_commits = frozenset(post_commit_ids)
    if any(
        not isinstance(commit, str) or not _GIT_OBJECT_RE.fullmatch(commit)
        for commit in post_commits
    ):
        raise SupplyError("post_commit_ids contains an invalid git object id")

    current_by_id: dict[str, dict[str, str]] = {}
    for path, blob in record_blobs.items():
        osv_id = _osv_id_from_path(path)
        if osv_id is None:
            raise SupplyError(
                f"current record path has no stable OSV identity: {path!r}"
            )
        if not _GIT_OBJECT_RE.fullmatch(blob):
            raise SupplyError(f"current record path {path!r} has an invalid blob id")
        current_by_id.setdefault(osv_id, {})[path] = blob

    if log_text and not log_text.endswith("\0"):
        raise SupplyError("git log output is not NUL-framed")

    appearances: dict[str, list[DisclosureAppearance]] = {}
    tokens = log_text.split("\0")
    position = 0
    while position < len(tokens):
        if tokens[position] != _COMMIT_MARKER:
            raise SupplyError("git log emitted a path before any commit record")
        if position + 2 >= len(tokens):
            raise SupplyError("truncated NUL-framed commit marker")
        commit = tokens[position + 1]
        stamp = tokens[position + 2]
        if not _GIT_OBJECT_RE.fullmatch(commit):
            raise SupplyError(f"malformed commit object id {commit!r}")
        try:
            parsed = datetime.fromisoformat(stamp)
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("commit timestamp is not timezone-aware")
            when = parsed.astimezone(UTC)
        except ValueError as exc:
            raise SupplyError(f"unparseable commit date {stamp!r}") from exc
        position += 3

        first_path = True
        while position < len(tokens) and tokens[position]:
            raw_path = tokens[position]
            # This exact pretty format inserts one LF before a commit's first path. Strip
            # that framing byte only once: if the real path begins with LF, Git emits two
            # and the second is preserved. Later paths receive no prefix. Parsing within
            # the empty-token commit boundary also keeps marker-looking filenames as data.
            if first_path:
                if not raw_path.startswith("\n"):
                    raise SupplyError(
                        "git log first path is missing its framing newline"
                    )
                path = raw_path[1:]
                first_path = False
            else:
                path = raw_path
            osv_id = _osv_id_from_path(path)
            if osv_id is not None:
                appearances.setdefault(osv_id, []).append(
                    DisclosureAppearance(
                        path=path,
                        add_commit=commit,
                        commit_time=when,
                    )
                )
            position += 1

        if position >= len(tokens):
            raise SupplyError("git log output is missing its final NUL delimiter")
        position += 1

    index: dict[str, DisclosureEvidence] = {}
    for osv_id, blobs in current_by_id.items():
        rows = appearances.get(osv_id)
        if not rows:
            raise SupplyError(
                f"current OSV identity {osv_id} has no add event in complete history"
            )
        identity_appearances = tuple(sorted(set(rows)))
        historical_paths = {appearance.path for appearance in identity_appearances}
        missing_paths = sorted(set(blobs) - historical_paths)
        if missing_paths:
            raise SupplyError(
                f"current OSV paths have no add event in complete history: {missing_paths!r}"
            )
        appearance_commits = {
            appearance.add_commit for appearance in identity_appearances
        }
        index[osv_id] = DisclosureEvidence(
            osv_id=osv_id,
            committed_feed_head=committed_feed_head,
            feed_head=feed_head,
            appearances=identity_appearances,
            post_commit_adds=tuple(sorted(appearance_commits & post_commits)),
            record_blobs=tuple(sorted(blobs.items())),
            feed_root=feed_root,
        )
    return index


def disclosure_index(
    repo_path: str,
    *,
    git: GitRunner,
    committed_feed_head: str,
    expected_feed_head: str,
    subdir: str = "vulns",
) -> dict[str, DisclosureEvidence]:
    """Derive identity evidence between a committed and current policy-pinned head.

    The canonical root detects truncation and unrelated histories, but it cannot
    authenticate a fork that shares that root. The caller must bind
    ``committed_feed_head`` in the harness commitment and obtain ``expected_feed_head``
    through owner policy or independent public-feed verification. This function proves
    the former is an ancestor of the latter and pins every query to exact object ids.
    """
    if not _GIT_OBJECT_RE.fullmatch(committed_feed_head):
        raise SupplyError("committed_feed_head must be a full git object id")
    if not _GIT_OBJECT_RE.fullmatch(expected_feed_head):
        raise SupplyError("expected_feed_head must be a full git object id")
    shallow = git(
        [
            "git",
            "--no-replace-objects",
            "-C",
            repo_path,
            "rev-parse",
            "--is-shallow-repository",
        ]
    ).strip()
    if shallow != "false":
        raise SupplyError(
            "OSS-Fuzz disclosure history must be a complete non-shallow clone; refusing "
            f"rev-parse result {shallow!r}"
        )
    _reject_local_history_overrides(repo_path, git=git)

    feed_head = git(
        [
            "git",
            "--no-replace-objects",
            "-C",
            repo_path,
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        ]
    ).strip()
    if not _GIT_OBJECT_RE.fullmatch(feed_head):
        raise SupplyError("could not resolve a full feed HEAD commit")
    if feed_head != expected_feed_head:
        raise SupplyError(
            "feed HEAD does not match independently approved policy head: "
            f"expected {expected_feed_head}, got {feed_head}"
        )

    resolved_committed_head = git(
        [
            "git",
            "--no-replace-objects",
            "-C",
            repo_path,
            "rev-parse",
            "--verify",
            f"{committed_feed_head}^{{commit}}",
        ]
    ).strip()
    if resolved_committed_head != committed_feed_head:
        raise SupplyError(
            "could not resolve the exact feed head bound by the harness commitment"
        )

    merge_bases = tuple(
        line.strip()
        for line in git(
            [
                "git",
                "--no-replace-objects",
                "-C",
                repo_path,
                "merge-base",
                committed_feed_head,
                feed_head,
            ]
        ).splitlines()
        if line.strip()
    )
    if merge_bases != (committed_feed_head,):
        raise SupplyError(
            "committed feed head is not an ancestor of the current approved feed head: "
            f"merge bases were {merge_bases!r}"
        )

    roots = tuple(
        filter(
            None,
            (
                line.strip()
                for line in git(
                    [
                        "git",
                        "--no-replace-objects",
                        "-C",
                        repo_path,
                        "rev-list",
                        "--max-parents=0",
                        feed_head,
                    ]
                ).splitlines()
            ),
        )
    )
    if roots != (CANONICAL_FEED_ROOT,):
        raise SupplyError(
            "OSS-Fuzz history is incomplete, grafted, or not the pinned canonical feed: "
            f"expected root {CANONICAL_FEED_ROOT}, got {roots!r}"
        )

    post_commit_ids = tuple(
        line.strip()
        for line in git(
            [
                "git",
                "--no-replace-objects",
                "-C",
                repo_path,
                "rev-list",
                feed_head,
                f"^{committed_feed_head}",
            ]
        ).splitlines()
        if line.strip()
    )
    if len(set(post_commit_ids)) != len(post_commit_ids) or any(
        not _GIT_OBJECT_RE.fullmatch(commit) for commit in post_commit_ids
    ):
        raise SupplyError(
            "feed commit delta contains an invalid or duplicate object id"
        )

    tree = git(
        [
            "git",
            "--no-replace-objects",
            "-C",
            repo_path,
            "ls-tree",
            "-r",
            "--full-tree",
            "-z",
            feed_head,
            "--",
            subdir,
        ]
    )
    record_blobs = parse_record_blobs(tree)
    if not record_blobs:
        raise SupplyError(
            f"no current records found under {subdir!r} at pinned feed head: refusing "
            "to report an empty feed as success"
        )

    out = git(
        [
            "git",
            "--no-replace-objects",
            "-C",
            repo_path,
            "log",
            "--full-history",
            "--diff-merges=separate",
            "--no-renames",
            "--diff-filter=A",
            "--name-only",
            "-z",
            "--format=format:" + _COMMIT_MARKER + "%x00%H%x00%cI%x00",
            feed_head,
        ]
    )
    index = parse_disclosure_index(
        out,
        record_blobs=record_blobs,
        committed_feed_head=committed_feed_head,
        post_commit_ids=post_commit_ids,
        feed_head=feed_head,
        feed_root=CANONICAL_FEED_ROOT,
    )
    if not index:
        raise SupplyError(
            f"no added records found under {subdir!r}: refusing to report an empty feed as "
            "success, since that is indistinguishable from a broken clone"
        )
    _reject_local_history_overrides(repo_path, git=git)
    return index


def eligible_for(
    candidates: Iterable[FreshCandidate],
    *,
    committed_feed_head: str,
    expected_feed_head: str,
) -> tuple[FreshCandidate, ...]:
    """Candidates whose every identity-add is after the bound feed snapshot.

    The pool is cumulative and never consumed. Eligibility is graph reachability relative
    to the exact head bound in one harness commitment, not a comparison between mutable
    or forgeable wall-clock fields.
    """
    if not _GIT_OBJECT_RE.fullmatch(committed_feed_head):
        raise SupplyError("committed_feed_head must be a full git object id")
    if not _GIT_OBJECT_RE.fullmatch(expected_feed_head):
        raise SupplyError("expected_feed_head must be a full git object id")
    eligible: list[FreshCandidate] = []
    for candidate in candidates:
        evidence = candidate.disclosure
        if evidence.committed_feed_head != committed_feed_head:
            raise SupplyError("candidate is bound to a different committed feed head")
        if evidence.feed_head != expected_feed_head:
            raise SupplyError("candidate is bound to a different current feed head")
        if evidence.all_adds_after_commitment:
            eligible.append(candidate)
    return tuple(eligible)


def load_osv_document(text: str | bytes) -> Mapping[str, Any]:
    """Parse exact verified OSV bytes through the module's single safe loader.

    JSON is a YAML subset and lets hardware-free unit tests exercise this fixed boundary
    without adding a base dependency. Live feed YAML uses lazily imported ``pyyaml``;
    install the ``ingest`` extra for operator ingestion.
    """
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        try:  # pragma: no cover - live YAML seam
            import yaml
        except ImportError as exc:  # pragma: no cover
            raise SupplyError(
                "reading the OSS-Fuzz feed needs pyyaml "
                "(pip install 'cathedral-cybergym[ingest]')"
            ) from exc
        document = yaml.safe_load(text)  # pragma: no cover
    if not isinstance(document, Mapping):
        raise SupplyError("OSV record did not parse to a mapping")
    return document
