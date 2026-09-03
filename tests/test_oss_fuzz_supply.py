"""Fresh supply: ingesting newly-disclosed OSS-Fuzz findings.

ARVO's published dataset is frozen (newest bug filed 2024-05-02), so a fresh candidate
pool has to be generated in-house from the live `google/oss-fuzz-vulns` feed. These tests
cover turning an OSV record into a sealable candidate and deciding which candidates could
be reward-eligible if the lane is separately activated.

The eligibility rule implements the feed-relative anti-lookup boundary. OSS-Fuzz
publishes the bug AND its testcase, so running the pipeline ourselves buys freshness,
never secrecy — the intended boundary against a baked answer is an identity absent from
the exact feed head bound by the harness and added only in the verified later graph delta.
Git's committer timestamp does not prove real-world disclosure time and never determines
eligibility.

Hardware-free and YAML-free: the tested core hashes exact synthetic JSON-as-YAML bytes
through the fixed loader and parses injected Git output, so neither pyyaml nor a live feed
checkout is needed for the pure cases. Adversarial integration tests use temporary Git
repositories.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cathedral_distill.oss_fuzz_supply as supply  # noqa: E402
from cathedral_distill.oss_fuzz_supply import (  # noqa: E402
    CANONICAL_FEED_ROOT,
    DisclosureAppearance,
    DisclosureEvidence,
    FreshCandidate,
    SupplyError,
    disclosure_index,
    eligible_for,
    parse_disclosure_index,
    parse_osv_record,
)

WHEN = datetime(2026, 8, 16, tzinfo=UTC)
RECORD_PATH = "vulns/zxc/OSV-2026-1157.yaml"
FEED_HEAD = "f" * 40
COMMITTED_HEAD = "d" * 40
FIRST_ADD = "a" * 40


def _evidence(
    *,
    osv_id="OSV-2026-1157",
    when=WHEN,
    add_commit=FIRST_ADD,
    feed_head=FEED_HEAD,
    committed_feed_head=COMMITTED_HEAD,
    appearances=None,
    post_commit_adds=None,
    record=None,
    record_blobs=None,
):
    if appearances is None:
        appearances = (
            DisclosureAppearance(
                path=RECORD_PATH,
                add_commit=add_commit,
                commit_time=when,
            ),
        )
    if post_commit_adds is None:
        post_commit_adds = tuple(
            sorted({appearance.add_commit for appearance in appearances})
        )
    if record_blobs is None:
        record_bytes = _record_bytes(_record() if record is None else record)
        record_blobs = ((RECORD_PATH, _git_blob(record_bytes)),)
    return DisclosureEvidence(
        osv_id=osv_id,
        committed_feed_head=committed_feed_head,
        feed_head=feed_head,
        appearances=tuple(sorted(appearances)),
        post_commit_adds=tuple(sorted(post_commit_adds)),
        record_blobs=tuple(sorted(record_blobs)),
    )


def _parse(record=None, *, evidence=None, record_path=RECORD_PATH):
    document = _record() if record is None else record
    record_bytes = _record_bytes(document)
    return parse_osv_record(
        record_bytes,
        disclosure=_evidence(record=document) if evidence is None else evidence,
        record_path=record_path,
    )


def _complete_git(
    log_text,
    *,
    shallow="false",
    root=CANONICAL_FEED_ROOT,
    head=FEED_HEAD,
    committed_head=COMMITTED_HEAD,
    merge_base=None,
    post_commits=(FIRST_ADD, "b" * 40),
    replacements="",
    tree=None,
):
    calls = []
    if tree is None:
        tree = f"100644 blob {'c' * 40}\t{RECORD_PATH}\0"

    def git(argv):
        calls.append(tuple(argv))
        if "--is-shallow-repository" in argv:
            return shallow + "\n"
        if "--git-path" in argv:
            return "/repo/.git/info/grafts\n"
        if "replace" in argv:
            return replacements
        if "--verify" in argv:
            return (committed_head if argv[-1] != "HEAD^{commit}" else head) + "\n"
        if "merge-base" in argv:
            return (committed_head if merge_base is None else merge_base) + "\n"
        if "--max-parents=0" in argv:
            return root + "\n"
        if "rev-list" in argv:
            return "".join(commit + "\n" for commit in post_commits)
        if "ls-tree" in argv:
            return tree
        if "log" in argv:
            return log_text
        raise AssertionError(f"unexpected git command: {argv!r}")

    return git, calls


def _record(**overrides):
    """An OSV record shaped like the real feed (modelled on OSV-2026-1157)."""
    document = {
        "id": "OSV-2026-1157",
        "summary": "Memcpy-param-overlap in zxc_decompress_chunk_wrapper_default",
        "details": "OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=546426939",
        "references": [
            {
                "type": "REPORT",
                "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=546426939",
            }
        ],
        "affected": [
            {
                "package": {"name": "zxc", "ecosystem": "OSS-Fuzz"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/hellobertrand/zxc.git",
                        "events": [
                            {"introduced": "b89b134299971f1edd2cefb9f1eaf3d93fdf1dad"},
                            {"fixed": "399de305e5ca322a0144c86ec85dd77757669c60"},
                        ],
                    }
                ],
                "ecosystem_specific": {"severity": "MEDIUM"},
            }
        ],
    }
    document.update(overrides)
    return document


def _record_bytes(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()


def _git_blob(record_bytes):
    header = f"blob {len(record_bytes)}\0".encode()
    return hashlib.sha1(header + record_bytes, usedforsecurity=False).hexdigest()


def _blobs(*paths):
    return {path: "c" * 40 for path in paths}


def _git_log(*commits):
    """Real ``git log -z --format=format:...`` framing for pure parser tests."""
    tokens = []
    for index, (commit, stamp, paths) in enumerate(commits):
        if index:
            tokens.append("")
        tokens.extend(("COMMIT", commit, stamp))
        tokens.extend(
            ("\n" if path_index == 0 else "") + path
            for path_index, path in enumerate(paths)
        )
    return "\0".join(tokens) + ("\0" if tokens else "")


def _run_git(repo, *args, env=None):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout


def _commit_all(repo, message, stamp):
    commit_env = os.environ.copy()
    commit_env.update(GIT_AUTHOR_DATE=stamp, GIT_COMMITTER_DATE=stamp)
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", message, env=commit_env)
    return _run_git(repo, "rev-parse", "HEAD").strip()


def _moved_identity_repo(tmp_path):
    """Real history: add under an LF path, delete, then add at a normal path."""
    repo = tmp_path / "feed"
    repo.mkdir()
    _run_git(repo, "init", "-q")
    _run_git(repo, "config", "user.name", "Test")
    _run_git(repo, "config", "user.email", "test@example.invalid")

    (repo / "README").write_text("root\n")
    root = _commit_all(repo, "root", "2022-01-01T00:00:00+00:00")

    old_relative = "vulns/odd\nsegment/OSV-2023-38.yaml"
    old_path = repo / old_relative
    old_path.parent.mkdir(parents=True)
    old_path.write_bytes(_record_bytes(_record(id="OSV-2023-38")))
    old_add = _commit_all(repo, "old identity", "2023-02-01T01:04:10+00:00")

    old_path.unlink()
    committed = _commit_all(
        repo, "delete before harness snapshot", "2024-01-01T00:00:00+00:00"
    )

    moved_relative = "vulns/new-project/OSV-2023-38.yaml"
    moved_path = repo / moved_relative
    moved_path.parent.mkdir(parents=True)
    moved_path.write_bytes(_record_bytes(_record(id="OSV-2023-38")))
    head = _commit_all(repo, "re-add after snapshot", "2025-09-24T11:24:46+00:00")
    return repo, root, old_add, committed, head, old_relative, moved_relative


def _merge_introduced_identity_repo(tmp_path):
    """Real history: a merge itself adds an identity, later deleted and re-added."""
    repo = tmp_path / "merge-feed"
    repo.mkdir()
    _run_git(repo, "init", "-q")
    _run_git(repo, "config", "user.name", "Test")
    _run_git(repo, "config", "user.email", "test@example.invalid")

    (repo / "README").write_text("root\n")
    root = _commit_all(repo, "root", "2019-01-01T00:00:00+00:00")
    main_branch = _run_git(repo, "branch", "--show-current").strip()

    _run_git(repo, "checkout", "-q", "-b", "side")
    (repo / "SIDE").write_text("side\n")
    _commit_all(repo, "side", "2019-06-01T00:00:00+00:00")

    _run_git(repo, "checkout", "-q", main_branch)
    (repo / "MAIN").write_text("main\n")
    _commit_all(repo, "main", "2019-07-01T00:00:00+00:00")
    _run_git(repo, "merge", "-q", "--no-ff", "--no-commit", "side")
    old_relative = "vulns/merge/OSV-2023-38.yaml"
    old_path = repo / old_relative
    old_path.parent.mkdir(parents=True)
    old_path.write_bytes(_record_bytes(_record(id="OSV-2023-38")))
    merge_add = _commit_all(repo, "merge adds identity", "2020-01-01T00:00:00+00:00")

    old_path.unlink()
    committed = _commit_all(
        repo, "delete before harness snapshot", "2024-01-01T00:00:00+00:00"
    )
    moved_relative = "vulns/new-project/OSV-2023-38.yaml"
    moved_path = repo / moved_relative
    moved_path.parent.mkdir(parents=True)
    moved_path.write_bytes(_record_bytes(_record(id="OSV-2023-38")))
    head = _commit_all(repo, "re-add after snapshot", "2025-01-01T00:00:00+00:00")
    return repo, root, merge_add, committed, head, old_relative, moved_relative


class TestARecordBecomesASealableCandidate:
    def test_the_vul_fix_pair_and_origin_are_extracted(self):
        """The pair IS the rebuild input, which is why ingestion never has to scrape
        Google's issue tracker."""
        candidate = _parse().candidate
        assert candidate.origin_id == "oss-fuzz:546426939"
        assert candidate.repo == "https://github.com/hellobertrand/zxc.git"
        assert candidate.introduced == "b89b134299971f1edd2cefb9f1eaf3d93fdf1dad"
        assert candidate.fixed == "399de305e5ca322a0144c86ec85dd77757669c60"
        assert candidate.project == "zxc"
        assert candidate.severity == "MEDIUM"
        assert candidate.descriptive_first_add_at == WHEN

    def test_the_origin_id_is_what_the_sealer_accepts(self):
        """It must hand straight to `seal_identity`, or ingest and seal disagree about
        what names a bug."""
        from cathedral_distill.cybergym_sealed import sealed_task_id
        from cathedral_distill.corpus_admission import public_catalog_task_id

        candidate = _parse().candidate
        # It IS a catalog id — which is exactly why it must be sealed before it is a task.
        assert public_catalog_task_id(candidate.origin_id) == "oss-fuzz:546426939"
        sealed = sealed_task_id(candidate.origin_id, seal_key=b"k")
        assert public_catalog_task_id(sealed) is None

    def test_the_project_comes_from_the_entry_the_commits_came_from(self):
        """A record with several affected entries must not label a candidate with entry
        0's project while rebuilding entry 1's commits."""
        record = _record()
        decoy = {
            "package": {"name": "WRONG-PROJECT"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "repo": "https://example/decoy",
                    "events": [{"introduced": "1.0"}, {"fixed": "2.0"}],
                }
            ],
            "ecosystem_specific": {"severity": "LOW"},
        }
        record["affected"] = [decoy, record["affected"][0]]
        candidate = _parse(record).candidate
        assert candidate.project == "zxc"
        assert candidate.severity == "MEDIUM"
        assert candidate.repo == "https://github.com/hellobertrand/zxc.git"

    def test_the_report_id_can_come_from_the_details_prose(self):
        candidate = _parse(_record(references=[])).candidate
        assert candidate.origin_id == "oss-fuzz:546426939"

    def test_the_candidate_carries_reproducible_feed_provenance(self):
        candidate = _parse().candidate
        assert candidate.record_path == RECORD_PATH
        assert candidate.disclosure == _evidence()
        assert candidate.disclosure.descriptive_first_add.add_commit == FIRST_ADD
        assert candidate.disclosure.committed_feed_head == COMMITTED_HEAD
        assert candidate.disclosure.feed_head == FEED_HEAD
        assert candidate.disclosure.feed_root == CANONICAL_FEED_ROOT
        expected_bytes = _record_bytes(_record())
        assert candidate.disclosure.blob_for(RECORD_PATH) == _git_blob(expected_bytes)
        assert (
            candidate.record_sha256
            == "sha256:" + hashlib.sha256(expected_bytes).hexdigest()
        )

    def test_matching_id_and_path_cannot_substitute_different_record_bytes(self):
        evidence = _evidence()
        substituted = _record()
        substituted["affected"][0]["ranges"][0]["repo"] = "https://attacker.invalid"
        with pytest.raises(SupplyError, match="do not match pinned blob"):
            _parse(substituted, evidence=evidence)

    def test_a_record_cannot_borrow_another_identitys_provenance(self):
        with pytest.raises(SupplyError, match="does not match disclosure identity"):
            _parse(_record(id="OSV-2026-9999"))

    def test_a_record_path_must_be_covered_by_its_evidence(self):
        with pytest.raises(SupplyError, match="not present at pinned feed head"):
            _parse(record_path="vulns/zxc/OSV-2026-1157-copy.yaml")


class TestUnusableRecordsAreReportedNotDropped:
    """~7% of the feed carries no `fixed` commit. A pipeline that silently swallowed
    those would hide a supply problem behind an empty worklist."""

    def test_a_record_without_a_fixed_commit_is_skipped_with_a_reason(self):
        record = _record()
        record["affected"][0]["ranges"][0]["events"] = [{"introduced": "abc"}]
        outcome = _parse(record)
        assert not outcome.usable
        assert (
            "introduced and fixed" in outcome.reason
            and "OSV-2026-1157" in outcome.reason
        )

    @pytest.mark.parametrize("placeholder", ["0", "unknown", ""])
    def test_a_placeholder_introduced_is_not_a_commit(self, placeholder):
        """`introduced: "0"` means "unknown", not a revision we can build."""
        record = _record()
        record["affected"][0]["ranges"][0]["events"] = [
            {"introduced": placeholder},
            {"fixed": "deadbeef"},
        ]
        assert not _parse(record).usable

    def test_a_non_git_range_is_not_usable(self):
        record = _record()
        record["affected"][0]["ranges"][0]["type"] = "SEMVER"
        assert not _parse(record).usable

    def test_a_range_without_a_repo_is_skipped(self):
        record = _record()
        record["affected"][0]["ranges"][0]["repo"] = ""
        assert "names no repo" in _parse(record).reason

    def test_a_record_with_no_report_id_is_skipped(self):
        outcome = _parse(_record(references=[], details=""))
        assert "no OSS-Fuzz report id" in outcome.reason

    def test_a_record_with_no_id_is_skipped(self):
        assert "no id" in _parse(_record(id="")).reason

    def test_a_non_mapping_fails_closed(self):
        record = ["not", "a", "record"]
        with pytest.raises(SupplyError, match="mapping"):
            parse_osv_record(
                _record_bytes(record),
                disclosure=_evidence(record=record),
                record_path=RECORD_PATH,
            )


class TestTheBoundaryIsTheGitGraphSnapshot:
    def test_identities_carry_every_add_and_post_snapshot_classification(self):
        log = _git_log(
            (
                FIRST_ADD,
                "2026-08-16T00:02:24+00:00",
                (
                    "vulns/zxc/OSV-2026-1157.yaml",
                    "vulns/zxc/OSV-2026-1158.yaml",
                ),
            )
        )
        index = parse_disclosure_index(
            log,
            record_blobs=_blobs(
                "vulns/zxc/OSV-2026-1157.yaml",
                "vulns/zxc/OSV-2026-1158.yaml",
            ),
            committed_feed_head=COMMITTED_HEAD,
            post_commit_ids=(FIRST_ADD,),
            feed_head=FEED_HEAD,
        )
        evidence = index["OSV-2026-1157"]
        assert evidence.descriptive_first_add.commit_time == datetime(
            2026, 8, 16, 0, 2, 24, tzinfo=UTC
        )
        assert evidence.descriptive_first_add.add_commit == FIRST_ADD
        assert evidence.all_adds_after_commitment
        assert len(index) == 2

    def test_a_pre_snapshot_add_survives_delete_and_readd(self):
        log = _git_log(
            ("b" * 40, "2026-08-16T00:00:00+00:00", (RECORD_PATH,)),
            (FIRST_ADD, "2025-01-05T00:00:00+00:00", (RECORD_PATH,)),
        )
        evidence = parse_disclosure_index(
            log,
            record_blobs={RECORD_PATH: _git_blob(_record_bytes(_record()))},
            committed_feed_head=COMMITTED_HEAD,
            post_commit_ids=("b" * 40,),
            feed_head=FEED_HEAD,
        )["OSV-2026-1157"]
        assert len(evidence.appearances) == 2
        assert evidence.post_commit_adds == ("b" * 40,)
        assert not evidence.all_adds_after_commitment

    def test_a_duplicate_or_moved_path_cannot_reset_identity_freshness(self):
        """The live feed contains this shape: one stable OSV id under an old project
        path and a much newer repo-derived path. It is one disclosure, not fresh supply."""
        old = "vulns/php/OSV-2023-38.yaml"
        migrated = "vulns/https:/github.com/php/php-src.git/OSV-2023-38.yaml"
        log = _git_log(
            ("b" * 40, "2025-09-24T11:24:46+00:00", (migrated,)),
            (FIRST_ADD, "2023-02-01T01:04:10+00:00", (old,)),
        )
        evidence = parse_disclosure_index(
            log,
            record_blobs=_blobs(old, migrated),
            committed_feed_head=COMMITTED_HEAD,
            post_commit_ids=("b" * 40,),
            feed_head=FEED_HEAD,
        )["OSV-2023-38"]
        assert evidence.descriptive_first_add.commit_time == datetime(
            2023, 2, 1, 1, 4, 10, tzinfo=UTC
        )
        assert evidence.paths == tuple(sorted((old, migrated)))
        assert evidence.record_blobs == tuple(
            sorted(((old, "c" * 40), (migrated, "c" * 40)))
        )
        assert not evidence.all_adds_after_commitment

    def test_a_path_move_still_carries_the_deleted_old_paths_add(self):
        old = "vulns/old-project/OSV-2023-38.yaml"
        moved = "vulns/new-project/OSV-2023-38.yaml"
        log = _git_log(
            ("b" * 40, "2025-09-24T11:24:46+00:00", (moved,)),
            (FIRST_ADD, "2023-02-01T01:04:10+00:00", (old,)),
        )
        evidence = parse_disclosure_index(
            log,
            record_blobs=_blobs(moved),
            committed_feed_head=COMMITTED_HEAD,
            post_commit_ids=("b" * 40,),
            feed_head=FEED_HEAD,
        )["OSV-2023-38"]
        assert evidence.paths == tuple(sorted((old, moved)))
        assert evidence.record_blobs == ((moved, "c" * 40),)
        assert not evidence.all_adds_after_commitment

    def test_an_old_same_identity_outside_the_current_subdir_is_not_hidden(self):
        old = "historical-archive/OSV-2023-38.yaml"
        current = "vulns/current/OSV-2023-38.yaml"
        log = _git_log(
            ("b" * 40, "2025-09-24T11:24:46+00:00", (current,)),
            (FIRST_ADD, "2023-02-01T01:04:10+00:00", (old,)),
        )
        evidence = parse_disclosure_index(
            log,
            record_blobs=_blobs(current),
            committed_feed_head=COMMITTED_HEAD,
            post_commit_ids=("b" * 40,),
            feed_head=FEED_HEAD,
        )["OSV-2023-38"]
        assert evidence.paths == tuple(sorted((old, current)))
        assert not evidence.all_adds_after_commitment

    def test_an_old_record_with_a_future_committer_time_stays_ineligible(self):
        log = _git_log((FIRST_ADD, "2099-01-05T00:00:00+00:00", (RECORD_PATH,)))
        evidence = parse_disclosure_index(
            log,
            record_blobs={RECORD_PATH: _git_blob(_record_bytes(_record()))},
            committed_feed_head=COMMITTED_HEAD,
            post_commit_ids=(),
            feed_head=FEED_HEAD,
        )["OSV-2026-1157"]
        assert evidence.descriptive_first_add.commit_time.year == 2099
        assert not evidence.all_adds_after_commitment
        candidate = _parse(evidence=evidence).candidate
        assert (
            eligible_for(
                [candidate],
                committed_feed_head=COMMITTED_HEAD,
                expected_feed_head=FEED_HEAD,
            )
            == ()
        )

    def test_a_post_snapshot_record_with_an_old_committer_time_is_eligible(self):
        log = _git_log((FIRST_ADD, "2000-01-05T00:00:00+00:00", (RECORD_PATH,)))
        evidence = parse_disclosure_index(
            log,
            record_blobs={RECORD_PATH: _git_blob(_record_bytes(_record()))},
            committed_feed_head=COMMITTED_HEAD,
            post_commit_ids=(FIRST_ADD,),
            feed_head=FEED_HEAD,
        )["OSV-2026-1157"]
        assert evidence.descriptive_first_add.commit_time.year == 2000
        assert evidence.all_adds_after_commitment
        candidate = _parse(evidence=evidence).candidate
        assert eligible_for(
            [candidate],
            committed_feed_head=COMMITTED_HEAD,
            expected_feed_head=FEED_HEAD,
        ) == (candidate,)

    def test_offsets_are_normalised_to_utc(self):
        """Descriptive audit timestamps are normalized, but never decide eligibility."""
        log = _git_log((FIRST_ADD, "2026-08-16T09:00:00+09:00", (RECORD_PATH,)))
        index = parse_disclosure_index(
            log,
            record_blobs=_blobs(RECORD_PATH),
            committed_feed_head=COMMITTED_HEAD,
            post_commit_ids=(FIRST_ADD,),
            feed_head=FEED_HEAD,
        )
        assert index["OSV-2026-1157"].descriptive_first_add.commit_time == datetime(
            2026, 8, 16, 0, 0, tzinfo=UTC
        )

    def test_a_path_before_any_commit_fails_closed(self):
        with pytest.raises(SupplyError, match="before any commit record"):
            parse_disclosure_index(
                RECORD_PATH + "\0",
                record_blobs=_blobs(RECORD_PATH),
                committed_feed_head=COMMITTED_HEAD,
                post_commit_ids=(FIRST_ADD,),
                feed_head=FEED_HEAD,
            )

    def test_an_unparseable_date_fails_closed(self):
        with pytest.raises(SupplyError, match="unparseable commit date"):
            parse_disclosure_index(
                _git_log((FIRST_ADD, "not-a-date", (RECORD_PATH,))),
                record_blobs=_blobs(RECORD_PATH),
                committed_feed_head=COMMITTED_HEAD,
                post_commit_ids=(FIRST_ADD,),
                feed_head=FEED_HEAD,
            )

    def test_a_naive_commit_timestamp_fails_closed(self):
        with pytest.raises(SupplyError, match="unparseable commit date"):
            parse_disclosure_index(
                _git_log((FIRST_ADD, "2026-08-16T09:00:00", (RECORD_PATH,))),
                record_blobs=_blobs(RECORD_PATH),
                committed_feed_head=COMMITTED_HEAD,
                post_commit_ids=(FIRST_ADD,),
                feed_head=FEED_HEAD,
            )

    def test_a_malformed_or_missing_commit_id_fails_closed(self):
        with pytest.raises(SupplyError, match="malformed commit object id"):
            parse_disclosure_index(
                _git_log(
                    (
                        "not-an-object",
                        "2026-08-16T09:00:00+00:00",
                        (RECORD_PATH,),
                    )
                ),
                record_blobs=_blobs(RECORD_PATH),
                committed_feed_head=COMMITTED_HEAD,
                post_commit_ids=(FIRST_ADD,),
                feed_head=FEED_HEAD,
            )

    def test_a_marker_looking_filename_remains_path_data(self):
        log = _git_log(
            (
                FIRST_ADD,
                "2026-08-16T00:00:00+00:00",
                ("COMMIT", "e" * 40, "2026-01-01T00:00:00+00:00", RECORD_PATH),
            )
        )
        evidence = parse_disclosure_index(
            log,
            record_blobs=_blobs(RECORD_PATH),
            committed_feed_head=COMMITTED_HEAD,
            post_commit_ids=(FIRST_ADD,),
            feed_head=FEED_HEAD,
        )["OSV-2026-1157"]
        assert evidence.appearances[0].add_commit == FIRST_ADD

    def test_line_delimited_log_output_is_refused(self):
        line_log = f"COMMIT {FIRST_ADD} 2026-08-16T00:00:00+00:00\n{RECORD_PATH}\n"
        with pytest.raises(SupplyError, match="not NUL-framed"):
            parse_disclosure_index(
                line_log,
                record_blobs=_blobs(RECORD_PATH),
                committed_feed_head=COMMITTED_HEAD,
                post_commit_ids=(FIRST_ADD,),
                feed_head=FEED_HEAD,
            )

    def test_nul_framing_preserves_newline_paths_and_their_old_add(self):
        old = "vulns/odd\nsegment/OSV-2023-38.yaml"
        moved = "vulns/new/OSV-2023-38.yaml"
        log = _git_log(
            ("b" * 40, "2025-01-01T00:00:00+00:00", (moved,)),
            (FIRST_ADD, "2023-01-01T00:00:00+00:00", (old,)),
        )
        evidence = parse_disclosure_index(
            log,
            record_blobs=_blobs(moved),
            committed_feed_head=COMMITTED_HEAD,
            post_commit_ids=("b" * 40,),
            feed_head=FEED_HEAD,
        )["OSV-2023-38"]
        assert old in evidence.paths
        assert not evidence.all_adds_after_commitment

    def test_a_depth_one_or_other_shallow_clone_is_refused_before_log_read(self):
        git, calls = _complete_git("must not be read", shallow="true")
        with pytest.raises(SupplyError, match="complete non-shallow clone"):
            disclosure_index(
                "/repo",
                git=git,
                committed_feed_head=COMMITTED_HEAD,
                expected_feed_head=FEED_HEAD,
            )
        assert len(calls) == 1
        assert "--is-shallow-repository" in calls[0]

    def test_a_shared_root_does_not_authenticate_an_unpinned_fork_head(self):
        """A fork can retain the canonical root and invent a later disclosure clock."""
        untrusted_head = "e" * 40
        git, calls = _complete_git("must not be read", head=untrusted_head)
        with pytest.raises(SupplyError, match="does not match independently approved"):
            disclosure_index(
                "/repo",
                git=git,
                committed_feed_head=COMMITTED_HEAD,
                expected_feed_head=FEED_HEAD,
            )
        assert not any("--max-parents=0" in call for call in calls)
        assert not any("log" in call for call in calls)

    def test_a_noncanonical_or_truncated_history_root_is_refused(self):
        git, calls = _complete_git("must not be read", root="e" * 40)
        with pytest.raises(SupplyError, match="incomplete, grafted, or not"):
            disclosure_index(
                "/repo",
                git=git,
                committed_feed_head=COMMITTED_HEAD,
                expected_feed_head=FEED_HEAD,
            )
        assert not any("log" in call for call in calls)

    def test_a_nonancestor_harness_snapshot_is_refused(self):
        git, calls = _complete_git("must not be read", merge_base="e" * 40)
        with pytest.raises(SupplyError, match="not an ancestor"):
            disclosure_index(
                "/repo",
                git=git,
                committed_feed_head=COMMITTED_HEAD,
                expected_feed_head=FEED_HEAD,
            )
        assert not any("--max-parents=0" in call for call in calls)
        assert not any("log" in call for call in calls)

    def test_local_replacement_refs_are_refused(self):
        git, calls = _complete_git("must not be read", replacements="e" * 40 + "\n")
        with pytest.raises(SupplyError, match="replacement refs are forbidden"):
            disclosure_index(
                "/repo",
                git=git,
                committed_feed_head=COMMITTED_HEAD,
                expected_feed_head=FEED_HEAD,
            )
        assert not any("--verify" in call for call in calls)

    def test_real_git_newline_path_is_preserved_by_the_index(
        self, tmp_path, monkeypatch
    ):
        repo, root, _, committed, head, old, moved = _moved_identity_repo(tmp_path)
        monkeypatch.setattr(supply, "CANONICAL_FEED_ROOT", root)

        evidence = disclosure_index(
            str(repo),
            git=lambda argv: (
                subprocess.run(argv, check=True, capture_output=True, text=True).stdout
            ),
            committed_feed_head=committed,
            expected_feed_head=head,
        )["OSV-2023-38"]
        assert old in evidence.paths
        assert moved in evidence.paths
        assert not evidence.all_adds_after_commitment

    def test_real_git_graft_that_preserves_head_root_and_baseline_is_refused(
        self, tmp_path
    ):
        repo, root, old_add, committed, head, _, moved = _moved_identity_repo(tmp_path)
        graft_path = repo / ".git" / "info" / "grafts"
        graft_path.write_text(f"{committed} {root}\n")

        assert _run_git(repo, "rev-parse", "HEAD").strip() == head
        assert _run_git(repo, "merge-base", committed, head).strip() == committed
        assert _run_git(repo, "rev-list", "--max-parents=0", head).strip() == root
        vulnerable_log = _run_git(
            repo,
            "log",
            "--diff-filter=A",
            "--name-only",
            "--format=%H",
            head,
            "--",
            "vulns",
        )
        assert moved in vulnerable_log
        assert old_add not in vulnerable_log

        with pytest.raises(SupplyError, match="graft file is forbidden"):
            disclosure_index(
                str(repo),
                git=lambda argv: (
                    subprocess.run(
                        argv, check=True, capture_output=True, text=True
                    ).stdout
                ),
                committed_feed_head=committed,
                expected_feed_head=head,
            )

    def test_real_git_merge_add_cannot_be_hidden_before_delete_and_readd(
        self, tmp_path, monkeypatch
    ):
        repo, root, merge_add, committed, head, old, moved = (
            _merge_introduced_identity_repo(tmp_path)
        )
        monkeypatch.setattr(supply, "CANONICAL_FEED_ROOT", root)

        evidence = disclosure_index(
            str(repo),
            git=lambda argv: (
                subprocess.run(argv, check=True, capture_output=True, text=True).stdout
            ),
            committed_feed_head=committed,
            expected_feed_head=head,
        )["OSV-2023-38"]

        # The merge is compared to two parents, but one add event remains one appearance.
        assert [appearance.add_commit for appearance in evidence.appearances].count(
            merge_add
        ) == 1
        assert {appearance.path for appearance in evidence.appearances} == {old, moved}
        assert evidence.post_commit_adds == (head,)
        assert not evidence.all_adds_after_commitment

    def test_an_empty_feed_is_refused_rather_than_reported_as_success(self):
        """Indistinguishable from a broken clone, and a silent empty feed would stall the
        pool while looking healthy."""
        git, _ = _complete_git("", tree="")
        with pytest.raises(SupplyError, match="refusing to report an empty feed"):
            disclosure_index(
                "/repo",
                git=git,
                committed_feed_head=COMMITTED_HEAD,
                expected_feed_head=FEED_HEAD,
            )

    def test_the_git_query_asks_for_commit_ids_additions_and_no_rename_guessing(self):
        log = _git_log((FIRST_ADD, "2026-08-16T00:00:00+00:00", (RECORD_PATH,)))
        git, calls = _complete_git(log)
        evidence = disclosure_index(
            "/repo",
            git=git,
            committed_feed_head=COMMITTED_HEAD,
            expected_feed_head=FEED_HEAD,
        )["OSV-2026-1157"]
        query = next(call for call in calls if "log" in call)
        assert "--full-history" in query
        assert "--diff-merges=separate" in query
        assert "--diff-filter=A" in query
        assert "--no-renames" in query
        assert "-z" in query
        assert "--format=format:COMMIT%x00%H%x00%cI%x00" in query
        assert query[-1] == FEED_HEAD
        assert "--" not in query
        tree_query = next(call for call in calls if "ls-tree" in call)
        assert "-z" in tree_query
        assert FEED_HEAD in tree_query
        assert evidence.record_blobs == ((RECORD_PATH, "c" * 40),)
        assert all("--no-replace-objects" in call for call in calls)


class TestEligibilityIsTheAntiLookupRule:
    def _candidate(self, *, post_commit_adds=(FIRST_ADD,), appearances=None):
        evidence = _evidence(
            appearances=appearances,
            post_commit_adds=post_commit_adds,
        )
        return FreshCandidate(
            osv_id=evidence.osv_id,
            origin_id="oss-fuzz:1",
            project="p",
            repo="r",
            introduced="a",
            fixed="b",
            crash_type="c",
            severity="MEDIUM",
            record_path=RECORD_PATH,
            record_sha256="sha256:" + "d" * 64,
            disclosure=evidence,
        )

    def test_only_identities_wholly_outside_the_snapshot_are_eligible(self):
        fresh = self._candidate()
        old_and_readded = self._candidate(
            post_commit_adds=("b" * 40,),
            appearances=(
                DisclosureAppearance(RECORD_PATH, FIRST_ADD, WHEN),
                DisclosureAppearance(
                    RECORD_PATH,
                    "b" * 40,
                    datetime(2026, 8, 20, tzinfo=UTC),
                ),
            ),
        )
        assert eligible_for(
            [old_and_readded, fresh],
            committed_feed_head=COMMITTED_HEAD,
            expected_feed_head=FEED_HEAD,
        ) == (fresh,)

    def test_the_pool_is_cumulative_not_consumed(self):
        candidates = [self._candidate() for _ in range(6)]
        assert (
            len(
                eligible_for(
                    candidates,
                    committed_feed_head=COMMITTED_HEAD,
                    expected_feed_head=FEED_HEAD,
                )
            )
            == 6
        )

    def test_two_harnesses_do_not_compete_for_one_slice(self):
        task = self._candidate()
        for _validator in range(2):
            assert eligible_for(
                [task],
                committed_feed_head=COMMITTED_HEAD,
                expected_feed_head=FEED_HEAD,
            ) == (task,)

    def test_candidate_bound_to_another_harness_snapshot_is_refused(self):
        task = self._candidate()
        with pytest.raises(SupplyError, match="different committed feed head"):
            eligible_for(
                [task],
                committed_feed_head="e" * 40,
                expected_feed_head=FEED_HEAD,
            )

    def test_candidate_bound_to_another_current_head_is_refused(self):
        task = self._candidate()
        with pytest.raises(SupplyError, match="different current feed head"):
            eligible_for(
                [task],
                committed_feed_head=COMMITTED_HEAD,
                expected_feed_head="e" * 40,
            )
