"""Fresh supply: ingesting newly-disclosed OSS-Fuzz findings.

ARVO's published dataset is frozen (newest bug filed 2024-05-02), so the paying pool has
to be generated in-house from the live `google/oss-fuzz-vulns` feed. These tests cover the
pure half: turning an OSV record into a sealable candidate, and deciding which candidates a
given harness may be paid on.

The eligibility rule carries the whole anti-lookup guarantee. OSS-Fuzz publishes the bug
AND its testcase, so running the pipeline ourselves buys freshness, never secrecy — the
only thing that makes a harness unable to have baked in the answer is that the bug was
disclosed after the harness was committed. So the clock has to be one we cannot forge, and
it has to move in one direction.

Hardware-free and YAML-free: the tested core takes already-parsed mappings and git output,
so neither pyyaml nor a git checkout is needed.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.oss_fuzz_supply import (  # noqa: E402
    FreshCandidate,
    SupplyError,
    disclosure_index,
    eligible_for,
    parse_disclosure_index,
    parse_osv_record,
)

WHEN = datetime(2026, 8, 16, tzinfo=UTC)


def _record(**overrides):
    """An OSV record shaped like the real feed (modelled on OSV-2026-1157)."""
    document = {
        "id": "OSV-2026-1157",
        "summary": "Memcpy-param-overlap in zxc_decompress_chunk_wrapper_default",
        "details": "OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=546426939",
        "references": [
            {"type": "REPORT",
             "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=546426939"}],
        "affected": [{
            "package": {"name": "zxc", "ecosystem": "OSS-Fuzz"},
            "ranges": [{
                "type": "GIT",
                "repo": "https://github.com/hellobertrand/zxc.git",
                "events": [
                    {"introduced": "b89b134299971f1edd2cefb9f1eaf3d93fdf1dad"},
                    {"fixed": "399de305e5ca322a0144c86ec85dd77757669c60"},
                ],
            }],
            "ecosystem_specific": {"severity": "MEDIUM"},
        }],
    }
    document.update(overrides)
    return document


class TestARecordBecomesASealableCandidate:
    def test_the_vul_fix_pair_and_origin_are_extracted(self):
        """The pair IS the rebuild input, which is why ingestion never has to scrape
        Google's issue tracker."""
        candidate = parse_osv_record(_record(), disclosed_at=WHEN).candidate
        assert candidate.origin_id == "oss-fuzz:546426939"
        assert candidate.repo == "https://github.com/hellobertrand/zxc.git"
        assert candidate.introduced == "b89b134299971f1edd2cefb9f1eaf3d93fdf1dad"
        assert candidate.fixed == "399de305e5ca322a0144c86ec85dd77757669c60"
        assert candidate.project == "zxc"
        assert candidate.severity == "MEDIUM"
        assert candidate.disclosed_at == WHEN

    def test_the_origin_id_is_what_the_sealer_accepts(self):
        """It must hand straight to `seal_identity`, or ingest and seal disagree about
        what names a bug."""
        from cathedral_distill.cybergym_sealed import sealed_task_id
        from cathedral_distill.corpus_admission import public_catalog_task_id

        candidate = parse_osv_record(_record(), disclosed_at=WHEN).candidate
        # It IS a catalog id — which is exactly why it must be sealed before it is a task.
        assert public_catalog_task_id(candidate.origin_id) == "oss-fuzz:546426939"
        sealed = sealed_task_id(candidate.origin_id, seal_key=b"k")
        assert public_catalog_task_id(sealed) is None

    def test_the_project_comes_from_the_entry_the_commits_came_from(self):
        """A record with several affected entries must not label a candidate with entry
        0's project while rebuilding entry 1's commits."""
        record = _record()
        decoy = {"package": {"name": "WRONG-PROJECT"},
                 "ranges": [{"type": "SEMVER", "repo": "https://example/decoy",
                             "events": [{"introduced": "1.0"}, {"fixed": "2.0"}]}],
                 "ecosystem_specific": {"severity": "LOW"}}
        record["affected"] = [decoy, record["affected"][0]]
        candidate = parse_osv_record(record, disclosed_at=WHEN).candidate
        assert candidate.project == "zxc"
        assert candidate.severity == "MEDIUM"
        assert candidate.repo == "https://github.com/hellobertrand/zxc.git"

    def test_the_report_id_can_come_from_the_details_prose(self):
        candidate = parse_osv_record(_record(references=[]), disclosed_at=WHEN).candidate
        assert candidate.origin_id == "oss-fuzz:546426939"


class TestUnusableRecordsAreReportedNotDropped:
    """~7% of the feed carries no `fixed` commit. A pipeline that silently swallowed
    those would hide a supply problem behind an empty worklist."""

    def test_a_record_without_a_fixed_commit_is_skipped_with_a_reason(self):
        record = _record()
        record["affected"][0]["ranges"][0]["events"] = [{"introduced": "abc"}]
        outcome = parse_osv_record(record, disclosed_at=WHEN)
        assert not outcome.usable
        assert "introduced and fixed" in outcome.reason and "OSV-2026-1157" in outcome.reason

    @pytest.mark.parametrize("placeholder", ["0", "unknown", ""])
    def test_a_placeholder_introduced_is_not_a_commit(self, placeholder):
        """`introduced: "0"` means "unknown", not a revision we can build."""
        record = _record()
        record["affected"][0]["ranges"][0]["events"] = [
            {"introduced": placeholder}, {"fixed": "deadbeef"}]
        assert not parse_osv_record(record, disclosed_at=WHEN).usable

    def test_a_non_git_range_is_not_usable(self):
        record = _record()
        record["affected"][0]["ranges"][0]["type"] = "SEMVER"
        assert not parse_osv_record(record, disclosed_at=WHEN).usable

    def test_a_range_without_a_repo_is_skipped(self):
        record = _record()
        record["affected"][0]["ranges"][0]["repo"] = ""
        assert "names no repo" in parse_osv_record(record, disclosed_at=WHEN).reason

    def test_a_record_with_no_report_id_is_skipped(self):
        outcome = parse_osv_record(_record(references=[], details=""), disclosed_at=WHEN)
        assert "no OSS-Fuzz report id" in outcome.reason

    def test_a_record_with_no_id_is_skipped(self):
        assert "no id" in parse_osv_record(_record(id=""), disclosed_at=WHEN).reason

    def test_a_non_mapping_fails_closed(self):
        with pytest.raises(SupplyError, match="mapping"):
            parse_osv_record(["not", "a", "record"], disclosed_at=WHEN)


class TestTheClockIsTheGitAddNotThePublishedField:
    def test_paths_are_dated_from_their_commit(self):
        log = ("COMMIT 2026-08-16T00:02:24+00:00\n"
               "vulns/zxc/OSV-2026-1157.yaml\n"
               "vulns/zxc/OSV-2026-1158.yaml\n")
        index = parse_disclosure_index(log)
        assert index["vulns/zxc/OSV-2026-1157.yaml"] == datetime(2026, 8, 16, 0, 2, 24, tzinfo=UTC)
        assert len(index) == 2

    def test_the_earliest_add_wins_when_a_record_is_re_added(self):
        """THE security-critical case. git lists newest-first, so the later sighting is
        the earlier commit. Taking the most recent add would let a delete/re-add reset the
        clock and present a long-public bug as fresh."""
        log = ("COMMIT 2026-08-16T00:00:00+00:00\n"
               "vulns/zxc/OSV-2026-1157.yaml\n"
               "COMMIT 2025-01-05T00:00:00+00:00\n"
               "vulns/zxc/OSV-2026-1157.yaml\n")
        index = parse_disclosure_index(log)
        assert index["vulns/zxc/OSV-2026-1157.yaml"].year == 2025

    def test_the_earliest_add_wins_regardless_of_log_order(self):
        """The minimum is taken explicitly rather than trusting git to emit newest-first:
        the ordering assumption fails in the dangerous direction."""
        log = ("COMMIT 2025-01-05T00:00:00+00:00\n"
               "vulns/zxc/OSV-2026-1157.yaml\n"
               "COMMIT 2026-08-16T00:00:00+00:00\n"
               "vulns/zxc/OSV-2026-1157.yaml\n")
        assert parse_disclosure_index(log)["vulns/zxc/OSV-2026-1157.yaml"].year == 2025

    def test_offsets_are_normalised_to_utc(self):
        """Comparisons against a commitment time must not depend on the committer's zone."""
        index = parse_disclosure_index("COMMIT 2026-08-16T09:00:00+09:00\nvulns/a.yaml\n")
        assert index["vulns/a.yaml"] == datetime(2026, 8, 16, 0, 0, tzinfo=UTC)

    def test_a_path_before_any_commit_fails_closed(self):
        with pytest.raises(SupplyError, match="before any commit date"):
            parse_disclosure_index("vulns/orphan.yaml\n")

    def test_an_unparseable_date_fails_closed(self):
        with pytest.raises(SupplyError, match="unparseable commit date"):
            parse_disclosure_index("COMMIT not-a-date\nvulns/a.yaml\n")

    def test_an_empty_feed_is_refused_rather_than_reported_as_success(self):
        """Indistinguishable from a broken clone, and a silent empty feed would stall the
        pool while looking healthy."""
        with pytest.raises(SupplyError, match="refusing to report an empty feed"):
            disclosure_index("/repo", git=lambda argv: "")

    def test_the_git_query_asks_only_for_additions(self):
        seen = {}

        def git(argv):
            seen["argv"] = argv
            return "COMMIT 2026-08-16T00:00:00+00:00\nvulns/a.yaml\n"

        disclosure_index("/repo", git=git)
        assert "--diff-filter=A" in seen["argv"]
        assert "vulns" in seen["argv"]


class TestEligibilityIsTheAntiLookupRule:
    def _candidate(self, when):
        return FreshCandidate(
            osv_id="OSV-1", origin_id="oss-fuzz:1", project="p", repo="r",
            introduced="a", fixed="b", crash_type="c", severity="MEDIUM",
            disclosed_at=when)

    def test_only_bugs_disclosed_after_the_commitment_are_eligible(self):
        commitment = datetime(2026, 8, 1, tzinfo=UTC)
        before = self._candidate(datetime(2026, 7, 31, tzinfo=UTC))
        after = self._candidate(datetime(2026, 8, 2, tzinfo=UTC))
        assert eligible_for([before, after], committed_at=commitment) == (after,)

    def test_the_boundary_is_strict(self):
        """A bug disclosed in the same instant as the commitment is not provably outside
        it, and the rule is worth nothing if its boundary is loose."""
        moment = datetime(2026, 8, 1, tzinfo=UTC)
        assert eligible_for([self._candidate(moment)], committed_at=moment) == ()

    def test_zones_are_compared_in_utc(self):
        commitment = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
        # 2026-08-01T22:00+09:00 is 13:00 UTC — after the commitment.
        later = self._candidate(datetime(2026, 8, 1, 22, 0, tzinfo=timezone(timedelta(hours=9))))
        assert eligible_for([later], committed_at=commitment) == (later,)

    def test_the_pool_is_cumulative_not_consumed(self):
        """Round size comes from commitment AGE, not from monthly supply — which is what
        makes a ~30-task round reachable at ~20 admitted pairs a month."""
        start = datetime(2026, 1, 1, tzinfo=UTC)
        monthly = [self._candidate(start + timedelta(days=30 * n)) for n in range(1, 7)]
        assert len(eligible_for(monthly, committed_at=start)) == 6
        # A harness committed later sees only what was disclosed after IT committed.
        assert len(eligible_for(monthly, committed_at=start + timedelta(days=100))) == 3

    def test_two_harnesses_do_not_compete_for_one_slice(self):
        """The same task is eligible for every harness committed before it — nothing is
        drawn down."""
        task = self._candidate(datetime(2026, 8, 10, tzinfo=UTC))
        for commitment in (datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 8, 9, tzinfo=UTC)):
            assert eligible_for([task], committed_at=commitment) == (task,)

    def test_a_naive_commitment_time_is_refused(self):
        with pytest.raises(SupplyError, match="timezone-aware"):
            eligible_for([], committed_at=datetime(2026, 8, 1))

    def test_a_naive_disclosure_time_is_refused(self):
        """An ambiguous timestamp on either side would make the boundary meaningless."""
        with pytest.raises(SupplyError, match="timezone-aware"):
            self._candidate(datetime(2026, 8, 1))
