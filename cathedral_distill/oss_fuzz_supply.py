"""Fresh supply: turn newly-disclosed OSS-Fuzz findings into sealable candidates.

The corpus this lane pays on has to be FRESH, and the obvious source is not. ARVO's
published dataset is a frozen snapshot -- its newest bug was filed 2024-05-02, and its
monthly counts taper to nothing across early 2024 (60, 30, 21, 17, 2), which is an
ingestion that stopped rather than a discovery rate that fell. So the ingest is ours.

The feed is ``google/oss-fuzz-vulns``: a public git repository of OSV records, still
committing daily, where 93% of records carry BOTH an ``introduced`` and a ``fixed``
commit. That pair, with the repo, IS the vul/fix input a re-seal needs, so ingestion
never has to scrape Google's issue tracker.

**The clock is the git-add commit, not the ``published`` field.** This is the whole
integrity argument and it is worth being precise about. A task is eligible for a harness
only if it was disclosed AFTER that harness was committed -- that is what makes it
impossible for the harness to have baked the answer in, and it is the ONLY guarantee
available here, because OSS-Fuzz publishes the bug and its testcase publicly. Running the
pipeline ourselves buys freshness, never secrecy. A ``published:`` value is a field inside
a file we could edit; the commit that first added that file is a third-party, append-only
timestamp we cannot forge. Keying eligibility to it means a miner can verify for
themselves that we neither backdated a task nor sat on one we had privately held --
turning the anti-lookup rule from "trust the screener" into something auditable.

**EARLIEST add, never the latest.** A record that was added, removed and re-added must
date from its FIRST appearance. Taking the most recent add would let a delete/re-add
reset the clock and present a long-public bug as fresh, which is exactly the direction an
attacker (or a careless operator) would want.

Layering follows the rest of this package: the parsing and eligibility logic here is pure
and fully tested, while the two impure seams -- reading YAML off disk and shelling out to
git -- are injected. That also keeps ``pyyaml`` out of the package's dependencies; the
loader imports it lazily and says so if it is missing.

What this module does NOT do: reproduce anything. Turning a candidate into an admitted
task means rebuilding both sides and checking the reference PoC crashes vul and spares
fix (ARVO's own tooling, ~81% success), then running ``corpus_admission`` and sealing the
id with ``cybergym_sealed``. That needs Docker, gcloud credentials and real build compute.
This module produces the worklist that stage consumes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Iterable, Mapping, Sequence

#: The upstream catalog a candidate is named for. OSV records reference the OSS-Fuzz
#: issue, so candidates are ``oss-fuzz:<n>`` — the form ``cybergym_sealed.parse_origin``
#: accepts and ``corpus_admission`` refuses if it ever reached a task id unsealed.
CATALOG = "oss-fuzz"

#: The OSS-Fuzz issue id inside a report URL. Both tracker generations appear in the feed
#: (3-5 digit ids from the old tracker, 8-9 digit from the new one); both are "the
#: OSS-Fuzz issue id" and both are what ARVO keys a rebuild on.
_REPORT_ID_RE = re.compile(r"detail\?id=(\d+)")

#: One line of ``git log --diff-filter=A --name-only``: the marker we ask for, then paths.
_COMMIT_MARKER = "COMMIT "


class SupplyError(ValueError):
    """The feed could not be read or parsed. Fails closed — never a silent empty batch."""


@dataclass(frozen=True)
class FreshCandidate:
    """One newly-disclosed upstream bug, with everything a re-seal needs to rebuild it.

    ``disclosed_at`` is the git-add timestamp (UTC), NOT the record's ``published`` field —
    see the module docstring on why the distinction is the integrity argument.

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
    origin_id: str          # oss-fuzz:<n>. A stable NAME for the bug — not a claim that
                            # ARVO has an entry for it (ARVO's dataset is frozen at 2024-05).
    project: str
    repo: str
    introduced: str         # commit the bug entered at
    fixed: str              # commit that patched it — the other half of the pair
    crash_type: str         # OSV's summary; CARRIES THE CRASHING SYMBOL, never disclose raw
    severity: str
    disclosed_at: datetime

    def __post_init__(self) -> None:
        if self.disclosed_at.tzinfo is None:
            raise SupplyError("disclosed_at must be timezone-aware (UTC)")


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


def parse_osv_record(document: Mapping[str, Any], *, disclosed_at: datetime) -> IngestOutcome:
    """One OSV document plus its git-add timestamp -> a candidate, or why not.

    ``disclosed_at`` is supplied by the caller rather than read from the document, because
    the document's own ``published`` field is not the clock this pipeline trusts.
    """
    if not isinstance(document, Mapping):
        raise SupplyError("an OSV record must be a mapping")
    osv_id = str(document.get("id", "") or "")
    if not osv_id:
        return IngestOutcome(None, "record has no id")

    report_id = _report_id(document)
    if not report_id:
        return IngestOutcome(None, f"{osv_id}: no OSS-Fuzz report id, cannot name the origin")

    git = _git_range(document)
    if git is None:
        # ~7% of the feed. Without both ends there is no vul/fix pair to rebuild.
        return IngestOutcome(None, f"{osv_id}: no GIT range with both introduced and fixed")
    affected, repo, introduced, fixed = git
    if not repo:
        return IngestOutcome(None, f"{osv_id}: GIT range names no repo")

    package = affected.get("package") or {}
    ecosystem_specific = affected.get("ecosystem_specific") or {}

    return IngestOutcome(FreshCandidate(
        osv_id=osv_id,
        origin_id=f"{CATALOG}:{report_id}",
        project=str((package or {}).get("name", "") or ""),
        repo=repo,
        introduced=introduced,
        fixed=fixed,
        crash_type=str(document.get("summary", "") or ""),
        severity=str(ecosystem_specific.get("severity", "") or ""),
        disclosed_at=disclosed_at,
    ))


# (argv) -> the command's stdout as text. Injected so the git seam is testable.
GitRunner = Callable[[Sequence[str]], str]


def parse_disclosure_index(log_text: str) -> dict[str, datetime]:
    """Map record path -> EARLIEST add time, from ``git log --diff-filter=A --name-only``.

    Expects the log formatted with ``--format=COMMIT %cI`` so each commit announces its
    own ISO-8601 date before the paths it added.

    Takes the MINIMUM date per path explicitly, rather than relying on git emitting
    commits newest-first. The ordering assumption would usually hold and is exactly the
    kind of thing that stops holding quietly — a merge, a graft, a ``--date-order`` change
    — and it fails in the dangerous direction: keeping a later add would let a
    delete/re-add reset the clock and present a long-public bug as fresh. Comparing dates
    costs nothing and cannot be surprised.
    """
    index: dict[str, datetime] = {}
    when: datetime | None = None
    for line in log_text.splitlines():
        line = line.rstrip("\n")
        if line.startswith(_COMMIT_MARKER):
            stamp = line[len(_COMMIT_MARKER):].strip()
            try:
                when = datetime.fromisoformat(stamp).astimezone(UTC)
            except ValueError as exc:
                raise SupplyError(f"unparseable commit date {stamp!r}") from exc
        elif line.strip():
            if when is None:
                raise SupplyError("git log emitted a path before any commit date")
            path = line.strip()
            seen = index.get(path)
            if seen is None or when < seen:
                index[path] = when
    return index


def disclosure_index(repo_path: str, *, git: GitRunner, subdir: str = "vulns") -> dict[str, datetime]:
    """Read the feed's add-history. The impure half of :func:`parse_disclosure_index`."""
    out = git([
        "git", "-C", repo_path, "log", "--diff-filter=A", "--name-only",
        "--format=" + _COMMIT_MARKER + "%cI", "--", subdir,
    ])
    index = parse_disclosure_index(out)
    if not index:
        raise SupplyError(
            f"no added records found under {subdir!r}: refusing to report an empty feed as "
            "success, since that is indistinguishable from a broken clone"
        )
    return index


def eligible_for(
    candidates: Iterable[FreshCandidate], *, committed_at: datetime,
) -> tuple[FreshCandidate, ...]:
    """The candidates a harness committed at ``committed_at`` may be PAID on.

    Strictly after, never equal: a bug disclosed in the same instant as the commitment is
    not provably outside it, and the whole rule is worth nothing if its boundary is loose.

    The pool is CUMULATIVE and is never consumed — eligibility is a property of one
    harness's commitment time, not a queue drawn down by rounds. That is what makes a
    round size of ~30 reachable at a measured supply near 20 admitted pairs a month: a
    harness accrues eligible tasks for as long as it stands committed (about 20 after a
    month, 30 after six weeks), rather than competing with other harnesses for a slice of
    the same monthly arrivals.
    """
    if committed_at.tzinfo is None:
        raise SupplyError("committed_at must be timezone-aware (UTC)")
    return tuple(
        c for c in candidates
        if c.disclosed_at.astimezone(UTC) > committed_at.astimezone(UTC)
    )


def load_osv_document(text: str) -> Mapping[str, Any]:
    """Parse one OSV record. The YAML seam, kept out of the tested core.

    ``pyyaml`` is imported lazily and is deliberately NOT a package dependency: nothing on
    the reward path parses YAML, and the ingest is operator tooling. Install it with the
    ``ingest`` extra.
    """
    try:  # pragma: no cover - the production seam; the tested core takes mappings
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise SupplyError(
            "reading the OSS-Fuzz feed needs pyyaml (pip install 'cathedral-cybergym[ingest]')"
        ) from exc
    document = yaml.safe_load(text)  # pragma: no cover
    if not isinstance(document, Mapping):  # pragma: no cover
        raise SupplyError("OSV record did not parse to a mapping")
    return document  # pragma: no cover
