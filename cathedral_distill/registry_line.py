"""The registry line — what a training miner actually submits.

A pull request must never carry the recipe. Publishing it would destroy the one
thing that makes confidential compute worth paying for, and a PR is not bound to
the attested run anyway. So the PR carries a **registry line**: identities,
digests, and a URI. The proof is the attested receipt at that URI, verified
automatically. The PR is the leaderboard, not the evidence.

This mirrors SparkDistill's shape — *"Hugging Face `proof/` + registry line"*,
where the validator re-checks the proof bundle rather than the prose.

Six fields, exactly as specified:

    miner_hotkey · track · checkpoint_digest · recipe_digest · receipt_uri · version

The strict key set is the actual leak protection. A miner cannot smuggle prompts,
dataset rows, or teacher configuration into an unexpected field, because any
unexpected field is a parse error rather than ignored data.

Note what `recipe_digest` does and does not do. It commits the miner to one exact
recipe, so a later claim of "that isn't what I ran" is refutable. It reveals
nothing about the recipe's contents. That asymmetry — binding without disclosure —
is the whole point.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Mapping

LINE_SCHEMA = "cathedral_registry_line_v1"

MAX_LINE_BYTES = 2048
MAX_URI_CHARS = 512

_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_TRACK_RE = re.compile(r"\A[a-z][a-z0-9_-]{0,63}\Z")
_VERSION_RE = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+\Z")
_HOTKEY_RE = re.compile(r"\A[1-9A-HJ-NP-Za-km-z]{47,48}\Z")  # base58, no 0OIl

_KEYS = frozenset(
    {
        "schema",
        "miner_hotkey",
        "track",
        "checkpoint_digest",
        "recipe_digest",
        "receipt_uri",
        "version",
        "signature",
    }
)


class RegistryLineError(ValueError):
    """Raised when a registry line is malformed or unacceptable."""


@dataclass(frozen=True)
class RegistryLine:
    """One submission record. Digests and identities only."""

    miner_hotkey: str
    track: str
    checkpoint_digest: str
    recipe_digest: str
    receipt_uri: str
    version: str
    signature: str = ""

    def __post_init__(self) -> None:
        if not _HOTKEY_RE.match(self.miner_hotkey):
            raise RegistryLineError("miner_hotkey must be a base58 ss58 address")
        if not _TRACK_RE.match(self.track):
            raise RegistryLineError("track must be lowercase kebab/snake, 1..64 chars")
        for name, value in (
            ("checkpoint_digest", self.checkpoint_digest),
            ("recipe_digest", self.recipe_digest),
        ):
            if not _DIGEST_RE.match(value):
                raise RegistryLineError(f"{name} must be sha256:<64 lowercase hex>")
        if self.checkpoint_digest == self.recipe_digest:
            # Almost certainly a copy-paste error, and it would make the two
            # commitments indistinguishable in later disputes.
            raise RegistryLineError("checkpoint_digest and recipe_digest must differ")
        if not _VERSION_RE.match(self.version):
            raise RegistryLineError("version must be semver major.minor.patch")
        self._check_uri(self.receipt_uri)

    @staticmethod
    def _check_uri(uri: str) -> None:
        if not uri or len(uri) > MAX_URI_CHARS:
            raise RegistryLineError(f"receipt_uri must be 1..{MAX_URI_CHARS} chars")
        if not uri.startswith(("https://", "ipfs://")):
            # Plain http would let anyone on the path swap the receipt a verifier
            # fetches. Content-addressed ipfs is safe because the CID pins bytes.
            raise RegistryLineError("receipt_uri must be https:// or ipfs://")
        if any(char.isspace() for char in uri):
            raise RegistryLineError("receipt_uri must not contain whitespace")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": LINE_SCHEMA,
            "miner_hotkey": self.miner_hotkey,
            "track": self.track,
            "checkpoint_digest": self.checkpoint_digest,
            "recipe_digest": self.recipe_digest,
            "receipt_uri": self.receipt_uri,
            "version": self.version,
            "signature": self.signature,
        }

    def signing_payload(self) -> bytes:
        """Bytes the miner signs — everything except the signature itself."""
        body = {k: v for k, v in self.as_dict().items() if k != "signature"}
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_line(self) -> str:
        """One canonical JSONL line. Diffs cleanly in a pull request."""
        encoded = json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":")
        )
        if len(encoded.encode("utf-8")) > MAX_LINE_BYTES:
            raise RegistryLineError("registry line exceeds maximum size")
        return encoded


def parse_line(text: str) -> RegistryLine:
    """Parse one registry line. Unknown fields are an error, not ignored data."""
    raw = text.strip()
    if not raw:
        raise RegistryLineError("empty registry line")
    if len(raw.encode("utf-8")) > MAX_LINE_BYTES:
        raise RegistryLineError("registry line exceeds maximum size")
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise RegistryLineError("registry line is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise RegistryLineError("registry line must be a JSON object")

    present = set(parsed)
    unknown = sorted(present - _KEYS)
    if unknown:
        # The strict key set is the leak protection: no smuggling recipe content
        # into a field nobody validates.
        raise RegistryLineError(f"unknown fields: {', '.join(unknown)}")
    missing = sorted(_KEYS - present - {"signature"})
    if missing:
        raise RegistryLineError(f"missing fields: {', '.join(missing)}")
    if parsed["schema"] != LINE_SCHEMA:
        raise RegistryLineError("unsupported registry line schema")

    return RegistryLine(
        miner_hotkey=str(parsed["miner_hotkey"]),
        track=str(parsed["track"]),
        checkpoint_digest=str(parsed["checkpoint_digest"]),
        recipe_digest=str(parsed["recipe_digest"]),
        receipt_uri=str(parsed["receipt_uri"]),
        version=str(parsed["version"]),
        signature=str(parsed.get("signature") or ""),
    )


class SubmissionRegistry:
    """Append-only registry of submissions, one line per entry."""

    def __init__(self) -> None:
        self._lines: list[RegistryLine] = []
        self._checkpoints: dict[str, RegistryLine] = {}

    def append(self, line: RegistryLine, *, require_signature: bool = True) -> RegistryLine:
        if require_signature and not line.signature:
            raise RegistryLineError("registry line must be signed")

        prior = self._checkpoints.get(line.checkpoint_digest)
        if prior is not None:
            if prior.miner_hotkey == line.miner_hotkey:
                raise RegistryLineError("checkpoint already submitted by this miner")
            # Resubmitting someone else's checkpoint is the plagiarism path. The
            # frontier's tie-keeps-incumbent rule would already deny the crown;
            # rejecting here means it never reaches scoring at all.
            raise RegistryLineError(
                "checkpoint_digest already submitted by another miner"
            )

        self._lines.append(line)
        self._checkpoints[line.checkpoint_digest] = line
        return line

    def submitter_of(self, checkpoint_digest: str) -> str | None:
        line = self._checkpoints.get(checkpoint_digest)
        return line.miner_hotkey if line else None

    def for_track(self, track: str) -> list[RegistryLine]:
        return [line for line in self._lines if line.track == track]

    def to_jsonl(self) -> str:
        return "\n".join(line.to_line() for line in self._lines)

    def __len__(self) -> int:
        return len(self._lines)


def parse_jsonl(text: str) -> Iterator[RegistryLine]:
    """Parse a registry file, skipping blank lines and `#` comments."""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        yield parse_line(stripped)


def load_registry(
    lines: Iterable[Mapping[str, Any]] | str,
    *,
    require_signature: bool = True,
) -> SubmissionRegistry:
    """Rebuild a registry from a JSONL file or an iterable of rows.

    A row that violates a rule is skipped rather than accepted, so a corrupted or
    hostile feed cannot rewrite who submitted what first.
    """
    registry = SubmissionRegistry()
    candidates = parse_jsonl(lines) if isinstance(lines, str) else (
        parse_line(json.dumps(dict(row))) for row in lines
    )
    for candidate in candidates:
        try:
            registry.append(candidate, require_signature=require_signature)
        except RegistryLineError:
            continue
    return registry
