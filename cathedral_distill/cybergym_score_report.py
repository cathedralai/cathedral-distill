"""Freeze and publish one complete CyberGym epoch to Cathedral's thin seam.

The CyberGym service already persists verified per-miner scores and a durable
``closed`` marker. Cathedral already has an authenticated intake and independently
verifies the same document before composition. What was missing was the producer:
nothing in this repository built the document that the intake accepts.

This module deliberately does only that boundary work:

* read one durably closed epoch from :class:`CyberGymScoreStore`;
* derive the evidence digest from the exact positive receipt set;
* emit the canonical complete score document;
* HMAC the exact bytes and POST them to the existing intake.

It does not compose a subnet vector, choose an allocation, hold a validator wallet,
or call Bittensor. The canonical validator remains the only weight writer.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping

from cathedral_distill.cybergym_evidence_manifest import manifest_digest
from cathedral_distill.cybergym_scores import CyberGymScoreError, CyberGymScoreStore

SEMANTIC_KEYS = (
    "producer_hotkey",
    "network",
    "netuid",
    "source_epoch",
    "generated_at",
    "complete",
    "score_units",
    "scores",
    "evidence_sha256",
)

SCORE_UNITS = "level_weighted_verified_solves"
MAX_BODY_BYTES = 65_536
MAX_SCORES = 8_192
MAX_HOTKEY_CHARS = 128
MAX_NETUID = 2**16 - 1
MAX_SOURCE_EPOCH = 2**31 - 1
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CyberGymScoreReportError(RuntimeError):
    """A complete epoch could not be represented or published safely."""


def _canonical_time(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CyberGymScoreReportError("generated_at must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise CyberGymScoreReportError("generated_at is not ISO-8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    parsed = parsed.astimezone(UTC)
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.") + (
        f"{parsed.microsecond // 1000:03d}Z"
    )


def _bounded_identity(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_HOTKEY_CHARS:
        raise CyberGymScoreReportError(
            f"{field} must be a non-empty string of at most {MAX_HOTKEY_CHARS} characters"
        )
    return value.strip()


def _score(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise CyberGymScoreReportError(f"score {value!r} is not numeric")
    out = float(value)
    if not math.isfinite(out) or out < 0.0:
        raise CyberGymScoreReportError(
            f"score {value!r} is not finite and non-negative"
        )
    return out


def normalize_report(document: Any) -> dict[str, Any]:
    """Return the exact semantic form accepted by Cathedral's intake.

    Keeping this validation on the producer side turns contract drift into a local
    refusal rather than a burned live lane. The constants are pinned by cross-repo
    tests in ``cathedral-validator``.
    """
    if not isinstance(document, Mapping):
        raise CyberGymScoreReportError("score report must be an object")
    if set(document) != set(SEMANTIC_KEYS):
        missing = sorted(set(SEMANTIC_KEYS) - set(document))
        extra = sorted(set(document) - set(SEMANTIC_KEYS))
        detail = []
        if missing:
            detail.append("missing " + ",".join(missing))
        if extra:
            detail.append("unexpected " + ",".join(extra))
        raise CyberGymScoreReportError(
            "invalid score report fields: " + "; ".join(detail)
        )

    producer = _bounded_identity(document["producer_hotkey"], field="producer_hotkey")
    network = _bounded_identity(document["network"], field="network")
    netuid = document["netuid"]
    source_epoch = document["source_epoch"]
    if (
        isinstance(netuid, bool)
        or not isinstance(netuid, int)
        or not 0 <= netuid <= MAX_NETUID
    ):
        raise CyberGymScoreReportError("netuid is out of range")
    if (
        isinstance(source_epoch, bool)
        or not isinstance(source_epoch, int)
        or not 0 <= source_epoch <= MAX_SOURCE_EPOCH
    ):
        raise CyberGymScoreReportError("source_epoch is out of range")
    if document["complete"] is not True:
        raise CyberGymScoreReportError("only a complete epoch may be exported")
    if document["score_units"] != SCORE_UNITS:
        raise CyberGymScoreReportError(f"score_units must be {SCORE_UNITS!r}")
    evidence = document["evidence_sha256"]
    if not isinstance(evidence, str) or _SHA256_RE.fullmatch(evidence) is None:
        raise CyberGymScoreReportError(
            "evidence_sha256 must be 64 lowercase hex characters"
        )
    raw_scores = document["scores"]
    if not isinstance(raw_scores, Mapping) or len(raw_scores) > MAX_SCORES:
        raise CyberGymScoreReportError(
            f"scores must contain at most {MAX_SCORES} entries"
        )
    scores: dict[str, float] = {}
    for raw_hotkey, raw_score in raw_scores.items():
        hotkey = _bounded_identity(raw_hotkey, field="miner_hotkey")
        if hotkey in scores:
            raise CyberGymScoreReportError(f"duplicate miner_hotkey {hotkey!r}")
        scores[hotkey] = _score(raw_score)

    return {
        "producer_hotkey": producer,
        "network": network,
        "netuid": netuid,
        "source_epoch": source_epoch,
        "generated_at": _canonical_time(document["generated_at"]),
        "complete": True,
        "score_units": SCORE_UNITS,
        "scores": scores,
        "evidence_sha256": evidence,
    }


def canonical_report_bytes(document: Mapping[str, Any]) -> bytes:
    normalized = normalize_report(document)
    body = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    if len(body) > MAX_BODY_BYTES:
        raise CyberGymScoreReportError(
            f"score report is {len(body)} bytes; intake limit is {MAX_BODY_BYTES}"
        )
    return body


def report_digest(document: Mapping[str, Any]) -> str:
    """The semantic digest Cathedral returns after accepting the document."""
    return hashlib.sha256(canonical_report_bytes(document)).hexdigest()


def build_score_report(
    score_store: CyberGymScoreStore,
    *,
    network: str,
    netuid: int,
    source_epoch: int,
    producer_hotkey: str,
) -> dict[str, Any]:
    """Build one report from the immutable durable close record.

    ``generated_at`` is the first persisted close time, not the current clock. A
    delayed retry therefore cannot make an old epoch look fresh, and a repeated
    export produces byte-identical output.
    """
    try:
        score_store.require_closed_epoch(source_epoch)
    except CyberGymScoreError as exc:
        raise CyberGymScoreReportError(str(exc)) from exc
    status = score_store.epoch_status(source_epoch)
    marked_at = status.get("marked_at")
    if not isinstance(marked_at, str) or not marked_at:
        raise CyberGymScoreReportError(
            f"closed epoch {int(source_epoch)} has no durable close timestamp"
        )

    normalized_network = _bounded_identity(network, field="network")
    normalized_producer = _bounded_identity(producer_hotkey, field="producer_hotkey")
    raw_scores: dict[str, Decimal] = {}
    for hotkey, value in score_store.epoch_scores(source_epoch).items():
        normalized_hotkey = _bounded_identity(str(hotkey), field="miner_hotkey")
        if normalized_hotkey in raw_scores:
            raise CyberGymScoreReportError(
                f"duplicate normalized miner_hotkey {normalized_hotkey!r}"
            )
        raw_scores[normalized_hotkey] = Decimal(value)
    scores = {hotkey: _score(value) for hotkey, value in raw_scores.items()}
    contributions = score_store.contributions(source_epoch)
    positive_entries = []
    for row in contributions:
        try:
            units = Decimal(str(row["earned_units"]))
        except (InvalidOperation, ValueError, TypeError) as exc:
            raise CyberGymScoreReportError(
                "stored earned_units is not a decimal"
            ) from exc
        if not units.is_finite() or units < 0:
            raise CyberGymScoreReportError(
                "stored earned_units is not finite and non-negative"
            )
        hotkey = _bounded_identity(str(row["miner_hotkey"]), field="miner_hotkey")
        receipt_id = str(row["receipt_id"])
        if not receipt_id:
            raise CyberGymScoreReportError("stored receipt_id is empty")
        if hotkey not in raw_scores or raw_scores[hotkey] != units:
            raise CyberGymScoreReportError(
                f"score and receipt provenance disagree for miner {hotkey!r}"
            )
        if units > 0:
            positive_entries.append(
                {
                    "miner_hotkey": hotkey,
                    "receipt_id": receipt_id,
                    "work_units": str(row["earned_units"]),
                }
            )

    document = {
        "producer_hotkey": normalized_producer,
        "network": normalized_network,
        "netuid": netuid,
        "source_epoch": source_epoch,
        "generated_at": marked_at,
        "complete": True,
        "score_units": SCORE_UNITS,
        "scores": scores,
        "evidence_sha256": manifest_digest(
            network=normalized_network,
            netuid=netuid,
            source_epoch=source_epoch,
            entries=positive_entries,
        ),
    }
    return normalize_report(document)


def body_hmac(body: bytes, secret: str) -> str:
    if not isinstance(body, bytes) or not body:
        raise CyberGymScoreReportError("score report body must be non-empty bytes")
    if not isinstance(secret, str) or not secret:
        raise CyberGymScoreReportError("HMAC secret is not configured")
    return (
        "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    )


def _safe_endpoint(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https" and parsed.hostname:
        return url
    if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
        return url
    raise CyberGymScoreReportError(
        "score intake URL must use HTTPS (HTTP is allowed only on loopback)"
    )


def publish_score_report(
    body: bytes,
    *,
    url: str,
    bearer_token: str,
    hmac_secret: str,
    timeout_seconds: float = 15.0,
) -> dict[str, Any]:
    """POST exact frozen bytes to Cathedral and verify the acceptance response."""
    if not isinstance(body, bytes) or not body:
        raise CyberGymScoreReportError("score report body must be non-empty bytes")
    if len(body) > MAX_BODY_BYTES:
        raise CyberGymScoreReportError(
            f"score report is {len(body)} bytes; intake limit is {MAX_BODY_BYTES}"
        )
    try:
        parsed = json.loads(body)
    except (UnicodeDecodeError, ValueError) as exc:
        raise CyberGymScoreReportError("score report body is not UTF-8 JSON") from exc
    normalized = normalize_report(parsed)
    if body != canonical_report_bytes(normalized):
        raise CyberGymScoreReportError(
            "score report body is not the canonical frozen byte representation"
        )
    expected_digest = report_digest(normalized)
    expected_body_digest = hashlib.sha256(body).hexdigest()
    if not isinstance(bearer_token, str) or not bearer_token:
        raise CyberGymScoreReportError("bearer token is not configured")
    try:
        timeout = float(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise CyberGymScoreReportError("timeout_seconds must be positive") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise CyberGymScoreReportError("timeout_seconds must be positive")

    request = urllib.request.Request(
        _safe_endpoint(url),
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer_token}",
            "X-Cathedral-Cybergym-Signature": body_hmac(body, hmac_secret),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read(MAX_BODY_BYTES + 1)
            status = int(getattr(response, "status", 200))
    except urllib.error.HTTPError as exc:
        detail = exc.read(2048).decode("utf-8", errors="replace")
        raise CyberGymScoreReportError(
            f"score intake refused the report with HTTP {exc.code}: {detail}"
        ) from exc
    except urllib.error.URLError as exc:
        raise CyberGymScoreReportError(
            f"score intake request failed: {exc.reason}"
        ) from exc
    except (OSError, TimeoutError) as exc:
        raise CyberGymScoreReportError(f"score intake request failed: {exc}") from exc
    if not 200 <= status < 300:
        raise CyberGymScoreReportError(f"score intake returned HTTP {status}")
    if len(response_body) > MAX_BODY_BYTES:
        raise CyberGymScoreReportError("score intake response exceeded the body limit")
    try:
        result = json.loads(response_body)
    except (UnicodeDecodeError, ValueError) as exc:
        raise CyberGymScoreReportError("score intake response was not JSON") from exc
    if not isinstance(result, dict) or result.get("accepted") is not True:
        raise CyberGymScoreReportError("score intake did not confirm acceptance")
    if result.get("report_sha256") != expected_digest:
        raise CyberGymScoreReportError(
            "score intake accepted a report with a different semantic digest"
        )
    if result.get("body_sha256") != expected_body_digest:
        raise CyberGymScoreReportError(
            "score intake accepted different authenticated body bytes"
        )
    return result


__all__ = [
    "CyberGymScoreReportError",
    "MAX_BODY_BYTES",
    "MAX_SCORES",
    "SCORE_UNITS",
    "SEMANTIC_KEYS",
    "body_hmac",
    "build_score_report",
    "canonical_report_bytes",
    "normalize_report",
    "publish_score_report",
    "report_digest",
]
