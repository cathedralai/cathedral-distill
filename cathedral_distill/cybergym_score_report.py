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

import base64
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

# Optional keys the tournament composer consumes (cathedral-validator
# OPTIONAL_SEMANTIC_KEYS must match): `nonce` (the epoch's chain-anchored batch
# nonce, the tie-break key) and `dispatched_units` (the common batch's total
# difficulty-weight, the base-100 denominator). Folded into the signed digest WHEN
# PRESENT, never required — a report without them stays byte-identical to today.
OPTIONAL_SEMANTIC_KEYS = (
    "nonce",
    "dispatched_units",
    "attestation_receipt",
)
_ALL_SEMANTIC_KEYS = SEMANTIC_KEYS + OPTIONAL_SEMANTIC_KEYS

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
    missing = sorted(set(SEMANTIC_KEYS) - set(document))
    extra = sorted(set(document) - set(_ALL_SEMANTIC_KEYS))
    if missing or extra:
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

    normalized: dict[str, Any] = {
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
    # Optional tournament inputs — normalized IDENTICALLY to the validator's
    # cybergym_contract.normalize_semantic_document (nonce.strip(); float(dispatched))
    # so a producer that emits them and the validator that re-derives the digest agree
    # byte-for-byte.
    if "nonce" in document:
        nonce = document["nonce"]
        if not isinstance(nonce, str) or not nonce.strip() or len(nonce) > 256:
            raise CyberGymScoreReportError("nonce must be a non-empty string <= 256 chars")
        normalized["nonce"] = nonce.strip()
    if "dispatched_units" in document:
        dispatched = document["dispatched_units"]
        if isinstance(dispatched, bool) or not isinstance(dispatched, (int, float)):
            raise CyberGymScoreReportError("dispatched_units must be a number")
        dispatched = float(dispatched)
        if not math.isfinite(dispatched) or dispatched < 0.0:
            raise CyberGymScoreReportError("dispatched_units must be finite and non-negative")
        normalized["dispatched_units"] = dispatched
    if "attestation_receipt" in document:
        # The spot-check sample: one {receipt, result_b64} the validator independently
        # DCAP-verifies. Only its two-key shell is validated here; the receipt object
        # is carried VERBATIM (the validator re-derives the exact bytes Cathedral
        # signed), and canonical_report_bytes sort_keys-canonicalizes it recursively
        # so both sides derive the same digest from the same object.
        ar = document["attestation_receipt"]
        if not isinstance(ar, Mapping):
            raise CyberGymScoreReportError("attestation_receipt must be an object")
        receipt = ar.get("receipt")
        result_b64 = ar.get("result_b64")
        if not isinstance(receipt, Mapping) or not receipt:
            raise CyberGymScoreReportError("attestation_receipt.receipt must be a non-empty object")
        if not isinstance(result_b64, str) or not result_b64 or len(result_b64) > 65536:
            raise CyberGymScoreReportError(
                "attestation_receipt.result_b64 must be a bounded base64 string"
            )
        try:
            base64.b64decode(result_b64, validate=True)
        except (ValueError, TypeError) as exc:
            raise CyberGymScoreReportError(
                "attestation_receipt.result_b64 is not valid base64"
            ) from exc
        normalized["attestation_receipt"] = {"receipt": dict(receipt), "result_b64": result_b64}
    return normalized


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


def require_attested_epoch(
    score_store: CyberGymScoreStore, source_epoch: int, *, allow_unattested: bool
) -> None:
    """Refuse to turn an unattested epoch into a publishable report.

    This is the boundary where a local SQLite file becomes the document a canonical
    validator composes weights from, and it is the last point at which the two can
    still be told apart. The wire contract carries no enforcement field — its
    semantic key set is pinned by cross-repo tests, so the producer cannot add one
    unilaterally — and `publish_score_report` is handed frozen bytes and a URL with
    no database in reach. An unattested epoch therefore has to be stopped here or
    not at all.

    The exposure this closes is not hypothetical: the loopback E2E verifiers run
    with no attestation policy on purpose, and the only difference between their
    export and a production one is the intake URL and the credentials file passed
    to the next command.

    An epoch whose posture was never recorded is refused too. That covers a
    database written before postures were stamped and one written by a producer
    that skipped the record; neither is evidence of attestation, and treating
    "nobody said" as "yes" is precisely the silence this exists to break.

    So is an epoch that records enforcement without recording WHICH policy was
    enforced. "Attestation was on" says nothing about which trust roots were in
    force, and an epoch that cannot name its policy cannot be shown to have refused
    anything in particular — the same silence, one level down.

    `allow_unattested` is the E2E's explicit acknowledgement. It does not make the
    resulting bytes safe — they remain indistinguishable on the wire — so it belongs
    only to a preview against a disposable loopback intake.
    """
    posture = score_store.attestation_posture(source_epoch)
    if posture is not None and posture["enforced"] and posture.get("policy_digest"):
        # A sanctioned enforced posture that NAMES its policy (policy_digest) is publishable. Two
        # qualify: per-miner Intel-TDX attestation, and the backend-verified hidden-set posture
        # (cathedral_distill.cybergym_hidden_set) — server-side differential + never-repeat hidden
        # sets + producer signature, no per-miner quote. Both are producer-trusted; `detail` names
        # which. What stays refused below is an epoch that recorded NO enforced policy at all.
        return
    if allow_unattested:
        return
    if posture is None:
        raise CyberGymScoreReportError(
            f"refusing to export CyberGym epoch {int(source_epoch)}: this score "
            "database does not record whether Intel-TDX attestation was enforced, so "
            "its solves cannot be shown to be attested. Re-close the epoch with a "
            "current build, or pass allow_unattested=True (CLI: "
            "--allow-unattested-e2e) if this is a loopback preview whose report will "
            "never reach a production intake."
        )
    if posture["enforced"]:
        raise CyberGymScoreReportError(
            f"refusing to export CyberGym epoch {int(source_epoch)}: it records that "
            "Intel-TDX attestation was enforced but not WHICH policy enforced it, so "
            "nothing here shows which trusted roots or enclave measurements a solve "
            "had to satisfy — and an epoch that cannot name its policy cannot be "
            "shown to have been resumed under the same one. Re-run the epoch with a "
            "current build, or pass allow_unattested=True (CLI: "
            "--allow-unattested-e2e) if this is a loopback preview whose report will "
            "never reach a production intake."
        )
    raise CyberGymScoreReportError(
        f"refusing to export CyberGym epoch {int(source_epoch)}: it was scored with "
        f"NO Intel-TDX attestation enforcement ({posture['detail']}), so every solve "
        "in it was credited unattested. The exported report carries no field that "
        "would let a validator tell it apart from an attested epoch, so publishing "
        "it to a production intake would pay emission for unattested work. Pass "
        "allow_unattested=True (CLI: --allow-unattested-e2e) only for a loopback "
        "preview."
    )


_SPOTCHECK_DOMAIN = b"cathedral-cybergym-spotcheck-v1"


def _spotcheck_miner(
    creditable: list[str], *, nonce: str, source_epoch: int
) -> str | None:
    """Which miner's attested receipt the report exposes for the validator spot-check.

    Chain-anchored and producer-independent (wallscaler #115 review, finding 2). Picking
    the *highest-scoring* miner let a producer that fabricates scores also choose which
    receipt is shown — one genuine attested solve among N fabricated ones would satisfy
    the check. Instead the miner is the argmin over the creditable-solve set of a
    domain-separated ``sha256(DOMAIN ‖ nonce ‖ source_epoch ‖ hotkey)`` — the same
    ungrindable, nonce-keyed shape as ``cybergym_tournament._nonce_digest`` and
    ``cybergym_mix.apportion``, with its own ``DOMAIN`` so this pick is independent of the
    tournament tie-break. The nonce is the chain-anchored batch nonce (#114), which no
    producer controls, so the choice is a pure function of published data (nonce + scores)
    that any third party re-derives; steering it would require dropping every creditable
    miner with a smaller digest, i.e. under-crediting real solves — visible and self-harming.
    A missing/empty nonce yields no pick (the pre-#114 pass-through).
    """
    if not creditable:
        return None
    nonce_bytes = nonce.encode("utf-8")
    if not nonce_bytes:
        return None
    epoch_bytes = str(int(source_epoch)).encode("ascii")

    def _digest(hotkey: str) -> str:
        return hashlib.sha256(
            _SPOTCHECK_DOMAIN + b"\x00" + nonce_bytes + b"\x00"
            + epoch_bytes + b"\x00" + hotkey.encode("utf-8")
        ).hexdigest()

    # sorted() first so an (astronomically unlikely) digest tie breaks deterministically.
    return min(sorted(creditable), key=_digest)


def build_score_report(
    score_store: CyberGymScoreStore,
    *,
    network: str,
    netuid: int,
    source_epoch: int,
    producer_hotkey: str,
    allow_unattested: bool = False,
) -> dict[str, Any]:
    """Build one report from the immutable durable close record.

    ``generated_at`` is the first persisted close time, not the current clock. A
    delayed retry therefore cannot make an old epoch look fresh, and a repeated
    export produces byte-identical output.

    Refuses an epoch that was not scored under an enforced Intel-TDX attestation
    policy unless the caller explicitly acknowledges it — see
    `require_attested_epoch`.
    """
    try:
        score_store.require_closed_epoch(source_epoch)
    except CyberGymScoreError as exc:
        raise CyberGymScoreReportError(str(exc)) from exc
    require_attested_epoch(
        score_store, source_epoch, allow_unattested=allow_unattested
    )
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
    # Attach the epoch's frontier context (batch nonce + dispatched_units) recorded
    # at scoring time, so the tournament composer can consume it. An epoch scored
    # before this shipped has no frontier row: the report then omits the fields and
    # the CyberGym lane composes exactly as it does today (single-epoch pass-through).
    frontier = score_store.epoch_frontier(source_epoch)
    if frontier is not None:
        document["nonce"] = frontier["nonce"]
        document["dispatched_units"] = float(frontier["dispatched_units"])
    # Attach one Intel-TDX receipt for the validator's spot-check, chosen by the CHAIN,
    # not the producer (wallscaler #115 review, finding 2). The chain-anchored batch nonce
    # (#114) keys a deterministic pick over the creditable-solve set — the positive-scored
    # miners, fully enumerable right here — and we expose THAT miner's attested receipt.
    # Because the producer does not control the nonce, it cannot surface a chosen receipt
    # by fabricating scores; see _spotcheck_miner. If the chain-named miner has no attested
    # sample (an unattested solve), the field is omitted — and finding 1's validator-side
    # posture ratchet turns omission into a lane burn once the audience has adopted
    # attestation, so dropping the field is not a free bypass. Without a nonce (an epoch
    # scored before #114) the report omits the field and the lane composes as it did then.
    if frontier is not None:
        creditable = sorted(h for h, v in scores.items() if v > 0.0)
        chosen = _spotcheck_miner(
            creditable, nonce=frontier["nonce"], source_epoch=source_epoch
        )
        if chosen is not None:
            sample = score_store.attestation_sample_for(source_epoch, chosen)
            if sample is not None:
                document["attestation_receipt"] = sample
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
    "require_attested_epoch",
]
