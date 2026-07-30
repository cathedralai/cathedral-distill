"""Producer side of the canonical CyberGym evidence manifest.

The score report a validator consumes carries an ``evidence_sha256``. On its own that
field commits to nothing: it is producer-chosen, so whoever holds the shared secret can
sign any 64-hex value. This module builds the digest it MUST equal, over the receipts
this validator actually scored and is asking to be paid for.

The consumer (cathedral-validator) rebuilds the same manifest from the receipts IT
admitted and requires exact equality before crediting anything, so the two sides either
agree exactly or the lane forfeits its share to burn. A producer cannot attest a set,
an amount, or a receipt it did not score.

``receipt_id`` already commits to the signed batch, result and ``items_root``, so
including it transitively binds the underlying work without restating it here.

This core is duplicated byte-for-byte in Cathedral's ``cybergym_contract`` and in
cathedral-validator's ``cathedral_thin/cybergym_evidence_manifest``, because no import
spans the three repositories. ``tests/test_cybergym_evidence_manifest.py`` pins the
schema string and the empty digest so drift fails a test here rather than silently
failing to verify a real report at the consumer.
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable, Mapping

SCHEMA = "cathedral_cybergym_evidence_manifest_v1"


class EvidenceManifestError(ValueError):
    """The manifest could not be built from the given entries."""


def _canonical_units(value: Any) -> str:
    """The exact quantity as a canonical decimal string.

    A string rather than a float: 12, 12.0 and "12.000" must all digest identically on
    both sides, and float repr is not a contract.
    """
    try:
        quantity = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise EvidenceManifestError(f"work_units {value!r} is not a decimal") from exc
    if not quantity.is_finite() or quantity < 0:
        raise EvidenceManifestError(f"work_units {value!r} is not a finite non-negative")
    normalized = quantity.normalize()
    # normalize() renders integers in exponent form (1E+1); expand those back.
    if normalized == normalized.to_integral_value():
        normalized = normalized.quantize(Decimal(1))
    return format(normalized, "f")


def build_manifest(
    *,
    network: str,
    netuid: int,
    source_epoch: int,
    entries: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """The canonical manifest body. ``entries`` may be in any order."""
    rows = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        hotkey = str(entry["miner_hotkey"])
        receipt_id = str(entry["receipt_id"])
        key = (hotkey, receipt_id)
        if key in seen:
            raise EvidenceManifestError(
                f"duplicate entry for {hotkey} / {receipt_id}"
            )
        seen.add(key)
        rows.append(
            {
                "miner_hotkey": hotkey,
                "receipt_id": receipt_id,
                "work_units": _canonical_units(entry["work_units"]),
            }
        )
    rows.sort(key=lambda row: (row["miner_hotkey"], row["receipt_id"]))
    return {
        "schema": SCHEMA,
        "network": str(network),
        "netuid": int(netuid),
        "source_epoch": int(source_epoch),
        "entries": rows,
    }


def canonical_bytes(manifest: Mapping[str, Any]) -> bytes:
    """sort_keys + compact separators + UTF-8, the same canonicalization as the report."""
    return json.dumps(
        dict(manifest), sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def manifest_digest(
    *,
    network: str,
    netuid: int,
    source_epoch: int,
    entries: Iterable[Mapping[str, Any]],
) -> str:
    """The 64 lowercase hex digest a report's ``evidence_sha256`` must equal."""
    manifest = build_manifest(
        network=network, netuid=netuid, source_epoch=source_epoch, entries=entries
    )
    return hashlib.sha256(canonical_bytes(manifest)).hexdigest()


def empty_digest(*, network: str, netuid: int, source_epoch: int) -> str:
    """The digest of a funded epoch in which the producer credited nobody."""
    return manifest_digest(
        network=network, netuid=netuid, source_epoch=source_epoch, entries=()
    )




def manifest_from_results(
    results: Iterable[Any],
    *,
    network: str,
    netuid: int,
    source_epoch: int,
) -> dict[str, Any]:
    """Build the manifest from this epoch's scored results.

    Accepts the ``MinerResult``-shaped objects ``score_epoch`` returns, or any object
    exposing ``miner_hotkey``, ``receipt_id`` and ``work_units``. Only CREDITABLE
    results are included: a result that earned nothing is not part of what is being
    paid, and including it would make the producer's digest disagree with the
    consumer's, which credits only what its admission rules allow.
    """
    entries = []
    for result in results:
        creditable = getattr(result, "creditable", True)
        if not creditable:
            continue
        units = getattr(result, "work_units", None)
        if units is None:
            continue
        entries.append(
            {
                "miner_hotkey": str(getattr(result, "miner_hotkey")),
                "receipt_id": str(getattr(result, "receipt_id")),
                "work_units": units,
            }
        )
    return build_manifest(
        network=network, netuid=netuid, source_epoch=source_epoch, entries=entries
    )


def evidence_sha256_for_results(
    results: Iterable[Any],
    *,
    network: str,
    netuid: int,
    source_epoch: int,
) -> str:
    """The exact value to put in the report's ``evidence_sha256``."""
    manifest = manifest_from_results(
        results, network=network, netuid=netuid, source_epoch=source_epoch
    )
    return hashlib.sha256(canonical_bytes(manifest)).hexdigest()


__all__ = [
    "SCHEMA",
    "EvidenceManifestError",
    "build_manifest",
    "canonical_bytes",
    "manifest_digest",
    "empty_digest",
    "manifest_from_results",
    "evidence_sha256_for_results",
]
