"""Remote-controlled, Cathedral-signed burn and mechanism-allocation config.

The validator must be able to change the burn fraction and the Compute-vs-Distill
split **without a redeploy**, but only when the change is authorized. So each is a
small signed, versioned document the validator pulls and verifies before applying:

  * `cathedral_burn_config_v1`   — the burn fraction and the burn destination.
  * `cathedral_lane_allocation_v1` — the share each lane (Compute CPU, Compute GPU,
    Distill, …) receives. Adding or changing a lane is a new entry here, not a
    validator rewrite.

Both are verified with the same trust discipline as a receipt or the key registry
(`receipt_keys.verify_key_registry`), and fail closed on any check:

  * **Signer authority** — the `signing_key_id` is resolved through the anchored
    `ReceiptKeyRegistry`; the verifier never trusts a caller-supplied key. (The
    registry itself is signed by a trusted operator root.)
  * **Network / subnet target** — `network` and `netuid` must equal what the
    operator runs; a config minted for another subnet is refused.
  * **Freshness** — a validity window plus a publication-age ceiling, so a stale
    signed config cannot be replayed indefinitely.
  * **Rollback protection** — a monotonic `config_version`; a config older than the
    one already applied is refused (an attacker cannot serve an old signed config
    to revert a change).
  * **Burn destination** — when the operator pins an expected burn hotkey, a config
    that redirects the burn elsewhere is refused.

`resolve_allocation` combines a verified burn config and a verified allocation
config into the exact inputs `lane_feed.compose_vector` consumes, and re-checks the
completeness invariant (Σ enabled allocations + burn == 1) so an incoherent pair is
rejected before it can compose a vector.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature

from cathedral_distill.distill_receipt import canonical_bytes  # shared canonical rule

BURN_CONFIG_SCHEMA = "cathedral_burn_config_v1"
ALLOCATION_CONFIG_SCHEMA = "cathedral_lane_allocation_v1"
MAX_CONFIG_BYTES = 65_536
MAX_LANES = 64
DEFAULT_MAX_AGE_SECONDS = 86_400

_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_LANE_RE = re.compile(r"\A[a-z0-9][a-z0-9_]{0,63}\Z")
_TIME_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_DECIMAL_RE = re.compile(r"\A(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,12})?\Z")
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})

_ENVELOPE_KEYS = frozenset(
    {"schema", "config_version", "network", "netuid", "generated_at",
     "valid_from", "valid_until", "signing_key_id", "signature"}
)
_BURN_KEYS = _ENVELOPE_KEYS | {"burn"}
_BURN_BODY_KEYS = frozenset({"fraction", "burn_hotkey"})
_ALLOCATION_KEYS = _ENVELOPE_KEYS | {"allocations"}
_ALLOCATION_ENTRY_KEYS = frozenset({"lane", "allocation", "enabled"})


class SignedConfigError(ValueError):
    """A signed config failed verification. Fails closed."""


@dataclass(frozen=True)
class BurnConfig:
    config_version: int
    network: str
    netuid: int
    fraction: Decimal
    burn_hotkey: str


@dataclass(frozen=True)
class AllocationConfig:
    config_version: int
    network: str
    netuid: int
    # lane id -> (allocation, enabled). A disabled lane contributes 0 and its
    # share is treated as burn by the composer.
    allocations: Mapping[str, tuple[Decimal, bool]]


# --------------------------------------------------------------------------- #
# Shared envelope verification
# --------------------------------------------------------------------------- #

def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise SignedConfigError(f"{name} must be canonical UTC time")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _exact_keys(value: Any, expected: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SignedConfigError(f"{label} must be an object")
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        raise SignedConfigError(f"{label} missing keys: {', '.join(missing)}")
    if unknown:
        raise SignedConfigError(f"{label} unknown keys: {', '.join(unknown)}")
    return value


def _decimal_fraction(value: object, label: str) -> Decimal:
    text = str(value)
    if _DECIMAL_RE.fullmatch(text) is None:
        raise SignedConfigError(f"{label} must be a canonical decimal string")
    dec = Decimal(text)
    if not Decimal(0) <= dec <= Decimal(1):
        raise SignedConfigError(f"{label} must be within 0..1")
    return dec


def _verify_envelope(
    data: bytes,
    key_registry: Any,
    expected_schema: str,
    key_set: frozenset[str],
    *,
    now: datetime | None,
    network: str,
    netuid: int,
    min_version: int,
    max_age_seconds: int,
) -> Mapping[str, Any]:
    """Parse + verify the shared signed-config envelope; return the document."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_CONFIG_BYTES:
        raise SignedConfigError("config is empty or oversized")
    try:
        document = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SignedConfigError("config is not UTF-8 JSON") from exc
    if not isinstance(document, dict) or frozenset(document) != key_set:
        raise SignedConfigError("config has missing or unknown fields")
    if document["schema"] != expected_schema:
        raise SignedConfigError("config schema is unsupported")

    # Signer authority: resolve through the anchored registry, at issue time.
    generated = _timestamp(document["generated_at"], "generated_at")
    signing_key_id = document["signing_key_id"]
    if not isinstance(signing_key_id, str) or _ID_RE.fullmatch(signing_key_id) is None:
        raise SignedConfigError("signing_key_id is invalid")
    try:
        public_key = key_registry.resolve(signing_key_id, at=generated)
    except Exception as exc:  # ReceiptKeyError or any resolver failure -> reject
        raise SignedConfigError(f"config signing key could not be resolved: {exc}") from exc

    signature = document["signature"]
    if not isinstance(signature, dict) or frozenset(signature) != _SIGNATURE_KEYS:
        raise SignedConfigError("config signature object is invalid")
    if signature["algorithm"] != "ed25519":
        raise SignedConfigError("config signature algorithm is unsupported")
    try:
        signature_bytes = base64.b64decode(signature["value_base64"], validate=True)
    except (TypeError, binascii.Error, ValueError) as exc:
        raise SignedConfigError("config signature is not canonical base64") from exc
    if len(signature_bytes) != 64:
        raise SignedConfigError("config signature must be 64 bytes")
    unsigned = {k: v for k, v in document.items() if k != "signature"}
    try:
        public_key.verify(signature_bytes, canonical_bytes(unsigned))
    except (InvalidSignature, ValueError) as exc:
        raise SignedConfigError("config signature verification failed") from exc

    # Network / subnet target.
    if document["network"] != network:
        raise SignedConfigError("config network does not match this validator")
    if isinstance(document["netuid"], bool) or document["netuid"] != netuid:
        raise SignedConfigError("config netuid does not match this validator")

    # Rollback protection: reject a config older than the applied fence.
    version = document["config_version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise SignedConfigError("config_version must be a non-negative integer")
    if isinstance(min_version, bool) or not isinstance(min_version, int) or min_version < 0:
        raise SignedConfigError("min_version must be a non-negative integer")
    if version < min_version:
        raise SignedConfigError(
            f"config_version {version} is older than the applied fence {min_version} (rollback)"
        )

    # Freshness: validity window plus a publication-age ceiling.
    valid_from = _timestamp(document["valid_from"], "valid_from")
    valid_until = _timestamp(document["valid_until"], "valid_until")
    if not valid_from < valid_until:
        raise SignedConfigError("config validity window is invalid")
    check = now or datetime.now(UTC)
    if check.tzinfo is None or check.utcoffset() != timedelta(0):
        raise SignedConfigError("verification time must be UTC")
    if not valid_from <= check < valid_until:
        raise SignedConfigError("config is outside its validity window")
    if (isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int)
            or max_age_seconds <= 0):
        raise SignedConfigError("max_age_seconds must be positive")
    if check - generated > timedelta(seconds=max_age_seconds):
        raise SignedConfigError("config is too stale")
    return document


# --------------------------------------------------------------------------- #
# Burn config
# --------------------------------------------------------------------------- #

def verify_burn_config(
    data: bytes,
    key_registry: Any,
    *,
    network: str,
    netuid: int,
    now: datetime | None = None,
    min_version: int = 0,
    expected_burn_hotkey: str | None = None,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> BurnConfig:
    """Verify a signed burn config and return it. Fails closed on any check.

    When `expected_burn_hotkey` is set, a config that redirects the burn to any
    other destination is refused.
    """
    document = _verify_envelope(
        data, key_registry, BURN_CONFIG_SCHEMA, _BURN_KEYS,
        now=now, network=network, netuid=netuid,
        min_version=min_version, max_age_seconds=max_age_seconds,
    )
    burn = _exact_keys(document["burn"], _BURN_BODY_KEYS, "burn")
    fraction = _decimal_fraction(burn["fraction"], "burn.fraction")
    burn_hotkey = burn["burn_hotkey"]
    if not isinstance(burn_hotkey, str) or not burn_hotkey:
        raise SignedConfigError("burn.burn_hotkey must be a non-empty string")
    if expected_burn_hotkey is not None and burn_hotkey != expected_burn_hotkey:
        raise SignedConfigError("burn destination does not match the pinned hotkey")
    return BurnConfig(
        config_version=int(document["config_version"]),
        network=network, netuid=netuid,
        fraction=fraction, burn_hotkey=burn_hotkey,
    )


# --------------------------------------------------------------------------- #
# Allocation config
# --------------------------------------------------------------------------- #

def verify_allocation_config(
    data: bytes,
    key_registry: Any,
    *,
    network: str,
    netuid: int,
    now: datetime | None = None,
    min_version: int = 0,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> AllocationConfig:
    """Verify a signed lane-allocation config and return it. Fails closed."""
    document = _verify_envelope(
        data, key_registry, ALLOCATION_CONFIG_SCHEMA, _ALLOCATION_KEYS,
        now=now, network=network, netuid=netuid,
        min_version=min_version, max_age_seconds=max_age_seconds,
    )
    entries = document["allocations"]
    if not isinstance(entries, list) or not entries or len(entries) > MAX_LANES:
        raise SignedConfigError("allocations must be a bounded non-empty list")
    allocations: dict[str, tuple[Decimal, bool]] = {}
    for entry in entries:
        row = _exact_keys(entry, _ALLOCATION_ENTRY_KEYS, "allocation entry")
        lane = row["lane"]
        if not isinstance(lane, str) or _LANE_RE.fullmatch(lane) is None:
            raise SignedConfigError("allocation lane id is invalid")
        if lane in allocations:
            raise SignedConfigError(f"duplicate lane {lane!r}")
        enabled = row["enabled"]
        if not isinstance(enabled, bool):
            raise SignedConfigError("allocation enabled must be a boolean")
        allocation = _decimal_fraction(row["allocation"], "allocation")
        allocations[lane] = (allocation, enabled)
    return AllocationConfig(
        config_version=int(document["config_version"]),
        network=network, netuid=netuid,
        allocations=allocations,
    )


# --------------------------------------------------------------------------- #
# Resolve the two configs into compose_vector inputs
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ResolvedAllocation:
    """The composition inputs derived from a verified burn + allocation config."""

    burn_fraction: Decimal
    burn_hotkey: str
    # lane id -> allocation (enabled lanes only; disabled lanes are excluded and
    # their share is already accounted to burn).
    lane_allocations: Mapping[str, Decimal]
    config_versions: tuple[int, int]  # (burn, allocation)


def resolve_allocation(burn: BurnConfig, allocation: AllocationConfig) -> ResolvedAllocation:
    """Combine a verified burn + allocation config into `compose_vector` inputs.

    Enforces the completeness invariant — Σ(enabled allocations) + burn == 1 — so
    an incoherent config pair is rejected before it can compose a vector. A
    disabled lane's share is folded into burn here (deterministic), matching the
    composer's missing-lane-to-burn rule.
    """
    if burn.network != allocation.network or burn.netuid != allocation.netuid:
        raise SignedConfigError("burn and allocation configs target different subnets")
    enabled = {lane: alloc for lane, (alloc, on) in allocation.allocations.items() if on}
    enabled_total = sum(enabled.values(), Decimal(0))
    if enabled_total + burn.fraction != Decimal(1):
        raise SignedConfigError(
            "enabled lane allocations plus burn must sum to exactly 1 "
            f"(got Σenabled={enabled_total} + burn={burn.fraction})"
        )
    return ResolvedAllocation(
        burn_fraction=burn.fraction,
        burn_hotkey=burn.burn_hotkey,
        lane_allocations=enabled,
        config_versions=(burn.config_version, allocation.config_version),
    )


# --------------------------------------------------------------------------- #
# Signing (test fixtures / operator tooling)
# --------------------------------------------------------------------------- #

def sign_config(unsigned_document: Mapping[str, object], signing_private_seed: bytes) -> dict:
    """Attach an Ed25519 signature to an unsigned config document."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if "signature" in unsigned_document:
        raise SignedConfigError("unsigned config must not carry a signature")
    if not isinstance(signing_private_seed, bytes) or len(signing_private_seed) != 32:
        raise SignedConfigError("signing private seed must be 32 bytes")
    document = dict(unsigned_document)
    signature = Ed25519PrivateKey.from_private_bytes(signing_private_seed).sign(
        canonical_bytes(document)
    )
    document["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return document


__all__ = [
    "SignedConfigError", "BurnConfig", "AllocationConfig", "ResolvedAllocation",
    "verify_burn_config", "verify_allocation_config", "resolve_allocation", "sign_config",
    "BURN_CONFIG_SCHEMA", "ALLOCATION_CONFIG_SCHEMA",
]
