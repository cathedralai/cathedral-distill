"""Externally observed, frozen eligibility for reward-bearing CyberGym epochs.

Miner signatures prove who made a claim; they do not prove when a validator or
chain observed it.  This module keeps that distinction explicit.  A signed
``RegistrationObservation`` binds a bundle registration to an observer receipt,
and ``freeze_eligibility_snapshot`` reduces verified pre-close observations to one
active commitment per paid identity.  The resulting digest is the only registry
evidence the reward path may use.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Iterable, Mapping


OBSERVATION_SCHEMA = "cathedral_cybergym_registration_observation_v1"
OBSERVATION_DOMAIN = b"cathedral-cybergym-registration-observation-v1\x00"
SNAPSHOT_SCHEMA = "cathedral_cybergym_eligibility_snapshot_v1"
SNAPSHOT_DOMAIN = b"cathedral-cybergym-eligibility-snapshot-v1\x00"

_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")

# (canonical observation payload, signature, observer key id) -> accepted.
ObservationVerifier = Callable[[bytes, str, str], bool]


class EligibilityError(ValueError):
    """Raised when reward eligibility evidence is malformed or unverifiable."""


def _aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EligibilityError(f"{label} must carry a timezone")


def _canonical_digest(domain: bytes, value: Mapping[str, Any]) -> str:
    try:
        body = json.dumps(
            value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise EligibilityError("eligibility evidence is not canonical JSON") from exc
    return "sha256:" + hashlib.sha256(domain + body).hexdigest()


@dataclass(frozen=True)
class RegistrationObservation:
    """An append-only observer receipt for one signed bundle registration.

    ``paid_identity`` must be a chain-resolved coldkey or an attested physical
    platform identity.  It is intentionally not inferred from the hotkey: an
    absent or unverified paid identity cannot receive reward eligibility.
    """

    source_epoch: int
    miner_hotkey: str
    bundle_digest: str
    paid_identity: str
    observed_at: datetime
    observed_block: int
    registry_version: str
    sequence: int
    observer_key_id: str
    signature: str

    def __post_init__(self) -> None:
        if isinstance(self.source_epoch, bool) or self.source_epoch < 0:
            raise EligibilityError("source_epoch must be a non-negative integer")
        if not self.miner_hotkey or not self.paid_identity:
            raise EligibilityError("miner_hotkey and paid_identity are required")
        if not _DIGEST_RE.match(self.bundle_digest):
            raise EligibilityError("bundle_digest must be a sha256 digest")
        _aware(self.observed_at, "observed_at")
        if isinstance(self.observed_block, bool) or self.observed_block < 0:
            raise EligibilityError("observed_block must be a non-negative integer")
        if not self.registry_version or not self.observer_key_id or not self.signature:
            raise EligibilityError("registry version, observer key id, and signature are required")
        if isinstance(self.sequence, bool) or self.sequence < 0:
            raise EligibilityError("sequence must be a non-negative integer")

    def signing_payload(self) -> bytes:
        body = {
            "schema": OBSERVATION_SCHEMA,
            "source_epoch": self.source_epoch,
            "miner_hotkey": self.miner_hotkey,
            "bundle_digest": self.bundle_digest,
            "paid_identity": self.paid_identity,
            "observed_at": self.observed_at.isoformat(),
            "observed_block": self.observed_block,
            "registry_version": self.registry_version,
            "sequence": self.sequence,
            "observer_key_id": self.observer_key_id,
        }
        return OBSERVATION_DOMAIN + json.dumps(
            body, sort_keys=True, ensure_ascii=True, separators=(",", ":")
        ).encode("ascii")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": OBSERVATION_SCHEMA,
            "source_epoch": self.source_epoch,
            "miner_hotkey": self.miner_hotkey,
            "bundle_digest": self.bundle_digest,
            "paid_identity": self.paid_identity,
            "observed_at": self.observed_at.isoformat(),
            "observed_block": self.observed_block,
            "registry_version": self.registry_version,
            "sequence": self.sequence,
            "observer_key_id": self.observer_key_id,
            "signature": self.signature,
        }

@dataclass(frozen=True)
class EligibilityEntry:
    """The single reward-eligible commitment for one paid identity."""

    miner_hotkey: str
    paid_identity: str
    bundle_digest: str
    observed_at: datetime
    observed_block: int
    observer_key_id: str
    sequence: int

    def __post_init__(self) -> None:
        if not self.miner_hotkey or not self.paid_identity:
            raise EligibilityError("entry miner_hotkey and paid_identity are required")
        if not _DIGEST_RE.match(self.bundle_digest):
            raise EligibilityError("entry bundle_digest must be a sha256 digest")
        _aware(self.observed_at, "entry observed_at")
        if isinstance(self.observed_block, bool) or self.observed_block < 0:
            raise EligibilityError("entry observed_block must be non-negative")
        if not self.observer_key_id:
            raise EligibilityError("entry observer_key_id is required")
        if isinstance(self.sequence, bool) or self.sequence < 0:
            raise EligibilityError("entry sequence must be non-negative")

    def as_dict(self) -> dict[str, Any]:
        return {
            "miner_hotkey": self.miner_hotkey,
            "paid_identity": self.paid_identity,
            "bundle_digest": self.bundle_digest,
            "observed_at": self.observed_at.isoformat(),
            "observed_block": self.observed_block,
            "observer_key_id": self.observer_key_id,
            "sequence": self.sequence,
        }


@dataclass(frozen=True)
class EligibilitySnapshot:
    """Immutable pre-anchor mapping used by dispatch and reward evaluation."""

    source_epoch: int
    registration_close: datetime
    anchor_block: int
    registry_version: str
    registry_digest: str
    entries: tuple[EligibilityEntry, ...]
    rejected_paid_identities: tuple[str, ...] = ()
    rejected_hotkeys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.source_epoch, bool) or self.source_epoch < 0:
            raise EligibilityError("snapshot source_epoch must be non-negative")
        _aware(self.registration_close, "registration_close")
        if isinstance(self.anchor_block, bool) or self.anchor_block < 0:
            raise EligibilityError("snapshot anchor_block must be non-negative")
        if not self.registry_version or not _DIGEST_RE.match(self.registry_digest):
            raise EligibilityError("snapshot registry evidence is invalid")
        paid = [entry.paid_identity for entry in self.entries]
        hotkeys = [entry.miner_hotkey for entry in self.entries]
        if len(paid) != len(set(paid)) or len(hotkeys) != len(set(hotkeys)):
            raise EligibilityError("snapshot must have one entry per paid identity and hotkey")
        for entry in self.entries:
            _aware(entry.observed_at, "entry observed_at")
            if entry.observed_at > self.registration_close or entry.observed_block >= self.anchor_block:
                raise EligibilityError("snapshot contains post-close eligibility evidence")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SNAPSHOT_SCHEMA,
            "source_epoch": self.source_epoch,
            "registration_close": self.registration_close.isoformat(),
            "anchor_block": self.anchor_block,
            "registry_version": self.registry_version,
            "registry_digest": self.registry_digest,
            "entries": [entry.as_dict() for entry in self.entries],
            "rejected_paid_identities": list(self.rejected_paid_identities),
            "rejected_hotkeys": list(self.rejected_hotkeys),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EligibilitySnapshot":
        """Rebuild a frozen snapshot without consulting mutable registry state."""
        expected = {
            "schema", "source_epoch", "registration_close", "anchor_block",
            "registry_version", "registry_digest", "entries",
            "rejected_paid_identities", "rejected_hotkeys",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise EligibilityError("snapshot has an unsupported key set")
        if (
            value.get("schema") != SNAPSHOT_SCHEMA
            or not isinstance(value["entries"], list)
            or not isinstance(value["rejected_paid_identities"], list)
            or not isinstance(value["rejected_hotkeys"], list)
        ):
            raise EligibilityError("snapshot schema is invalid")
        try:
            entries = tuple(
                EligibilityEntry(
                    miner_hotkey=row["miner_hotkey"],
                    paid_identity=row["paid_identity"],
                    bundle_digest=row["bundle_digest"],
                    observed_at=datetime.fromisoformat(row["observed_at"]),
                    observed_block=row["observed_block"],
                    observer_key_id=row["observer_key_id"],
                    sequence=row["sequence"],
                )
                for row in value["entries"]
            )
            return cls(
                source_epoch=value["source_epoch"],
                registration_close=datetime.fromisoformat(value["registration_close"]),
                anchor_block=value["anchor_block"],
                registry_version=value["registry_version"],
                registry_digest=value["registry_digest"],
                entries=entries,
                rejected_paid_identities=tuple(value["rejected_paid_identities"]),
                rejected_hotkeys=tuple(value["rejected_hotkeys"]),
            )
        except (KeyError, TypeError, ValueError, EligibilityError) as exc:
            raise EligibilityError("snapshot fields are malformed") from exc

    @property
    def digest(self) -> str:
        return _canonical_digest(SNAPSHOT_DOMAIN, self.as_dict())

    def reward_evidence_identity(self) -> dict[str, Any]:
        return {
            "schema": SNAPSHOT_SCHEMA,
            "digest": self.digest,
            "source_epoch": self.source_epoch,
            "anchor_block": self.anchor_block,
            "entries": len(self.entries),
        }

    def entry_for(self, miner_hotkey: str) -> EligibilityEntry | None:
        return next((entry for entry in self.entries if entry.miner_hotkey == miner_hotkey), None)

    def is_eligible(self, miner_hotkey: str, bundle_digest: str, *, source_epoch: int) -> bool:
        entry = self.entry_for(miner_hotkey)
        return bool(
            source_epoch == self.source_epoch
            and entry is not None
            and entry.bundle_digest == bundle_digest
        )


def ed25519_observation_verifier(keys: Mapping[str, bytes]) -> ObservationVerifier:
    """Hardware-free observer verifier; production supplies anchored chain keys."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    def verify(payload: bytes, signature: str, observer_key_id: str) -> bool:
        public = keys.get(observer_key_id)
        if not isinstance(public, bytes) or len(public) != 32:
            return False
        try:
            raw = base64.b64decode(signature, validate=True)
            Ed25519PublicKey.from_public_bytes(public).verify(raw, payload)
        except (InvalidSignature, ValueError, binascii.Error):
            return False
        return True

    return verify


def _registry_digest(registry: Any) -> str:
    identity = getattr(registry, "reward_evidence_identity", lambda: None)()
    if not isinstance(identity, Mapping) or not _DIGEST_RE.match(str(identity.get("digest", ""))):
        raise EligibilityError("registry has no canonical verified evidence identity")
    return str(identity["digest"])


def freeze_eligibility_snapshot(
    *,
    registry: Any,
    observations: Iterable[RegistrationObservation],
    observation_verifier: ObservationVerifier,
    source_epoch: int,
    registration_close: datetime,
    anchor_block: int,
    registry_version: str,
) -> EligibilitySnapshot:
    """Verify pre-close observations and freeze one commitment per paid identity.

    Competing observations are rejected as a group instead of selecting a convenient
    winner.  This removes both the many-bundle post-anchor choice and multi-hotkey
    paid-identity farming channels.
    """
    _aware(registration_close, "registration_close")
    if not registry_version:
        raise EligibilityError("registry_version is required")
    if isinstance(anchor_block, bool) or anchor_block <= 0:
        raise EligibilityError("anchor_block must be positive")

    verified: dict[tuple[str, str, str], RegistrationObservation] = {}
    for observation in observations:
        if (
            observation.source_epoch != source_epoch
            or observation.registry_version != registry_version
            or observation.observed_at > registration_close
            or observation.observed_block >= anchor_block
        ):
            continue
        try:
            observed = observation_verifier(
                observation.signing_payload(), observation.signature, observation.observer_key_id
            )
            registered = registry.is_cryptographically_verified_by(
                observation.bundle_digest, observation.miner_hotkey
            )
        except Exception:  # noqa: BLE001 - untrusted evidence never becomes eligible
            continue
        if observed is not True or registered is not True:
            continue
        key = (observation.paid_identity, observation.miner_hotkey, observation.bundle_digest)
        current = verified.get(key)
        if current is None or (
            observation.observed_block,
            observation.observed_at,
            observation.sequence,
            observation.observer_key_id,
        ) < (
            current.observed_block,
            current.observed_at,
            current.sequence,
            current.observer_key_id,
        ):
            verified[key] = observation

    candidates = tuple(verified.values())
    by_identity: dict[str, list[RegistrationObservation]] = {}
    by_hotkey: dict[str, list[RegistrationObservation]] = {}
    for observation in candidates:
        by_identity.setdefault(observation.paid_identity, []).append(observation)
        by_hotkey.setdefault(observation.miner_hotkey, []).append(observation)

    rejected_paid = {
        identity for identity, rows in by_identity.items()
        if len({(row.miner_hotkey, row.bundle_digest) for row in rows}) != 1
    }
    rejected_hotkeys = {
        hotkey for hotkey, rows in by_hotkey.items()
        if len({(row.paid_identity, row.bundle_digest) for row in rows}) != 1
    }
    entries = tuple(
        sorted(
            (
                EligibilityEntry(
                    miner_hotkey=row.miner_hotkey,
                    paid_identity=row.paid_identity,
                    bundle_digest=row.bundle_digest,
                    observed_at=row.observed_at,
                    observed_block=row.observed_block,
                    observer_key_id=row.observer_key_id,
                    sequence=row.sequence,
                )
                for row in candidates
                if row.paid_identity not in rejected_paid and row.miner_hotkey not in rejected_hotkeys
            ),
            key=lambda entry: (entry.paid_identity, entry.miner_hotkey, entry.bundle_digest),
        )
    )
    return EligibilitySnapshot(
        source_epoch=source_epoch,
        registration_close=registration_close,
        anchor_block=anchor_block,
        registry_version=registry_version,
        registry_digest=_registry_digest(registry),
        entries=entries,
        rejected_paid_identities=tuple(sorted(rejected_paid)),
        rejected_hotkeys=tuple(sorted(rejected_hotkeys)),
    )


__all__ = [
    "EligibilityEntry",
    "EligibilityError",
    "EligibilitySnapshot",
    "OBSERVATION_SCHEMA",
    "ObservationVerifier",
    "RegistrationObservation",
    "SNAPSHOT_SCHEMA",
    "ed25519_observation_verifier",
    "freeze_eligibility_snapshot",
]
