"""Maintainer registration and bundle version chains.

Gittensor anchors maintainer identity in GitHub repository roles — a relationship
that already exists and that anyone can check. A private prompt bundle or swarm
graph has no such anchor: there is nothing external to consult, and anyone can
claim to have written one.

So the anchor here is weaker on purpose, and named honestly:

    maintainer hotkey + bundle content digest + first valid registration

That establishes **who registered this exact artifact first**. It does not
establish authorship or legal ownership of the ideas inside, and public wording
should say *registered maintainer* rather than *owner*. Overclaiming here would
be the same failure as overclaiming what attestation proves.

Updates reference their predecessor, forming a chain, which gives a maintainer a
durable lineage rather than a series of unrelated submissions.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Iterable, Mapping

REGISTRATION_SCHEMA = "cathedral_bundle_registration_v1"
REGISTRATION_DOMAIN = b"cathedral-bundle-registration-v1\x00"

# Verifies a registration signature: (signing_payload, signature_str, miner_hotkey)
# -> True iff the signature is a valid signature over signing_payload by the key
# bound to miner_hotkey. Injected so production wires sr25519 against the ss58
# hotkey while the hardware-free path uses `ed25519_registration_verifier`.
SignatureVerifier = Callable[[bytes, str, str], bool]

MAX_TRACK_CHARS = 64
MAX_VERSION_CHARS = 32


class RegistrationError(ValueError):
    """Raised when a registration cannot be accepted."""


@dataclass(frozen=True)
class BundleRegistration:
    """A maintainer's claim over one exact bundle digest."""

    miner_hotkey: str
    track: str
    bundle_digest: str
    version: str
    registered_at: datetime
    parent_digest: str | None = None
    signature: str = ""

    def __post_init__(self) -> None:
        if not self.miner_hotkey:
            raise RegistrationError("miner_hotkey is required")
        if not self.track or len(self.track) > MAX_TRACK_CHARS:
            raise RegistrationError("track must be 1..64 chars")
        if not self.bundle_digest.startswith("sha256:"):
            raise RegistrationError("bundle_digest must be a sha256: digest")
        if not self.version or len(self.version) > MAX_VERSION_CHARS:
            raise RegistrationError("version must be 1..32 chars")
        if self.parent_digest is not None:
            if not self.parent_digest.startswith("sha256:"):
                raise RegistrationError("parent_digest must be a sha256: digest")
            if self.parent_digest == self.bundle_digest:
                raise RegistrationError("a bundle cannot be its own parent")

    def signing_payload(self) -> bytes:
        """Exact bytes the maintainer signs. Domain-separated, canonical.

        `registered_at` is covered. It used to be outside the payload, which was
        tolerable while it was only provenance metadata, and is not tolerable now
        that it is REWARD EVIDENCE: `cybergym_validator.evaluate_emission_gates`
        derives `no_contamination` from it (the commitment must pre-date the batch
        draw), so an unsigned timestamp meant the default-ON anti-contamination gate
        could be satisfied by backdating a field nobody signed. Signing it makes
        backdating a forgery instead of an edit.
        """
        body = {
            "schema": REGISTRATION_SCHEMA,
            "miner_hotkey": self.miner_hotkey,
            "track": self.track,
            "bundle_digest": self.bundle_digest,
            "version": self.version,
            "parent_digest": self.parent_digest,
            "registered_at": self.registered_at.isoformat(),
        }
        return REGISTRATION_DOMAIN + json.dumps(
            body, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": REGISTRATION_SCHEMA,
            "miner_hotkey": self.miner_hotkey,
            "track": self.track,
            "bundle_digest": self.bundle_digest,
            "version": self.version,
            "parent_digest": self.parent_digest,
            "registered_at": self.registered_at.isoformat(),
            "signature": self.signature,
        }


def bundle_digest(*parts: bytes) -> str:
    """Digest a bundle from its component bytes.

    Parts are hashed in the order given, each length-prefixed, so that
    concatenation boundaries cannot be shifted to produce a collision between
    two different component lists.
    """
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(len(part).to_bytes(8, "big"))
        hasher.update(part)
    return "sha256:" + hasher.hexdigest()


class BundleRegistry:
    """First valid signed registration establishes the claim over a digest."""

    def __init__(self) -> None:
        self._by_digest: dict[str, BundleRegistration] = {}

    def register(
        self,
        registration: BundleRegistration,
        *,
        verify_signature: bool = True,
        signature_verifier: SignatureVerifier | None = None,
    ) -> BundleRegistration:
        """Accept a registration, or raise.

        When `verify_signature` is true the registration must be signed, and if a
        `signature_verifier` is supplied the signature is **cryptographically
        verified** over `signing_payload()` against `miner_hotkey` — a forged or
        wrong-key signature is rejected. Production wires an sr25519 verifier bound
        to the ss58 hotkey; the hardware-free path uses
        `ed25519_registration_verifier`. With no verifier, only the presence of a
        signature is checked (the ordering-rule path, no keys).
        """
        if verify_signature and not registration.signature:
            raise RegistrationError("registration must be signed")
        if verify_signature and signature_verifier is not None:
            try:
                ok = signature_verifier(
                    registration.signing_payload(),
                    registration.signature,
                    registration.miner_hotkey,
                )
            except Exception as exc:  # a verifier failure is a rejection, never a pass
                raise RegistrationError(f"registration signature check failed: {exc}") from exc
            if ok is not True:
                raise RegistrationError("registration signature does not verify")

        existing = self._by_digest.get(registration.bundle_digest)
        if existing is not None:
            if existing.miner_hotkey == registration.miner_hotkey:
                raise RegistrationError("bundle already registered by this maintainer")
            # Someone else already claimed this exact artifact. First wins; a
            # later claimant cannot displace it by re-registering the same bytes.
            raise RegistrationError(
                "bundle_digest already claimed by another maintainer"
            )

        if registration.parent_digest is not None:
            parent = self._by_digest.get(registration.parent_digest)
            if parent is None:
                raise RegistrationError("parent_digest is not a registered bundle")
            if parent.miner_hotkey != registration.miner_hotkey:
                # Otherwise a maintainer could graft their submission onto a
                # stronger maintainer's lineage and inherit its history.
                raise RegistrationError(
                    "parent_digest belongs to a different maintainer"
                )
            if parent.track != registration.track:
                raise RegistrationError("a version chain cannot change track")

        self._by_digest[registration.bundle_digest] = registration
        return registration

    def claim_for(self, digest: str) -> BundleRegistration | None:
        return self._by_digest.get(digest)

    def is_registered_by(self, digest: str, miner_hotkey: str) -> bool:
        claim = self._by_digest.get(digest)
        return claim is not None and claim.miner_hotkey == miner_hotkey

    def lineage(self, digest: str) -> list[BundleRegistration]:
        """Chain from this bundle back to its root, newest first.

        Cycles are impossible by construction — a parent must already be
        registered when its child is accepted — but the visited set is kept so a
        corrupted store degrades to a truncated chain rather than a hang.
        """
        chain: list[BundleRegistration] = []
        seen: set[str] = set()
        cursor: str | None = digest
        while cursor is not None and cursor not in seen:
            seen.add(cursor)
            claim = self._by_digest.get(cursor)
            if claim is None:
                break
            chain.append(claim)
            cursor = claim.parent_digest
        return chain

    def track_bundles(self, track: str) -> list[BundleRegistration]:
        return sorted(
            (r for r in self._by_digest.values() if r.track == track),
            key=lambda r: (r.registered_at, r.bundle_digest),
        )

    def maintainers_on(self, track: str) -> set[str]:
        return {r.miner_hotkey for r in self._by_digest.values() if r.track == track}

    def as_public_index(self) -> list[dict[str, Any]]:
        """Publishable index. Digests and identities only — never bundle contents."""
        return [
            claim.as_dict()
            for claim in sorted(
                self._by_digest.values(),
                key=lambda r: (r.track, r.registered_at, r.bundle_digest),
            )
        ]


def ed25519_registration_verifier(keys: Mapping[str, bytes]) -> SignatureVerifier:
    """A `SignatureVerifier` that checks the Ed25519 signature over the payload
    against `keys[miner_hotkey]` (32-byte raw public keys). The hardware-free
    stand-in for production sr25519; a wrong key, wrong signer, or forged
    signature returns False (fail closed)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    def verify(payload: bytes, signature: str, miner_hotkey: str) -> bool:
        public = keys.get(miner_hotkey)
        if not isinstance(public, bytes) or len(public) != 32:
            return False
        try:
            sig = base64.b64decode(signature, validate=True)
        except (binascii.Error, ValueError):
            return False
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(sig, payload)
        except (InvalidSignature, ValueError):
            return False
        return True

    return verify


def load_registry(
    rows: Iterable[Mapping[str, Any]],
    *,
    verify_signature: bool = False,
    signature_verifier: SignatureVerifier | None = None,
) -> BundleRegistry:
    """Rebuild a registry from published rows, preserving registration order.

    Rows are replayed oldest-first so first-wins resolves exactly as it did
    live. Any row that would violate a rule — including a signature that does not
    verify when a `signature_verifier` is supplied — is skipped rather than
    accepted, keeping a corrupted or forged feed from rewriting history.
    """
    registry = BundleRegistry()
    ordered = sorted(rows, key=lambda row: str(row.get("registered_at") or ""))
    for row in ordered:
        try:
            registry.register(
                BundleRegistration(
                    miner_hotkey=str(row["miner_hotkey"]),
                    track=str(row["track"]),
                    bundle_digest=str(row["bundle_digest"]),
                    version=str(row["version"]),
                    registered_at=datetime.fromisoformat(str(row["registered_at"])),
                    parent_digest=row.get("parent_digest") or None,
                    signature=str(row.get("signature") or ""),
                ),
                verify_signature=verify_signature,
                signature_verifier=signature_verifier,
            )
        except (RegistrationError, KeyError, ValueError):
            continue
    return registry
