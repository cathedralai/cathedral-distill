"""Real confidential-compute attestation verification — the injected quote check.

`compute_receipt` takes an injected `gpu_attestation_verifier` / `cpu_quote_verifier`;
this module is a production-shaped implementation of one, built to the discipline
SparkProof's security audit (gittensor-model-hub/SparkProof) established the hard
way. Three findings from that audit are encoded here as mandatory, fail-closed
checks — they are exactly the ways an attestation looks verified but isn't:

  * **SEC-1/2/3 — self-consistency is forgeable.** A miner can hand-write an
    attestation blob with `passed:true` and a self-referential nonce; recomputing
    a nonce and trusting a boolean proves nothing. So the token's signature MUST be
    cryptographically verified against **trusted roots the verifier holds** (in
    production: NVIDIA NRAS JWKS / Intel DCAP roots), never a key the token carries.
  * **SEC-TDX-1 — a genuine TEE is not the right TEE.** An Intel-signed quote from
    *any* attacker-controlled enclave verifies unless you check the measurement. So
    the measurement (MRTD / launch measurement, and the GPU vBIOS/CC measurement)
    MUST be in a **pinned allow-list** of known-good enclave measurements.
  * **SEC-5 — pinning the request is not proof of the run.** A digest recomputed
    from a body the claimant supplies proves config integrity, not that the work
    ran. So `report_data` MUST equal the value the *verifier* expects — the nonce
    binding the attestation to this receipt/epoch — not a self-chosen constant.

This is hardware-free: the token is a normalized, Ed25519-signed evidence document,
so the discipline is fully testable. Production swaps the token parser for the real
NRAS token / DCAP quote formats and the trusted roots for NVIDIA's JWKS + Intel's
DCAP collateral; the verification *shape* — trusted-root signature, measurement
allow-list, nonce binding, fail-closed — is unchanged.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from cathedral_distill.distill_receipt import canonical_bytes  # shared canonical rule

ATTESTATION_SCHEMA = "cathedral_cc_attestation_v1"
MAX_TOKEN_BYTES = 65_536
DEFAULT_MAX_AGE_SECONDS = 86_400

_TEES = frozenset({"amd_sev_snp", "intel_tdx"})
_TIME_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_HEX_RE = re.compile(r"\A[0-9a-f]{16,256}\Z")
_TOKEN_KEYS = frozenset(
    {"schema", "tee", "measurement", "gpu_measurement", "report_data",
     "issued_at", "signing_key_id", "signature"}
)
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})


class AttestationError(ValueError):
    """A confidential-compute attestation failed verification. Fails closed."""


@dataclass(frozen=True)
class AttestationPolicy:
    """The verifier-held trust anchors — none of this comes from the token."""

    # signing_key_id -> 32-byte root public key. Production: NVIDIA NRAS JWKS keys
    # and Intel DCAP roots. A token signed by a key NOT here is refused (SEC-1/2/3).
    trusted_roots: Mapping[str, bytes]
    # Pinned known-good enclave measurements (SEC-TDX-1). A genuine quote whose
    # measurement is not here is refused.
    allowed_measurements: frozenset[str]
    # Pinned GPU (vBIOS / CC) measurements; None disables the GPU-measurement check.
    allowed_gpu_measurements: frozenset[str] | None = None
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise AttestationError(f"{name} must be canonical UTC time")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _exact_keys(value: Any, expected: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AttestationError(f"{label} must be an object")
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        raise AttestationError(f"{label} missing keys: {', '.join(missing)}")
    if unknown:
        raise AttestationError(f"{label} unknown keys: {', '.join(unknown)}")
    return value


def verify_attestation(
    token: bytes,
    *,
    expected_report_data: str,
    policy: AttestationPolicy,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Verify a confidential-compute attestation token. Fails closed on any check.

    Order: structure, signer resolved through the verifier's trusted roots (never
    the token's own key), Ed25519 signature, measurement allow-list, GPU-measurement
    allow-list, report_data == expected (nonce binding), freshness.
    """
    if not isinstance(token, bytes) or not token or len(token) > MAX_TOKEN_BYTES:
        raise AttestationError("attestation token is empty or oversized")
    try:
        doc = json.loads(token.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise AttestationError("attestation token is not UTF-8 JSON") from exc
    _exact_keys(doc, _TOKEN_KEYS, "attestation token")
    if doc["schema"] != ATTESTATION_SCHEMA:
        raise AttestationError("unsupported attestation schema")
    if doc["tee"] not in _TEES:
        raise AttestationError("tee must be amd_sev_snp or intel_tdx")

    # SEC-1/2/3: the signing key is resolved from the roots the VERIFIER holds, so
    # a token cannot vouch for itself with a key it supplies.
    key_id = doc["signing_key_id"]
    if not isinstance(key_id, str) or not key_id:
        raise AttestationError("signing_key_id is invalid")
    root = policy.trusted_roots.get(key_id)
    if not isinstance(root, bytes) or len(root) != 32:
        raise AttestationError(f"attestation signer {key_id!r} is not a trusted root")
    sig = _exact_keys(doc["signature"], _SIGNATURE_KEYS, "signature")
    if sig["algorithm"] != "ed25519":
        raise AttestationError("unsupported attestation signature algorithm")
    try:
        signature_bytes = base64.b64decode(sig["value_base64"], validate=True)
    except (TypeError, binascii.Error, ValueError) as exc:
        raise AttestationError("attestation signature is not canonical base64") from exc
    unsigned = {k: v for k, v in doc.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(root).verify(signature_bytes, canonical_bytes(unsigned))
    except (InvalidSignature, ValueError) as exc:
        raise AttestationError("attestation signature verification failed") from exc

    # SEC-TDX-1: a genuine TEE is not the right TEE — the measurement must be pinned.
    if not isinstance(doc["measurement"], str) or doc["measurement"] not in policy.allowed_measurements:
        raise AttestationError("attestation measurement is not in the allow-list")
    gpu_m = doc["gpu_measurement"]
    if gpu_m is not None:
        if policy.allowed_gpu_measurements is None or gpu_m not in policy.allowed_gpu_measurements:
            raise AttestationError("GPU measurement is not in the allow-list")

    # SEC-5: report_data must be the nonce the verifier expects for THIS receipt,
    # not a value the claimant chose.
    report_data = doc["report_data"]
    if not isinstance(report_data, str) or _HEX_RE.fullmatch(report_data) is None:
        raise AttestationError("report_data must be a hex string")
    if report_data != expected_report_data:
        raise AttestationError("report_data is not bound to this receipt (nonce mismatch)")

    # Freshness.
    issued = _timestamp(doc["issued_at"], "issued_at")
    check = now or datetime.now(UTC)
    if check.tzinfo is None or check.utcoffset() != timedelta(0):
        raise AttestationError("verification time must be UTC")
    if (isinstance(policy.max_age_seconds, bool) or not isinstance(policy.max_age_seconds, int)
            or policy.max_age_seconds <= 0):
        raise AttestationError("max_age_seconds must be positive")
    if abs((check - issued).total_seconds()) > policy.max_age_seconds:
        raise AttestationError("attestation is stale or issued in the future")
    return doc


# --------------------------------------------------------------------------- #
# Factories: adapt `verify_attestation` to compute_receipt's injected seams
# --------------------------------------------------------------------------- #

def gpu_attestation_verifier(
    policy: AttestationPolicy,
    token_provider: Callable[[str], bytes | None],
    *,
    expected_report_data: str,
    now: datetime | None = None,
) -> Callable[[Mapping[str, Any]], bool]:
    """A `compute_receipt.gpu_attestation_verifier` that does real verification.

    The receipt pins the token by `attestation_report_digest`; `token_provider`
    resolves that digest to the raw signed token (production: fetch the NRAS token
    the receipt committed to). The token is verified, its bytes must hash to the
    pinned digest, and its GPU measurement must be allow-listed.
    """
    import hashlib

    def verify(gpu_block: Mapping[str, Any]) -> bool:
        digest = str(gpu_block.get("attestation_report_digest") or "")
        token = token_provider(digest)
        if not isinstance(token, bytes):
            return False
        if "sha256:" + hashlib.sha256(token).hexdigest() != digest:
            return False  # the receipt's commitment must match the fetched token
        try:
            verify_attestation(token, expected_report_data=expected_report_data,
                               policy=policy, now=now)
        except AttestationError:
            return False
        return True

    return verify


def cpu_quote_verifier(
    policy: AttestationPolicy,
    token_provider: Callable[[str], bytes | None],
    *,
    expected_report_data: str | Callable[[Mapping[str, Any]], str],
    now: datetime | None = None,
) -> Callable[[Mapping[str, Any]], bool]:
    """A `compute_receipt.cpu_quote_verifier` that does real verification.

    `token_provider` resolves the receipt to its raw CPU-TEE quote, which is then
    verified against the trusted roots and the measurement allow-list. Fails closed.

    The lookup key is the receipt's own `receipt_id` (the per-receipt handle), NOT
    `policy_registry_digest`: that digest identifies the signed policy REGISTRY and
    is a constant shared by every receipt in a release, so it can neither address a
    single quote nor equal `sha256(token)`. The previous implementation required
    `sha256(token) == policy_registry_digest`, which no real receipt can satisfy —
    the verifier returned False for every input, so wiring it produced a total
    compute-lane outage and the only "working" configuration was to leave real
    quote verification off entirely.

    `expected_report_data` may be a callable so the caller can derive per-receipt
    report_data (binding the quote to this subject_hotkey/epoch/receipt_id) rather
    than pinning one constant across every receipt a verifier ever sees. A plain
    string keeps the previous behaviour."""

    def verify(evidence: Mapping[str, Any]) -> bool:
        key = str(evidence.get("receipt_id") or "")
        if not key:
            # No receipt identity supplied: refuse rather than fall back to a
            # registry-wide key that cannot address a single quote.
            return False
        token = token_provider(key)
        if not isinstance(token, bytes):
            return False
        try:
            want = (
                expected_report_data(evidence)
                if callable(expected_report_data)
                else expected_report_data
            )
        except Exception:
            return False
        try:
            doc = verify_attestation(token, expected_report_data=want,
                                    policy=policy, now=now)
        except AttestationError:
            return False
        # the quote's measurement must also match the receipt's measurement
        return doc["measurement"] == evidence.get("measurement")

    return verify


def sign_attestation(unsigned: Mapping[str, Any], root_seed: bytes) -> bytes:
    """Sign an attestation token (test / operator tooling). Returns the token bytes."""
    if "signature" in unsigned:
        raise AttestationError("unsigned token must not carry a signature")
    if not isinstance(root_seed, bytes) or len(root_seed) != 32:
        raise AttestationError("root seed must be 32 bytes")
    doc = dict(unsigned)
    signature = Ed25519PrivateKey.from_private_bytes(root_seed).sign(canonical_bytes(doc))
    doc["signature"] = {"algorithm": "ed25519", "value_base64": base64.b64encode(signature).decode("ascii")}
    return json.dumps(doc).encode("utf-8")


__all__ = [
    "AttestationError", "AttestationPolicy", "ATTESTATION_SCHEMA",
    "verify_attestation", "gpu_attestation_verifier", "cpu_quote_verifier", "sign_attestation",
]
