"""Bind a sealed-eval receipt to a Polaris attested run.

Polaris (`scaffold/polaris.py`, `POST /v1/attest`) runs a Docker image inside a
TDX box and binds two halves into the hardware quote's report_data:

    report_data[0:32]  = sha256(nonce_hex || e2e_pubkey_b64)
    report_data[32:64] = sha256(image_digest || sha256hex(stdout))

That second half is the useful one here. If the eval image prints the eval
receipt to stdout and nothing else, the quote proves *this eval image produced
this score* — which is exactly the distillation track's claim, and it costs a
CPU box rather than a GPU.

Two things make this non-obvious.

**The circularity.** The receipt carries `attestation.report_data_hex`, which is
derived from stdout, which is the receipt. So the bound document is the receipt
in *pre-attestation* form: attestation fields blanked, `receipt_id` and
`signature` absent. That still covers everything load-bearing — model digests,
evalset digests, grader digests, and the score. The attestation fields added
afterwards are evidence *about* the run, not inputs *to* it.

**stdout is a cryptographic surface, not a log.** Any stray print, warning, or
progress bar changes sha256(stdout) and silently breaks the binding. The eval
image must write the canonical receipt to stdout and route everything else to
stderr. `polaris_stdout` below is the single definition of those bytes.

Note on MRTD: per `scaffold/polaris.py`, the base-VM measurement is invariant
across workloads, so image identity rides on report_data[32:64] and MRTD is not
an image check. Do not add an MRTD comparison here expecting it to pin the image.
"""
from __future__ import annotations

import hashlib
from typing import Any, Mapping

from cathedral_distill.eval_receipt import (
    EvalReceiptError,
    canonical_json,
    validate_receipt,
)

POLARIS_KIND = "polaris_tdx"

_BLANK_ATTESTATION = {
    "kind": POLARIS_KIND,
    "evidence_digest": "",
    "evidence_uri": "",
    "policy_digest": "",
    "report_data_hex": "",
}


class PolarisBindingError(EvalReceiptError):
    """Raised when a receipt does not match the quote that supposedly covers it."""


def pre_attestation_document(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """The receipt form that the attested image commits to.

    Blanking the attestation block (rather than dropping it) keeps the key set
    stable, so the same strict validator accepts the document before and after
    the quote is attached.
    """
    document = {
        key: value
        for key, value in receipt.items()
        if key not in {"receipt_id", "signature"}
    }
    document["attestation"] = dict(_BLANK_ATTESTATION)
    return document


def polaris_stdout(receipt: Mapping[str, Any]) -> bytes:
    """The exact bytes the eval image must write to stdout.

    No trailing newline: `PolarisClient.attest` hashes the stdout string as
    returned, and a newline the image adds but the verifier does not expect
    would break the binding. Print with `sys.stdout.buffer.write(...)`.
    """
    return canonical_json(pre_attestation_document(receipt))


def expected_polaris_report_data(
    receipt: Mapping[str, Any],
    *,
    nonce: str,
    e2e_pubkey_b64: str,
    image_digest: str,
) -> bytes:
    """Recompute the 64 bytes Polaris should have bound for this receipt.

    Mirrors `PolarisClient.attest` exactly, including that the image digest and
    the stdout digest are concatenated as *hex text* before hashing, not as raw
    bytes. Deviating here produces a verifier that rejects every honest run.
    """
    if not nonce or not e2e_pubkey_b64:
        raise PolarisBindingError("nonce and e2e_pubkey_b64 are required")
    if not image_digest.startswith("sha256:"):
        raise PolarisBindingError("image_digest must be a sha256: content digest")
    stdout_hex = hashlib.sha256(polaris_stdout(receipt)).hexdigest()
    low = hashlib.sha256((nonce + e2e_pubkey_b64).encode("utf-8")).digest()
    high = hashlib.sha256((image_digest + stdout_hex).encode("utf-8")).digest()
    return low + high


def verify_polaris_receipt(
    receipt: Mapping[str, Any],
    *,
    nonce: str,
    e2e_pubkey_b64: str,
    image_digest: str,
    report_data: bytes,
    intel_verified: bool,
    allowed_image_digests: frozenset[str] | set[str] | None = None,
) -> Mapping[str, Any]:
    """Verify an eval receipt against a Polaris attest result. Fails closed.

    `allowed_image_digests` is the validator's own allowlist of eval images. It
    is the control that stops a miner from attesting a genuine TDX run of an
    image that grades leniently: the quote would be real, the score would be
    real, and the result would still be worthless. A run whose image is not
    pinned is rejected rather than merely flagged.
    """
    validated = validate_receipt(receipt)

    if str(validated["attestation"]["kind"]) != POLARIS_KIND:
        raise PolarisBindingError(f"receipt attestation kind is not {POLARIS_KIND}")
    if not intel_verified:
        raise PolarisBindingError(
            "Polaris did not verify the quote against Intel's chain"
        )
    if len(report_data) != 64:
        raise PolarisBindingError("report_data must be exactly 64 bytes")
    if allowed_image_digests is not None and image_digest not in allowed_image_digests:
        raise PolarisBindingError(f"eval image {image_digest} is not allowlisted")

    expected = expected_polaris_report_data(
        validated,
        nonce=nonce,
        e2e_pubkey_b64=e2e_pubkey_b64,
        image_digest=image_digest,
    )
    # Compare both halves separately so a failure says which binding broke:
    # identity (wrong nonce/session) versus execution (wrong image or score).
    if report_data[:32] != expected[:32]:
        raise PolarisBindingError(
            "identity binding failed: nonce or session key does not match this quote"
        )
    if report_data[32:] != expected[32:]:
        raise PolarisBindingError(
            "execution binding failed: this quote does not cover this receipt's "
            "image or score"
        )

    recorded = str(validated["attestation"]["report_data_hex"] or "")
    if recorded and recorded != report_data.hex():
        raise PolarisBindingError("receipt records a different report_data")
    return validated


def attach_polaris_attestation(
    receipt: Mapping[str, Any],
    *,
    report_data: bytes,
    evidence_digest: str,
    evidence_uri: str,
    policy_digest: str,
) -> dict[str, Any]:
    """Attach quote evidence to a pre-attestation receipt.

    Caller still has to recompute `receipt_id` and re-sign; this deliberately
    does not, so signing stays in one place.
    """
    if len(report_data) != 64:
        raise PolarisBindingError("report_data must be exactly 64 bytes")
    document = pre_attestation_document(receipt)
    document["attestation"] = {
        "kind": POLARIS_KIND,
        "evidence_digest": evidence_digest,
        "evidence_uri": evidence_uri,
        "policy_digest": policy_digest,
        "report_data_hex": report_data.hex(),
    }
    return document
