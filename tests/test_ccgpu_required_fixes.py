"""Fixes strictly required before a real confidential-GPU lane can be trusted.

Each test here fails on the pre-fix code. They were written after a live
confidential-GPU canary run on 2026-07-29 (GCP `a3-highgpu-1g` + Intel TDX +
H100, and `g4-standard-48` + SEV + RTX PRO 6000) established what real hardware
actually emits.

1. Policy gating against an AMD SEV-SNP receipt raised a bare ``KeyError``.
   ``KeyError`` is not a ``ComputeReceiptError``, so it escaped every caller's
   ``except`` and aborted the entire composition rather than failing one receipt.
2. The GPU attestation verifier received only the ``platform.gpu`` block, which
   carries no receipt identity. One physical GPU and one genuine attestation
   report could therefore back N hotkeys: the only cross-check
   (``bound_measurement == measurement``) compares two fields the same signer
   controls. No injected verifier *could* catch it, because it never saw the
   hotkey.
3. ``attestation.cpu_quote_verifier`` required ``sha256(token) ==
   policy_registry_digest``. That digest identifies the signed policy registry
   and is shared by every receipt in a release, so the equality is unsatisfiable
   and the factory returned False for every input.
"""

from __future__ import annotations

import pytest

from cathedral_distill import attestation as att
from cathedral_distill import compute_receipt as cr

from test_compute_receipt import (  # noqa: E402  - reuse the canonical fixtures
    KEY,
    KEYREG,
    MEASUREMENT,
    NOW,
    SEV_MEASUREMENT,
    SOURCE_EPOCH,
    _accept_gpu,
    _gpu_platform,
    _sev_body,
    _sev_receipt,
)


# --------------------------------------------------------------------------
# 1. SEV + policy gating must fail closed, not crash the composition
# --------------------------------------------------------------------------


def test_sev_receipt_under_tdx_shaped_tcb_policy_fails_closed_not_keyerror():
    """An operator enabling the documented TCB policy must not be able to have a
    miner abort the whole epoch's vector with a standard SEV-shaped receipt."""
    receipt = _sev_receipt()
    with pytest.raises(cr.ComputeReceiptError) as exc:
        cr.verify_receipt(
            receipt,
            KEYREG,
            now_iso=NOW,
            source_epoch=SOURCE_EPOCH,
            allowed_tcb_statuses={"UpToDate"},
        )
    assert "cannot be evaluated" in str(exc.value)
    # the whole point: a ComputeReceiptError is catchable by the composition path
    assert not isinstance(exc.value, KeyError)


def test_sev_receipt_under_advisory_policy_fails_closed_not_keyerror():
    receipt = _sev_receipt()
    with pytest.raises(cr.ComputeReceiptError) as exc:
        cr.verify_receipt(
            receipt,
            KEYREG,
            now_iso=NOW,
            source_epoch=SOURCE_EPOCH,
            allowed_advisories={"INTEL-SA-00001"},
        )
    assert "cannot be evaluated" in str(exc.value)
    assert not isinstance(exc.value, KeyError)


def test_sev_receipt_still_verifies_when_no_tdx_shaped_policy_is_supplied():
    """The fix must not regress the ordinary SEV path."""
    doc = cr.verify_receipt(
        _sev_receipt(), KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH
    )
    assert doc["tcb"]["tee_type"] == "sev_snp"


# --------------------------------------------------------------------------
# 2. The GPU verifier must receive the receipt identity (anti-Sybil binding)
# --------------------------------------------------------------------------


def _capture_gpu_verifier(seen: list):
    def verify(evidence):
        seen.append(dict(evidence))
        return True

    return verify


def test_gpu_verifier_receives_subject_hotkey_and_epoch():
    seen: list = []
    cr.verify_receipt(
        _sev_receipt(platform=_gpu_platform(cpu_tee=cr.CPU_TEE_SEV, bound=SEV_MEASUREMENT)),
        KEYREG,
        now_iso=NOW,
        source_epoch=SOURCE_EPOCH,
        gpu_attestation_verifier=_capture_gpu_verifier(seen),
    )
    assert len(seen) == 1
    ev = seen[0]
    # the raw GPU block is still present ...
    for k in ("cc_mode", "vbios_measurement", "attestation_report_digest", "bound_measurement"):
        assert k in ev, f"GPU block key {k} lost"
    # ... plus the identity a verifier needs to bind GPU <-> miner <-> epoch
    for k in ("receipt_id", "subject_hotkey", "source_epoch", "epoch_id", "cpu_measurement"):
        assert k in ev, f"identity key {k} not handed to the GPU verifier"
    assert ev["source_epoch"] == SOURCE_EPOCH


def test_an_injected_verifier_can_now_reject_one_gpu_report_backing_two_hotkeys():
    """With identity in hand, an injected verifier CAN enforce one-GPU-one-identity.

    Pre-fix this was impossible: both receipts presented byte-identical evidence
    to the verifier, so nothing downstream could tell them apart.

    Scope, stated precisely because the earlier name for this test overclaimed: what
    is proven here is that the evidence now carries the identity, so a verifier like
    the stateful one below can reject the duplicate. The verifier SHIPPED in
    `attestation.gpu_attestation_verifier` does NOT do this: it compares one constant
    `expected_report_data` and ignores the receipt identity, so it accepts one token
    for two hotkeys. Closing that is a change to the shipped factory (bind
    hotkey/epoch/receipt_id into the expected report data, and compare the attested
    GPU measurement to the receipt's) and is recorded as outstanding, not done.
    """
    claimed: dict[str, str] = {}

    def one_gpu_one_identity(evidence):
        report = evidence["attestation_report_digest"]
        owner = evidence["subject_hotkey"]
        first = claimed.setdefault(report, owner)
        return first == owner

    gpu_platform = _gpu_platform(cpu_tee=cr.CPU_TEE_SEV, bound=SEV_MEASUREMENT)
    first = _sev_receipt(platform=gpu_platform)
    cr.verify_receipt(
        first, KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH,
        gpu_attestation_verifier=one_gpu_one_identity,
    )

    # same GPU + same attestation report, different miner hotkey
    body = _sev_body(platform=gpu_platform)
    body["subject_hotkey"] = "5SybilTwin"
    second = cr.build_receipt(body, KEY, signing_key_id="compute-test-1")
    with pytest.raises(cr.ComputeReceiptError, match="GPU attestation did not verify"):
        cr.verify_receipt(
            second, KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH,
            gpu_attestation_verifier=one_gpu_one_identity,
        )


def test_existing_single_arg_gpu_verifiers_still_work():
    """Additive change: a verifier that only reads the GPU keys is unaffected."""
    doc = cr.verify_receipt(
        _sev_receipt(platform=_gpu_platform(cpu_tee=cr.CPU_TEE_SEV, bound=SEV_MEASUREMENT)),
        KEYREG,
        now_iso=NOW,
        source_epoch=SOURCE_EPOCH,
        gpu_attestation_verifier=_accept_gpu,
    )
    assert doc["platform"]["class"] == cr.PLATFORM_GPU


def test_cpu_quote_verifier_also_receives_receipt_identity():
    seen: list = []

    def verify(evidence):
        seen.append(dict(evidence))
        return True

    cr.verify_receipt(
        _sev_receipt(), KEYREG, now_iso=NOW, source_epoch=SOURCE_EPOCH,
        cpu_quote_verifier=verify,
    )
    assert seen and "receipt_id" in seen[0] and "subject_hotkey" in seen[0]


# --------------------------------------------------------------------------
# 3. The shipped cpu_quote_verifier factory must be satisfiable
# --------------------------------------------------------------------------


def test_shipped_cpu_quote_verifier_refuses_without_receipt_identity():
    """No receipt_id -> refuse, rather than fall back to a registry-wide key."""
    verifier = att.cpu_quote_verifier(
        policy=None, token_provider=lambda _k: b"x", expected_report_data="whatever"
    )
    assert verifier({"measurement": MEASUREMENT}) is False


def test_shipped_cpu_quote_verifier_looks_the_token_up_by_receipt_id():
    """Pre-fix the lookup key was policy_registry_digest and the result was then
    required to hash to that same digest, unsatisfiable for any real receipt."""
    asked: list[str] = []

    def token_provider(key):
        asked.append(key)
        return None  # we only care which key it was asked for

    verifier = att.cpu_quote_verifier(
        policy=None, token_provider=token_provider, expected_report_data="rd"
    )
    verifier({"receipt_id": "receipt-abc", "policy_registry_digest": "sha256:" + "0" * 64})
    assert asked == ["receipt-abc"], (
        "token must be resolved by the per-receipt id, not the registry-wide digest"
    )


def test_expected_report_data_may_be_derived_per_receipt():
    """A constant report_data cannot bind a quote to one receipt; allow a callable."""
    derived: list[str] = []

    def rd(evidence):
        value = f"{evidence['subject_hotkey']}:{evidence['source_epoch']}"
        derived.append(value)
        return value

    verifier = att.cpu_quote_verifier(
        policy=None, token_provider=lambda _k: b"token-bytes", expected_report_data=rd
    )
    # verify_attestation will reject these bytes; we assert only that the
    # per-receipt report_data was derived before the quote check ran.
    verifier({"receipt_id": "r1", "subject_hotkey": "5Miner", "source_epoch": 7})
    assert derived == ["5Miner:7"]
