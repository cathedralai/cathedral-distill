"""Confidential-compute attestation verification (adapted from SparkProof's audit).

Proves the three fail-closed disciplines their security review established, and
that the resulting verifier plugs into compute_receipt's injected seam so a GPU
receipt admits ONLY on a genuinely-verified, measurement-pinned, nonce-bound quote.
"""
from __future__ import annotations

import hashlib
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import attestation as att  # noqa: E402
from cathedral_distill import compute_receipt as cr  # noqa: E402
from cathedral_distill.receipt_keys import ReceiptKeyRegistry  # noqa: E402

# NVIDIA/Intel roots the VERIFIER holds (test stand-in); a separate key signs receipts.
ROOT = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
ROOT_PUB = ROOT.public_key().public_bytes_raw()
RKEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
KEYREG = ReceiptKeyRegistry.from_keys({"compute-1": RKEY.public_key().public_bytes_raw()})

NOW = datetime(2026, 7, 25, 12, 15, tzinfo=UTC)
NOW_ISO = "2026-07-25T12:15:00.000000Z"
EPOCH = 11
SEV_MEAS = "sev-snp-measurement-sha384:" + "cd" * 48
GPU_MEAS = "gpu-vbios-sha256:" + "ab" * 32
REPORT = "de" * 32  # the nonce the verifier expects, bound into report_data


def _policy(**over):
    base = dict(trusted_roots={"nvidia-nras-root-1": ROOT_PUB},
                allowed_measurements=frozenset({SEV_MEAS}),
                allowed_gpu_measurements=frozenset({GPU_MEAS}))
    base.update(over)
    return att.AttestationPolicy(**base)


def _token(*, measurement=SEV_MEAS, gpu_measurement=GPU_MEAS, report_data=REPORT,
           key_id="nvidia-nras-root-1", seed=None, issued="2026-07-25T12:10:00Z"):
    body = {"schema": att.ATTESTATION_SCHEMA, "tee": "amd_sev_snp", "measurement": measurement,
            "gpu_measurement": gpu_measurement, "report_data": report_data,
            "issued_at": issued, "signing_key_id": key_id}
    return att.sign_attestation(body, (seed or bytes(range(32, 64))))


# --------------------------------------------------------------------------- #
# The verifier discipline (verify_attestation)
# --------------------------------------------------------------------------- #

def test_genuine_attestation_verifies():
    doc = att.verify_attestation(_token(), expected_report_data=REPORT, policy=_policy(), now=NOW)
    assert doc["tee"] == "amd_sev_snp"


def test_sec123_untrusted_signer_is_rejected():
    # SEC-1/2/3: a token signed by a key the verifier does not hold is refused —
    # no "self-consistency" pass.
    with pytest.raises(att.AttestationError, match="not a trusted root"):
        att.verify_attestation(_token(key_id="attacker-key"), expected_report_data=REPORT,
                               policy=_policy(), now=NOW)


def test_sec123_forged_signature_is_rejected():
    # right key_id, but signed by a DIFFERENT key than the trusted root
    forged = _token(seed=bytes(range(64, 96)))
    with pytest.raises(att.AttestationError, match="signature verification failed"):
        att.verify_attestation(forged, expected_report_data=REPORT, policy=_policy(), now=NOW)


def test_sectdx1_measurement_not_in_allowlist_is_rejected():
    # SEC-TDX-1: a genuinely-signed quote whose measurement isn't pinned is refused.
    other = "sev-snp-measurement-sha384:" + "ff" * 48
    with pytest.raises(att.AttestationError, match="measurement is not in the allow-list"):
        att.verify_attestation(_token(measurement=other), expected_report_data=REPORT,
                               policy=_policy(), now=NOW)


def test_sectdx1_gpu_measurement_not_in_allowlist_is_rejected():
    with pytest.raises(att.AttestationError, match="GPU measurement is not in the allow-list"):
        att.verify_attestation(_token(gpu_measurement="gpu-vbios-sha256:" + "00" * 32),
                               expected_report_data=REPORT, policy=_policy(), now=NOW)


def test_sec5_report_data_not_bound_is_rejected():
    # SEC-5: report_data must be the verifier's expected nonce, not a self-chosen one.
    with pytest.raises(att.AttestationError, match="not bound to this receipt"):
        att.verify_attestation(_token(report_data="00" * 32), expected_report_data=REPORT,
                               policy=_policy(), now=NOW)


def test_stale_attestation_is_rejected():
    late = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)  # >24h after issued
    with pytest.raises(att.AttestationError, match="stale"):
        att.verify_attestation(_token(), expected_report_data=REPORT, policy=_policy(), now=late)


# --------------------------------------------------------------------------- #
# Wired through compute_receipt's injected gpu_attestation_verifier
# --------------------------------------------------------------------------- #

def _gpu_receipt(token):
    digest = "sha256:" + hashlib.sha256(token).hexdigest()
    body = {
        "schema": cr.RECEIPT_SCHEMA, "subject_hotkey": "5GpuMiner", "epoch_id": 7,
        "source_epoch": EPOCH, "issued_at": "2026-07-25T12:00:00.000000Z",
        "platform_pseudonym": "platform-x", "measurement": SEV_MEAS,
        "policy_registry_release": 1, "policy_registry_digest": "sha256:" + "aa" * 32,
        "policy_profile_ids": ["gpu-v1"],
        "tcb": {"tee_type": "sev_snp", "policy_debug_disabled": True, "boot_loader_svn": 3,
                "tee_svn": 0, "snp_svn": 8, "microcode_svn": 72, "reported_tcb": "0" * 16,
                "collateral_current": True},
        "channel": {"status": "passed", "binding_digest": "sha256:" + "bb" * 32},
        "work": {"challenge_id": "c-11", "manifest_digest": "sha256:" + "cc" * 32,
                 "result_digest": "sha256:" + "dd" * 32, "status": "passed", "work_units": "20"},
        "assurance": {"schema": cr.ASSURANCE_SCHEMA, "claims": {n: {"status": "passed"}
                      for n in ("channel", "hardware", "software", "work")}},
        "lifecycle": {"state": "issued", "revocation_reference": None,
                      "worker_evidence_expires_at": "2026-07-26T12:00:00.000000Z"},
        "platform": {"class": cr.PLATFORM_GPU, "cpu_tee": cr.CPU_TEE_SEV,
                     "gpu": {"cc_mode": "on", "vbios_measurement": "sha256:" + "ee" * 32,
                             "attestation_report_digest": digest, "bound_measurement": SEV_MEAS}},
    }
    return cr.build_receipt(body, RKEY, signing_key_id="compute-1")


def test_gpu_receipt_admits_only_on_a_verified_attestation():
    token = _token()
    receipt = _gpu_receipt(token)
    digest = receipt["platform"]["gpu"]["attestation_report_digest"]
    verifier = att.gpu_attestation_verifier(_policy(), {digest: token}.get,
                                            expected_report_data=REPORT, now=NOW)
    doc = cr.verify_receipt(receipt, KEYREG, now_iso=NOW_ISO, source_epoch=EPOCH,
                            gpu_attestation_verifier=verifier)
    assert cr.platform_class(doc) == cr.PLATFORM_GPU


def test_gpu_receipt_with_forged_attestation_is_refused():
    # a token whose measurement isn't allow-listed → the injected verifier returns
    # False → the GPU lane never admits.
    bad = _token(measurement="sev-snp-measurement-sha384:" + "ff" * 48)
    receipt = _gpu_receipt(bad)
    digest = receipt["platform"]["gpu"]["attestation_report_digest"]
    verifier = att.gpu_attestation_verifier(_policy(), {digest: bad}.get,
                                            expected_report_data=REPORT, now=NOW)
    with pytest.raises(cr.ComputeReceiptError, match="GPU attestation did not verify"):
        cr.verify_receipt(receipt, KEYREG, now_iso=NOW_ISO, source_epoch=EPOCH,
                          gpu_attestation_verifier=verifier)


def test_gpu_receipt_with_a_swapped_token_is_refused():
    # the receipt commits to a token digest; a different token that doesn't hash to
    # it is refused even if it is itself valid.
    receipt = _gpu_receipt(_token())
    digest = receipt["platform"]["gpu"]["attestation_report_digest"]
    verifier = att.gpu_attestation_verifier(_policy(), {digest: _token(report_data="11" * 32)}.get,
                                            expected_report_data=REPORT, now=NOW)
    with pytest.raises(cr.ComputeReceiptError, match="GPU attestation did not verify"):
        cr.verify_receipt(receipt, KEYREG, now_iso=NOW_ISO, source_epoch=EPOCH,
                          gpu_attestation_verifier=verifier)


# --------------------------------------------------------------------------- #
# The policy's own content, made checkable (`attestation_policy_digest`)
# --------------------------------------------------------------------------- #

def test_the_policy_digest_is_stable_across_equal_policies():
    """Canonical before digested, or a correct restart looks like an attack.

    Trusted roots arrive as a dict and measurements as a frozenset, neither of which
    has a defined iteration order. If the digest inherited that order, an operator
    restarting a verifier from unchanged configuration would be refused at random —
    and the first fix anyone reaches for is to turn the control off.
    """
    other = att.AttestationPolicy(
        trusted_roots=dict({"nvidia-nras-root-1": bytes(ROOT_PUB)}),
        allowed_measurements=frozenset([SEV_MEAS]),
        allowed_gpu_measurements=frozenset([GPU_MEAS]),
    )
    assert att.attestation_policy_digest(_policy()) == att.attestation_policy_digest(other)
    assert att.attestation_policy_digest(None) == ""
    assert att.attestation_policy_digest(_policy()).startswith("sha256:")


@pytest.mark.parametrize(
    "change",
    [
        # An added signer: the swap that admits a claimant's own key while the
        # enforcement flag still reads "on".
        {"trusted_roots": {"nvidia-nras-root-1": ROOT_PUB, "miners-own": b"\x02" * 32}},
        # A replaced signer.
        {"trusted_roots": {"nvidia-nras-root-1": b"\x03" * 32}},
        # A renamed signer, same key material.
        {"trusted_roots": {"some-other-root": ROOT_PUB}},
        # A widened enclave allow-list (SEC-TDX-1).
        {"allowed_measurements": frozenset(
            {SEV_MEAS, "sev-snp-measurement-sha384:" + "11" * 48}
        )},
        # Turning the GPU-measurement check off entirely.
        {"allowed_gpu_measurements": None},
        # A longer freshness window admits staler quotes.
        {"max_age_seconds": att.DEFAULT_MAX_AGE_SECONDS * 2},
    ],
)
def test_every_verdict_changing_field_changes_the_digest(change):
    """Each knob that can admit a quote the old policy refused must be visible."""
    assert att.attestation_policy_digest(
        _policy(**change)
    ) != att.attestation_policy_digest(_policy())


def test_a_policy_field_the_manifest_cannot_bind_is_refused_rather_than_dropped():
    """A new knob must break this loudly instead of silently escaping the digest.

    The whole failure being fixed is a verdict-deciding input that the posture
    record could not see change. Adding a field to `AttestationPolicy` without
    encoding it here would recreate that exactly, one field smaller, so the manifest
    checks its own completeness against the dataclass.
    """
    import dataclasses

    @dataclasses.dataclass(frozen=True)
    class _Grown(att.AttestationPolicy):
        require_debug_disabled: bool = True

    grown = _Grown(trusted_roots={"nvidia-nras-root-1": ROOT_PUB},
                   allowed_measurements=frozenset({SEV_MEAS}))
    with pytest.raises(att.AttestationError, match="does not bind"):
        att.attestation_policy_digest(grown)


@pytest.mark.parametrize(
    "policy,match",
    [
        (dict(trusted_roots={"root": "not-bytes"}), "raw public-key bytes"),
        (dict(trusted_roots={"": ROOT_PUB}), "non-empty strings"),
        (dict(allowed_measurements=SEV_MEAS), "set of measurement strings"),
        (dict(allowed_measurements=frozenset({7})), "entries must be strings"),
        (dict(max_age_seconds="3600"), "max_age_seconds must be an int"),
    ],
)
def test_a_policy_that_cannot_be_encoded_faithfully_refuses_to_digest(policy, match):
    """Refusing to digest is fail-closed: a partial digest binds a partial policy."""
    with pytest.raises(att.AttestationError, match=match):
        att.attestation_policy_digest(_policy(**policy))
