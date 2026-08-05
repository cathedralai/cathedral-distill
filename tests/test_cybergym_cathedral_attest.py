"""The Cathedral attest.v1 → CyberGym submission adapter, proven without hardware.

A fixture receipt mirrors the real `attest.v1 · tdx_cpu` worker receipt shape (kind
`tdx-1.5`, `verification.intel_verified` + `report_data_match`, sealed policy, a
`result.txt` artifact = the commitment). The tests prove the adapter binds an
attestation to exactly one `(task_id, poc, trace)` and fails closed on a wrong TEE,
an unverified quote, a replay/lift to another submission, an unsealed worker, and a
stale receipt — the properties that make an attested solve un-forgeable.
"""
from __future__ import annotations

import base64
import hashlib
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.cybergym_cathedral_attest import (  # noqa: E402
    commitment_sha256,
    tee_kind,
    verify_boot_attestation,
    verify_cathedral_attestation,
)

TASK = "arvo:368"
POC_SHA = "sha256:" + "ab" * 32
TRACE_ID = "sha256:" + "cd" * 32
NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def _receipt(*, task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID, kind="tdx-1.5",
             intel_verified=True, report_data_match=True, reuse="forbidden",
             egress="none", hardware="tdx_cpu", exit_code=0, status="ready",
             started="2026-07-30T11:59:00Z", artifact_sha=None):
    """A well-formed receipt whose result.txt artifact commits to (task,poc,trace)."""
    sha = artifact_sha if artifact_sha is not None else commitment_sha256(
        task_id=task_id, poc_sha256=poc_sha256, trace_id=trace_id)
    return {
        "receipt_id": "352e0bb4-2f92-4d18-b468-f65a93a46d77",
        "receipt_status": status, "exit_code": exit_code, "started_at": started,
        "files_sha256": "72" * 16, "artifacts_sha256": "58" * 16, "policy_sha256": "02" * 16,
        "task_policy": {"reuse": reuse, "egress": egress, "hardware_class": hardware},
        "verification": {"intel_verified": intel_verified, "report_data_match": report_data_match},
        "artifacts": [{"path": "result.txt", "sha256": sha, "size_bytes": 209}],
        "tee_attestation": {"kind": kind, "quote_b64": "BAACAIEA…",
                            "bound_digest": "sha256:57cd", "result_sha256": "3a39"},
    }


def _ok(receipt):
    return verify_cathedral_attestation(receipt, task_id=TASK, poc_sha256=POC_SHA,
                                        trace_id=TRACE_ID, now=NOW)


# --------------------------------------------------------------------------- #
# the happy path + tee mapping
# --------------------------------------------------------------------------- #
def test_a_genuine_sealed_tdx_receipt_binds_the_submission():
    r = _ok(_receipt())
    assert r.attested and r.tee == "intel_tdx" and r.reason == "attested_intel_tdx"
    assert r.artifact_sha256 == commitment_sha256(task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID)


def test_tee_kind_maps_tdx_and_refuses_sev():
    assert tee_kind({"tee_attestation": {"kind": "tdx-1.5"}}) == "intel_tdx"
    assert tee_kind({"tee_attestation": {"kind": "sev-snp-1"}}) == "amd_sev_snp"


# --------------------------------------------------------------------------- #
# fail-closed: wrong TEE / unverified / unsealed
# --------------------------------------------------------------------------- #
def test_an_amd_sev_quote_is_refused():
    r = _ok(_receipt(kind="sev-snp-1"))
    assert not r.attested and "Intel TDX" in r.reason


def test_unverified_quote_is_refused():
    assert not _ok(_receipt(intel_verified=False)).attested
    assert not _ok(_receipt(report_data_match=False)).attested


def test_unsealed_worker_is_refused():
    assert not _ok(_receipt(reuse="allowed")).attested       # replayable worker
    assert not _ok(_receipt(egress="allow:*")).attested      # can phone home
    assert not _ok(_receipt(hardware="cpu")).attested        # not a TEE
    assert not _ok(_receipt(exit_code=1)).attested
    assert not _ok(_receipt(status="pending")).attested


# --------------------------------------------------------------------------- #
# fail-closed: the binding — replay / lift / tamper
# --------------------------------------------------------------------------- #
def test_attestation_cannot_be_replayed_for_another_task():
    # a receipt attesting task arvo:1065 can't credit an arvo:368 submission
    other = _receipt(task_id="arvo:1065")
    r = verify_cathedral_attestation(other, task_id="arvo:368", poc_sha256=POC_SHA,
                                     trace_id=TRACE_ID, now=NOW)
    assert not r.attested and "does not bind" in r.reason


def test_attestation_cannot_be_paired_with_a_different_poc_or_trace():
    r = _receipt()
    assert not verify_cathedral_attestation(
        r, task_id=TASK, poc_sha256="sha256:" + "99" * 32, trace_id=TRACE_ID, now=NOW).attested
    assert not verify_cathedral_attestation(
        r, task_id=TASK, poc_sha256=POC_SHA, trace_id="sha256:" + "99" * 32, now=NOW).attested


def test_missing_result_artifact_is_refused():
    r = _receipt()
    r["artifacts"] = []
    assert not _ok(r).attested


def test_stale_attestation_is_refused():
    old = _receipt(started="2026-07-01T00:00:00Z")
    assert not _ok(old).attested


def test_a_naive_timestamp_does_not_crash_and_is_still_freshness_checked():
    # regression: a tz-less started_at must not raise (the "never raises" contract)
    # — it is read as UTC and judged by the same window, fresh or stale.
    assert _ok(_receipt(started="2026-07-30T11:59:00")).attested        # naive, ~1 min old
    assert not _ok(_receipt(started="2026-07-01T00:00:00")).attested    # naive, a month old


def test_a_missing_timestamp_fails_closed_not_open():
    # regression: omitting started_at must NOT bypass the staleness window (else an
    # old-but-genuine receipt replays forever by dropping the field).
    r = _receipt()
    del r["started_at"]
    a = _ok(r)
    assert not a.attested and "timestamp" in a.reason


def test_a_malformed_receipt_fails_closed_without_raising():
    assert not verify_cathedral_attestation({}, task_id=TASK, poc_sha256=POC_SHA,
                                            trace_id=TRACE_ID, now=NOW).attested


# --------------------------------------------------------------------------- #
# trustless mode: an injected raw-quote verifier
# --------------------------------------------------------------------------- #
def test_trustless_mode_verifies_the_raw_quote_and_ignores_the_issuer_flag():
    seen = {}

    def verifier(quote_b64, expected_rd_hex):
        seen["quote"] = quote_b64
        seen["rd"] = expected_rd_hex
        return True

    # even with Cathedral's own flags false, a passing raw-quote verify credits it
    r = verify_cathedral_attestation(_receipt(intel_verified=False, report_data_match=False),
                                     task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID,
                                     now=NOW, quote_verifier=verifier,
                                     artifacts_digest_recipe=lambda a: "58" * 16)
    assert r.attested and r.trustless and r.reason == "attested_intel_tdx_trustless"
    assert seen["quote"].startswith("BAAC") and len(seen["rd"]) == 64


def test_trustless_mode_fails_closed_when_the_quote_is_rejected():
    r = verify_cathedral_attestation(_receipt(), task_id=TASK, poc_sha256=POC_SHA,
                                     trace_id=TRACE_ID, now=NOW,
                                     quote_verifier=lambda q, rd: False,
                                     artifacts_digest_recipe=lambda a: "58" * 16)
    assert not r.attested and "raw TDX quote" in r.reason


# --------------------------------------------------------------------------- #
# custom.v1 boot quote — a sealed TDX worker running the real corpus image
# --------------------------------------------------------------------------- #
SSH_PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexampleexamplekey cathedral"


def _boot_receipt(*, ssh_pubkey=SSH_PUB, kind="tdx-1.5", intel_verified=True,
                  binding_verified=True, verified=True, status="ready", nonce="9c99da63",
                  started="2026-07-30T11:59:00Z"):
    """A custom.v1 boot receipt whose report_data binds the ssh key, per the real recipe
    report_data[0:32] = sha256(nonce_hex || base64(ssh_pubkey))."""
    pub_b64 = base64.b64encode(ssh_pubkey.strip().encode()).decode()
    rd = hashlib.sha256((nonce + pub_b64).encode()).hexdigest()
    return {"receipt_id": "74bb4a0b-9b61-4d10-bcfd-9a1d2e958b7d", "receipt_status": status,
            "kind": kind, "intel_verified": intel_verified, "intel_status": "verified",
            "binding_verified": binding_verified, "verified": verified,
            "nonce": nonce, "pubkey_b64": pub_b64, "report_data": rd,
            "quote_b64": "BAACAIEA…", "started_at": started}


def _boot(receipt, *, key=SSH_PUB, now=NOW, **kw):
    return verify_boot_attestation(receipt, expected_ssh_pubkey=key, now=now, **kw)


def test_a_genuine_boot_quote_binds_the_operator_ssh_key():
    a = _boot(_boot_receipt())
    assert a.attested and a.tee == "intel_tdx" and a.key_bound and a.miner_attested
    assert a.reason == "attested_intel_tdx_boot_key_bound"
    # SAFETY: a boot quote NEVER binds the PoC/trace, whatever else it proves
    assert a.result_bound is False


def test_boot_quote_without_an_expected_key_never_attests():
    # the closed footgun: with no expected key, attested=True could only mean "SOME
    # genuine TDX worker booted", which any party with any TDX worker satisfies.
    # The key is now a required argument, and an absent value refuses outright
    # rather than returning an attested-but-unbound result a caller could credit.
    with pytest.raises(TypeError, match="expected_ssh_pubkey"):
        verify_boot_attestation(_boot_receipt())
    a = verify_boot_attestation(_boot_receipt(), expected_ssh_pubkey=None, now=NOW)
    assert not a.attested and not a.key_bound and not a.miner_attested
    assert "never credit" in a.reason
    a = verify_boot_attestation(_boot_receipt(), expected_ssh_pubkey="  ", now=NOW)
    assert not a.attested and "never credit" in a.reason


def test_boot_quote_bound_to_a_different_key_is_refused():
    # a boot quote for someone else's key can't vouch for our reproduction
    a = _boot(_boot_receipt(ssh_pubkey="ssh-ed25519 AAAAotherkey x"))
    assert not a.attested and "bind the expected ssh key" in a.reason


def test_boot_quote_issuer_trust_still_requires_verified_flags():
    assert _boot(_boot_receipt()).attested                       # verified flags true
    assert not _boot(_boot_receipt(intel_verified=False, verified=False)).attested
    assert not _boot(_boot_receipt(binding_verified=False, verified=False)).attested
    assert not _boot(_boot_receipt(verified=False)).attested


def test_boot_quote_refuses_wrong_tee_and_unready():
    assert not _boot(_boot_receipt(kind="sev-snp-1")).attested
    assert not _boot(_boot_receipt(status="provisioning")).attested


def test_a_stale_boot_quote_is_refused():
    a = _boot(_boot_receipt(started="2026-07-01T00:00:00Z"))
    assert not a.attested and "stale" in a.reason


def test_a_future_dated_boot_quote_is_refused():
    a = _boot(_boot_receipt(started="2026-07-30T13:00:00Z"))  # an hour past NOW
    assert not a.attested and "future" in a.reason


def test_a_boot_quote_without_a_timestamp_fails_closed():
    # omitting started_at must not disable the freshness window, or an
    # old-but-genuine boot receipt replays forever by dropping the field
    r = _boot_receipt()
    del r["started_at"]
    a = _boot(r)
    assert not a.attested and "timestamp" in a.reason


def test_the_same_boot_quote_cannot_verify_indefinitely():
    # bounded like verify_cathedral_attestation: one enclave boot must not keep
    # vouching for submissions days or months later
    r = _boot_receipt()
    assert _boot(r, now=NOW).attested
    assert not _boot(r, now=NOW + timedelta(days=2)).attested


def test_boot_quote_trustless_mode_checks_the_raw_quote():
    seen = {}
    ok = _boot(_boot_receipt(intel_verified=False, verified=False),
               quote_verifier=lambda q, rd: seen.setdefault("q", q) or True)
    assert ok.attested and seen["q"].startswith("BAAC")
    bad = _boot(_boot_receipt(), quote_verifier=lambda q, rd: False)
    assert not bad.attested and "raw boot quote" in bad.reason


# --------------------------------------------------------------------------- #
# trustless seam: the artifacts list -> scalar binding (Phase 2)
# --------------------------------------------------------------------------- #
def test_trustless_without_the_scalar_recipe_fails_closed():
    """Passing a quote_verifier switches to the trustless path. Without the
    list->scalar binding recipe, report_data (which binds the scalar) and the
    commitment (which binds the list) are never tied, so a genuine quote could be
    re-paired with a swapped result.txt. The path must refuse, not trust."""
    r = verify_cathedral_attestation(
        _receipt(), task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID, now=NOW,
        quote_verifier=lambda q, rd: True,   # a quote that "verifies"
    )
    assert not r.attested
    assert "list→scalar binding recipe" in r.reason


def test_trustless_refuses_when_the_scalar_does_not_match_the_list():
    """With the recipe supplied, a receipt whose claimed artifacts_sha256 does not
    equal the recomputed digest of its artifacts[] list is refused — this is the
    swapped-result.txt attack."""
    r = verify_cathedral_attestation(
        _receipt(), task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID, now=NOW,
        quote_verifier=lambda q, rd: True,
        artifacts_digest_recipe=lambda artifacts: "ff" * 16,  # != receipt's "58"*16
    )
    assert not r.attested
    assert "does not match the artifacts[] list" in r.reason


def test_trustless_passes_when_scalar_binds_the_list_and_the_quote_verifies():
    """The whole chain holds: recomputed scalar == claimed scalar, and the quote
    verifies against report_data derived from it."""
    r = verify_cathedral_attestation(
        _receipt(), task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID, now=NOW,
        quote_verifier=lambda q, rd: True,
        artifacts_digest_recipe=lambda artifacts: "58" * 16,  # == receipt's claim
    )
    assert r.attested and r.trustless
    assert r.reason == "attested_intel_tdx_trustless"


def test_a_recipe_that_throws_is_a_refusal_never_a_pass():
    def broken(artifacts):
        raise ValueError("bad recipe")

    r = verify_cathedral_attestation(
        _receipt(), task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID, now=NOW,
        quote_verifier=lambda q, rd: True, artifacts_digest_recipe=broken,
    )
    assert not r.attested and "recipe failed" in r.reason


def test_trusted_issuer_default_is_unchanged_by_the_seam_fix():
    """No quote_verifier -> trusted-issuer path -> the scalar recipe is irrelevant."""
    assert _ok(_receipt()).attested


# --------------------------------------------------------------------------- #
# persistent-enclave path (#94/#95) — the enclave holds the signing key
# --------------------------------------------------------------------------- #
from cathedral_distill.cybergym_cathedral_attest import (  # noqa: E402
    EnclaveAttestation,
    enclave_commitment_bytes,
    verify_persistent_enclave_attestation,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

_ENCLAVE_KEY = Ed25519PrivateKey.generate()
_OUTSIDE_KEY = Ed25519PrivateKey.generate()


def _enclave_pub_b64(key=_ENCLAVE_KEY):
    return base64.b64encode(key.public_key().public_bytes_raw()).decode()


def _enclave_receipt(*, task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID,
                     verdict=None, sign_key=_ENCLAVE_KEY, pub_key=_ENCLAVE_KEY,
                     kind="tdx-1.5", intel_verified=True, binding_verified=True,
                     status="ready", nonce="9c99da63", started="2026-07-30T11:59:00Z",
                     sign_task=None, sign_poc=None, sign_trace=None, sign_verdict=...):
    """A persistent-enclave receipt: report_data binds the ENCLAVE public key and the
    enclave signs the (task, poc, trace[, verdict]) commitment with its own key.

    The sign_* overrides let a test sign a DIFFERENT message than the one the
    verifier will recompute, to prove a mismatched/looked-up commitment is refused.
    """
    pub_b64 = _enclave_pub_b64(pub_key)
    rd = hashlib.sha256((nonce + pub_b64).encode()).hexdigest()
    signed = enclave_commitment_bytes(
        task_id=task_id if sign_task is None else sign_task,
        poc_sha256=poc_sha256 if sign_poc is None else sign_poc,
        trace_id=trace_id if sign_trace is None else sign_trace,
        verdict=verdict if sign_verdict is ... else sign_verdict,
    )
    receipt = {
        "receipt_id": "e1c1a5e0-enclave", "receipt_status": status, "kind": kind,
        "intel_verified": intel_verified,
        "intel_status": "verified" if intel_verified else "failed",
        "binding_verified": binding_verified, "nonce": nonce,
        "enclave_pubkey_b64": pub_b64, "report_data": rd, "quote_b64": "BAACAIEA…",
        "started_at": started,
        "enclave_signature_b64": base64.b64encode(sign_key.sign(signed)).decode(),
    }
    if verdict is not None:
        receipt["verdict"] = verdict
    return receipt


def _enclave(receipt, **kw):
    kw.setdefault("now", NOW)
    return verify_persistent_enclave_attestation(
        receipt, task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID, **kw)


def test_persistent_enclave_solve_is_result_bound():
    a = _enclave(_enclave_receipt())
    assert isinstance(a, EnclaveAttestation)
    assert a.attested and a.tee == "intel_tdx"
    assert a.key_bound is True
    # the property the two simpler profiles cannot give together: real corpus AND
    # a signature that binds the exact solve.
    assert a.result_bound is True
    assert a.reason == "attested_intel_tdx_enclave_result_bound"
    assert a.enclave_key_b64 == _enclave_pub_b64()


def test_a_looked_up_poc_signed_outside_the_enclave_is_refused():
    # The whole point of #94: a miner with a valid boot quote but a PoC obtained
    # anywhere cannot produce the enclave key's signature over it. Signing with a
    # key other than the one the boot quote binds must fail closed.
    a = _enclave(_enclave_receipt(sign_key=_OUTSIDE_KEY))
    assert not a.attested and not a.result_bound
    assert "not signed by the attested enclave key" in a.reason


def test_report_data_must_bind_the_enclave_key_not_some_other_key():
    # boot quote binds a DIFFERENT public key than the signer/claimed key
    r = _enclave_receipt()
    r["report_data"] = hashlib.sha256(("9c99da63" + _enclave_pub_b64(_OUTSIDE_KEY)).encode()).hexdigest()
    a = _enclave(r)
    assert not a.attested and "does not bind the enclave public key" in a.reason


def test_commitment_cannot_be_replayed_for_another_task_or_poc():
    # signed for a different task than the verifier checks -> signature mismatch
    assert not _enclave(_enclave_receipt(sign_task="arvo:999")).attested
    assert not _enclave(_enclave_receipt(sign_poc="sha256:" + "00" * 32)).attested
    assert not _enclave(_enclave_receipt(sign_trace="sha256:" + "11" * 32)).attested


def test_in_enclave_verdict_is_carried_inside_the_signature():
    # #95: the differential runs in-enclave and the verdict is part of the signed
    # commitment, so an external party trusts PASS/FAIL from the signature alone.
    a = _enclave(_enclave_receipt(verdict="pass"), require_verdict=True)
    assert a.attested and a.result_bound and a.verdict == "pass"


def test_a_flipped_verdict_breaks_the_signature():
    # the enclave signed "pass"; the receipt claims "fail" -> recomputed bytes differ
    r = _enclave_receipt(verdict="pass", sign_verdict="pass")
    r["verdict"] = "fail"
    a = _enclave(r, require_verdict=True)
    assert not a.attested and not a.result_bound


def test_require_verdict_refuses_a_boot_only_commitment():
    # #95 mode demands the verdict be in the signature; a #94-shape commitment
    # (no verdict) is refused when the caller requires one.
    a = _enclave(_enclave_receipt(verdict=None), require_verdict=True)
    assert not a.attested and "no verdict" in a.reason


def test_enclave_path_is_stale_future_and_missing_timestamp_checked():
    assert not _enclave(_enclave_receipt(started="2026-07-01T00:00:00Z")).attested   # stale
    assert not _enclave(_enclave_receipt(started="2026-08-01T00:00:00Z")).attested   # future
    r = _enclave_receipt()
    r.pop("started_at")
    assert not _enclave(r).attested


def test_enclave_path_refuses_non_tdx_and_unverified():
    assert not _enclave(_enclave_receipt(kind="sev-snp-1")).attested
    assert not _enclave(_enclave_receipt(intel_verified=False)).attested
    assert not _enclave(_enclave_receipt(binding_verified=False)).attested


def test_enclave_path_fails_closed_on_a_malformed_receipt():
    assert not verify_persistent_enclave_attestation(
        {}, task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID, now=NOW).attested
    # a non-Ed25519 enclave key is refused, not crashed
    r = _enclave_receipt()
    r["enclave_pubkey_b64"] = base64.b64encode(b"tooshort").decode()
    assert not _enclave(r).attested


def test_enclave_trustless_mode_checks_the_raw_quote():
    ok = _enclave(_enclave_receipt(), quote_verifier=lambda q, rd: True)
    assert ok.attested and ok.trustless and ok.result_bound
    bad = _enclave(_enclave_receipt(), quote_verifier=lambda q, rd: False)
    assert not bad.attested and "failed independent verification" in bad.reason
