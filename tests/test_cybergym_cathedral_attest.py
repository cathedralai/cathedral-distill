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
# persistent-enclave path (#94/#95) — result-bound, on the real receipt shape
# --------------------------------------------------------------------------- #
import hashlib as _hashlib  # noqa: E402

from cathedral_distill.cybergym_cathedral_attest import (  # noqa: E402
    EnclaveAttestation,
    enclave_commitment_bytes,
    enclave_result_bytes,
    verify_persistent_enclave_attestation,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

_ENCLAVE_KEY = Ed25519PrivateKey.generate()
_OUTSIDE_KEY = Ed25519PrivateKey.generate()
APPROVED_WORKLOAD = "649e90742fe3bdb4f523b57429a51d0f29119011ddae5f86070b191a437519fa"


def _pub_b64(key=_ENCLAVE_KEY):
    return base64.b64encode(key.public_key().public_bytes_raw()).decode()


MINER = "5EnclaveMiner"
NONCE = "cgnonce-sha256:" + "ab" * 32


def _result_and_receipt(*, task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID,
                        miner_hotkey=MINER, nonce=NONCE,
                        verdict=None, sign_key=_ENCLAVE_KEY, pub_key=_ENCLAVE_KEY,
                        workload=APPROVED_WORKLOAD, cpu_tee="intel_tdx",
                        intel_verified=True, report_data_match=True,
                        execution_binding_verified=True, status="ready",
                        issued="2026-07-30T11:59:00Z",
                        sign_task=None, sign_poc=None, sign_trace=None,
                        sign_miner=None, sign_nonce=None, sign_verdict=...):
    """A live-shaped `cathedral_customer_receipt_v1` plus the enclave result whose
    sha256 it binds. sign_* overrides sign a DIFFERENT commitment than the envelope
    declares, to prove a tampered/looked-up result is refused."""
    sig = sign_key.sign(enclave_commitment_bytes(
        task_id=task_id if sign_task is None else sign_task,
        poc_sha256=poc_sha256 if sign_poc is None else sign_poc,
        trace_id=trace_id if sign_trace is None else sign_trace,
        miner_hotkey=miner_hotkey if sign_miner is None else sign_miner,
        nonce=nonce if sign_nonce is None else sign_nonce,
        verdict=verdict if sign_verdict is ... else sign_verdict))
    result = enclave_result_bytes(
        enclave_pubkey_b64=_pub_b64(pub_key), task_id=task_id, poc_sha256=poc_sha256,
        trace_id=trace_id, miner_hotkey=miner_hotkey, nonce=nonce, verdict=verdict,
        signature_b64=base64.b64encode(sig).decode())
    receipt = {
        "receipt_id": "19ed3639-enclave", "receipt_status": status,
        "schema": "cathedral_customer_receipt_v1", "cpu_tee": cpu_tee,
        "execution_class": "tdx_cpu" if cpu_tee == "intel_tdx" else "cc_gpu",
        "issued_at": issued,
        "workload_sha256": workload,
        "result_sha256": _hashlib.sha256(result).hexdigest(),
        "intel_verified": intel_verified, "report_data_match": report_data_match,
        "execution_binding_verified": execution_binding_verified,
    }
    return result, receipt


def _verify(result, receipt, *, workload=APPROVED_WORKLOAD, miner_hotkey=MINER,
            nonce=NONCE, **kw):
    kw.setdefault("now", NOW)
    return verify_persistent_enclave_attestation(
        receipt, task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID,
        miner_hotkey=miner_hotkey, nonce=nonce,
        result_bytes=result, expected_workload_sha256=workload, **kw)


def test_persistent_enclave_solve_is_result_bound():
    a = _verify(*_result_and_receipt())
    assert isinstance(a, EnclaveAttestation)
    assert a.attested and a.tee == "intel_tdx"
    assert a.result_bound and a.workload_bound and a.signature_bound
    assert a.reason == "attested_intel_tdx_enclave_result_bound"
    assert a.enclave_key_b64 == _pub_b64()


def test_a_workload_that_is_not_the_approved_solver_is_refused():
    # The anti-lookup control: only the approved solver workload may earn. A miner
    # who runs a "print the looked-up answer" workload has a different workload_sha256.
    result, receipt = _result_and_receipt(workload="00" * 32)
    a = _verify(result, receipt)
    assert not a.attested and "approved solver workload" in a.reason
    # and an empty expected workload is itself a refusal, never a wildcard
    result, receipt = _result_and_receipt()
    a = _verify(result, receipt, workload="")
    assert not a.attested and "unpinned workload" in a.reason


def test_a_swapped_result_breaks_the_result_sha256_binding():
    # attest a genuine result, then submit different result_bytes: the hash no
    # longer matches the attested result_sha256.
    result, receipt = _result_and_receipt(verdict="pass")
    other, _ = _result_and_receipt(task_id="arvo:999", verdict="pass")
    a = _verify(other, receipt)
    assert not a.attested and "do not match the attested result_sha256" in a.reason


def test_result_that_commits_to_another_task_is_refused():
    # a well-formed, correctly-hashed result whose commitment is for another task
    result, receipt = _result_and_receipt(task_id="arvo:999")
    a = _verify(result, receipt)  # verifier still checks against TASK
    assert not a.attested and "different task/poc/trace" in a.reason


def test_a_tampered_enclave_signature_is_refused():
    # envelope declares (task,poc,trace) but the signature is over a different one
    result, receipt = _result_and_receipt(sign_task="arvo:999")
    a = _verify(result, receipt)
    assert not a.attested and "signature does not verify" in a.reason


def test_in_enclave_verdict_is_carried_in_the_result():
    a = _verify(*_result_and_receipt(verdict="pass"), require_verdict=True)
    assert a.attested and a.result_bound and a.verdict == "pass"


def test_a_flipped_verdict_breaks_the_signature():
    # signed "pass" but the envelope commitment says "fail": recomputed bytes differ
    result, receipt = _result_and_receipt(verdict="fail", sign_verdict="pass")
    a = _verify(result, receipt, require_verdict=True)
    assert not a.attested


def test_require_verdict_refuses_a_verdict_less_result():
    a = _verify(*_result_and_receipt(verdict=None), require_verdict=True)
    assert not a.attested and "no verdict" in a.reason


def test_untrusted_receipt_fields_are_refused():
    assert not _verify(*_result_and_receipt(intel_verified=False)).attested
    assert not _verify(*_result_and_receipt(report_data_match=False)).attested
    assert not _verify(*_result_and_receipt(execution_binding_verified=False)).attested


def test_receipt_verifier_seam_gates_and_marks_trustless():
    ok = _verify(*_result_and_receipt(), receipt_verifier=lambda r: True)
    assert ok.attested and ok.trustless and ok.result_bound
    bad = _verify(*_result_and_receipt(), receipt_verifier=lambda r: False)
    assert not bad.attested and "failed independent verification" in bad.reason
    boom = _verify(*_result_and_receipt(), receipt_verifier=lambda r: 1 / 0)
    assert not boom.attested and "receipt verifier failed" in boom.reason


def test_enclave_path_freshness_is_bounded():
    assert not _verify(*_result_and_receipt(issued="2026-07-01T00:00:00Z")).attested   # stale
    assert not _verify(*_result_and_receipt(issued="2026-08-01T00:00:00Z")).attested   # future
    result, receipt = _result_and_receipt()
    receipt.pop("issued_at")
    assert not _verify(result, receipt).attested


def test_enclave_path_refuses_non_tdx():
    assert not _verify(*_result_and_receipt(cpu_tee="amd_sev_snp")).attested


def test_enclave_path_fails_closed_on_malformed_input():
    # empty receipt / not-ready
    assert not verify_persistent_enclave_attestation(
        {}, task_id=TASK, poc_sha256=POC_SHA, trace_id=TRACE_ID,
        miner_hotkey=MINER, nonce=NONCE,
        result_bytes=b"{}", expected_workload_sha256=APPROVED_WORKLOAD, now=NOW).attested
    # result bytes that hash-match the receipt but are not an enclave envelope
    junk = b'{"schema":"nope"}'
    _, receipt = _result_and_receipt()
    receipt["result_sha256"] = _hashlib.sha256(junk).hexdigest()
    a = _verify(junk, receipt)
    assert not a.attested and "not an enclave result envelope" in a.reason


def test_a_result_signed_for_one_miner_is_refused_for_another():
    # #104 self-review fix: the commitment binds miner_hotkey + nonce, so another
    # miner (or another dispatch) cannot replay a genuine result and earn credit.
    result, receipt = _result_and_receipt(verdict="pass")
    assert _verify(result, receipt, require_verdict=True).attested
    assert not _verify(result, receipt, miner_hotkey="5OtherMiner").attested
    assert not _verify(result, receipt, nonce="cgnonce-sha256:" + "99" * 32).attested
