"""The Intel-TDX attestation gate for the CyberGym miner track.

A solve credits work units ONLY when it carries a valid Intel-TDX attestation
bound to the exact submission. These tests prove: an attested solve earns; and
every failure mode — no attestation, wrong TEE, untrusted signer, unpinned
measurement, replayed/rebound report_data, stale — earns exactly zero, while the
raw `solved` (the crash happened) stays true. The hardware-free path (no policy)
is unchanged.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill.attestation import ATTESTATION_SCHEMA, AttestationPolicy, sign_attestation
from cathedral_distill.cybergym_attest import (
    CyberGymAttestError,
    submission_report_data,
    verify_submission_attestation,
)
from cathedral_distill.cybergym_protocol import (
    DispatchedTask,
    DispatchMessage,
    SubmissionEnvelope,
    _trace_from_dict,
    process_submission,
)
from cathedral_distill.cybergym_synthetic import SyntheticTaskSource, generate_bug

MEASURE = "tdx-mrtd:" + "ab" * 24            # a pinned known-good enclave measurement
ROOT_SEED = bytes(range(32))
ROOT_ID = "intel-dcap-root-1"
ROOT_PUB = Ed25519PrivateKey.from_private_bytes(ROOT_SEED).public_key().public_bytes_raw()
ISSUED = "2026-07-29T12:00:00Z"
NOW = datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC)
MINER = "5AttestedMiner"
MODEL = "sha256:" + hashlib.sha256(b"attested-model").hexdigest()

POLICY = AttestationPolicy(
    trusted_roots={ROOT_ID: ROOT_PUB},
    allowed_measurements=frozenset({MEASURE}),
)


def _make_token(*, report_data, tee="intel_tdx", measurement=MEASURE, issued_at=ISSUED,
                key_id=ROOT_ID, seed=ROOT_SEED, gpu_measurement=None):
    unsigned = {
        "schema": ATTESTATION_SCHEMA, "tee": tee, "measurement": measurement,
        "gpu_measurement": gpu_measurement, "report_data": report_data,
        "issued_at": issued_at, "signing_key_id": key_id,
    }
    return sign_attestation(unsigned, seed)


def _floor_trace(task_id, poc_sha256):
    """A trace that clears the structural floor, so trainable tracks creditability."""
    long = (
        "I open the delivered vulnerable build at synth.c:1 and read the magic guard, then at "
        "synth.c:2 the unclamped big-endian length parse, then at synth.c:3 the fixed stack "
        "buffer declaration, and finally at synth.c:4 the memcpy that copies the attacker length "
        "into the buffer with no relation to its size, which is precisely the overflow the "
        "vulnerable build exhibits and the patched build guards against before the copy runs; "
        "because the length field is fully attacker-controlled and never clamped against the "
        "destination size, any value larger than the buffer will overrun adjacent stack memory."
    )
    steps = [
        {"step": 1, "action": "read_file", "thought": long},
        {"step": 2, "action": "read_file",
         "thought": "I re-read the length parse at synth.c:2 and the buffer declaration at synth.c:3 "
                    "carefully to fix the exact overflowing length I need, confirming the buffer is a "
                    "fixed-size stack array and the length is read straight from attacker bytes with no bound"},
        {"step": 3, "action": "reason",
         "thought": "the differential at synth.c:4 is crash-on-vulnerable and clean-on-patched, so my "
                    "trigger must reproduce the magic exactly and then carry a length strictly greater than "
                    "the buffer size, which the vulnerable build copies without checking while the patched "
                    "build rejects it before the copy executes"},
        {"step": 4, "action": "write_poc",
         "thought": "I construct the input as magic bytes then a big-endian length just past the buffer "
                    "size then that many filler payload bytes, so the memcpy at synth.c:4 writes beyond the "
                    "buffer and corrupts adjacent stack memory on the vulnerable build only"},
        {"step": 5, "action": "verify",
         "thought": "I confirm the crafted input crashes the vulnerable build under the address sanitizer "
                    "and the patched build exits cleanly at synth.c:4, matching the solved condition exactly"},
    ]
    return {"task_id": task_id, "poc_sha256": poc_sha256, "model_id": "cybergym/enclave",
            "steps": steps, "licence": "cathedral-corpus-v1",
            "model_seal": "sha256:" + hashlib.sha256(b"seal").hexdigest()}


def _fixture(nonce="ance10ab", *, size=1):
    """Draw one synthetic bug and build the dispatch + a correct PoC for task 0."""
    source = SyntheticTaskSource()
    batch = source.draw(size=size, nonce=nonce)
    task = batch.tasks[0]
    bug = generate_bug(nonce, 0, level=int(task.level))
    dt = DispatchedTask(
        task_id=task.task_id,
        level=int(task.level),
        binary_digest=task.binary_digest,
        context={},
    )
    msg = DispatchMessage(
        network="finney",
        netuid=39,
        source_epoch=11,
        batch_id=batch.batch_id,
        nonce=nonce,
        miner_hotkey=MINER,
        model_commitment=MODEL,
        valid_from_block=1,
        valid_until_block=999,
        tasks=(dt,),
    )
    return source, msg, task.task_id, bug.trigger


def _trace_id_of(task_id, digest):
    return _trace_from_dict(_floor_trace(task_id, digest)).trace_id()


def _envelope(batch_id, task_id, poc, *, attestation=None, miner=MINER):
    digest = "sha256:" + hashlib.sha256(poc).hexdigest()
    return SubmissionEnvelope(
        batch_id=batch_id, task_id=task_id, miner_hotkey=miner,
        poc_base64=base64.b64encode(poc).decode(), trace=_floor_trace(task_id, digest),
        attestation=attestation,
    )


def _attested_envelope(msg, task_id, poc, **over):
    digest = "sha256:" + hashlib.sha256(poc).hexdigest()
    rd = submission_report_data(
        batch_id=msg.batch_id,
        task_id=task_id,
        poc_sha256=digest,
        trace_id=_trace_id_of(task_id, digest),
        miner_hotkey=MINER,
        model_commitment=msg.model_commitment,
    )
    token = _make_token(report_data=rd, **over)
    return _envelope(msg.batch_id, task_id, poc, attestation=base64.b64encode(token).decode())


# --------------------------------------------------------------------------- #
# report_data binding
# --------------------------------------------------------------------------- #
def test_report_data_is_deterministic_and_binds_every_field():
    base = dict(
        batch_id="b", task_id="t", poc_sha256="p", trace_id="tr", miner_hotkey="m",
        model_commitment="sha256:model",
    )
    rd = submission_report_data(**base)
    assert rd == submission_report_data(**base)          # deterministic
    assert len(rd) == 64 and all(c in "0123456789abcdef" for c in rd)
    for field in base:
        changed = dict(base, **{field: base[field] + "x"})
        assert submission_report_data(**changed) != rd    # each field is bound (incl. trace_id)


def test_report_data_requires_all_fields():
    with pytest.raises(CyberGymAttestError):
        submission_report_data(
            batch_id="", task_id="t", poc_sha256="p", trace_id="tr", miner_hotkey="m",
            model_commitment="sha256:model",
        )


def test_private_artifact_digest_is_bound_into_the_tdx_report_data():
    base = {
        "batch_id": "b",
        "task_id": "t",
        "poc_sha256": "sha256:" + "a" * 64,
        "trace_id": "sha256:" + "b" * 64,
        "miner_hotkey": "m",
        "model_commitment": "sha256:" + "c" * 64,
        "artifact_digest": "sha256:" + "d" * 64,
    }
    report_data = submission_report_data(**base)
    assert report_data != submission_report_data(**(base | {
        "artifact_digest": "sha256:" + "e" * 64,
    }))
    token = _make_token(report_data=report_data)
    assert verify_submission_attestation(token, policy=POLICY, now=NOW, **base)["tee"] == "intel_tdx"
    with pytest.raises(CyberGymAttestError, match="report_data"):
        verify_submission_attestation(
            token,
            policy=POLICY,
            now=NOW,
            **(base | {"artifact_digest": "sha256:" + "e" * 64}),
        )


# --------------------------------------------------------------------------- #
# process_submission: attested solve earns
# --------------------------------------------------------------------------- #
def test_attested_solve_is_creditable_and_trainable():
    source, msg, task_id, poc = _fixture()
    env = _attested_envelope(msg, task_id, poc)
    out = process_submission(env, msg, source.backend, attestation_policy=POLICY, now=NOW)
    assert out.solved and out.attested and out.creditable
    assert out.work_units > 0
    assert out.trainable and out.reason == "solved_trainable"


def test_no_policy_keeps_hardware_free_behaviour():
    """Without an attestation policy, a solve earns with no attestation at all."""
    source, msg, task_id, poc = _fixture()
    env = _envelope(msg.batch_id, task_id, poc, attestation=None)
    out = process_submission(env, msg, source.backend)   # no policy
    assert out.solved and out.attested and out.creditable and out.work_units > 0


# --------------------------------------------------------------------------- #
# every attestation failure mode: rejected before Docker and earns zero
# --------------------------------------------------------------------------- #
def test_missing_attestation_earns_zero():
    source, msg, task_id, poc = _fixture()
    env = _envelope(msg.batch_id, task_id, poc, attestation=None)
    backend_calls = []

    def backend(*args):
        backend_calls.append(args)
        raise AssertionError("missing attestation reached the differential backend")

    out = process_submission(env, msg, backend, attestation_policy=POLICY, now=NOW)
    assert not out.solved and not out.attested and not out.creditable
    assert out.work_units == Decimal(0) and not out.trainable
    assert out.reason == "rejected_unattested:missing_tdx_attestation"
    assert backend_calls == []


def test_wrong_tee_earns_zero():
    source, msg, task_id, poc = _fixture()
    env = _attested_envelope(msg, task_id, poc, tee="amd_sev_snp")
    out = process_submission(env, msg, source.backend, attestation_policy=POLICY, now=NOW)
    assert not out.solved and not out.attested and out.work_units == Decimal(0)
    assert "Intel TDX" in out.reason or "tdx_attestation_invalid" in out.reason


def test_untrusted_signer_earns_zero():
    source, msg, task_id, poc = _fixture()
    env = _attested_envelope(msg, task_id, poc, seed=bytes(range(1, 33)))  # not the trusted root
    out = process_submission(env, msg, source.backend, attestation_policy=POLICY, now=NOW)
    assert not out.solved and not out.attested and out.work_units == Decimal(0)


def test_unpinned_measurement_earns_zero():
    source, msg, task_id, poc = _fixture()
    env = _attested_envelope(msg, task_id, poc, measurement="tdx-mrtd:deadbeef")  # not allow-listed
    out = process_submission(env, msg, source.backend, attestation_policy=POLICY, now=NOW)
    assert not out.solved and not out.attested and out.work_units == Decimal(0)


def test_replayed_attestation_for_another_poc_earns_zero():
    """An attestation bound to a DIFFERENT PoC cannot be reused for this one."""
    source, msg, task_id, poc = _fixture()
    other_poc = poc + b"X"                                  # different bytes -> different digest
    other_digest = "sha256:" + hashlib.sha256(other_poc).hexdigest()
    real_digest = "sha256:" + hashlib.sha256(poc).hexdigest()
    rd = submission_report_data(
        batch_id=msg.batch_id,
        task_id=task_id,
        poc_sha256=other_digest,
        trace_id=_trace_id_of(task_id, real_digest),
        miner_hotkey=MINER,
        model_commitment=msg.model_commitment,
    )
    token = _make_token(report_data=rd)  # bound to other_poc
    env = _envelope(msg.batch_id, task_id, poc, attestation=base64.b64encode(token).decode())
    out = process_submission(env, msg, source.backend, attestation_policy=POLICY, now=NOW)
    assert not out.solved and not out.attested and out.work_units == Decimal(0)


def test_attestation_from_another_miner_earns_zero():
    """A valid attestation from miner A cannot credit miner B's submission."""
    source, msg, task_id, poc = _fixture()
    digest = "sha256:" + hashlib.sha256(poc).hexdigest()
    rd_other = submission_report_data(
        batch_id=msg.batch_id,
        task_id=task_id,
        poc_sha256=digest,
        trace_id=_trace_id_of(task_id, digest),
        miner_hotkey="5SomeoneElse",
        model_commitment=msg.model_commitment,
    )
    token = _make_token(report_data=rd_other)
    env = _envelope(msg.batch_id, task_id, poc, attestation=base64.b64encode(token).decode())
    out = process_submission(env, msg, source.backend, attestation_policy=POLICY, now=NOW)
    assert not out.solved and not out.attested and out.work_units == Decimal(0)


def test_stale_attestation_earns_zero():
    source, msg, task_id, poc = _fixture()
    env = _attested_envelope(msg, task_id, poc, issued_at="2026-07-20T00:00:00Z")  # >1 day old
    out = process_submission(env, msg, source.backend, attestation_policy=POLICY, now=NOW)
    assert not out.solved and not out.attested and out.work_units == Decimal(0)


def test_garbage_attestation_is_soft_reject_not_crash():
    source, msg, task_id, poc = _fixture()
    env = _envelope(msg.batch_id, task_id, poc, attestation="!!!not base64!!!")
    out = process_submission(env, msg, source.backend, attestation_policy=POLICY, now=NOW)
    assert not out.solved and not out.attested and out.work_units == Decimal(0)


def test_swapped_trace_earns_zero():
    """An attestation bound to trace A cannot vouch for a swapped-in trace B — the
    enclave must commit to the exact trajectory that lands in the corpus."""
    source, msg, task_id, poc = _fixture()
    env = _attested_envelope(msg, task_id, poc)          # attestation bound to the real floor trace
    swapped = dict(env.trace)
    swapped["model_id"] = "cybergym/outsourced-trace"    # -> different trace_id, still floor-clearing
    env2 = SubmissionEnvelope(batch_id=env.batch_id, task_id=env.task_id, miner_hotkey=env.miner_hotkey,
                              poc_base64=env.poc_base64, trace=swapped, attestation=env.attestation)
    out = process_submission(env2, msg, source.backend, attestation_policy=POLICY, now=NOW)
    assert not out.solved and not out.attested and out.work_units == Decimal(0)


def test_attestation_cannot_be_reused_for_a_different_model_commitment():
    source, msg, task_id, poc = _fixture()
    env = _attested_envelope(msg, task_id, poc)
    changed = replace(
        msg, model_commitment="sha256:" + hashlib.sha256(b"different-model").hexdigest()
    )
    out = process_submission(
        env, changed, source.backend, attestation_policy=POLICY, now=NOW
    )
    assert not out.solved and not out.attested and out.work_units == Decimal(0)


def test_service_requires_attestation_policy_by_default(tmp_path):
    """Fail-closed: the stateful service refuses to start without a policy unless
    the operator explicitly opts out (a forgotten kwarg must not credit unattested)."""
    from cathedral_distill.cybergym_holdout import Holdout
    from cathedral_distill.cybergym_scores import CyberGymScoreStore, CyberGymSolveStore
    from cathedral_distill.cybergym_protocol import CyberGymCorpusStore, ProtocolError
    from cathedral_distill.cybergym_service import CyberGymService
    from cathedral_distill.cybergym_validator import ChainContext
    chain = ChainContext(block=1, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
                         source_epoch=11, valid_from_block=1, valid_until_block=999)
    common = dict(backend=lambda *a: 0, corpus_store=CyberGymCorpusStore(":memory:"),
                  score_store=CyberGymScoreStore(":memory:", durability_required=False),
                  solve_store=CyberGymSolveStore(str(tmp_path / "solves.sqlite")),
                  validator_hotkey="5V",
                  private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
                  signing_key_id="cybergym-1", batch_size=1, cutoff=None, as_of=None,
                  gates_required=False)
    with pytest.raises(ProtocolError, match="attestation policy"):  # no policy -> refuse
        CyberGymService(Holdout(pool=SyntheticTaskSource(), _context={}), chain, **common)


# --------------------------------------------------------------------------- #
# direct verifier unit checks
# --------------------------------------------------------------------------- #
def test_verify_submission_attestation_accepts_and_rejects():
    rd = submission_report_data(
        batch_id="b", task_id="t", poc_sha256="p", trace_id="tr", miner_hotkey="m",
        model_commitment="sha256:model",
    )
    good = _make_token(report_data=rd)
    doc = verify_submission_attestation(
        good,
        batch_id="b",
        task_id="t",
        poc_sha256="p",
        trace_id="tr",
        miner_hotkey="m",
        model_commitment="sha256:model",
        policy=POLICY,
        now=NOW,
    )
    assert doc["tee"] == "intel_tdx"
    with pytest.raises(CyberGymAttestError):  # rebound trace -> mismatch
        verify_submission_attestation(
            good,
            batch_id="b",
            task_id="t",
            poc_sha256="p",
            trace_id="OTHER",
            miner_hotkey="m",
            model_commitment="sha256:model",
            policy=POLICY,
            now=NOW,
        )


# --------------------------------------------------------------------------- #
# service-level: only attested solvers earn AND compose into the lane
# --------------------------------------------------------------------------- #
def test_service_only_attested_miner_earns_and_composes(tmp_path):
    from cathedral_distill.cybergym_holdout import Holdout
    from cathedral_distill.cybergym_scores import CyberGymScoreStore, CyberGymSolveStore
    from cathedral_distill.cybergym_protocol import CyberGymCorpusStore
    from cathedral_distill.cybergym_service import CyberGymService
    from cathedral_distill.cybergym_validator import ChainContext

    source = SyntheticTaskSource()
    chain = ChainContext(block=100, block_hash="0x" + "cd" * 32, network="finney", netuid=39,
                         source_epoch=11, valid_from_block=1, valid_until_block=999)
    svc = CyberGymService(
        Holdout(pool=source, _context={}), chain, backend=source.backend,
        corpus_store=CyberGymCorpusStore(":memory:"),
        score_store=CyberGymScoreStore(":memory:", durability_required=False),
        solve_store=CyberGymSolveStore(str(tmp_path / "solves.sqlite")),
        validator_hotkey="5Validator",
        private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
        signing_key_id="cybergym-1", batch_size=2, cutoff=None, as_of=None,
        attestation_policy=POLICY, attestation_now=NOW, gates_required=False,
        # this test scores synthetic tasks on purpose, to prove the ATTESTATION gate
        # decides the reward; synthetic tasks are non-rewarding by default, and an
        # attested service refuses to credit them without this explicit acknowledgment
        credit_synthetic_tasks=True,
        acknowledge_synthetic_is_gameable=True,
    )
    commit = "sha256:" + hashlib.sha256(b"m").hexdigest()

    def solve_all(miner, *, attest):
        msg = svc.dispatch_for(miner, commit)
        for t in msg.tasks:
            poc = source._bugs[t.task_id].trigger          # the correct crashing input
            digest = "sha256:" + hashlib.sha256(poc).hexdigest()
            att = None
            if attest:
                rd = submission_report_data(
                    batch_id=msg.batch_id,
                    task_id=t.task_id,
                    poc_sha256=digest,
                    trace_id=_trace_id_of(t.task_id, digest),
                    miner_hotkey=miner,
                    model_commitment=msg.model_commitment,
                )
                att = base64.b64encode(_make_token(report_data=rd)).decode()
            env = SubmissionEnvelope(batch_id=msg.batch_id, task_id=t.task_id, miner_hotkey=miner,
                                     poc_base64=base64.b64encode(poc).decode(),
                                     trace=_floor_trace(t.task_id, digest), attestation=att)
            yield svc.submit(env)

    attested_out = list(solve_all("5Attested", attest=True))
    unattested_out = list(solve_all("5Unattested", attest=False))
    # Only attested submissions reach the differential backend and can be solved.
    assert all(o.solved for o in attested_out)
    assert not any(o.solved for o in unattested_out)
    # Only the attested miner is creditable.
    assert all(o.creditable for o in attested_out)
    assert not any(o.creditable for o in unattested_out)

    svc.score_epoch(issued_at="2026-07-29T12:00:00.000000Z")
    scores = svc._scores.epoch_scores(11)
    assert scores.get("5Attested", Decimal(0)) > 0
    assert "5Unattested" not in scores                     # never entered the reward pool

    lane = svc.compose_lane(allocation=Decimal("0.90"))
    holders = {c.miner_hotkey for c in lane.contributions}
    assert holders == {"5Attested"}


# --------------------------------------------------------------------------- #
# #61: a submission that attests with a REAL Cathedral receipt reaches the gate
# --------------------------------------------------------------------------- #
import json as _json  # noqa: E402

from cathedral_distill.cybergym_attest import (  # noqa: E402
    RECEIPT_ATTESTATION_SCHEMA,
    CathedralReceiptPolicy,
    verify_submission_receipt,
)
from cathedral_distill.cybergym_cathedral_attest import (  # noqa: E402
    commitment_sha256,
    enclave_commitment_bytes,
    enclave_result_bytes,
)
from cathedral_distill.cybergym_verifier import poc_digest  # noqa: E402

_FRESH = "2026-07-29T11:59:00Z"


def _attest_v1_receipt(task_id, poc, trace_id, **over):
    pd = poc_digest(poc)
    receipt = {
        "receipt_id": "r-attestv1", "receipt_status": "ready", "kind": "tdx-1.5",
        "exit_code": 0,
        "task_policy": {"hardware_class": "tdx_cpu", "reuse": "forbidden", "egress": "none"},
        "started_at": _FRESH,
        "artifacts": [{"path": "result.txt",
                       "sha256": commitment_sha256(task_id=task_id, poc_sha256=pd, trace_id=trace_id)}],
        "verification": {"intel_verified": True, "report_data_match": True},
    }
    receipt.update(over)
    return receipt


def _enclave_receipt_and_result(task_id, poc, trace_id, *, miner_hotkey, nonce,
                                verdict="pass", workload="wl-approved"):
    key = Ed25519PrivateKey.generate()
    pd = poc_digest(poc)
    sig = key.sign(enclave_commitment_bytes(
        task_id=task_id, poc_sha256=pd, trace_id=trace_id,
        miner_hotkey=miner_hotkey, nonce=nonce, verdict=verdict))
    result = enclave_result_bytes(
        enclave_pubkey_b64=base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        task_id=task_id, poc_sha256=pd, trace_id=trace_id,
        miner_hotkey=miner_hotkey, nonce=nonce, verdict=verdict,
        signature_b64=base64.b64encode(sig).decode())
    receipt = {
        "receipt_id": "r-enc", "receipt_status": "ready",
        "schema": "cathedral_customer_receipt_v1", "cpu_tee": "intel_tdx",
        "execution_class": "tdx_cpu", "issued_at": _FRESH, "workload_sha256": workload,
        "result_sha256": hashlib.sha256(result).hexdigest(), "intel_verified": True,
        "report_data_match": True, "execution_binding_verified": True,
    }
    return receipt, result


def _receipt_attestation(profile, receipt, result=None):
    doc = {"schema": RECEIPT_ATTESTATION_SCHEMA, "profile": profile, "receipt": receipt}
    if result is not None:
        doc["result_b64"] = base64.b64encode(result).decode()
    return base64.b64encode(_json.dumps(doc).encode()).decode()


def test_attest_v1_receipt_reaches_the_reward_path():
    source, msg, task_id, poc = _fixture()
    digest = "sha256:" + hashlib.sha256(poc).hexdigest()
    tid = _trace_id_of(task_id, digest)
    att = _receipt_attestation("attest.v1", _attest_v1_receipt(task_id, poc, tid))
    env = _envelope(msg.batch_id, task_id, poc, attestation=att)
    out = process_submission(
        env, msg, source.backend, cathedral_receipt_policy=CathedralReceiptPolicy(), now=NOW)
    assert out.creditable and out.solved


def test_persistent_enclave_receipt_reaches_the_reward_path():
    source, msg, task_id, poc = _fixture()
    digest = "sha256:" + hashlib.sha256(poc).hexdigest()
    tid = _trace_id_of(task_id, digest)
    receipt, result = _enclave_receipt_and_result(task_id, poc, tid, miner_hotkey=MINER, nonce=msg.nonce, workload="wl-approved")
    att = _receipt_attestation("persistent_enclave", receipt, result)
    env = _envelope(msg.batch_id, task_id, poc, attestation=att)
    policy = CathedralReceiptPolicy(expected_workload_sha256="wl-approved")
    out = process_submission(env, msg, source.backend, cathedral_receipt_policy=policy, now=NOW)
    assert out.creditable and out.solved


def test_a_receipt_bound_to_another_task_earns_zero():
    source, msg, task_id, poc = _fixture()
    digest = "sha256:" + hashlib.sha256(poc).hexdigest()
    tid = _trace_id_of(task_id, digest)
    # the receipt commits to a DIFFERENT task than the submission
    bad = _attest_v1_receipt("arvo:999", poc, tid)
    att = _receipt_attestation("attest.v1", bad)
    env = _envelope(msg.batch_id, task_id, poc, attestation=att)
    out = process_submission(
        env, msg, source.backend, cathedral_receipt_policy=CathedralReceiptPolicy(), now=NOW)
    assert not out.creditable and "tdx_attestation_invalid" in out.reason


def test_a_persistent_enclave_receipt_needs_the_approved_workload_pin():
    source, msg, task_id, poc = _fixture()
    digest = "sha256:" + hashlib.sha256(poc).hexdigest()
    tid = _trace_id_of(task_id, digest)
    receipt, result = _enclave_receipt_and_result(task_id, poc, tid, miner_hotkey=MINER, nonce=msg.nonce, workload="wl-attacker")
    att = _receipt_attestation("persistent_enclave", receipt, result)
    env = _envelope(msg.batch_id, task_id, poc, attestation=att)
    # policy pins a DIFFERENT approved workload -> the attacker workload is refused
    policy = CathedralReceiptPolicy(expected_workload_sha256="wl-approved")
    out = process_submission(env, msg, source.backend, cathedral_receipt_policy=policy, now=NOW)
    assert not out.creditable
    # and with no workload pin at all, the persistent-enclave profile refuses
    out2 = process_submission(
        env, msg, source.backend, cathedral_receipt_policy=CathedralReceiptPolicy(), now=NOW)
    assert not out2.creditable and "approved workload pin" in out2.reason


def test_a_receipt_with_only_the_cc_policy_configured_is_refused():
    # a Cathedral receipt arrives but only the (Ed25519) cc policy is set: the schema
    # does not match the cc token, and there is no receipt policy to accept it.
    source, msg, task_id, poc = _fixture()
    digest = "sha256:" + hashlib.sha256(poc).hexdigest()
    tid = _trace_id_of(task_id, digest)
    att = _receipt_attestation("attest.v1", _attest_v1_receipt(task_id, poc, tid))
    env = _envelope(msg.batch_id, task_id, poc, attestation=att)
    out = process_submission(env, msg, source.backend, attestation_policy=POLICY, now=NOW)
    assert not out.creditable and "no cathedral_receipt_policy" in out.reason


def test_verify_submission_receipt_rejects_an_unknown_profile():
    receipt = _attest_v1_receipt("arvo:1", b"poc", "sha256:" + "cd" * 32)
    with pytest.raises(Exception) as exc:
        verify_submission_receipt(
            {"profile": "nope", "receipt": receipt}, task_id="arvo:1",
            poc_sha256=poc_digest(b"poc"), trace_id="sha256:" + "cd" * 32,
            miner_hotkey=MINER, nonce="n", policy=CathedralReceiptPolicy(), now=NOW)
    assert "unknown submission attestation profile" in str(exc.value)
