"""A REAL Intel-TDX Cathedral receipt earns, end to end — captured as a regression.

The sibling `test_cybergym_attested_receipt_admission` proves the *gate* with a
synthetic quote (everything real except the enclave). This file closes the last gap:
it replays a **genuine Cathedral `attest.v1` receipt**, produced on Cathedral
`tdx_cpu` hardware with the funded compute token on 2026-08-05 (worker
`12a95732-9eb3-494e-beaf-98900ffb6a22`), through the merged reward path and asserts
the miner is credited and composes to the v3 CyberGym lane weight.

The one insight that makes this work on the customer `v1` API (no `report_data`
surface, no new platform grant — see CYBERGYM_ATTESTED_E2E_STATUS_2026-08-05.md): the
`enclave_result_bytes` envelope is **byte-deterministic** given a fixed key, so the
miner never needs the enclave's *sealed* result. It reconstructs the identical bytes
(`result_b64` in the fixture) and the receipt's `result_sha256` authenticates them.

What is real here: the Cathedral-signed `cathedral_customer_receipt_v1`, its Intel-DCAP
`intel_verified` / `execution_binding_verified` posture, `cpu_tee=intel_tdx`, and its
`result_sha256` / `workload_sha256` bindings. The loop tests admit the receipt on those
trusted-issuer flags (as the production gate does by default); a separate test verifies
Cathedral's **Ed25519 signature** over the canonical receipt bytes when the operator's
published trust file is supplied via `CATHEDRAL_RECEIPT_TRUSTED_KEYS` — so a forged receipt
with the right flags is caught there. The enclave key is a fixed test key standing in for
an enclave-generated one — identical bytes for a fixed-key signature, so it adds no trust
to *this* proof. The dispatch nonce is chain-anchored (invariant to wall-clock), so the
frozen receipt stays reproducible.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Reuse the production-shaped harness (durable stores, enforced posture, real
# differential seam) from the admission suite rather than rebuilding it.
import test_cybergym_attested_receipt_admission as H
from cathedral_distill import cybergym_score_report as report
from cathedral_distill.cybergym_attest import (
    CathedralReceiptPolicy,
    PROFILE_PERSISTENT_ENCLAVE,
    RECEIPT_ATTESTATION_SCHEMA,
)
from cathedral_distill.cybergym_protocol import SubmissionEnvelope, _trace_from_dict
from cathedral_distill.cybergym_verifier import poc_digest
from cathedral_distill.lane_feed import Lane, LaneContribution, compose_vector

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "cybergym-real-tdx-receipt.json").read_text()
)
RECEIPT = FIXTURE["receipt"]
RESULT_BYTES = base64.b64decode(FIXTURE["result_b64"])
EXPECT = FIXTURE["expected"]
WORKLOAD = RECEIPT["workload_sha256"]

# One instant after the receipt was issued (2026-08-05T12:06:53Z): freshness must pass
# and it must not read as "from the future". The nonce does not depend on this.
AFTER_ISSUE = datetime(2026, 8, 5, 12, 10, 0, tzinfo=UTC)

# Cathedral signs a `cathedral_customer_receipt_v1` over the canonical JSON of every
# top-level field except `signature` (see cathedral-compute
# `customer_receipt.py::customer_receipt_signed_bytes`). Replicated here so the
# signature test binds to Cathedral's exact contract, not an approximation.
def _cathedral_signed_bytes(receipt: dict) -> bytes:
    unsigned = {k: v for k, v in receipt.items() if k != "signature"}
    return json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("ascii")


# Cathedral's `cathedral_customer_receipt_trusted_keys_v1` registry — a PINNED copy of
# https://cathedral.computer/customer-receipt-trusted-keys.json (holds the public key for
# `cathedral-customer-receipt-2026-07-31-01`). Pinned, not runtime-fetched, on purpose: the
# trust file is not authenticated by the receipt, so fetching it over TLS from the same
# operator whose receipts we check gives TLS's guarantees, not the receipt's — pin it and
# distribute through an independent channel, treating a change as an event. `CATHEDRAL_RECEIPT
# _TRUSTED_KEYS` overrides the path (e.g. to test a rotation).
PINNED_TRUST_FILE = Path(__file__).parent / "fixtures" / "cathedral-customer-receipt-trusted-keys.json"
TRUST_FILE = os.environ.get("CATHEDRAL_RECEIPT_TRUSTED_KEYS") or str(PINNED_TRUST_FILE)


@pytest.fixture
def clock(monkeypatch):
    """Pin the harness clock past the recorded receipt's issue time (auto-restored)."""
    monkeypatch.setattr(H, "NOW", AFTER_ISSUE)


def _service(tmp_path):
    return H._service(
        tmp_path,
        policy=None,
        name="real-tdx",
        receipt_policy=CathedralReceiptPolicy(expected_workload_sha256=WORKLOAD),
    )


def _attestation_token(receipt=RECEIPT, result_b64=FIXTURE["result_b64"]) -> str:
    token = {
        "schema": RECEIPT_ATTESTATION_SCHEMA,
        "profile": PROFILE_PERSISTENT_ENCLAVE,
        "receipt": receipt,
        "result_b64": result_b64,
    }
    return base64.b64encode(json.dumps(token).encode()).decode()


def _submission(dispatch, *, miner_hotkey=H.MINER, token=None) -> SubmissionEnvelope:
    task = dispatch.tasks[0]
    return SubmissionEnvelope(
        batch_id=dispatch.batch_id,
        task_id=task.task_id,
        miner_hotkey=miner_hotkey,
        poc_base64=base64.b64encode(H.CRASHING).decode(),
        trace=H._trace(task.task_id, poc_digest(H.CRASHING)),
        artifact_digest=task.artifact_digest,
        attestation=token if token is not None else _attestation_token(),
    )


def test_the_fixture_is_a_genuine_intel_tdx_result_binding():
    """The recorded receipt is a real Cathedral TDX receipt binding OUR bytes.

    If Cathedral ever changed the receipt shape this fixture stands on, this is the
    test that fails first, before any of the loop assertions below.
    """
    assert RECEIPT["schema"] == "cathedral_customer_receipt_v1"
    assert RECEIPT["cpu_tee"] == "intel_tdx"
    assert RECEIPT["intel_verified"] is True
    assert RECEIPT["execution_binding_verified"] is True
    assert RECEIPT["signature"]["algorithm"] == "ed25519"
    # The receipt binds exactly the bytes the miner reconstructs.
    assert hashlib.sha256(RESULT_BYTES).hexdigest() == RECEIPT["result_sha256"]
    # And the reconstructed envelope commits to the dispatched solve.
    envelope = json.loads(RESULT_BYTES)
    assert envelope["commitment"]["task_id"] == EXPECT["task_id"]
    assert envelope["commitment"]["nonce"] == EXPECT["nonce"]
    assert envelope["commitment"]["miner_hotkey"] == EXPECT["miner_hotkey"]


def test_the_signature_is_well_formed_over_cathedrals_canonical_bytes():
    """The receipt carries an Ed25519 signature over Cathedral's canonical bytes,
    and those bytes bind our result + workload.

    This does NOT prove the signer is Cathedral (that needs the published key — see
    the crypto test below); it proves the signed message is the exact contract input
    and covers the fields the reward path relies on, so the crypto test only has to
    supply a key.
    """
    assert RECEIPT["signature"]["algorithm"] == "ed25519"
    sig = base64.b64decode(RECEIPT["signature"]["value_base64"], validate=True)
    assert len(sig) == 64  # Ed25519 signature width
    signed = _cathedral_signed_bytes(RECEIPT)
    doc = json.loads(signed)
    assert "signature" not in doc
    assert doc["result_sha256"] == RECEIPT["result_sha256"]
    assert doc["workload_sha256"] == RECEIPT["workload_sha256"]
    assert doc["signing_key_id"] == RECEIPT["signing_key_id"]


def test_the_receipt_signature_verifies_against_cathedrals_published_key():
    """Prove the fixture is genuinely Cathedral-signed — verified against the PINNED key.

    Closes the one gap the loop tests leave open: they trust the receipt's
    `intel_verified`/`execution_binding_verified` flags; this verifies Cathedral's
    Ed25519 signature over the canonical receipt bytes against the pinned trusted-keys
    registry, so a forged receipt with the right flags fails here. Runs unconditionally
    now that the trust file is pinned (was gated on an env var before it was located).
    """
    keys = json.loads(Path(TRUST_FILE).read_text())["keys"]
    entry = keys[RECEIPT["signing_key_id"]]
    assert entry["algorithm"] == "ed25519"
    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(entry["public_key_base64"], validate=True)
    )
    signature = base64.b64decode(RECEIPT["signature"]["value_base64"], validate=True)
    # Raises InvalidSignature if the receipt was not signed by this key.
    public_key.verify(signature, _cathedral_signed_bytes(RECEIPT))


def test_a_missing_attestation_is_refused_by_the_receipt_policy_service(tmp_path, clock):
    """Enforcement is not vacuous: with the receipt policy configured, a submission
    that carries NO attestation is refused before the differential runs. Together
    with the cross-miner and wrong-workload refusals, this shows the credit above is
    the receipt doing work, not the gate waved through."""
    service = _service(tmp_path)
    dispatch = H._dispatch(service)
    runner = service.holdout.pool._run
    task = dispatch.tasks[0]
    no_attestation = SubmissionEnvelope(
        batch_id=dispatch.batch_id,
        task_id=task.task_id,
        miner_hotkey=H.MINER,
        poc_base64=base64.b64encode(H.CRASHING).decode(),
        trace=H._trace(task.task_id, poc_digest(H.CRASHING)),
        artifact_digest=task.artifact_digest,
        attestation=None,
    )
    outcome = service.submit(no_attestation, authenticated_caller=H.MINER)
    assert outcome.reason == "rejected_unattested:missing_tdx_attestation"
    assert not outcome.attested and not outcome.creditable
    assert outcome.work_units == Decimal(0)
    assert runner.runs == []


def test_the_dispatch_the_receipt_was_bound_to_is_reproducible(tmp_path, clock):
    """The frozen receipt is bound to the batch this service deterministically draws.

    The receipt's committed `(task, poc, trace, miner, nonce)` must equal what a fresh
    service dispatches — otherwise the fixture would be a receipt for some other batch
    and the credit below would be meaningless.
    """
    dispatch = H._dispatch(_service(tmp_path))
    task = dispatch.tasks[0]
    trace_id = _trace_from_dict(H._trace(task.task_id, poc_digest(H.CRASHING))).trace_id()
    assert task.task_id == EXPECT["task_id"]
    assert dispatch.nonce == EXPECT["nonce"]
    assert poc_digest(H.CRASHING) == EXPECT["poc_sha256"]
    assert trace_id == EXPECT["trace_id"]


def test_the_real_receipt_credits_the_miner_and_composes_the_v3_weight(tmp_path, clock):
    """The whole loop on a real Intel-TDX receipt: credit -> score -> report -> weight."""
    service = _service(tmp_path)
    assert service._scores.attestation_posture(H.EPOCH)["enforced"] is True

    dispatch = H._dispatch(service)
    runner = service.holdout.pool._run

    outcome = service.submit(_submission(dispatch), authenticated_caller=H.MINER)
    assert outcome.attested and outcome.solved and outcome.creditable
    assert outcome.trainable
    assert outcome.work_units == Decimal(2)
    assert outcome.reason == "solved_trainable"
    # The gate admitted it, so the real differential actually ran.
    assert runner.runs != []

    # Score + close, then export the signed consumer report.
    service.score_epoch(issued_at="2026-08-05T12:15:00.000000Z")
    assert service._scores.epoch_scores(H.EPOCH) == {H.MINER: Decimal(2)}
    document = report.build_score_report(
        service._scores, network="finney", netuid=39,
        source_epoch=H.EPOCH, producer_hotkey="5Producer",
    )
    assert document["complete"] is True
    assert document["scores"] == {H.MINER: 2.0}
    body = report.canonical_report_bytes(document)
    assert report.report_digest(document) == hashlib.sha256(body).hexdigest()

    # Validator side: compose the SN39 v3 vector (70% TDX / 30% CyberGym / 0% burn).
    # In steady state both lanes carry verified work, so no lane forfeits to burn and
    # the CyberGym miner's share is exactly the lane's 0.30 of total emission.
    cybergym = Lane(
        "cybergym", Decimal("0.30"),
        [LaneContribution(m, "cg-epoch-21", Decimal(str(u)))
         for m, u in document["scores"].items()],
    )
    tdx = Lane("tdx", Decimal("0.70"),
               [LaneContribution("5TdxMiner", "tdx-epoch-21", Decimal("5"))])
    vector = compose_vector([tdx, cybergym], burn_hotkey="5Burn", burn_fraction=Decimal("0"))

    assert Decimal(str(vector["burn_snapshot"]["forced_burn_percentage"])) == Decimal("0")
    weights = {r["miner_hotkey"]: Decimal(str(r["weight"])) for r in vector["weights"]}
    assert weights[H.MINER] == Decimal("0.3")

    # The 0.30 is the CyberGym lane's whole allocation, captured because this miner is
    # the sole cybergym earner. When only the cybergym lane carries work, the same
    # 0.30 shows up as a pre-burn weight of 1.0 with the TDX lane's 0.70 forfeited to a
    # forced 70% burn — the identical effective share, expressed the other way.
    cg_only = compose_vector(
        [Lane("tdx", Decimal("0.70"), []), cybergym],
        burn_hotkey="5Burn", burn_fraction=Decimal("0"),
    )
    assert Decimal(str(cg_only["burn_snapshot"]["forced_burn_percentage"])) == Decimal("70")
    cg_only_w = {r["miner_hotkey"]: Decimal(str(r["weight"])) for r in cg_only["weights"]}
    assert cg_only_w[H.MINER] == Decimal("1")  # pre-burn; effective = 1 * (1 - 0.70) = 0.30


def test_a_second_miner_cannot_replay_the_real_receipt(tmp_path, clock):
    """The commitment binds the miner, so another miner's batch cannot spend it."""
    service = _service(tmp_path)
    # A different miner, dispatched its own batch, submits the real miner's receipt.
    other = "5SomeoneElseXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    dispatch = service.dispatch_for(other, H.MODEL, authenticated_caller=other)
    runner = service.holdout.pool._run

    outcome = service.submit(
        _submission(dispatch, miner_hotkey=other), authenticated_caller=other
    )
    assert not outcome.attested and not outcome.creditable
    assert "different" in outcome.reason  # commits to a different …/miner/nonce
    # Refused before the differential — a stolen receipt cannot spend verifier capacity.
    assert runner.runs == []


def test_the_real_receipt_is_refused_under_a_wrong_approved_workload_pin(tmp_path, clock):
    """Pinning a different approved solver refuses the receipt: the workload allowlist
    is what stops a workload that merely echoes a looked-up answer from earning."""
    service = H._service(
        tmp_path, policy=None, name="wrong-wl",
        receipt_policy=CathedralReceiptPolicy(expected_workload_sha256="00" * 32),
    )
    dispatch = H._dispatch(service)
    outcome = service.submit(_submission(dispatch), authenticated_caller=H.MINER)
    assert not outcome.attested and not outcome.creditable
    assert "approved solver workload" in outcome.reason
