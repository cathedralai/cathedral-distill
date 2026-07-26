"""The whole track, end to end, hardware-free.

One test walks the entire path a real submission takes:

    build set → seal → open inside the "enclave" → run a student → grade →
    receipt → attestation binding → validation → validator spot-check →
    registry line → frontier submission → crown → emission share

Everything else in the suite checks one layer; this file checks the seams.
The "student" is a deliberately imperfect extractor so the score is neither 0
nor 1 and every failure path stays exercised.
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import challenge as ch  # noqa: E402
from cathedral_distill import eval_receipt as er  # noqa: E402
from cathedral_distill import evalset  # noqa: E402
from cathedral_distill import frontier as fr  # noqa: E402
from cathedral_distill import polaris_attest as pa  # noqa: E402
from cathedral_distill import registry_line as rlx  # noqa: E402
from cathedral_distill import runner as rn  # noqa: E402
from cathedral_distill import sealed_set as ss  # noqa: E402

MINER = "5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G"
NONCE = "a3f1" * 16
PUBKEY = "ZTJlLXB1YmtleS1mb3ItYmluZGluZy10ZXN0cw=="
IMAGE = "sha256:" + "1c" * 32
BLOCK_LATER = "0x" + "d4" * 32


def _student(items_by_prompt):
    """An imperfect student: perfect extraction on ~3 of 4 items.

    Failure modes are realistic, chosen by a stable per-item key so the run is
    deterministic: one drops a field, one mangles the reference, one truncates
    the content hash (the classic Card-sinking mistake).
    """

    def infer(prompt: str) -> str:
        item = items_by_prompt[prompt]
        expected = dict(item.checks["expected"])
        bucket = int(item.item_id[-3:]) % 8
        if bucket == 0:
            expected.pop("obligation_count")          # missing field
        elif bucket == 1:
            expected["reference"] = "C(2024) 0000"     # wrong fact
        elif bucket == 2:
            expected["content_hash"] = expected["content_hash"][:16]  # truncated hash
        return json.dumps(expected)

    return infer


@pytest.fixture(scope="module")
def pipeline():
    """Run the full chain once; the tests below each assert one seam."""
    # 1 · author + seal
    items = evalset.build(seed=39, items=24, canaries=3)
    enclave_key = X25519PrivateKey.generate()
    enclave_pub = enclave_key.public_key().public_bytes_raw()
    sealed = ss.seal(evalset.EVALSET_ID, items, enclave_pub)

    # 2 · open inside the enclave, with the attestation binding enforced
    opened = ss.open_sealed(
        sealed, enclave_key,
        attested_application_key_sha256=sealed.application_key_sha256,
    )

    # 3 · run + grade
    identity = {
        "network": "finney", "netuid": 39, "source_epoch": 4300,
        "eval_id": "sha256:" + "e5" * 32,
        "validator_hotkey": "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw",
        "miner_hotkey": MINER,
        "nonce_base64": "3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "issued_at": "2026-07-26T21:00:00Z", "completed_at": "2026-07-26T21:04:00Z",
        "valid_from_block": 6_100_000, "valid_until_block": 6_100_360,
    }
    result = rn.run_eval(
        opened,
        _student({item.prompt: item for item in opened}),
        identity=identity,
        model={"model_id": "cathedral/student-hx0-1b",
               "weights_digest": "sha256:" + "aa" * 32,
               "tokenizer_digest": "sha256:" + "bb" * 32},
        runtime={"image_digest": IMAGE, "runner_digest": "sha256:" + "cc" * 32},
        evalset={"evalset_id": evalset.EVALSET_ID,
                 "sealed_digest": sealed.sealed_digest,
                 "plaintext_digest": sealed.plaintext_digest,
                 "item_count": len(opened),
                 "key_grant_id": "grant-e2e-001"},
    )

    # 4 · attestation binding (offline recipe — identical bytes to live)
    report_data = pa.expected_polaris_report_data(
        result.receipt, nonce=NONCE, e2e_pubkey_b64=PUBKEY, image_digest=IMAGE)
    attested = pa.attach_polaris_attestation(
        result.receipt, report_data=report_data,
        evidence_digest="sha256:" + "0f" * 32,
        evidence_uri="https://receipts.example/e2e/quote.bin",
        policy_digest="sha256:" + "0e" * 32)
    attested["receipt_id"] = er.receipt_id_for(attested)
    attested["signature"] = {"algorithm": "sr25519", "value_base64": "AA=="}

    return {
        "items": opened, "sealed": sealed, "result": result,
        "receipt": attested, "report_data": report_data,
    }


def test_receipt_validates_and_binds(pipeline):
    receipt = pa.verify_polaris_receipt(
        pipeline["receipt"],
        nonce=NONCE, e2e_pubkey_b64=PUBKEY, image_digest=IMAGE,
        report_data=pipeline["report_data"], intel_verified=True,
        allowed_image_digests={IMAGE})
    assert er.creditable_as_verified_work(pipeline["receipt"])
    # The imperfect student: 3 of every 8 buckets fail → score strictly inside (0, 1).
    assert Decimal("0.5") < Decimal(str(receipt["score"]["score"])) < Decimal("1")


def test_stdout_bytes_are_the_bound_preimage(pipeline):
    # What the runner prints is exactly what the quote hashes.
    stdout = pa.polaris_stdout(pipeline["result"].receipt)
    assert not stdout.endswith(b"\n")
    assert json.loads(stdout)["score"] == pipeline["receipt"]["score"]


def test_score_matches_the_retained_outcomes(pipeline):
    outcomes = pipeline["result"].outcomes
    receipt_score = pipeline["receipt"]["score"]
    assert receipt_score["graded_items"] == len(outcomes)
    assert receipt_score["passed_items"] == sum(o.passed for o in outcomes)


def test_validator_spot_check_passes_for_honest_run(pipeline):
    result, receipt = pipeline["result"], pipeline["receipt"]
    indices = ch.derive_challenge_indices(
        receipt_id=receipt["receipt_id"], block_hash=BLOCK_LATER,
        item_count=len(result.outcomes), k=6)
    opened = [
        ch.OpenedItem(
            index=i,
            item_id=result.outcomes[i].item_id,
            output_commitment=result.outcomes[i].output_commitment,
            passed=result.outcomes[i].passed,
            proof=ch.build_proof(list(result.leaves), i),
        )
        for i in indices
    ]
    verdicts = {o.item_id: o.passed for o in result.outcomes}
    check = ch.spot_check(
        opened=opened,
        items_root_value=receipt["score"]["items_root"],
        expected_indices=indices,
        regrade=lambda item_id, _c: verdicts[item_id])
    assert check.passed


def test_spot_check_catches_a_forged_items_root(pipeline):
    """A miner that inflates passed_items must rebuild items_root to keep the
    receipt self-consistent — and then no honest opening proves against it."""
    result, receipt = pipeline["result"], pipeline["receipt"]
    forged_leaves = [
        er.item_leaf(o.item_id, o.output_commitment, True)  # everything "passed"
        for o in result.outcomes
    ]
    forged_root = er.items_root(forged_leaves)
    assert forged_root != receipt["score"]["items_root"]
    honest_opening = ch.OpenedItem(
        index=0,
        item_id=result.outcomes[0].item_id,
        output_commitment=result.outcomes[0].output_commitment,
        passed=result.outcomes[0].passed,
        proof=ch.build_proof(list(result.leaves), 0))
    check = ch.spot_check(
        opened=[honest_opening], items_root_value=forged_root,
        expected_indices=[0], regrade=lambda *_: True)
    assert not check.passed


def test_canaries_are_flagged_for_the_validator(pipeline):
    canaries = ss.contamination_canaries(pipeline["items"])
    assert len(canaries) == 3
    assert all(c.startswith("hx0-") for c in canaries)


def test_registry_line_carries_the_submission(pipeline):
    line = rlx.RegistryLine(
        miner_hotkey=MINER,
        track="hermes-extract-v0",
        checkpoint_digest=pipeline["receipt"]["model"]["weights_digest"],
        recipe_digest="sha256:" + "9d" * 32,
        receipt_uri="https://receipts.example/e2e/receipt.json",
        version="1.0.0", signature="sig")
    registry = rlx.SubmissionRegistry()
    registry.append(line)
    assert registry.submitter_of(pipeline["receipt"]["model"]["weights_digest"]) == MINER


def test_frontier_crowns_the_run_and_pays_it(pipeline):
    receipt = pipeline["receipt"]
    policy = fr.TrackPolicy(track="hermes-extract-v0",
                            max_latency_p50_ms=Decimal("5000"))
    frontier = fr.Frontier([policy])
    decision = frontier.submit(policy.track, fr.Candidate(
        miner_hotkey=MINER,
        bundle_digest="sha256:" + "9d" * 32,
        checkpoint_digest=receipt["model"]["weights_digest"],
        receipt_id=receipt["receipt_id"],
        score=Decimal(str(receipt["score"]["score"])),
        latency_p50_ms=Decimal(str(receipt["score"]["latency_p50_ms"])),
        cost_usd=Decimal("2"),
        submitted_at=datetime(2026, 7, 26, 21, 5, tzinfo=UTC),
        attested=True, teacher_permitted=True, reproduced=True,
        contamination_detected=False, registered_bundle=True,
        independent_evaluator=True))
    assert decision.crowned
    shares = frontier.emission_shares()
    assert shares["burn"] == Decimal("0.10")
    assert shares["champion:hermes-extract-v0"] == Decimal("0.90")


def test_set_is_deterministic_across_builds(pipeline):
    again = evalset.build(seed=39, items=24, canaries=3)
    sealed_again = ss.seal(
        evalset.EVALSET_ID, again,
        X25519PrivateKey.generate().public_key().public_bytes_raw())
    # Same plaintext digest even under a different enclave key.
    assert sealed_again.plaintext_digest == pipeline["sealed"].plaintext_digest
