"""Launch-hardening tests for the frontier (issue #1, gate 5 + derived gates).

Proves the four properties the review required: a nonzero qualification floor,
crown liveness (TTL / proof-of-life / revocation / availability / contamination
pay burn), canonical reconstructible state so validators converge regardless of
restart or order, and gates DERIVED from verified evidence rather than accepted
as caller-supplied booleans.
"""
from __future__ import annotations

import hashlib
import sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import bundle_registry as br  # noqa: E402
from cathedral_distill import eval_receipt as er  # noqa: E402
from cathedral_distill import frontier as fr  # noqa: E402
from cathedral_distill import roles as ro  # noqa: E402
from cathedral_distill import teacher_registry as tr  # noqa: E402

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
POLICY = fr.TrackPolicy(track="hermes", min_score_to_crown=Decimal("0.05"),
                        crown_ttl_s=3600)


def _digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _base_receipt(**overrides):
    leaves = [er.item_leaf(i, f"item-{i}", _digest(f"out-{i}"), i < 7) for i in range(10)]
    doc = {
        "schema": er.SCHEMA, "network": "finney", "netuid": 39, "source_epoch": 4211,
        "eval_id": _digest("eval"), "validator_hotkey": "5Validator", "miner_hotkey": "5Miner",
        "nonce_base64": "3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "issued_at": "2026-07-25T09:00:00Z", "completed_at": "2026-07-25T09:04:00Z",
        "valid_from_block": 6_000_000, "valid_until_block": 6_000_360,
        "model": {"model_id": "cathedral/student", "weights_digest": _digest("weights"),
                  "tokenizer_digest": _digest("tokenizer")},
        "runtime": {"image_digest": _digest("image"), "runner_digest": _digest("runner"),
                    "decode_digest": _digest("decode")},
        "evalset": {"evalset_id": "frontend_v0", "sealed_digest": _digest("sealed"),
                    "plaintext_digest": _digest("plain"), "item_count": 10,
                    "key_grant_id": "grant-0001"},
        "grader": {"grader_id": "g", "grader_digest": _digest("grader"),
                   "harness_digest": _digest("harness")},
        "score": {"graded_items": 10, "passed_items": 7, "score": "0.7",
                  "items_root": er.items_root(leaves), "input_tokens": 4096,
                  "output_tokens": 8192, "latency_p50_ms": "812.5",
                  "latency_p95_ms": "1904.25", "work_units": "10"},
        "eval_authorization": None,
        "attestation": {"kind": "none", "evidence_digest": "", "evidence_uri": "",
                        "policy_digest": "", "report_data_hex": ""},
    }
    doc.update(overrides)
    doc["receipt_id"] = er.receipt_id_for(doc)
    doc["signature"] = {"algorithm": "sr25519", "value_base64": "AA=="}
    return doc


def _creditable_receipt(**overrides):
    """A tdx receipt whose report_data binding validates — so it is creditable."""
    doc = _base_receipt(**overrides)
    report_data = er.expected_report_data(doc).hex()
    doc["attestation"] = {"kind": "tdx", "evidence_digest": _digest("evidence"),
                          "evidence_uri": "", "policy_digest": _digest("policy"),
                          "report_data_hex": report_data}
    doc["receipt_id"] = er.receipt_id_for(doc)
    doc["signature"] = {"algorithm": "sr25519", "value_base64": "AA=="}
    return doc


def _teacher_registry():
    reg = tr.TeacherRegistry()
    reg.add(tr.TeacherRecord(
        teacher_id="yunwei/kimi-k3/2026", licence_digest=_digest("lic"),
        licence_uri="https://x/lic", reviewed_at=NOW - timedelta(days=1),
        review_expires_at=NOW + timedelta(days=30), reviewer="jared",
        permitted_purposes=frozenset({tr.PURPOSE_DISTILLATION}),
        commercial_use=True, competing_model_training=True))
    return reg


def _bundle_registry(digest: str, hotkey: str = "5Miner"):
    reg = br.BundleRegistry()
    reg.register(br.BundleRegistration(
        miner_hotkey=hotkey, track="hermes", bundle_digest=digest, version="v1",
        registered_at=NOW, signature="sig"), verify_signature=False)
    return reg


def _full_evidence(**over):
    """Evidence where every gate's check genuinely passes."""
    receipt = _creditable_receipt()
    repro = _creditable_receipt(validator_hotkey="5Validator2")  # independent re-run
    digest = _digest("bundle")
    ev = dict(
        receipt=receipt, miner_hotkey="5Miner", submitted_at=NOW, cost_usd=Decimal("2"),
        teacher_registry=_teacher_registry(), teacher_id="yunwei/kimi-k3/2026",
        licence_checked_at=NOW,
        bundle_registry=_bundle_registry(digest), bundle_digest=digest,
        training_participant=ro.Participant(coldkey="ck-miner",
                                            hotkeys={ro.Role.TRAINING_MINER: "5Miner"}),
        evaluator_participant=ro.Participant(coldkey="ck-eval",
                                             hotkeys={ro.Role.SERVING_MINER: "5Eval"}),
        reproduction_receipt=repro,
        canary_passed=1, canary_total=8, canary_chance_rate=Decimal("0.25"),
    )
    ev.update(over)
    return fr.CandidateEvidence(**ev)


# --------------------------------------------------------------------------- #
# Nonzero qualification floor
# --------------------------------------------------------------------------- #

def test_zero_floor_is_rejected():
    with pytest.raises(fr.FrontierError, match="nonzero qualification floor"):
        fr.TrackPolicy(track="t", min_score_to_crown=Decimal("0"))


def test_default_floor_is_nonzero():
    assert fr.TrackPolicy(track="t").min_score_to_crown > 0


# --------------------------------------------------------------------------- #
# Crown liveness -> burn
# --------------------------------------------------------------------------- #

def _crown(f, *, at=NOW):
    ev = _full_evidence(submitted_at=at)
    decision = f.submit(POLICY.track, fr.derive_candidate(ev, POLICY))
    assert decision.crowned, decision.reason
    return decision


def test_live_champion_is_paid():
    f = fr.Frontier([POLICY])
    _crown(f)
    shares = f.emission_shares(now=NOW)
    assert shares[f"champion:{POLICY.track}"] == Decimal("0.90")
    assert shares["burn"] == Decimal("0.10")


def test_stale_crown_pays_burn():
    f = fr.Frontier([POLICY])
    _crown(f, at=NOW)
    later = NOW + timedelta(seconds=POLICY.crown_ttl_s + 1)
    shares = f.emission_shares(now=later)
    assert f"champion:{POLICY.track}" not in shares
    assert shares["burn"] == Decimal("1")          # nothing live -> all burn


@pytest.mark.parametrize("flag", ["revoked", "available", "contaminated"])
def test_revoked_unavailable_or_contaminated_crown_pays_burn(flag):
    f = fr.Frontier([POLICY])
    _crown(f)
    kwargs = {flag: (False if flag == "available" else True)}
    f.set_liveness(POLICY.track, **kwargs)
    shares = f.emission_shares(now=NOW)          # within TTL, but not live
    assert f"champion:{POLICY.track}" not in shares
    assert shares["burn"] == Decimal("1")


def test_revalidation_restores_payment():
    f = fr.Frontier([POLICY])
    _crown(f, at=NOW)
    stale = NOW + timedelta(seconds=POLICY.crown_ttl_s + 1)
    assert f.emission_shares(now=stale)["burn"] == Decimal("1")
    f.set_liveness(POLICY.track, revalidated_at=stale)     # proof-of-life
    assert f.emission_shares(now=stale)[f"champion:{POLICY.track}"] == Decimal("0.90")


# --------------------------------------------------------------------------- #
# Canonical, reconstructible state
# --------------------------------------------------------------------------- #

def test_state_digest_is_restart_and_order_independent():
    a = fr.Frontier([POLICY, fr.TrackPolicy(track="other")])
    b = fr.Frontier([fr.TrackPolicy(track="other"), POLICY])
    for f in (a, b):
        _crown(f)
    assert a.state_digest() == b.state_digest()


def test_from_state_round_trips_and_pays_the_same():
    f = fr.Frontier([POLICY])
    _crown(f)
    restored = fr.Frontier.from_state([POLICY], f.state())
    assert restored.state_digest() == f.state_digest()
    assert restored.emission_shares(now=NOW) == f.emission_shares(now=NOW)


def test_from_state_rejects_unknown_track():
    f = fr.Frontier([POLICY])
    _crown(f)
    with pytest.raises(fr.FrontierError, match="unknown track"):
        fr.Frontier.from_state([fr.TrackPolicy(track="different")], f.state())


# --------------------------------------------------------------------------- #
# Gates derived from evidence, not booleans
# --------------------------------------------------------------------------- #

def test_fully_evidenced_candidate_passes_every_gate():
    candidate = fr.derive_candidate(_full_evidence(), POLICY)
    gates = fr.evaluate_gates(candidate, POLICY)
    assert gates.passed, gates.failures


def test_unattested_receipt_derives_attested_false():
    ev = _full_evidence(receipt=_base_receipt())  # kind "none" -> not creditable
    candidate = fr.derive_candidate(ev, POLICY)
    assert candidate.attested is False
    assert fr.GATE_ATTESTED_RECEIPT in fr.evaluate_gates(candidate, POLICY).failures


def test_self_evaluation_derives_independent_false():
    same = ro.Participant(coldkey="shared", hotkeys={ro.Role.TRAINING_MINER: "5Miner"})
    ev = _full_evidence(training_participant=same, evaluator_participant=same)
    candidate = fr.derive_candidate(ev, POLICY)
    assert candidate.independent_evaluator is False
    assert fr.GATE_INDEPENDENT_EVALUATOR in fr.evaluate_gates(candidate, POLICY).failures


def test_unregistered_bundle_derives_registered_false():
    ev = _full_evidence(bundle_registry=br.BundleRegistry())  # nothing registered
    candidate = fr.derive_candidate(ev, POLICY)
    assert candidate.registered_bundle is False


def test_missing_teacher_registration_derives_permitted_false():
    ev = _full_evidence(teacher_registry=None, teacher_id="", licence_checked_at=None)
    candidate = fr.derive_candidate(ev, POLICY)
    assert candidate.teacher_permitted is False


def test_no_reproduction_derives_reproduced_false():
    ev = _full_evidence(reproduction_receipt=None)
    candidate = fr.derive_candidate(ev, POLICY)
    assert candidate.reproduced is False


def test_same_evaluator_reproduction_does_not_count():
    # A "reproduction" from the SAME validator is not independent.
    ev = _full_evidence(reproduction_receipt=_creditable_receipt())  # same validator_hotkey
    assert fr.derive_candidate(ev, POLICY).reproduced is False


def test_canary_contamination_derives_contamination_true():
    ev = _full_evidence(canary_passed=6, canary_total=8)  # far above chance
    candidate = fr.derive_candidate(ev, POLICY)
    assert candidate.contamination_detected is True
    assert fr.GATE_NO_CONTAMINATION in fr.evaluate_gates(candidate, POLICY).failures


def test_absent_canary_evidence_fails_contamination_closed():
    ev = _full_evidence(canary_passed=0, canary_total=0)
    assert fr.derive_candidate(ev, POLICY).contamination_detected is True


def test_empty_evidence_cannot_forge_gates():
    # The headline: with no verifiable evidence, every derivable gate is False —
    # a caller cannot pass all-true booleans through the sanctioned path.
    ev = fr.CandidateEvidence(receipt=_base_receipt(), miner_hotkey="5Miner",
                              submitted_at=NOW, cost_usd=Decimal("2"))
    candidate = fr.derive_candidate(ev, POLICY)
    assert not candidate.attested
    assert not candidate.teacher_permitted
    assert not candidate.reproduced
    assert not candidate.registered_bundle
    assert not candidate.independent_evaluator
    assert candidate.contamination_detected            # fail-closed
    assert not fr.evaluate_gates(candidate, POLICY).passed
