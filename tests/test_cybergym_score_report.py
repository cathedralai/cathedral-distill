"""Durable CyberGym score report: closed store -> exact authenticated bytes."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from cathedral_distill import cybergym_score_report as report
from cathedral_distill import cybergym_scores as scores_module
from cathedral_distill.attestation import (
    AttestationPolicy,
    attestation_policy_digest,
)
from cathedral_distill.cybergym_evidence_manifest import manifest_digest
from cathedral_distill.cybergym_scores import (
    EPOCH_CLOSED,
    CyberGymScoreError,
    CyberGymScoreStore,
)

EPOCH = 42
CLOSED_AT = "2026-08-03T10:11:12.123456+00:00"

# The posture record binds the policy's CONTENT, so a fixture that claims
# enforcement has to name a policy exactly as a running verifier does.
DCAP_ROOT = bytes(range(32))
ATTACKER_ROOT = bytes(range(1, 33))
POLICY = AttestationPolicy(
    trusted_roots={"intel-dcap-root-1": DCAP_ROOT},
    allowed_measurements=frozenset({"tdx-mrtd:" + "ab" * 24}),
)
POLICY_DIGEST = attestation_policy_digest(POLICY)


def _store(tmp_path, rows=(), *, attested=True):
    store = CyberGymScoreStore(str(tmp_path / "scores.sqlite"))
    # A producer stamps its Intel-TDX posture when it opens the epoch; an export
    # refuses anything it cannot show was attested, so the default here is the
    # production posture and the exceptions say so explicitly.
    if attested:
        store.record_attestation_posture(
            EPOCH,
            enforced=True,
            detail="policy configured",
            policy_digest=POLICY_DIGEST,
        )
    with store._connection:
        for hotkey, units, receipt_id in rows:
            store._connection.execute(
                "INSERT INTO cybergym_scores"
                "(miner_hotkey, epoch, score, earned_units, receipt_id) "
                "VALUES (?,?,?,?,?)",
                (hotkey, EPOCH, float(units), str(units), receipt_id),
            )
    return store


def _build(store):
    return report.build_score_report(
        store,
        network="finney",
        netuid=39,
        source_epoch=EPOCH,
        producer_hotkey="5Producer",
    )


def test_closed_epoch_builds_the_exact_consumer_contract(tmp_path):
    store = _store(
        tmp_path, [("5MinerB", "3.5", "receipt-b"), ("5MinerA", "8", "receipt-a")]
    )
    store.mark_epoch(EPOCH, state=EPOCH_CLOSED, scored_miners=2, at=CLOSED_AT)

    document = _build(store)

    assert set(document) == set(report.SEMANTIC_KEYS)
    assert document["generated_at"] == "2026-08-03T10:11:12.123Z"
    assert document["score_units"] == "level_weighted_verified_solves"
    assert document["scores"] == {"5MinerA": 8.0, "5MinerB": 3.5}
    assert document["evidence_sha256"] == manifest_digest(
        network="finney",
        netuid=39,
        source_epoch=EPOCH,
        entries=[
            {"miner_hotkey": "5MinerA", "receipt_id": "receipt-a", "work_units": "8"},
            {"miner_hotkey": "5MinerB", "receipt_id": "receipt-b", "work_units": "3.5"},
        ],
    )
    body = report.canonical_report_bytes(document)
    assert body == report.canonical_report_bytes(json.loads(body))
    assert report.report_digest(document) == hashlib.sha256(body).hexdigest()


def test_open_epoch_refuses_export_and_empty_closed_epoch_is_explicit(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(report.CyberGymScoreReportError, match="state is 'open'"):
        _build(store)

    store.mark_epoch(EPOCH, state=EPOCH_CLOSED, scored_miners=0, at=CLOSED_AT)
    document = _build(store)
    assert document["scores"] == {}
    assert document["evidence_sha256"] == manifest_digest(
        network="finney", netuid=39, source_epoch=EPOCH, entries=[]
    )


def test_closed_epoch_retries_preserve_timestamp_and_report_bytes(tmp_path):
    store = _store(tmp_path, [("5Miner", "8", "receipt-a")])
    store.mark_epoch(EPOCH, state=EPOCH_CLOSED, at=CLOSED_AT)
    first = report.canonical_report_bytes(_build(store))

    store.mark_epoch(
        EPOCH,
        state=EPOCH_CLOSED,
        detail="same scoring pass retried",
        at="2026-08-03T11:12:13.999999+00:00",
    )
    second = report.canonical_report_bytes(_build(store))

    assert first == second
    assert store.epoch_status(EPOCH)["marked_at"] == CLOSED_AT
    with pytest.raises(CyberGymScoreError, match="change closed.*immutable"):
        store.mark_epoch(EPOCH, state=scores_module.EPOCH_INCOMPLETE)


def test_closed_epoch_accepts_exact_replay_but_rejects_every_new_receipt(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(scores_module, "validate_structure", lambda receipt: receipt)
    store = _store(tmp_path)
    first = {
        "miner_hotkey": "5Miner",
        "source_epoch": EPOCH,
        "receipt_id": "receipt-a",
        "score": {"work_units": "8"},
    }
    store.record(first)
    store.mark_epoch(EPOCH, state=EPOCH_CLOSED, at=CLOSED_AT)
    store.record(first)

    replacement = {**first, "receipt_id": "receipt-b"}
    with pytest.raises(CyberGymScoreError, match="replacement.*closed epoch"):
        store.record(replacement)
    newcomer = {
        **first,
        "miner_hotkey": "5Other",
        "receipt_id": "receipt-c",
    }
    with pytest.raises(CyberGymScoreError, match="new.*closed epoch"):
        store.record(newcomer)


def test_hmac_is_over_the_exact_frozen_bytes():
    body = b'{"exact":"bytes"}'
    expected = hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    assert report.body_hmac(body, "secret") == "sha256=" + expected


def test_publish_posts_exact_bytes_and_verifies_acceptance(tmp_path, monkeypatch):
    store = _store(tmp_path)
    store.mark_epoch(EPOCH, state=EPOCH_CLOSED, at=CLOSED_AT)
    body = report.canonical_report_bytes(_build(store))
    captured = {}

    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return json.dumps(
                {
                    "accepted": True,
                    "report_sha256": hashlib.sha256(body).hexdigest(),
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                }
            ).encode()

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(report.urllib.request, "urlopen", fake_urlopen)
    result = report.publish_score_report(
        body,
        url="https://publisher.example/v1/cybergym/scores",
        bearer_token="token",
        hmac_secret="secret",
        timeout_seconds=7,
    )

    request = captured["request"]
    assert request.data == body
    assert request.get_header("Authorization") == "Bearer token"
    assert request.get_header("X-cathedral-cybergym-signature") == report.body_hmac(
        body, "secret"
    )
    assert captured["timeout"] == 7
    assert result["accepted"] is True


def test_publish_rejects_an_acceptance_for_different_body_bytes(tmp_path, monkeypatch):
    store = _store(tmp_path)
    store.mark_epoch(EPOCH, state=EPOCH_CLOSED, at=CLOSED_AT)
    body = report.canonical_report_bytes(_build(store))

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return json.dumps(
                {
                    "accepted": True,
                    "report_sha256": hashlib.sha256(body).hexdigest(),
                    "body_sha256": "0" * 64,
                }
            ).encode()

    monkeypatch.setattr(report.urllib.request, "urlopen", lambda *_a, **_kw: Response())
    with pytest.raises(report.CyberGymScoreReportError, match="different.*body bytes"):
        report.publish_score_report(
            body,
            url="http://127.0.0.1:8000/v1/cybergym/scores",
            bearer_token="token",
            hmac_secret="secret",
        )


def test_publish_refuses_cleartext_non_loopback(tmp_path):
    store = _store(tmp_path)
    store.mark_epoch(EPOCH, state=EPOCH_CLOSED, at=CLOSED_AT)
    body = report.canonical_report_bytes(_build(store))
    with pytest.raises(report.CyberGymScoreReportError, match="must use HTTPS"):
        report.publish_score_report(
            body,
            url="http://publisher.example/v1/cybergym/scores",
            bearer_token="token",
            hmac_secret="secret",
        )


# --------------------------------------------------------------------------- #
# The Intel-TDX posture gate: what may become a publishable report at all
# --------------------------------------------------------------------------- #

def test_an_unattested_epoch_is_not_exportable_without_an_explicit_acknowledgement(
    tmp_path,
):
    """The loopback E2E's scores must not become production-shaped bytes by default.

    An unattested run and an attested run produce the same table, the same close
    marker, and the same wire report — the contract has no enforcement field and
    cannot grow one without the intake. So the difference has to stop something
    here, at the only place both halves are still visible, or it stops nothing.
    """
    store = _store(tmp_path, [("5Miner", "8", "receipt-a")], attested=False)
    store.record_attestation_posture(
        EPOCH, enforced=False, detail="no Intel-TDX attestation policy"
    )
    store.mark_epoch(EPOCH, state=EPOCH_CLOSED, scored_miners=1, at=CLOSED_AT)

    with pytest.raises(report.CyberGymScoreReportError, match="NO Intel-TDX"):
        _build(store)

    acknowledged = report.build_score_report(
        store,
        network="finney",
        netuid=39,
        source_epoch=EPOCH,
        producer_hotkey="5Producer",
        allow_unattested=True,
    )
    assert acknowledged["scores"] == {"5Miner": 8.0}


def test_an_unrecorded_posture_is_refused_rather_than_assumed_attested(tmp_path):
    """"Nobody said" is not evidence of attestation.

    A database written before postures were stamped looks exactly like one written
    by a producer that skipped the record. Neither shows enforcement, so both fail
    closed and the operator is told which of the two answers is missing.
    """
    store = _store(tmp_path, [("5Miner", "8", "receipt-a")], attested=False)
    store.mark_epoch(EPOCH, state=EPOCH_CLOSED, scored_miners=1, at=CLOSED_AT)

    assert store.attestation_posture(EPOCH) is None
    with pytest.raises(report.CyberGymScoreReportError, match="does not record"):
        _build(store)


def test_attestation_posture_cannot_change_midway_through_an_epoch(tmp_path):
    """A restart may not downgrade enforcement and keep scoring the same epoch.

    Half-attested and half-unattested solves would be credited under one signed
    receipt with nothing able to separate them, so the second, disagreeing open
    refuses instead.
    """
    store = _store(tmp_path, attested=False)

    store.record_attestation_posture(
        EPOCH, enforced=True, detail="policy configured", policy_digest=POLICY_DIGEST
    )
    with pytest.raises(CyberGymScoreError, match="may not change enforcement"):
        store.record_attestation_posture(EPOCH, enforced=False, detail="policy dropped")
    assert store.attestation_posture(EPOCH)["enforced"] is True


# --------------------------------------------------------------------------- #
# The posture must pin the policy's CONTENT, not merely its existence
# --------------------------------------------------------------------------- #

def test_the_pinned_posture_binds_which_policy_not_merely_that_one_existed(tmp_path):
    """A swapped trust root is a changed posture, even with enforcement still on.

    Pinning the enforcement FLAG pins the existence of a policy. What decides
    verdicts is its content: a restart that keeps `enforced=True` while replacing
    `trusted_roots` with a key the claimant holds admits every quote the epoch's
    opening policy refused, and the flag reads "enforced" throughout. So the digest
    over the policy is what the epoch is actually pinned to.
    """
    store = _store(tmp_path, attested=False)
    store.record_attestation_posture(
        EPOCH, enforced=True, detail="intel root", policy_digest=POLICY_DIGEST
    )

    swapped = attestation_policy_digest(
        AttestationPolicy(
            trusted_roots={
                "intel-dcap-root-1": DCAP_ROOT,
                "miners-own-key": ATTACKER_ROOT,
            },
            allowed_measurements=POLICY.allowed_measurements,
        )
    )
    with pytest.raises(CyberGymScoreError, match="attestation POLICY changed"):
        store.record_attestation_posture(
            EPOCH, enforced=True, detail="swapped root", policy_digest=swapped
        )
    assert store.attestation_posture(EPOCH)["policy_digest"] == POLICY_DIGEST


def test_an_identical_policy_resumes_the_epoch_without_complaint(tmp_path):
    """Canonical before digested: an equal policy must not spuriously refuse.

    A guard that fired on dict insertion order or frozenset iteration order would be
    an outage dressed as a control — the operator's correct restart would look like
    an attack. The digest is taken over a normalised manifest, so a policy rebuilt
    from the same material in a different order is the same policy.
    """
    store = _store(tmp_path, attested=False)
    store.record_attestation_posture(
        EPOCH, enforced=True, detail="intel root", policy_digest=POLICY_DIGEST
    )

    rebuilt = AttestationPolicy(
        # Same material, rebuilt as different (but equal) mapping and set objects,
        # exactly as a restart rebuilds a policy from configuration.
        trusted_roots=dict({"intel-dcap-root-1": bytes(DCAP_ROOT)}),
        allowed_measurements=frozenset(sorted(POLICY.allowed_measurements)),
        allowed_gpu_measurements=None,
    )
    store.record_attestation_posture(
        EPOCH,
        enforced=True,
        detail="restarted",
        policy_digest=attestation_policy_digest(rebuilt),
    )
    assert store.attestation_posture(EPOCH)["policy_digest"] == POLICY_DIGEST


def test_enforcement_cannot_be_claimed_without_naming_the_policy(tmp_path):
    """"Attestation was on" is not a claim about which quotes were accepted."""
    store = _store(tmp_path, attested=False)

    with pytest.raises(CyberGymScoreError, match="without an attestation policy digest"):
        store.record_attestation_posture(EPOCH, enforced=True, detail="policy configured")
    assert store.attestation_posture(EPOCH) is None


def test_an_epoch_pinned_without_a_policy_digest_cannot_be_resumed_or_exported(tmp_path):
    """The pre-existing-epoch case fails closed, like an unrecorded posture does.

    The first posture table stored only the flag. Those rows survive an upgrade, and
    an epoch opened by that build cannot be shown to have been resumed under the
    same policy — there is nothing to compare against. Treating it as attested would
    hand the swap back to anyone who could arrange one restart under the old build.
    """
    store = _store(tmp_path, [("5Miner", "8", "receipt-a")], attested=False)
    # Exactly what the older build wrote: enforcement claimed, policy unnamed.
    with store._connection:
        store._connection.execute(
            "INSERT INTO cybergym_epoch_attestation"
            "(epoch, enforced, detail, policy_digest, recorded_at) VALUES (?,?,?,?,?)",
            (EPOCH, 1, "policy configured", "", CLOSED_AT),
        )
    store.mark_epoch(EPOCH, state=EPOCH_CLOSED, scored_miners=1, at=CLOSED_AT)

    assert store.attestation_posture(EPOCH)["policy_digest"] == ""
    with pytest.raises(CyberGymScoreError, match="without recording WHICH policy"):
        store.record_attestation_posture(
            EPOCH, enforced=True, detail="resumed", policy_digest=POLICY_DIGEST
        )
    with pytest.raises(report.CyberGymScoreReportError, match="not WHICH policy"):
        _build(store)

    # The loopback acknowledgement is still the only way through, and it is loud.
    assert report.build_score_report(
        store,
        network="finney",
        netuid=39,
        source_epoch=EPOCH,
        producer_hotkey="5Producer",
        allow_unattested=True,
    )["scores"] == {"5Miner": 8.0}


def test_an_unattested_epoch_may_not_name_a_policy(tmp_path):
    """The flag and the digest must agree, or the record says two things at once."""
    store = _store(tmp_path, attested=False)

    with pytest.raises(CyberGymScoreError, match="as unattested while naming"):
        store.record_attestation_posture(
            EPOCH, enforced=False, detail="no policy", policy_digest=POLICY_DIGEST
        )


def test_a_posture_table_without_the_digest_column_is_migrated_in_place(tmp_path):
    """An existing database opens and keeps its rows; the column arrives empty.

    Empty is the fail-closed value, not a silent pass: the row still claims
    enforcement, and both the resume guard and the exporter refuse it (see
    `test_an_epoch_pinned_without_a_policy_digest_cannot_be_resumed_or_exported`).
    """
    import sqlite3

    path = tmp_path / "legacy.sqlite"
    legacy = sqlite3.connect(str(path))
    legacy.execute(
        "CREATE TABLE cybergym_epoch_attestation ("
        "  epoch INTEGER PRIMARY KEY, enforced INTEGER NOT NULL,"
        "  detail TEXT NOT NULL, recorded_at TEXT NOT NULL)"
    )
    legacy.execute(
        "INSERT INTO cybergym_epoch_attestation VALUES (?,?,?,?)",
        (EPOCH, 1, "policy configured", CLOSED_AT),
    )
    legacy.commit()
    legacy.close()

    store = CyberGymScoreStore(str(path))

    assert store.attestation_posture(EPOCH) == {
        "enforced": True,
        "detail": "policy configured",
        "policy_digest": "",
        "recorded_at": CLOSED_AT,
    }
    # Idempotent: reopening an already-migrated database is a no-op.
    assert CyberGymScoreStore(str(path)).attestation_posture(EPOCH)["policy_digest"] == ""


# --- epoch frontier (batch nonce + dispatched_units) for the tournament -------
def test_epoch_frontier_first_write_wins_and_refuses_a_mismatch(tmp_path):
    store = _store(tmp_path)
    assert store.epoch_frontier(EPOCH) is None
    store.record_frontier(EPOCH, "cgnonce-x", "11")
    assert store.epoch_frontier(EPOCH) == {"nonce": "cgnonce-x", "dispatched_units": "11"}
    store.record_frontier(EPOCH, "cgnonce-x", "11")  # byte-identical retry is idempotent
    with pytest.raises(CyberGymScoreError):
        store.record_frontier(EPOCH, "cgnonce-x", "12")  # a different value refuses


def test_build_score_report_emits_the_frontier_when_recorded(tmp_path):
    store = _store(tmp_path, [("5MinerA", "8", "receipt-a")])
    store.mark_epoch(EPOCH, state=EPOCH_CLOSED, scored_miners=1, at=CLOSED_AT)
    store.record_frontier(EPOCH, "cgnonce-sha256:abc", "11")
    document = _build(store)
    assert document["nonce"] == "cgnonce-sha256:abc"
    # a float, normalized identically to cathedral-validator so the digest agrees
    assert document["dispatched_units"] == 11.0


def test_build_score_report_omits_the_frontier_when_absent(tmp_path):
    """An epoch scored before the frontier shipped keeps the byte-identical report."""
    store = _store(tmp_path, [("5MinerA", "8", "receipt-a")])
    store.mark_epoch(EPOCH, state=EPOCH_CLOSED, scored_miners=1, at=CLOSED_AT)
    document = _build(store)
    assert "nonce" not in document and "dispatched_units" not in document
