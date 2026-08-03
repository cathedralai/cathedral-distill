"""Durable CyberGym score report: closed store -> exact authenticated bytes."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from cathedral_distill import cybergym_score_report as report
from cathedral_distill import cybergym_scores as scores_module
from cathedral_distill.cybergym_evidence_manifest import manifest_digest
from cathedral_distill.cybergym_scores import (
    EPOCH_CLOSED,
    CyberGymScoreError,
    CyberGymScoreStore,
)

EPOCH = 42
CLOSED_AT = "2026-08-03T10:11:12.123456+00:00"


def _store(tmp_path, rows=()):
    store = CyberGymScoreStore(str(tmp_path / "scores.sqlite"))
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
