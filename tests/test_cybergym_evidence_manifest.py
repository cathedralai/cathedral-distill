"""The producer side of the canonical evidence manifest.

A score report's ``evidence_sha256`` must commit to the receipts this validator scored,
because the consumer rebuilds the same manifest from the receipts IT admitted and
requires exact equality. Three repositories implement this core and no import spans
them, so the schema string and the empty digest are PINNED here rather than merely
computed: drift must fail a test, not fail to verify a real report in production.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from cathedral_distill import cybergym_evidence_manifest as ev


class _Result:
    """MinerResult-shaped, which is what score_epoch returns."""

    def __init__(self, hotkey, receipt_id, work_units, creditable=True):
        self.miner_hotkey = hotkey
        self.receipt_id = receipt_id
        self.work_units = work_units
        self.creditable = creditable


def test_the_schema_string_is_pinned():
    assert ev.SCHEMA == "cathedral_cybergym_evidence_manifest_v1"


def test_the_empty_digest_is_deterministic_and_pinned():
    digest = ev.empty_digest(network="finney", netuid=39, source_epoch=11)
    expected = hashlib.sha256(
        json.dumps(
            {
                "schema": ev.SCHEMA,
                "network": "finney",
                "netuid": 39,
                "source_epoch": 11,
                "entries": [],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert digest == expected


def test_only_creditable_results_are_attested():
    """A result that earned nothing is not part of what is being paid.

    Including it would make the producer's digest disagree with the consumer's, which
    credits only what its own admission rules allow, and the lane would burn on every
    honest epoch.
    """
    kw = dict(network="finney", netuid=39, source_epoch=11)
    scored = [
        _Result("5A", "r1", "12"),
        _Result("5B", "r2", "3"),
        _Result("5C", "r3", "9", creditable=False),
    ]
    assert ev.evidence_sha256_for_results(scored, **kw) == ev.manifest_digest(
        entries=[
            {"miner_hotkey": "5A", "receipt_id": "r1", "work_units": "12"},
            {"miner_hotkey": "5B", "receipt_id": "r2", "work_units": "3"},
        ],
        **kw,
    )


def test_the_producer_digest_is_order_independent():
    kw = dict(network="finney", netuid=39, source_epoch=11)
    a = ev.evidence_sha256_for_results(
        [_Result("5B", "r2", 12), _Result("5A", "r1", "3.5")], **kw
    )
    b = ev.evidence_sha256_for_results(
        [_Result("5A", "r1", "3.50"), _Result("5B", "r2", "12.000")], **kw
    )
    assert a == b


def test_an_epoch_with_nothing_creditable_uses_the_empty_digest():
    kw = dict(network="finney", netuid=39, source_epoch=11)
    assert ev.evidence_sha256_for_results(
        [_Result("5C", "r3", "9", creditable=False)], **kw
    ) == ev.empty_digest(**kw)


@pytest.mark.parametrize(
    "field,value",
    [("network", "test"), ("netuid", 1), ("source_epoch", 12)],
)
def test_the_digest_is_audience_and_epoch_bound(field, value):
    base = dict(network="finney", netuid=39, source_epoch=11)
    other = dict(base)
    other[field] = value
    scored = [_Result("5A", "r1", "12")]
    assert ev.evidence_sha256_for_results(scored, **base) != (
        ev.evidence_sha256_for_results(scored, **other)
    )


def test_changing_any_committed_field_changes_the_digest():
    kw = dict(network="finney", netuid=39, source_epoch=11)
    base = ev.evidence_sha256_for_results([_Result("5A", "r1", "12")], **kw)
    assert base != ev.evidence_sha256_for_results([_Result("5B", "r1", "12")], **kw)
    assert base != ev.evidence_sha256_for_results([_Result("5A", "r2", "12")], **kw)
    assert base != ev.evidence_sha256_for_results([_Result("5A", "r1", "13")], **kw)


@pytest.mark.parametrize("bad", ["-1", "nan", "inf", "abc"])
def test_an_unusable_amount_is_refused(bad):
    with pytest.raises(ev.EvidenceManifestError):
        ev.evidence_sha256_for_results(
            [_Result("5A", "r1", bad)], network="finney", netuid=39, source_epoch=11
        )
