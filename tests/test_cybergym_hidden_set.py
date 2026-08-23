"""The backend-verified hidden-set attestation posture is production-publishable.

The launch anti-gaming model when per-miner Intel-TDX is not enforced. An epoch stamped
with this posture must pass the exporter's `require_attested_epoch` gate WITHOUT the
`--allow-unattested-e2e` override — while a genuinely unattested epoch still refuses, and
a hidden-set posture whose controls are off is refused at the source.
"""
from __future__ import annotations

import pytest

from cathedral_distill.cybergym_hidden_set import (
    HiddenSetPolicy,
    HiddenSetPolicyError,
    hidden_set_policy_digest,
)
from cathedral_distill.cybergym_score_report import (
    CyberGymScoreReportError,
    require_attested_epoch,
)
from cathedral_distill.cybergym_scores import CyberGymScoreStore


CORPUS = "sha256:" + "cd" * 32


def _store(tmp_path):
    return CyberGymScoreStore(str(tmp_path / "scores.sqlite"))


def test_hidden_set_epoch_is_publishable_without_the_override(tmp_path):
    store = _store(tmp_path)
    policy = HiddenSetPolicy(corpus_digest=CORPUS)
    store.record_attestation_posture(
        7, enforced=True, detail=policy.detail(), policy_digest=hidden_set_policy_digest(policy))
    # accepted for a production intake with NO --allow-unattested-e2e
    require_attested_epoch(store, 7, allow_unattested=False)
    posture = store.attestation_posture(7)
    assert posture["enforced"] and posture["policy_digest"] == hidden_set_policy_digest(policy)
    assert "Intel-TDX" not in policy.detail().replace("NO per-miner Intel-TDX", "")  # never claims TDX
    assert "recur" in policy.detail().lower()  # honest: states tasks recur, does NOT over-claim never-repeat


def test_unattested_epoch_still_refuses(tmp_path):
    store = _store(tmp_path)
    store.record_attestation_posture(8, enforced=False, detail="no policy", policy_digest="")
    with pytest.raises(CyberGymScoreReportError):
        require_attested_epoch(store, 8, allow_unattested=False)


def test_unrecorded_epoch_still_refuses(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(CyberGymScoreReportError):
        require_attested_epoch(store, 9, allow_unattested=False)


def test_require_secure_refuses_a_gameable_posture():
    # a hidden-set posture with a control off, or with no corpus named, is NOT verified
    for weak in (
        HiddenSetPolicy(corpus_digest=CORPUS, real_differential=False),
        HiddenSetPolicy(corpus_digest=CORPUS, opaque_handles=False),
        HiddenSetPolicy(corpus_digest=CORPUS, gates_required=False),
        HiddenSetPolicy(corpus_digest=""),  # controls on but no corpus bound -> refused
    ):
        with pytest.raises(HiddenSetPolicyError):
            weak.require_secure()
    HiddenSetPolicy(corpus_digest=CORPUS).require_secure()  # all controls on + corpus named -> ok


def test_digest_binds_the_controls_and_the_corpus():
    # weakening a control OR swapping the corpus changes the digest, so a resume that does either is
    # refused by the posture guard on the same terms a swapped Intel-TDX policy is.
    base = hidden_set_policy_digest(HiddenSetPolicy(corpus_digest=CORPUS))
    assert base != hidden_set_policy_digest(HiddenSetPolicy(corpus_digest=CORPUS, gates_required=False))
    assert base != hidden_set_policy_digest(HiddenSetPolicy(corpus_digest=CORPUS, real_differential=False))
    assert base != hidden_set_policy_digest(HiddenSetPolicy(corpus_digest="sha256:" + "ee" * 32))  # corpus swap
    assert hidden_set_policy_digest(None) == ""
