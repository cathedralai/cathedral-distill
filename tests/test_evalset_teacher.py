"""Tests for the hermes-extract-v0 set and the teacher client."""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import evalset  # noqa: E402
from cathedral_distill import teacher as tc  # noqa: E402
from cathedral_distill import teacher_registry as tr  # noqa: E402
from cathedral_distill.grader import grade_item  # noqa: E402

NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Eval set
# --------------------------------------------------------------------------- #

def test_build_is_deterministic():
    a = evalset.build(seed=39)
    b = evalset.build(seed=39)
    assert [i.as_dict() for i in a] == [i.as_dict() for i in b]
    assert evalset.manifest(a)["content_digest"] == evalset.manifest(b)["content_digest"]


def test_different_seed_different_set():
    assert (evalset.manifest(evalset.build(seed=39))["content_digest"]
            != evalset.manifest(evalset.build(seed=40))["content_digest"])


def test_counts_and_canaries():
    items = evalset.build(seed=39, items=32, canaries=4)
    assert len(items) == 32
    assert sum(bool(i.checks.get("canary")) for i in items) == 4


def test_every_item_cites_a_real_pool_url():
    pool = {u for u, _c, _p in evalset.SOURCE_POOL}
    for item in evalset.build(seed=39):
        assert item.checks["expected"]["source_url"] in pool


def test_canary_references_are_minted_not_public():
    for item in evalset.build(seed=39):
        if item.checks.get("canary"):
            assert item.checks["expected"]["reference"].startswith("CANARY/")


def test_prompt_contains_the_hash_the_model_must_copy():
    for item in evalset.build(seed=39, items=8, canaries=1):
        digest = item.checks["expected"]["content_hash"]
        assert f"content_hash: {digest}" in item.prompt
        assert len(digest) == 64


def test_perfect_extraction_passes_grading():
    for item in evalset.build(seed=39, items=8, canaries=1):
        output = json.dumps(item.checks["expected"])
        assert grade_item(item.item_id, output, item.checks).passed


def test_truncated_content_hash_fails_grading():
    # The classic Card-sinking mistake must fail even though everything else is right.
    item = evalset.build(seed=39, items=4, canaries=0)[0]
    wrong = dict(item.checks["expected"])
    wrong["content_hash"] = wrong["content_hash"][:32]
    assert not grade_item(item.item_id, json.dumps(wrong), item.checks).passed


def test_uppercased_hash_fails_but_uppercased_title_passes():
    item = evalset.build(seed=39, items=4, canaries=0)[0]
    upper_hash = dict(item.checks["expected"])
    upper_hash["content_hash"] = upper_hash["content_hash"].upper()
    assert not grade_item(item.item_id, json.dumps(upper_hash), item.checks).passed
    upper_title = dict(item.checks["expected"])
    upper_title["title"] = upper_title["title"].upper()
    assert grade_item(item.item_id, json.dumps(upper_title), item.checks).passed


def test_invalid_shape_requests_are_rejected():
    with pytest.raises(ValueError):
        evalset.build(items=0)
    with pytest.raises(ValueError):
        evalset.build(items=4, canaries=4)


# --------------------------------------------------------------------------- #
# Teacher client
# --------------------------------------------------------------------------- #

def _config():
    return tc.TeacherConfig(
        provider="yunwei", model="kimi-k3", version="2026-07-27",
        base_url="https://teacher.example/v1", api_key="sk-test", top_logprobs=3)


def _transport(replies):
    calls = []

    def send(body):
        calls.append(body)
        return replies(body) if callable(replies) else replies

    send.calls = calls
    return send


def _reply(content, with_logprobs=True):
    choice = {"message": {"content": content}}
    if with_logprobs:
        choice["logprobs"] = {"content": [
            {"token": "x", "top_logprobs": [
                {"token": "x", "logprob": -0.01},
                {"token": "y", "logprob": -4.2},
                {"token": "z", "logprob": -5.0},
                {"token": "w", "logprob": -9.9},  # beyond k, must be trimmed
            ]}
        ]}
    return {"choices": [choice]}


def test_generate_records_everything_needed_to_reproduce():
    transport = _transport(_reply('{"a":1}'))
    record = tc.TeacherClient(_config(), transport).generate("extract this", seed=7)
    assert record.completion == '{"a":1}'
    assert record.teacher_id == "yunwei/kimi-k3/2026-07-27"
    assert record.seed == 7
    assert record.record_hash.startswith("sha256:")
    sent = transport.calls[0]
    assert sent["seed"] == 7 and sent["logprobs"] is True


def test_logprobs_are_carried_and_trimmed_to_k():
    record = tc.TeacherClient(_config(), _transport(_reply("out"))).generate("p", seed=1)
    assert record.top_k_logprobs is not None
    assert len(record.top_k_logprobs[0]["top"]) == 3  # trimmed from 4 to k


def test_missing_logprobs_is_recorded_as_none_not_error():
    record = tc.TeacherClient(
        _config(), _transport(_reply("out", with_logprobs=False))
    ).generate("p", seed=1)
    assert record.top_k_logprobs is None


def test_record_hash_is_content_addressed():
    client = tc.TeacherClient(_config(), _transport(_reply("same")))
    a = client.generate("p", seed=1)
    b = client.generate("p", seed=1)
    c = client.generate("p", seed=2)
    assert a.record_hash == b.record_hash
    assert a.record_hash != c.record_hash


def test_api_key_never_appears_in_record_or_repr():
    record = tc.TeacherClient(_config(), _transport(_reply("out"))).generate("p", seed=1)
    blob = json.dumps(record.as_dict()) + repr(_config())
    assert "sk-test" not in blob


def test_from_env_refuses_to_guess_a_hostname():
    with pytest.raises(tc.TeacherError, match="will not guess"):
        tc.TeacherConfig.from_env({"KIMI_API_KEY": "sk-x"})
    with pytest.raises(tc.TeacherError, match="https://"):
        tc.TeacherConfig.from_env(
            {"TEACHER_BASE_URL": "http://relay.example", "KIMI_API_KEY": "sk-x"})


def _registry(permitted=True):
    return tr.TeacherRegistry({
        "yunwei/kimi-k3/2026-07-27": tr.TeacherRecord(
            teacher_id="yunwei/kimi-k3/2026-07-27",
            licence_digest=tr.licence_digest(b"licence"),
            licence_uri="https://example/licence",
            reviewed_at=NOW - timedelta(days=1),
            review_expires_at=NOW + timedelta(days=30),
            reviewer="cathedral-policy",
            permitted_purposes=frozenset(
                {tr.PURPOSE_DISTILLATION} if permitted else {tr.PURPOSE_INFERENCE}),
            competing_model_training=permitted,
        )
    })


def test_corpus_is_licence_gated_before_the_first_token():
    transport = _transport(_reply("out"))
    client = tc.TeacherClient(_config(), transport)
    with pytest.raises(tr.TeacherNotPermitted):
        tc.build_corpus(client, ["p1", "p2"], registry=_registry(permitted=False), at=NOW)
    assert transport.calls == []  # not a single request went out


def test_corpus_generation_with_permitted_teacher():
    client = tc.TeacherClient(_config(), _transport(_reply('{"ok":1}')))
    records = tc.build_corpus(client, ["p1", "p2", "p3"], registry=_registry(), at=NOW)
    assert [r.seed for r in records] == [0, 1, 2]


def test_filter_dedupes_and_applies_task_check():
    client = tc.TeacherClient(
        _config(),
        _transport(lambda body: _reply(
            '{"ok":1}' if body["seed"] < 2 else "not json")))
    records = tc.build_corpus(client, ["a", "b", "c"], registry=_registry(), at=NOW)

    def keep(record):
        try:
            json.loads(record.completion)
            return True
        except ValueError:
            return False

    kept = tc.filter_corpus(records, keep=keep)
    # seeds 0 and 1 return identical JSON (deduped to one), seed 2 fails keep.
    assert len(kept) == 1


def test_corpus_manifest_is_digest_only():
    client = tc.TeacherClient(_config(), _transport(_reply('{"ok":1}')))
    records = tc.build_corpus(client, ["a"], registry=_registry(), at=NOW)
    manifest = tc.corpus_manifest(records)
    assert manifest["rows"] == 1
    assert manifest["with_logprobs"] == 1
    assert manifest["corpus_digest"].startswith("sha256:")
    assert "prompt" not in json.dumps(manifest)
