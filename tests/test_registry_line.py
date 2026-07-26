"""Tests for the registry line.

The property that matters most: a registry line cannot carry recipe content. The
strict key set is what enforces it, so unknown fields must be a parse error rather
than ignored data.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import registry_line as rlx  # noqa: E402

HOTKEY = "5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G"
OTHER_HOTKEY = "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw"
CKPT = "sha256:" + "a1" * 32
RECIPE = "sha256:" + "b2" * 32


def _line(**kw):
    base = dict(
        miner_hotkey=HOTKEY,
        track="hermes-extract-v0",
        checkpoint_digest=CKPT,
        recipe_digest=RECIPE,
        receipt_uri="https://receipts.cathedral.computer/abc.json",
        version="1.0.0",
        signature="sig",
    )
    base.update(kw)
    return rlx.RegistryLine(**base)


def test_round_trips_through_canonical_jsonl():
    line = _line()
    assert rlx.parse_line(line.to_line()) == line


def test_canonical_form_is_stable():
    assert _line().to_line() == _line().to_line()


def test_carries_only_the_six_fields_plus_schema_and_signature():
    parsed = json.loads(_line().to_line())
    assert set(parsed) == {
        "schema", "miner_hotkey", "track", "checkpoint_digest",
        "recipe_digest", "receipt_uri", "version", "signature",
    }


def test_recipe_content_cannot_be_smuggled_in_an_extra_field():
    payload = json.loads(_line().to_line())
    payload["system_prompt"] = "You are a legal extraction agent..."
    with pytest.raises(rlx.RegistryLineError, match="unknown fields: system_prompt"):
        rlx.parse_line(json.dumps(payload))


def test_missing_field_is_rejected():
    payload = json.loads(_line().to_line())
    del payload["recipe_digest"]
    with pytest.raises(rlx.RegistryLineError, match="missing fields: recipe_digest"):
        rlx.parse_line(json.dumps(payload))


def test_signature_may_be_absent_at_parse_time():
    payload = json.loads(_line().to_line())
    del payload["signature"]
    assert rlx.parse_line(json.dumps(payload)).signature == ""


def test_signing_payload_excludes_the_signature():
    assert b"sig" not in _line().signing_payload()
    assert _line().signing_payload() == _line(signature="other").signing_payload()


# --------------------------------------------------------------------------- #
# Field validation
# --------------------------------------------------------------------------- #

def test_bad_digest_is_rejected():
    with pytest.raises(rlx.RegistryLineError, match="checkpoint_digest"):
        _line(checkpoint_digest="sha256:NOTHEX")
    with pytest.raises(rlx.RegistryLineError, match="recipe_digest"):
        _line(recipe_digest="deadbeef")


def test_identical_digests_are_rejected():
    with pytest.raises(rlx.RegistryLineError, match="must differ"):
        _line(recipe_digest=CKPT)


def test_plain_http_receipt_uri_is_rejected():
    # Anyone on the path could swap the receipt a verifier fetches.
    with pytest.raises(rlx.RegistryLineError, match="https:// or ipfs://"):
        _line(receipt_uri="http://receipts.example/abc.json")


def test_ipfs_uri_is_accepted():
    assert _line(receipt_uri="ipfs://bafy123").receipt_uri.startswith("ipfs://")


def test_uri_with_whitespace_is_rejected():
    with pytest.raises(rlx.RegistryLineError, match="whitespace"):
        _line(receipt_uri="https://example/a b.json")


def test_non_semver_version_is_rejected():
    with pytest.raises(rlx.RegistryLineError, match="semver"):
        _line(version="v1")


def test_bad_hotkey_is_rejected():
    with pytest.raises(rlx.RegistryLineError, match="ss58"):
        _line(miner_hotkey="alice")


def test_track_must_be_lowercase_slug():
    with pytest.raises(rlx.RegistryLineError, match="lowercase"):
        _line(track="Hermes Extract")


def test_oversized_uri_is_rejected():
    # The URI cap fires before the whole-line cap, which is the tighter bound.
    with pytest.raises(rlx.RegistryLineError, match="1..512 chars"):
        _line(receipt_uri="https://example/" + "a" * 600)


def test_oversized_untrusted_line_is_rejected_at_parse():
    # Unreachable through the constructor, since every field is bounded. Still
    # enforced on the parse side, because that is where untrusted bytes arrive.
    payload = json.loads(_line().to_line())
    payload["track"] = "x" * 4000
    with pytest.raises(rlx.RegistryLineError, match="maximum size"):
        rlx.parse_line(json.dumps(payload))


# --------------------------------------------------------------------------- #
# Submission registry
# --------------------------------------------------------------------------- #

def test_append_and_lookup():
    reg = rlx.SubmissionRegistry()
    reg.append(_line())
    assert reg.submitter_of(CKPT) == HOTKEY
    assert len(reg) == 1


def test_unsigned_submission_is_rejected():
    reg = rlx.SubmissionRegistry()
    with pytest.raises(rlx.RegistryLineError, match="must be signed"):
        reg.append(_line(signature=""))


def test_another_miner_cannot_resubmit_the_same_checkpoint():
    # The plagiarism path, denied before it reaches scoring.
    reg = rlx.SubmissionRegistry()
    reg.append(_line(miner_hotkey=HOTKEY))
    with pytest.raises(rlx.RegistryLineError, match="already submitted by another"):
        reg.append(_line(miner_hotkey=OTHER_HOTKEY))


def test_same_miner_cannot_double_submit():
    reg = rlx.SubmissionRegistry()
    reg.append(_line())
    with pytest.raises(rlx.RegistryLineError, match="already submitted by this miner"):
        reg.append(_line())


def test_for_track_filters():
    reg = rlx.SubmissionRegistry()
    reg.append(_line())
    reg.append(_line(track="other-track", checkpoint_digest="sha256:" + "c3" * 32))
    assert len(reg.for_track("hermes-extract-v0")) == 1


def test_jsonl_skips_blanks_and_comments():
    text = f"# a comment\n\n{_line().to_line()}\n"
    assert len(list(rlx.parse_jsonl(text))) == 1


def test_load_registry_preserves_first_submitter_against_hostile_feed():
    reg = rlx.SubmissionRegistry()
    reg.append(_line(miner_hotkey=HOTKEY))
    hostile = reg.to_jsonl() + "\n" + _line(miner_hotkey=OTHER_HOTKEY).to_line()
    rebuilt = rlx.load_registry(hostile)
    assert rebuilt.submitter_of(CKPT) == HOTKEY
    assert len(rebuilt) == 1


def test_load_registry_skips_malformed_rows_without_failing():
    text = f"{_line().to_line()}\nnot json at all\n"
    with pytest.raises(rlx.RegistryLineError):
        list(rlx.parse_jsonl(text))
