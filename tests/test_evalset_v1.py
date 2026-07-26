"""Tests for the hardened hermes-extract-v1 set.

What must hold: the ground truth actually follows the stated authority rule,
extracting any non-authoritative document fails, mixing documents fails, and
the whole set stays deterministic.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import evalset_v1 as v1  # noqa: E402
from cathedral_distill.grader import grade_item  # noqa: E402

_HASHES = re.compile(r"^content_hash: ([0-9a-f]{64})$", re.MULTILINE)


def _items(**kw):
    return v1.build(seed=41, items=16, canaries=2, **kw) if kw else v1.build(
        seed=41, items=16, canaries=2)


def test_deterministic():
    a, b = v1.build(seed=41), v1.build(seed=41)
    assert [i.as_dict() for i in a] == [i.as_dict() for i in b]


def test_different_seed_differs():
    assert ([i.as_dict() for i in v1.build(seed=41)]
            != [i.as_dict() for i in v1.build(seed=42)])


def test_bundles_contain_multiple_documents_and_hashes():
    for item in _items():
        hashes = _HASHES.findall(item.prompt)
        assert len(hashes) >= 4  # ≥3 contenders + ≥1 noise
        assert len(set(hashes)) == len(hashes)  # every document distinct


def test_expected_hash_is_one_of_the_bundle_hashes():
    for item in _items():
        assert item.checks["expected"]["content_hash"] in _HASHES.findall(item.prompt)


def test_ground_truth_follows_the_stated_rule():
    """Re-derive the winner from the prompt text alone; it must match expected."""
    doc_re = re.compile(
        r"url: (?P<url>\S+)\ncontent_hash: (?P<hash>[0-9a-f]{64})\n"
        r"--- document \d+ ---\n# (?P<title>[^\n]+)\nIssuer: (?P<issuer>[^\n]+)\n"
        r"Source class: (?P<cls>[^\n]+)\nPublished: (?P<pub>[^\n]+)\n"
        r"Reference: (?P<ref>[^\n]+)")
    for item in _items():
        topic = item.prompt.rsplit("QUESTION: Extract the authoritative record for: ", 1)[1].strip()
        docs = [m.groupdict() for m in doc_re.finditer(item.prompt)]
        on_topic = [d for d in docs if topic in d["title"] or topic in item.prompt[
            item.prompt.find(d["hash"]):item.prompt.find(d["hash"]) + 2000]]
        # apply the rule over documents whose body mentions the topic
        contenders = [d for d in docs if f" {topic} " in ("# " + d["title"] + " ")
                      or topic in d["title"]]
        assert contenders, "topic must appear in at least one title"
        winner = max(contenders,
                     key=lambda d: (-v1.CLASS_RANK.index(d["cls"]), d["pub"]))
        assert winner["hash"] == item.checks["expected"]["content_hash"]
        assert winner["ref"] == item.checks["expected"]["reference"]


def test_perfect_answer_passes():
    for item in _items():
        assert grade_item(item.item_id, json.dumps(item.checks["expected"]),
                          item.checks).passed


def test_extracting_a_distractor_fails():
    """A well-formed answer from the wrong document must fail."""
    doc_re = re.compile(
        r"content_hash: (?P<hash>[0-9a-f]{64})\n--- document \d+ ---\n"
        r"# (?P<title>[^\n]+)\nIssuer: (?P<issuer>[^\n]+)\nSource class: [^\n]+\n"
        r"Published: (?P<pub>[^\n]+)\nReference: (?P<ref>[^\n]+)\nSource: (?P<url>\S+)")
    failures = 0
    for item in _items():
        expected_hash = item.checks["expected"]["content_hash"]
        for m in doc_re.finditer(item.prompt):
            if m["hash"] == expected_hash:
                continue
            wrong = {
                "title": m["title"], "issuer": m["issuer"], "published": m["pub"],
                "reference": m["ref"], "source_url": m["url"],
                "content_hash": m["hash"],
                "obligation_count": item.checks["expected"]["obligation_count"],
            }
            verdict = grade_item(item.item_id, json.dumps(wrong), item.checks)
            assert not verdict.passed
            failures += 1
            break
    assert failures == len(_items())


def test_mixing_documents_fails():
    """Right fields, wrong document's hash — the evidence-selection trap."""
    for item in _items():
        other = next(h for h in _HASHES.findall(item.prompt)
                     if h != item.checks["expected"]["content_hash"])
        mixed = dict(item.checks["expected"], content_hash=other)
        assert not grade_item(item.item_id, json.dumps(mixed), item.checks).passed


def test_both_decision_modes_are_present():
    modes = {i.checks["decided_by"] for i in v1.build(seed=41)}
    assert modes == {"class", "date"}


def test_canaries_minted_and_counted():
    items = v1.build(seed=41, items=32, canaries=4)
    marked = [i for i in items if i.checks.get("canary")]
    assert len(marked) == 4
    for item in marked:
        assert item.checks["expected"]["reference"].startswith("CANARY/") or any(
            d.startswith("CANARY/") for d in re.findall(r"Reference: (\S+)", item.prompt))


def test_prompts_are_materially_longer_than_v0():
    from cathedral_distill import evalset as v0
    v0_len = sum(len(i.prompt) for i in v0.build(seed=39)) / 32
    v1_len = sum(len(i.prompt) for i in v1.build(seed=41)) / 32
    assert v1_len > 2.5 * v0_len
