"""Tests for deterministic grading.

Focus: the grader must be tolerant about packaging, strict about answers, and
byte-identical across runs. The last property is what the TDX binding depends on.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import grader as g  # noqa: E402

CHECKS = {
    "kind": "extraction",
    "expected": {"invoice_no": "INV-2026-0042", "total": 1240.5, "currency": "USD"},
    "required_fields": ["invoice_no", "total", "currency"],
    "normalize_default": {"casefold": True, "collapse_whitespace": True},
    "normalize": {"total": {"tolerance": 0.01}},
}


def _grade(output, checks=None):
    return g.grade_item("inv-001", output, checks or CHECKS)


def test_clean_json_passes():
    out = '{"invoice_no": "INV-2026-0042", "total": 1240.50, "currency": "USD"}'
    assert _grade(out).passed


def test_markdown_fenced_json_passes():
    # Small models wrap output constantly; that is formatting, not error.
    out = 'Here you go:\n```json\n{"invoice_no":"INV-2026-0042","total":1240.5,"currency":"USD"}\n```'
    assert _grade(out).passed


def test_json_embedded_in_prose_passes():
    out = 'The result is {"invoice_no":"INV-2026-0042","total":1240.5,"currency":"USD"} as requested.'
    assert _grade(out).passed


def test_nested_braces_recovered_correctly():
    out = '{"invoice_no":"INV-2026-0042","total":1240.5,"currency":"USD","meta":{"a":{"b":1}}}'
    assert _grade(out).passed


def test_brace_inside_string_does_not_break_recovery():
    checks = {**CHECKS, "expected": {**CHECKS["expected"], "invoice_no": "INV-{2026}-0042"}}
    out = 'x {"invoice_no":"INV-{2026}-0042","total":1240.5,"currency":"USD"} y'
    assert _grade(out, checks).passed


def test_case_and_whitespace_normalized():
    out = '{"invoice_no":"  inv-2026-0042 ","total":1240.5,"currency":"usd"}'
    assert _grade(out).passed


def test_numeric_tolerance_respected():
    assert _grade('{"invoice_no":"INV-2026-0042","total":1240.505,"currency":"USD"}').passed
    assert not _grade('{"invoice_no":"INV-2026-0042","total":1250.0,"currency":"USD"}').passed


def test_number_as_string_with_thousands_separator():
    out = '{"invoice_no":"INV-2026-0042","total":"1,240.50","currency":"USD"}'
    assert _grade(out).passed


def test_wrong_value_fails_and_reports_field():
    result = _grade('{"invoice_no":"INV-2026-9999","total":1240.5,"currency":"USD"}')
    assert not result.passed
    assert result.field_scores["invoice_no"] is False
    assert result.field_scores["currency"] is True


def test_missing_field_fails():
    result = _grade('{"invoice_no":"INV-2026-0042","total":1240.5}')
    assert not result.passed
    assert result.field_scores["currency"] is False


def test_unparseable_output_fails_cleanly():
    result = _grade("I could not find an invoice number, sorry.")
    assert not result.passed
    assert result.reason == "unparseable_json"
    assert all(ok is False for ok in result.field_scores.values())


def test_empty_output_fails_cleanly():
    assert _grade("").reason == "empty_output"
    assert _grade(None).reason == "empty_output"


def test_top_level_array_is_a_schema_violation_not_a_rescue():
    # Well-formed JSON of the wrong shape must fail as a shape error. Scanning
    # inside for a brace span would grade an arbitrary list element.
    result = _grade('[{"invoice_no":"INV-2026-0042"}]')
    assert not result.passed
    assert result.reason == "wrong_json_shape"


def test_multi_element_array_is_never_partially_graded():
    out = '[{"invoice_no":"INV-2026-0042","total":1240.5,"currency":"USD"},{"x":1}]'
    assert _grade(out).reason == "wrong_json_shape"


def test_scalar_json_is_a_shape_violation():
    assert _grade("42").reason == "wrong_json_shape"
    assert _grade('"just a string"').reason == "wrong_json_shape"


def test_fenced_array_is_also_a_shape_violation():
    assert _grade('```json\n[{"a":1}]\n```').reason == "wrong_json_shape"


def test_oversized_output_is_rejected():
    assert _grade("x" * (g.MAX_OUTPUT_BYTES + 1)).reason == "output_too_large"


def test_extra_fields_allowed_by_default_but_can_be_forbidden():
    out = '{"invoice_no":"INV-2026-0042","total":1240.5,"currency":"USD","note":"hi"}'
    assert _grade(out).passed
    strict = {**CHECKS, "forbid_extra_fields": True}
    assert not _grade(out, strict).passed
    assert _grade(out, strict).reason == "unexpected_fields"


def test_bool_is_not_coerced_to_number():
    checks = {**CHECKS, "expected": {"flag": 1}, "required_fields": ["flag"]}
    assert not _grade('{"flag": true}', checks).passed


def test_none_expected_requires_none():
    checks = {**CHECKS, "expected": {"note": None}, "required_fields": ["note"]}
    assert _grade('{"note": null}', checks).passed
    assert not _grade('{"note": "something"}', checks).passed


def test_nan_and_infinity_never_match():
    checks = {**CHECKS, "expected": {"total": 1240.5}, "required_fields": ["total"]}
    assert not _grade('{"total": "NaN"}', checks).passed
    assert not _grade('{"total": "Infinity"}', checks).passed


def test_unordered_list_match_without_hashable_elements():
    checks = {
        **CHECKS,
        "expected": {"lines": [{"sku": "A"}, {"sku": "B"}]},
        "required_fields": ["lines"],
    }
    assert _grade('{"lines":[{"sku":"B"},{"sku":"A"}]}', checks).passed
    assert not _grade('{"lines":[{"sku":"A"}]}', checks).passed


def test_ordered_list_respects_order():
    checks = {
        **CHECKS,
        "expected": {"steps": ["a", "b"]},
        "required_fields": ["steps"],
        "normalize": {"steps": {"ordered": True}},
    }
    assert _grade('{"steps":["a","b"]}', checks).passed
    assert not _grade('{"steps":["b","a"]}', checks).passed


def test_unicode_normalized_consistently():
    # Composed vs decomposed forms must grade identically (NFKC).
    checks = {**CHECKS, "expected": {"name": "café"}, "required_fields": ["name"]}
    assert _grade('{"name":"cafe\\u0301"}', checks).passed


def test_grading_is_deterministic_across_repeated_runs():
    out = '{"invoice_no":"INV-2026-0042","total":1240.5,"currency":"usd"}'
    verdicts = [_grade(out).passed for _ in range(50)]
    assert len(set(verdicts)) == 1


def test_unknown_grader_kind_is_an_error():
    with pytest.raises(g.GraderError, match="unknown grader kind"):
        g.grade_item("x", "{}", {"kind": "vibes"})


def test_misconfigured_item_raises_rather_than_failing_silently():
    with pytest.raises(g.GraderError, match="expected"):
        g.grade_item("x", "{}", {"kind": "extraction"})
    with pytest.raises(g.GraderError, match="no expected value"):
        g.grade_item("x", "{}", {"kind": "extraction", "expected": {"a": 1},
                                 "required_fields": ["b"]})


def test_grader_digest_is_stable_and_well_formed():
    first = g.grader_digest()
    assert first == g.grader_digest()
    assert first.startswith("sha256:") and len(first) == 71


def test_partial_score_is_diagnostic_only():
    result = _grade('{"invoice_no":"INV-2026-0042","total":1240.5,"currency":"EUR"}')
    assert not result.passed
    assert 0 < result.partial < 1
