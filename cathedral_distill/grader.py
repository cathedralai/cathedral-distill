"""Deterministic grading for sealed evaluations.

Two rules govern everything here.

**No model grades a model.** An LLM judge is a scoring surface a miner can
optimize against, and it makes the score depend on a third model nobody pinned.
Every grader in this module is exact-match after declared normalization, so the
same output always yields the same verdict on any machine.

**Determinism is a security property, not a nicety.** The grader digest is
pinned in the receipt and the score is bound into a TDX quote. A grader that
returns different answers across runs — set iteration order, locale-dependent
casing, floating-point accumulation, wall-clock — silently breaks the binding
and produces disputes nobody can resolve. Where a choice existed, this module
takes the boring, reproducible one.

The first grader is schema-constrained extraction: a document in, a strict JSON
object out. It is graded field by field against an expected object, which is the
cleanest signal available and the one small distilled students are actually good
at. `GRADERS` is a registry, so adding frontend/code later is a new entry rather
than a rewrite of the harness.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

MAX_OUTPUT_BYTES = 262_144

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
_WS_RE = re.compile(r"\s+")


class GraderError(ValueError):
    """Raised when a grader is misconfigured. Never raised for a bad model output."""


@dataclass(frozen=True)
class ItemResult:
    """The verdict for one item.

    `passed` is what the receipt binds. `field_scores` and `reason` exist for
    operator diagnosis and are deliberately not part of the score, so improving
    diagnostics can never change a historical result.
    """

    item_id: str
    passed: bool
    reason: str
    field_scores: Mapping[str, bool] = field(default_factory=dict)

    @property
    def partial(self) -> float:
        if not self.field_scores:
            return 1.0 if self.passed else 0.0
        return sum(1 for ok in self.field_scores.values() if ok) / len(self.field_scores)


def parse_model_json(text: str) -> tuple[dict[str, Any] | None, str]:
    """Recover a JSON object from raw model output.

    Small instruction-tuned models wrap JSON in prose or markdown fences far more
    often than large ones. Refusing to unwrap that would measure formatting
    compliance rather than extraction quality, so the recovery ladder is:
    whole string, fenced block, then first balanced brace span.

    This is tolerance about *packaging* only. The object itself is still graded
    strictly, so nothing here lets a wrong answer pass.
    """
    if text is None:
        return None, "empty_output"
    raw = text.strip()
    if not raw:
        return None, "empty_output"
    if len(raw.encode("utf-8")) > MAX_OUTPUT_BYTES:
        return None, "output_too_large"

    # Whole-string JSON first. If the model emitted well-formed JSON of the
    # wrong shape — an array where an object was demanded — that is a schema
    # violation, and we must not "rescue" it by scanning for a brace span
    # inside. Doing so would grade an arbitrary element of a list and make the
    # verdict depend on where a brace happened to fall.
    for candidate in (raw, (_FENCE_RE.search(raw).group(1).strip()
                            if _FENCE_RE.search(raw) else None)):
        if candidate is None:
            continue
        try:
            parsed = json.loads(candidate)
        except (ValueError, RecursionError):
            continue
        if isinstance(parsed, dict):
            return parsed, ""
        return None, "wrong_json_shape"

    # Not valid JSON on its own: the object is embedded in prose. Recovering it
    # here is tolerance about packaging only.
    candidates: list[str] = []
    start = raw.find("{")
    if start != -1:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(raw)):
            char = raw[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(raw[start : index + 1])
                    break

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except (ValueError, RecursionError):
            continue
        if isinstance(parsed, dict):
            return parsed, ""
    return None, "unparseable_json"


def normalize_text(value: str, rules: Mapping[str, Any]) -> str:
    """Apply declared normalization. Order is fixed so results are reproducible."""
    text = unicodedata.normalize("NFKC", value)
    if rules.get("strip", True):
        text = text.strip()
    if rules.get("collapse_whitespace", True):
        text = _WS_RE.sub(" ", text)
    if rules.get("casefold", True):
        # casefold, not lower: lower() is locale-surprising on some alphabets.
        text = text.casefold()
    if rules.get("strip_punctuation", False):
        text = "".join(
            char for char in text if not unicodedata.category(char).startswith("P")
        )
    return text


def values_match(actual: Any, expected: Any, rules: Mapping[str, Any]) -> bool:
    """Compare one extracted field against its expected value."""
    if expected is None:
        return actual is None
    if isinstance(expected, bool) or isinstance(actual, bool):
        return actual is expected
    if isinstance(expected, (int, float)):
        try:
            actual_number = float(
                actual if not isinstance(actual, str) else actual.replace(",", "").strip()
            )
        except (TypeError, ValueError):
            return False
        tolerance = float(rules.get("tolerance", 0.0))
        if math.isnan(actual_number) or math.isinf(actual_number):
            return False
        return abs(actual_number - float(expected)) <= tolerance
    if isinstance(expected, list):
        if not isinstance(actual, list):
            return False
        if rules.get("ordered", False):
            if len(actual) != len(expected):
                return False
            return all(
                values_match(a, e, rules) for a, e in zip(actual, expected)
            )
        # Unordered comparison without relying on hashability of the elements.
        remaining = list(expected)
        if len(actual) != len(remaining):
            return False
        for item in actual:
            for index, candidate in enumerate(remaining):
                if values_match(item, candidate, rules):
                    remaining.pop(index)
                    break
            else:
                return False
        return True
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        if set(actual) != set(expected):
            return False
        return all(values_match(actual[k], expected[k], rules) for k in expected)
    if isinstance(expected, str):
        if actual is None or isinstance(actual, (list, dict)):
            return False
        return normalize_text(str(actual), rules) == normalize_text(expected, rules)
    return actual == expected


def grade_extraction(item_id: str, output_text: str, checks: Mapping[str, Any]) -> ItemResult:
    """Grade one schema-constrained extraction item."""
    expected = checks.get("expected")
    if not isinstance(expected, Mapping):
        raise GraderError(f"item {item_id}: checks.expected must be an object")
    required: Sequence[str] = checks.get("required_fields") or list(expected)
    rules_by_field: Mapping[str, Any] = checks.get("normalize") or {}
    default_rules: Mapping[str, Any] = checks.get("normalize_default") or {}

    parsed, reason = parse_model_json(output_text)
    if parsed is None:
        # A model that cannot emit JSON fails every field. Recorded explicitly so
        # format collapse is distinguishable from wrong answers in diagnostics.
        return ItemResult(
            item_id=item_id,
            passed=False,
            reason=reason,
            field_scores={name: False for name in required},
        )

    if checks.get("forbid_extra_fields", False) and set(parsed) - set(expected):
        return ItemResult(
            item_id=item_id,
            passed=False,
            reason="unexpected_fields",
            field_scores={name: False for name in required},
        )

    scores: dict[str, bool] = {}
    for name in required:
        if name not in expected:
            raise GraderError(f"item {item_id}: required field {name!r} has no expected value")
        rules = {**default_rules, **(rules_by_field.get(name) or {})}
        scores[name] = name in parsed and values_match(parsed[name], expected[name], rules)

    passed = all(scores.values())
    return ItemResult(
        item_id=item_id,
        passed=passed,
        reason="" if passed else "field_mismatch",
        field_scores=scores,
    )


GRADERS: dict[str, Callable[[str, str, Mapping[str, Any]], ItemResult]] = {
    "extraction": grade_extraction,
}


def grade_item(item_id: str, output_text: str, checks: Mapping[str, Any]) -> ItemResult:
    """Dispatch one item to its grader."""
    kind = str(checks.get("kind") or "")
    grader = GRADERS.get(kind)
    if grader is None:
        raise GraderError(f"item {item_id}: unknown grader kind {kind!r}")
    return grader(item_id, output_text, checks)


def grader_digest() -> str:
    """Content digest of this module, pinned in the receipt as `grader_digest`.

    Hashing the source is what makes "score 0.71" mean something later: a score
    is only comparable to another score produced by the same grading code.
    """
    return "sha256:" + hashlib.sha256(
        Path(__file__).read_bytes()
    ).hexdigest()
