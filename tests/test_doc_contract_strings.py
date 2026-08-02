"""Every contract string a tracked doc names must be one the code defines.

A doc that names a schema the package does not have is a copy-pasteable instruction
to build a document that will be rejected. That is not hypothetical: the launch
ceremony's key-registry example carried `cathedral_receipt_keys_v1`, which is not a
constant anywhere — the real one is `cathedral_receipt_key_registry_v1` — so the
registry it told an operator to sign was refused with "key registry schema is
unsupported". Following it verbatim meant no live receipt had a resolvable signer.

That doc lives under `.internal/`, which is gitignored, so no check could reach it.
The contract it depended on is now stated in `docs/INTEGRATION_CONTRACT.md` instead,
where this test holds it to the code. Two directions are checked:

* every `cathedral_*_vN` identifier in a tracked doc resolves to a real constant, so
  a typo or a renamed schema fails here rather than at an operator;
* the lane id and the publisher's mechanism id are not presented as the same thing,
  because confusing them composes a 100% burn epoch with no error anywhere
  (see `test_lane_allocation_binding.py`).

This does not check prose. It checks the strings a reader would copy.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "cathedral_distill"

# `cathedral_<something>_v<N>`, whether or not the doc wrapped it in backticks.
SCHEMA_LIKE = re.compile(r"cathedral_[a-z0-9_]*_v[0-9]+")

DOCS = sorted(
    [*(ROOT / "docs").glob("*.md"), ROOT / "README.md", ROOT / "site" / "README.md"]
)

REWARD_ACTIVATION_DOCS = (
    ROOT / "README.md",
    ROOT / "docs" / "POSITIONING.md",
    ROOT / "docs" / "MINING.md",
)

OWNER_ONLY_REWARD_SHORTCUTS = (
    "owner flip",
    "on-chain flip",
    "registering the mechanism's emission weight is an owner step",
    "the mechanism registered on chain (owner steps in progress)",
    "the flip that pays",
)

REWARD_PROOF_TERMS = (
    "mechanism 0",
    "mechanism 1",
    "signed vector",
    "signed allocation policy",
    "forfeited",
    "active",
    "incentive",
    "emission",
    "external miner",
)


def _defined_in_code() -> set[str]:
    """Every schema-shaped literal the package actually contains."""
    found: set[str] = set()
    for path in PACKAGE.glob("*.py"):
        found.update(SCHEMA_LIKE.findall(path.read_text(encoding="utf-8")))
    return found


def _named_in(path: Path) -> set[str]:
    return set(SCHEMA_LIKE.findall(path.read_text(encoding="utf-8")))


def _reward_activation_doc_errors() -> list[str]:
    errors: list[str] = []
    for path in REWARD_ACTIVATION_DOCS:
        text = path.read_text(encoding="utf-8").lower()
        for claim in OWNER_ONLY_REWARD_SHORTCUTS:
            if claim in text:
                errors.append(f"{path.relative_to(ROOT)} repeats shortcut: {claim}")
        missing = [phrase for phrase in REWARD_PROOF_TERMS if phrase not in text]
        if missing:
            errors.append(f"{path.relative_to(ROOT)} is missing proof terms: {missing}")
    return errors


def test_the_package_defines_the_schemas_it_is_expected_to():
    """Guard the guard: if extraction breaks, everything below passes vacuously."""
    defined = _defined_in_code()
    for expected in (
        "cathedral_receipt_key_registry_v1",
        "cathedral_burn_config_v1",
        "cathedral_lane_allocation_v1",
        "cathedral_cybergym_receipt_v1",
    ):
        assert expected in defined, f"{expected} is not defined in the package"


def test_no_tracked_doc_names_a_schema_the_code_does_not_define():
    defined = _defined_in_code()
    unknown: list[str] = []
    for path in DOCS:
        for name in sorted(_named_in(path) - defined):
            unknown.append(f"  {path.relative_to(ROOT)}: {name}")
    assert not unknown, (
        "these docs name schema strings the package does not define, so anything "
        "built from them is refused:\n" + "\n".join(unknown)
    )


def test_the_registry_schema_is_stated_and_correct():
    """The specific string the ceremony got wrong, now stated where it is checked."""
    from cathedral_distill.receipt_keys import REGISTRY_SCHEMA

    contract = (ROOT / "docs" / "INTEGRATION_CONTRACT.md").read_text(encoding="utf-8")
    assert REGISTRY_SCHEMA in contract, (
        f"docs/INTEGRATION_CONTRACT.md no longer states {REGISTRY_SCHEMA}; it is the "
        "string an operator needs to sign a registry that verifies"
    )
    # and the wrong one is not lying around anywhere tracked
    for path in DOCS:
        text = path.read_text(encoding="utf-8")
        assert "cathedral_receipt_keys_v1" not in text, (
            f"{path.relative_to(ROOT)} uses cathedral_receipt_keys_v1, which no "
            f"verifier accepts; the registry schema is {REGISTRY_SCHEMA}"
        )


def test_the_lane_id_is_documented_and_not_confused_with_the_mechanism_id():
    from cathedral_distill.cybergym_service import CYBERGYM_LANE

    contract = (ROOT / "docs" / "INTEGRATION_CONTRACT.md").read_text(encoding="utf-8")
    assert CYBERGYM_LANE in contract
    assert "mechanism id" in contract, (
        "the lane-vs-mechanism-id distinction is undocumented; confusing them "
        "composes a 100% burn epoch with no error anywhere"
    )

    # No tracked doc may present cybergym_v0 as a lane value.
    offenders: list[str] = []
    for path in DOCS:
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1
        ):
            if "cybergym_v0" not in line:
                continue
            lowered = line.lower()
            claims_lane = '"lane"' in lowered or "lane:" in lowered
            names_mechanism = "mechanism" in lowered
            if claims_lane and not names_mechanism:
                offenders.append(f"  {path.relative_to(ROOT)}:{number} {line.strip()[:90]}")
    assert not offenders, (
        "cybergym_v0 is the publisher's MechanismSpec id, not a lane id; used as a "
        f"lane it burns the epoch. The lane id is {CYBERGYM_LANE!r}:\n"
        + "\n".join(offenders)
    )

    reward_errors = _reward_activation_doc_errors()
    assert not reward_errors, (
        "reward activation must state both mechanism architectures and effective "
        "chain proof, not only a subnet-owner action:\n" + "\n".join(reward_errors)
    )


def test_the_staleness_bound_is_documented_where_operators_will_look():
    """The 24h ceiling is invisible next to a year-long valid_until."""
    from cathedral_distill.receipt_keys import DEFAULT_MAX_AGE_SECONDS

    for relative in ("docs/INTEGRATION_CONTRACT.md", "docs/VALIDATING.md"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert str(DEFAULT_MAX_AGE_SECONDS) in text, (
            f"{relative} does not state the {DEFAULT_MAX_AGE_SECONDS}s registry "
            "staleness bound. A registry with a year-long valid_until is refused the "
            "next day, and nothing else warns about it"
        )


@pytest.mark.parametrize(
    "constant, module",
    [
        ("REGISTRY_SCHEMA", "cathedral_distill.receipt_keys"),
        ("BURN_CONFIG_SCHEMA", "cathedral_distill.signed_config"),
        ("ALLOCATION_CONFIG_SCHEMA", "cathedral_distill.signed_config"),
    ],
)
def test_each_signing_schema_constant_is_documented(constant, module):
    """An operator signs these three; each must be findable in a tracked doc."""
    import importlib

    value = getattr(importlib.import_module(module), constant)
    assert any(value in path.read_text(encoding="utf-8") for path in DOCS), (
        f"{module}.{constant} == {value!r} appears in no tracked doc, so an operator "
        "has to read the source to sign a document that verifies"
    )
