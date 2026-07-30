"""What is on the launch path, and what a signed number can still do.

Two jobs, both about keeping a future change deliberate rather than accidental.

1. **Compute `work_units` are asserted, not derived**, pinned here as a
   DOCUMENTING test, named after the gap it documents rather than a property it
   proves. Distill derives units from `passed_items` and CyberGym derives them from
   the level weights, both re-checkable by any validator. Compute validates its
   `work_units` as a canonical decimal and passes it straight through, so whoever
   holds the anchored signing key sets the number, and after normalization one
   receipt with a 30-digit value takes essentially the whole lane. No quantity in
   the receipt body (`challenge_id`, `manifest_digest`, `result_digest`, `status`)
   lets a validator re-derive the work, so there is nothing to bound it against
   without either a contract change or an invented economic cap. This test exists
   so the behaviour cannot change silently while that decision is open.

2. **The launch path is exactly four receipt kinds**. Fuzz-harness generation
   (`harness_gen.py`) is standalone: no receipt family, no dispatch, no lane, and
   nothing in the package imports it. And this package never writes weights to a
   chain at all: it composes a pre-burn vector and hands it over. Both are pinned
   so that wiring either one becomes a deliberate act with a failing test.
"""
from __future__ import annotations

import ast
import json
import sys
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import admission as adm  # noqa: E402
from cathedral_distill import compute_receipt as cr  # noqa: E402
from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill import signed_config as sc  # noqa: E402
from cathedral_distill.testing import IntegrationFixtures  # noqa: E402

NOW_ISO = "2026-07-25T12:30:00.000000Z"
SOURCE_EPOCH = 11
LANE_CPU = "cathedral_confidential_tdx"
LANE_DISTILL = "cathedral_distill"
PACKAGE = Path(__file__).resolve().parents[1] / "cathedral_distill"

FX = IntegrationFixtures(source_epoch=SOURCE_EPOCH)


def _verify(receipt, kind=itf.KIND_COMPUTE_CPU, lane=LANE_CPU):
    return itf.verify_lane_receipt(
        kind, receipt, lane=lane, key_registry=FX.registry, source_epoch=SOURCE_EPOCH,
        now_iso=NOW_ISO, consumption_ledger=itf.NO_REPLAY_LEDGER,
    )


# --------------------------------------------------------------------------- #
# 1. Compute work_units: what a signed number can do (DOCUMENTING)
# --------------------------------------------------------------------------- #

def test_documents_that_a_signed_compute_work_units_value_captures_the_lane():
    """DOCUMENTING a known gap, not asserting a desired property.

    A 30-digit `work_units` verifies PASS and leaves an honest miner in the same
    lane with a normalized weight of zero. Closing this needs an owner decision
    (see the module docstring); until then this pins the behaviour.
    """
    from datetime import UTC, datetime

    burn = sc.verify_burn_config(FX.burn_config(), FX.registry, network="finney", netuid=39,
                                 now=datetime(2026, 7, 25, 12, 30, tzinfo=UTC))
    allocation = sc.verify_allocation_config(
        FX.allocation_config([
            {"lane": LANE_CPU, "allocation": "0.50", "enabled": True},
            {"lane": LANE_DISTILL, "allocation": "0.40", "enabled": True},
        ]),
        FX.registry, network="finney", netuid=39,
        now=datetime(2026, 7, 25, 12, 30, tzinfo=UTC),
    )
    resolved = sc.resolve_allocation(burn, allocation)

    honest = _verify(FX.cpu_receipt(subject="5Honest", work_units="30"))
    whale = _verify(FX.cpu_receipt(subject="5Whale", work_units="9" * 30))
    assert honest.verdict == itf.PASS
    assert whale.verdict == itf.PASS                       # nothing rejects the number
    assert whale.work_units == Decimal("9" * 30)

    composed = itf.compose_integrated(resolved, [honest, whale])
    weights = {w["miner_hotkey"]: w["weight"] for w in composed["feed"]["weights"]}
    assert weights["5Honest"] == pytest.approx(0.0, abs=1e-9)
    assert weights["5Whale"] > 0.5
    assert json.dumps(composed["audit"])


def test_compute_work_units_grammar_is_the_only_bound_today():
    """The decimal grammar caps the digit count, which is input sanity, not a
    work bound: 31 integer digits are refused, and the reachable supremum is
    999999999999999999999999999999.999999999999 (30 integer digits plus the 12
    decimal places the grammar allows)."""
    too_long = _verify(FX.cpu_receipt(subject="5Whale", work_units="1" + "0" * 30))
    assert too_long.verdict == itf.FAIL
    assert "canonical decimal string" in too_long.detail

    at_the_grammar_limit = _verify(FX.cpu_receipt(subject="5Whale", work_units="1" + "0" * 29))
    assert at_the_grammar_limit.verdict == itf.PASS

    supremum = _verify(FX.cpu_receipt(subject="5Whale", work_units="9" * 30 + "." + "9" * 12))
    assert supremum.verdict == itf.PASS
    assert supremum.work_units == Decimal("9" * 30 + "." + "9" * 12)


def test_the_other_two_lanes_do_derive_their_units():
    """The contrast that makes the Compute gap a gap: Distill's units must equal
    its own verified item count, so a signer cannot inflate them."""
    forged = dict(FX.distill_receipt(passed=28, graded=32))
    forged["work"] = dict(forged["work"])
    forged["work"]["work_units"] = "999999"
    decision = _verify(forged, kind=itf.KIND_DISTILL, lane=LANE_DISTILL)
    assert decision.verdict == itf.FAIL


def test_an_omitted_policy_set_is_not_the_same_as_an_empty_one():
    """An operator who omits an allowlist and one who pins an empty allowlist must
    get different answers, or "I forgot to configure the policy" silently becomes
    "everything is admitted". Omitted (None) skips the check; empty admits nothing.
    """
    receipt = FX.cpu_receipt(subject="5Miner", work_units="10")
    assert _verify(receipt).verdict == itf.PASS          # omitted: no policy applied

    empty_allowlist = itf.verify_lane_receipt(
        itf.KIND_COMPUTE_CPU, receipt, lane=LANE_CPU, key_registry=FX.registry,
        source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO,
        consumption_ledger=itf.NO_REPLAY_LEDGER,
        allowed_measurements=frozenset(),
    )
    assert empty_allowlist.verdict == itf.FAIL
    assert "not admitted by policy" in empty_allowlist.detail

    pinned = itf.verify_lane_receipt(
        itf.KIND_COMPUTE_CPU, receipt, lane=LANE_CPU, key_registry=FX.registry,
        source_epoch=SOURCE_EPOCH, now_iso=NOW_ISO,
        consumption_ledger=itf.NO_REPLAY_LEDGER,
        allowed_measurements=frozenset({str(receipt["measurement"])}),
    )
    assert pinned.verdict == itf.PASS


# --------------------------------------------------------------------------- #
# 2. The launch path is four kinds, and nothing here writes to a chain
# --------------------------------------------------------------------------- #

def test_the_composition_path_admits_exactly_four_receipt_kinds():
    assert itf._KINDS == frozenset({
        itf.KIND_COMPUTE_CPU, itf.KIND_COMPUTE_GPU, itf.KIND_DISTILL, itf.KIND_CYBERGYM,
    })
    # admission adds only the sealed-evaluation lane
    assert adm._KINDS == itf._KINDS | {adm.KIND_EVAL}


def test_harness_generation_is_not_wired_into_any_launch_path():
    """`harness_gen` is a standalone capability: no kind, no receipt family, no
    dispatch. Wiring it should be a deliberate act that fails this test first."""
    assert not any("harness" in kind for kind in itf._KINDS | adm._KINDS)

    importers = [
        path.name for path in sorted(PACKAGE.glob("*.py"))
        if path.name != "harness_gen.py" and "harness_gen" in path.read_text(encoding="utf-8")
    ]
    assert importers == [], f"harness_gen is now reachable from {importers}"

    # and it defines no receipt schema of its own that a verifier could admit
    harness_source = (PACKAGE / "harness_gen.py").read_text(encoding="utf-8")
    assert "RECEIPT_SCHEMA" not in harness_source
    assert "build_receipt" not in harness_source


def test_the_package_never_writes_weights_to_a_chain():
    """Composition is preview/shadow by construction: this package produces a
    pre-burn vector and stops. There is no chain writer to invoke, so no mode of
    this package can invoke one."""
    # Parsed, not grepped. A substring scan reads comments and prose, so a module
    # that only MENTIONS the chain (for example "a live validator reads this from
    # the subtensor") counted as a chain writer. What matters is whether the
    # package can actually reach one: an import of a chain library, or a call to a
    # weight-writing name.
    forbidden_imports = ("bittensor", "substrateinterface", "async_substrate_interface")
    forbidden_calls = ("set_weights", "commit_weights", "root_set_weights",
                       "set_weights_extrinsic", "commit_weights_extrinsic")
    offenders: dict[str, list[str]] = {}
    for path in sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        hits: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                hits += [f"import {a.name}" for a in node.names
                         if a.name.split(".")[0] in forbidden_imports]
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root in forbidden_imports:
                    hits.append(f"from {node.module} import ...")
            elif isinstance(node, ast.Attribute) and node.attr in forbidden_calls:
                hits.append(f".{node.attr}")
            elif isinstance(node, ast.Name) and node.id in forbidden_calls:
                hits.append(node.id)
            elif isinstance(node, ast.FunctionDef) and node.name in forbidden_calls:
                hits.append(f"def {node.name}")
        if hits:
            offenders[path.name] = sorted(set(hits))
    assert offenders == {}, f"a chain-writing surface appeared in {offenders}"

    # the composed artifact is explicitly the PRE-burn input, not a published vector
    from datetime import UTC, datetime

    burn = sc.verify_burn_config(FX.burn_config(), FX.registry, network="finney", netuid=39,
                                 now=datetime(2026, 7, 25, 12, 30, tzinfo=UTC))
    allocation = sc.verify_allocation_config(
        FX.allocation_config([{"lane": LANE_CPU, "allocation": "0.90", "enabled": True}]),
        FX.registry, network="finney", netuid=39,
        now=datetime(2026, 7, 25, 12, 30, tzinfo=UTC),
    )
    resolved = sc.resolve_allocation(burn, allocation)
    composed = itf.compose_integrated(resolved, [_verify(FX.cpu_receipt())])
    assert composed["feed"]["pre_burn"] is True
