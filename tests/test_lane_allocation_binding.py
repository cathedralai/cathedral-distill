"""The signed allocation's lane name and the composing code must be the same string.

Nothing else checks that they agree, and disagreeing is silent in the worst way:
both configs verify, the vector composes, and every contribution is dropped as
"lane not in the allocation config" — a 100% burn epoch whose only trace is a
`drop_reason` in an audit row. Every miner earns nothing and the run looks normal.

The name is easy to get wrong because a CyberGym deployment carries two ids in two
namespaces: the lane id `cathedral_cybergym` that the allocation config and the
composers match on, and the mechanism id `cybergym_v0` that names the MechanismSpec
registered with the cathedral publisher. The launch ceremony put the mechanism id in
the `lane` field; this pins the difference so that cannot recur quietly.
"""
from __future__ import annotations

import base64
import json
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill import receipt_keys as rk  # noqa: E402
from cathedral_distill import signed_config as sc  # noqa: E402
from cathedral_distill.cybergym_protocol import ProtocolError  # noqa: E402
from cathedral_distill.cybergym_service import (  # noqa: E402
    CYBERGYM_LANE,
    lane_allocation_for,
)

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
ROOT = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
CFG = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
STAMP = "2026-07-30T00:00:00Z"
UNTIL = "2027-07-30T00:00:00Z"

# The publisher's MechanismSpec id. NOT a lane id — that is the whole point.
MECHANISM_ID = "cybergym_v0"


def _b64(key) -> str:
    return base64.b64encode(key.public_key().public_bytes_raw()).decode()


def _registry():
    unsigned = {
        "schema": rk.REGISTRY_SCHEMA,
        "release": 1,
        "generated_at": STAMP,
        "valid_from": STAMP,
        "valid_until": UNTIL,
        "registry_key_id": "root",
        "keys": [
            {"key_id": "config-1", "public_key_base64": _b64(CFG),
             "valid_from": STAMP, "valid_until": UNTIL, "status": "active"},
        ],
    }
    signed = rk.sign_key_registry(unsigned, ROOT.private_bytes_raw())
    return rk.verify_key_registry(
        json.dumps(signed).encode(),
        trusted_roots={"root": ROOT.public_key().public_bytes_raw()},
        now=NOW,
    )


def _resolved(lane: str, allocation: str = "0.90", burn: str = "0.10"):
    registry = _registry()
    envelope = {
        "config_version": 1, "network": "finney", "netuid": 39,
        "generated_at": STAMP, "valid_from": STAMP, "valid_until": UNTIL,
        "signing_key_id": "config-1",
    }
    burn_doc = dict(envelope, schema=sc.BURN_CONFIG_SCHEMA,
                    burn={"fraction": burn, "burn_hotkey": "5Burn"})
    alloc_doc = dict(envelope, schema=sc.ALLOCATION_CONFIG_SCHEMA,
                     allocations=[{"lane": lane, "allocation": allocation,
                                   "enabled": True}])
    seed = CFG.private_bytes_raw()
    verified_burn = sc.verify_burn_config(
        json.dumps(sc.sign_config(burn_doc, seed)).encode(), registry,
        network="finney", netuid=39, now=NOW)
    verified_alloc = sc.verify_allocation_config(
        json.dumps(sc.sign_config(alloc_doc, seed)).encode(), registry,
        network="finney", netuid=39, now=NOW)
    return sc.resolve_allocation(verified_burn, verified_alloc)


def _compose(resolved):
    decision = itf.ReceiptDecision(
        CYBERGYM_LANE, itf.KIND_CYBERGYM, "receipt-1", "5Miner",
        itf.PASS, Decimal("8"), "verified")
    return itf.compose_integrated(resolved, [decision])


# --------------------------------------------------------------------------- #
# The failure the guard exists to prevent
# --------------------------------------------------------------------------- #


def test_the_mechanism_id_in_the_lane_field_burns_the_whole_epoch():
    """Signed, verified, composed — and every miner earns nothing."""
    resolved = _resolved(MECHANISM_ID)  # the ceremony doc's original mistake
    assert dict(resolved.lane_allocations) == {MECHANISM_ID: Decimal("0.90")}

    out = _compose(resolved)
    (row,) = out["audit"]["receipts"]
    assert row["verdict"] == itf.PASS          # the receipt was fine
    assert row["credited"] is False            # and it earned nothing
    assert "not in the allocation config" in row["drop_reason"]
    assert out["feed"]["weights"] == []
    assert out["feed"]["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(100.0)


def test_the_guard_refuses_the_mismatch_and_names_what_is_funded():
    resolved = _resolved(MECHANISM_ID)
    with pytest.raises(ProtocolError) as caught:
        lane_allocation_for(resolved)
    message = str(caught.value)
    assert f"does not fund lane {CYBERGYM_LANE!r}" in message
    assert MECHANISM_ID in message                     # what IS funded
    assert "100% burn" in message                      # what would have happened
    assert "MechanismSpec id, not a lane id" in message  # and why it happened


def test_the_correct_lane_id_composes_and_pays():
    resolved = _resolved(CYBERGYM_LANE)
    assert lane_allocation_for(resolved) == Decimal("0.90")

    out = _compose(resolved)
    (row,) = out["audit"]["receipts"]
    assert row["credited"] is True
    assert [w["miner_hotkey"] for w in out["feed"]["weights"]] == ["5Miner"]
    # only the base burn, not a forfeited lane
    assert out["feed"]["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(10.0)


# --------------------------------------------------------------------------- #
# The guard itself
# --------------------------------------------------------------------------- #


def test_a_zero_funded_lane_is_returned_not_refused():
    """Zero is a real allocation decision, not a missing lane.

    The guard is about the lane NAME. An operator who deliberately funds the lane
    with nothing gets that answer back, and the caller decides what it means.
    """
    resolved = _resolved(CYBERGYM_LANE, allocation="0.00", burn="1.00")
    assert lane_allocation_for(resolved) == Decimal("0")


def test_an_explicit_lane_id_is_honoured():
    resolved = _resolved("some_future_lane", allocation="0.90")
    assert lane_allocation_for(resolved, "some_future_lane") == Decimal("0.90")
    with pytest.raises(ProtocolError, match="does not fund lane"):
        lane_allocation_for(resolved, CYBERGYM_LANE)


def test_the_guard_refuses_something_that_is_not_a_resolved_allocation():
    with pytest.raises(ProtocolError, match="expected a ResolvedAllocation"):
        lane_allocation_for({"cathedral_cybergym": Decimal("0.9")})


def test_an_empty_allocation_config_says_none_rather_than_nothing():
    class Empty:
        lane_allocations: dict = {}

    with pytest.raises(ProtocolError, match=r"it funds: \(none\)"):
        lane_allocation_for(Empty())


# --------------------------------------------------------------------------- #
# The two namespaces stay distinct
# --------------------------------------------------------------------------- #


def test_the_lane_id_is_not_the_mechanism_id():
    assert CYBERGYM_LANE == "cathedral_cybergym"
    assert CYBERGYM_LANE != MECHANISM_ID


def test_no_shipped_module_reports_the_mechanism_id_as_a_lane():
    """The repro server's /healthz used to advertise `lane: cybergym_v0`.

    An operator reading a healthz payload to find the lane name for their
    allocation config would have been told the wrong string by the code itself.
    """
    root = Path(__file__).resolve().parents[1] / "cathedral_distill"
    offenders = []
    for path in sorted(root.glob("*.py")):
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if '"lane"' in line and MECHANISM_ID in line:
                offenders.append(f"{path.name}:{number}")
    assert offenders == [], f"mechanism id used as a lane value: {offenders}"
