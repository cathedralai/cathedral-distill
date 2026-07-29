"""Cross-repo contract: does distill's `cathedral_assurance_receipt_v2` actually
match `cathedralai/cathedralconfidential`'s (the authoritative issuer's) schema?

`distill_receipt.RECEIPT_SCHEMA` and `compute_receipt.py` both claim to speak
`cathedral_assurance_receipt_v2` — but nothing in this repo checks that claim
against the real implementation. This module pins the upstream schema's exact
top-level key set (`cathedral/receipt.py::_TOP_KEYS`, fetched read-only from
`cathedralai/cathedralconfidential` main @ `8cacd8517eb4b7f14007b8bec0867a64c615091e`,
2026-07-28 — update the pin and this comment together if that repo's schema moves)
so the relationship is an executable, reviewable fact instead of a prose claim.

**Known, tracked divergence — not a silent one.** The shared body
(`distill_receipt._SHARED_KEYS`) matches upstream exactly: that's the honest part
of "versioned extension of the same v2." But `cathedralconfidential`'s parser does
`frozenset(document) != _TOP_KEYS -> reject` (no extension point, no unknown-key
tolerance) — see `cathedral/receipt.py`'s `parse_and_verify` — while
`compute_receipt._RECEIPT_KEYS` adds a top-level `"platform"` key that
`cathedralconfidential` never emits and always rejects. Concretely:

  * a receipt `compute_receipt.build_receipt` produces is refused by
    `cathedralconfidential`'s own parser (extra key `"platform"`);
  * a receipt `cathedralconfidential`'s issuer actually emits is refused by
    `compute_receipt.verify_receipt` (`platform` is a required field here).

So the integrated compute (CPU/GPU) lane cannot admit anything the authoritative
issuer produces, and vice versa — not NOT_PROVEN, a guaranteed reject on both
sides. This is a real architectural decision pending resolution (extend
`cathedralconfidential`'s schema to accept `platform`, or give distill's compute
receipt a distinct schema name instead of claiming byte-identity with v2), not
something this repo can close unilaterally. If either test below starts failing
because someone “fixed” one side without updating the other, that is this
contract doing its job — resolve it as a decision, then update the pin.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import compute_receipt as cr  # noqa: E402
from cathedral_distill import distill_receipt as dr  # noqa: E402

# cathedralai/cathedralconfidential @ 8cacd85, cathedral/receipt.py `_TOP_KEYS`.
# This is `cathedral_assurance_receipt_v2`'s ACTUAL top-level key set, verified
# by fetching the file — not derived from this repo's own assumptions about it.
CATHEDRALCONFIDENTIAL_V2_TOP_KEYS = frozenset({
    "schema", "receipt_id", "epoch_id", "source_epoch", "subject_hotkey",
    "platform_pseudonym", "policy_registry_release", "policy_registry_digest",
    "policy_profile_ids", "measurement", "tcb", "channel", "work", "assurance",
    "lifecycle", "issued_at", "signing_key_id", "signature",
})

# The extra top-level keys each distill receipt family adds beyond the shared v2
# body — and therefore beyond what cathedralconfidential's exact-match parser
# will ever accept. Update this alongside any deliberate schema change.
KNOWN_EXTRA_KEYS = {
    "compute_receipt (platform.class=confidential_cpu|confidential_gpu)": {"platform"},
    "distill_receipt (the evaluation block)": {"evaluation"},
}


def test_shared_body_matches_the_upstream_v2_key_set_exactly():
    # The one part of the "versioned extension" claim that is actually true today:
    # the fields distill's receipts share with cathedralconfidential's v2 are
    # byte-identical in name and count. If this starts failing, the shared body
    # drifted from upstream — re-pin CATHEDRALCONFIDENTIAL_V2_TOP_KEYS only after
    # confirming the drift is intentional and upstream-aware.
    assert dr._SHARED_KEYS == CATHEDRALCONFIDENTIAL_V2_TOP_KEYS


def test_compute_receipt_diverges_from_upstream_v2_by_exactly_platform():
    # Documents the KNOWN divergence precisely: compute_receipt adds exactly one
    # top-level key, "platform", that cathedralconfidential's exact-match parser
    # (frozenset(document) != _TOP_KEYS -> reject) will never accept. If this
    # assertion changes, the divergence widened or narrowed — investigate before
    # updating it, since either direction changes the cross-repo blocker's shape.
    extra = cr._RECEIPT_KEYS - CATHEDRALCONFIDENTIAL_V2_TOP_KEYS
    assert extra == {"platform"}


def test_distill_receipt_diverges_from_upstream_v2_by_exactly_evaluation():
    extra = dr._RECEIPT_KEYS - CATHEDRALCONFIDENTIAL_V2_TOP_KEYS
    assert extra == {"evaluation"}


def test_a_genuine_cathedralconfidential_v2_receipt_is_not_admitted_by_compute_receipt():
    # The concrete failure mode: a receipt shaped exactly like what the real
    # issuer emits (upstream's key set, no "platform") is missing a field
    # compute_receipt's structural check requires -> rejected, fail-closed.
    upstream_shaped = {key: None for key in CATHEDRALCONFIDENTIAL_V2_TOP_KEYS}
    with pytest.raises(dr.DistillReceiptError, match="platform"):
        dr.exact_keys(upstream_shaped, cr._RECEIPT_KEYS, "compute receipt")
