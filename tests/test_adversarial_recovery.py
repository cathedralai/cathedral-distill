"""Consolidated adversarial recovery test (issue #1, P0-holdout gate #5).

Given EVERY public artifact together — the sealed-set manifest, the published
receipt, and the bundle registry's public index — an attacker must not be able to
recover any expected answer, any prompt, or which items are canaries. Per-artifact
non-leak is tested elsewhere; this aggregates them and asserts no secret marker
survives into anything publishable.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402

from cathedral_distill import bundle_registry as br  # noqa: E402
from cathedral_distill import sealed_set as ss  # noqa: E402

# Distinctive markers we seed into the SECRET fields; if any appears in a public
# artifact, the holdout leaked.
SECRET_ANSWER = "ANSWER_MARKER_c0ffee_do_not_publish"
SECRET_PROMPT = "PROMPT_MARKER_deadbeef_extract_the_authority"
CANARY_ANSWER = "CANARY_MARKER_feedface_only_a_contaminated_model_knows"


def _items():
    return [
        ss.EvalItem(item_id="item-0", prompt=f"{SECRET_PROMPT} #0",
                    checks={"expected": SECRET_ANSWER}),
        ss.EvalItem(item_id="item-1", prompt=f"{SECRET_PROMPT} #1",
                    checks={"expected": "b", "canary": True, "answer": CANARY_ANSWER}),
        ss.EvalItem(item_id="item-2", prompt=f"{SECRET_PROMPT} #2", checks={"expected": "c"}),
    ]


def _public_artifacts():
    items = _items()
    enclave_public = X25519PrivateKey.generate().public_key().public_bytes_raw()
    sealed = ss.seal("hermes-extract-live", items, enclave_public)

    # a bundle registry public index (digests + identities only)
    registry = br.BundleRegistry()
    registry.register(br.BundleRegistration(
        miner_hotkey="5Miner", track="hermes-extract-live",
        bundle_digest=br.bundle_digest(b"recipe"), version="1.0.0",
        registered_at=__import__("datetime").datetime(2026, 7, 26, 12, 0),
        signature="sig"))

    # everything an attacker could scrape, serialized together
    return json.dumps({
        "sealed_manifest": sealed.manifest(),
        "bundle_index": registry.as_public_index(),
        # the sealed_digest / plaintext_digest are commitments; include them too
        "sealed_digest": sealed.sealed_digest,
        "plaintext_digest": sealed.plaintext_digest,
    }, sort_keys=True), sealed, items


def test_no_secret_survives_into_any_public_artifact():
    blob, _sealed, _items = _public_artifacts()
    for marker in (SECRET_ANSWER, SECRET_PROMPT, CANARY_ANSWER):
        assert marker not in blob, f"{marker!r} leaked into a public artifact"


def test_public_manifest_hides_which_items_are_canaries():
    _blob, sealed, items = _public_artifacts()
    manifest_text = json.dumps(sealed.manifest(), sort_keys=True)
    # the canary list is a validator-only derivation, never in the public manifest
    canaries = ss.contamination_canaries(items)
    assert canaries == ["item-1"]                      # validator can see it...
    assert "item-1" not in manifest_text               # ...the public manifest cannot
    assert "canary" not in manifest_text


def test_ciphertext_is_encrypted_not_plaintext():
    _blob, sealed, _items = _public_artifacts()
    # even if the (non-published) ciphertext were scraped, it is AES-GCM sealed —
    # the secret markers are not recoverable from the bytes.
    for marker in (SECRET_ANSWER.encode(), SECRET_PROMPT.encode(), CANARY_ANSWER.encode()):
        assert marker not in sealed.ciphertext
