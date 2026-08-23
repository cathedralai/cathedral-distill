"""The backend-verified hidden-set attestation posture.

This is the launch anti-gaming model when per-miner Intel-TDX attestation is NOT
enforced. It is NOT dev-unattested and it is NOT disguised as Intel-TDX — it is a
distinct, NAMED production posture that rests only on controls the Cathedral-run
backend actually enforces itself. Every control this posture asserts is one the
runtime must really provide; it deliberately does NOT claim any property the
deployed model does not deliver (see the honest residual below):

  * real_differential — every credited solve's PoC is re-run against the real
    vul/fix builds by the trusted backend, so a verdict cannot be forged. The
    producer refuses this posture on a synthetic backend, which has no such
    differential to verify against;
  * opaque_handles — each round's tasks are dispatched under an opaque, per-round
    FRESH handle keyed by a PINNED seed (the same underlying bug gets a different
    handle every round, and the handle is a non-invertible HMAC). This is the
    anti-LOOKUP control: a miner cannot invert a handle to the public OSS-Fuzz id
    and pre-fetch that bug's published reference PoC. The pin is load-bearing — an
    UNpinned handle key is a public constant and invertible, so the producer refuses
    this posture unless the seed is pinned;
  * gates_required — the anti-gaming emission gates (registered-bundle / eligibility
    / contamination) are enforced on the paying path, not bypassed. The producer
    refuses this posture on a gates-off configuration;
  * corpus_digest — the identity of the sealed corpus the differential runs against
    is bound into the policy digest, so a resume that swaps it for a weaker/different
    corpus changes the digest and is refused.

Recording this posture stamps the epoch ``enforced=True`` with THIS policy's digest,
so ``cybergym_score_report.require_attested_epoch`` accepts it and export succeeds
without ``--allow-unattested-e2e`` — while the ``detail`` names it honestly and never
claims Intel-TDX. A resume that weakens a control or swaps the sealed corpus changes
the digest and is refused on the same terms a swapped Intel-TDX policy is; a dropped
handle-key pin or a gates-off run is refused earlier still, at producer construction.

The honest residual, stated plainly: this posture does NOT provide never-repeat.
The deployed model reuses one corpus and draws each round's set by nonce, so the
same bug recurs across rounds. Opaque handles stop a miner from LOOKING UP a bug's
public reference PoC, but they do not stop a miner that genuinely solved a bug in an
earlier round from recognising it (by its stable level-gated context) and resubmitting
its own prior solution — the agent runs on the miner's own hardware here, so nothing
binds the submitted PoC to a fresh computation. Cryptographic per-round isolation of a
capable-but-lazy miner is exactly what per-miner Intel-TDX (Stage 2) adds; this posture
does not claim it. What it does claim — a real backend differential, no public-answer
lookup, enforced gates, a bound corpus, a producer signature — it enforces. The
remaining trust is the Cathedral-run producer key, the same residual every
producer-signed report carries; a compromised producer key can mint fabricated scores.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

HIDDEN_SET_POLICY_SCHEMA = "cathedral_cybergym_hidden_set_policy_v1"


class HiddenSetPolicyError(ValueError):
    """A hidden-set posture was requested without the controls that make it one."""


@dataclass(frozen=True)
class HiddenSetPolicy:
    """The backend-verified hidden-set anti-gaming posture (see module docstring).

    Every field is a control the runtime MUST actually enforce for the posture to
    mean anything, so the secure values are the defaults and :meth:`require_secure`
    refuses a posture whose controls are off rather than stamp a gameable epoch as
    verified. A control is included here ONLY if the runtime genuinely provides it —
    never-repeat is deliberately absent because the deployed model recurs tasks (see
    the module docstring's honest residual), so the posture must not assert it.
    """

    real_differential: bool = True    # verdicts come from the real vul/fix docker differential
    opaque_handles: bool = True       # tasks are dispatched under a PINNED, non-invertible handle key
    gates_required: bool = True       # the anti-gaming emission gates are enforced on the paying path
    # The identity of the sealed corpus the differential runs against (e.g. sha256 of the real ARVO
    # manifest). Bound into the digest so a resume that swaps the corpus for a weaker/different one
    # changes the policy digest and is refused by `record_attestation_posture`'s first-write-wins
    # guard — the controls alone are constant booleans and would not catch a substance swap.
    corpus_digest: str = ""
    version: str = "v1"

    def manifest(self) -> dict:
        return {
            "schema": HIDDEN_SET_POLICY_SCHEMA,
            "version": self.version,
            "real_differential": bool(self.real_differential),
            "opaque_handles": bool(self.opaque_handles),
            "gates_required": bool(self.gates_required),
            "corpus_digest": str(self.corpus_digest or ""),
        }

    def require_secure(self) -> None:
        """Fail closed unless every control the posture rests on is on.

        A hidden-set epoch scored with the differential faked, handles transparent, or
        the gates off is gameable and must NOT be stamped as verified — it stays
        unattested and the export gate refuses it, which is the correct outcome.
        """
        missing = [
            name for name, on in (
                ("real_differential", self.real_differential),
                ("opaque_handles", self.opaque_handles),
                ("gates_required", self.gates_required),
            ) if not on
        ]
        if missing:
            raise HiddenSetPolicyError(
                "refusing to record a hidden-set posture with these controls off: "
                + ", ".join(missing)
                + ". Without them the epoch is gameable and cannot be shown to be "
                "backend-verified; run it under the real differential + opaque pinned "
                "handles + enforced gates, or leave the posture unstamped (unattested)."
            )
        if not str(self.corpus_digest or "").strip():
            # A posture that does not name the corpus its differential ran against cannot bind that
            # corpus into its digest, so a resume could swap it for a weaker one under an unchanged
            # digest. Naming it is what makes the resume guard mean anything for the substance.
            raise HiddenSetPolicyError(
                "refusing to record a hidden-set posture with no corpus_digest: the posture must name "
                "the sealed corpus its differential verified against, or a resume could swap it unseen."
            )

    def detail(self) -> str:
        return (
            "backend-verified hidden-set (NO per-miner Intel-TDX): server-side vul/fix "
            "differential + opaque per-round-fresh task handles (pinned) + enforced "
            "anti-gaming gates, producer-signed (tasks recur — NOT never-repeat)"
        )


def hidden_set_policy_digest(policy: HiddenSetPolicy | None) -> str:
    """``sha256:<hex>`` over the policy manifest, or ``""`` for no policy — mirrors
    ``cathedral_receipt_policy_digest`` so the posture record binds the same way."""
    if policy is None:
        return ""
    return "sha256:" + hashlib.sha256(
        json.dumps(policy.manifest(), sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


__all__ = [
    "HIDDEN_SET_POLICY_SCHEMA",
    "HiddenSetPolicy",
    "HiddenSetPolicyError",
    "hidden_set_policy_digest",
]
