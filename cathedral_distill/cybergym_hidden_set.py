"""The backend-verified hidden-set attestation posture.

This is the launch anti-gaming model when per-miner Intel-TDX attestation is NOT
enforced. It is NOT dev-unattested and it is NOT disguised as Intel-TDX — it is a
distinct, NAMED production posture that rests on three controls the Cathedral-run
backend enforces itself:

  * server-side differential — every credited solve's PoC is re-run against the
    real vul/fix builds by the trusted backend, so a verdict cannot be forged;
  * per-round hidden, never-repeat task sets under opaque handles keyed by a PINNED
    seed — a miner is blind to the set until dispatch and never sees the same task
    twice, so it cannot pre-fetch a reference answer (the anti-lookup control
    Intel-TDX egress would otherwise provide). The pin is load-bearing: an UNpinned
    handle key is a public constant and INVERTIBLE to the real task id, so the
    producer refuses this posture unless the seed is pinned — an unpinned run's
    handles are not opaque and the posture would be a lie;
  * a producer-signed report — the trust root is the Cathedral-run producer key,
    exactly as it already is for every producer-HMAC report the validator ingests.

Recording this posture stamps the epoch ``enforced=True`` with THIS policy's digest,
so ``cybergym_score_report.require_attested_epoch`` accepts it and export succeeds
without ``--allow-unattested-e2e`` — while the ``detail`` names it honestly, never
claiming Intel-TDX. The digest binds the controls AND the corpus identity
(``corpus_digest``), so a resume that weakens a control or swaps the sealed corpus
changes the digest and is refused on the same terms a swapped Intel-TDX policy is;
a dropped handle-key pin is refused earlier still, at producer startup.

The honest trade-off, stated plainly: this posture credits work on the strength of
the Cathedral-run backend + producer key, not a per-miner hardware quote. A
compromised producer key can mint fabricated scores — the same residual every
producer-signed report carries. It does not add trust surface beyond that; it makes
the already-trusted producer's hidden-set epochs production-publishable and auditable.
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

    Every field is a control that MUST hold for the posture to mean anything, so the
    secure values are the defaults and :meth:`require_secure` refuses a posture whose
    controls are off rather than stamp a gameable epoch as verified.
    """

    real_differential: bool = True    # verdicts come from the real vul/fix docker differential
    never_repeat: bool = True         # per-round hidden sets are never re-dispatched to a miner
    opaque_handles: bool = True       # tasks are dispatched under a PINNED, non-invertible handle key
    gates_required: bool = True       # the anti-gaming emission gates are enforced
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
            "never_repeat": bool(self.never_repeat),
            "opaque_handles": bool(self.opaque_handles),
            "gates_required": bool(self.gates_required),
            "corpus_digest": str(self.corpus_digest or ""),
        }

    def require_secure(self) -> None:
        """Fail closed unless every control the posture rests on is on.

        A hidden-set epoch scored with the differential faked, tasks repeated, handles
        transparent, or the gates off is gameable and must NOT be stamped as verified —
        it stays unattested and the export gate refuses it, which is the correct outcome.
        """
        missing = [
            name for name, on in (
                ("real_differential", self.real_differential),
                ("never_repeat", self.never_repeat),
                ("opaque_handles", self.opaque_handles),
                ("gates_required", self.gates_required),
            ) if not on
        ]
        if missing:
            raise HiddenSetPolicyError(
                "refusing to record a hidden-set posture with these controls off: "
                + ", ".join(missing)
                + ". Without them the epoch is gameable and cannot be shown to be "
                "backend-verified; run it under the real differential + never-repeat "
                "hidden sets, or leave the posture unstamped (unattested)."
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
            "differential + per-round hidden never-repeat task sets under opaque handles, "
            "producer-signed"
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
