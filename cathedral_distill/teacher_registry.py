"""Cathedral-reviewed teacher allowlist.

A maintainer must never be the party that asserts its own teacher's licence
permits distillation. That is the same mistake as letting a worker declare its
own score, with worse consequences: Cathedral publishes signed receipts, and a
receipt proving a licence-violating distillation occurred is evidence against
Cathedral rather than for it.

So permission lives here, in a registry Cathedral reviews, and a teacher absent
from it is rejected. Fail closed.

Two properties beyond a plain allowlist:

**Licences are pinned by digest.** Model licences change. A record names the exact
licence text it was reviewed against; if the published text no longer hashes to
that digest, the review is stale and the teacher is refused until re-reviewed.
Without this, a vendor could tighten terms and Cathedral would keep minting
receipts under a permission that no longer exists.

**Reviews expire.** A permission granted once is not a permission forever. A
record past `review_expires_at` is refused the same as an unknown teacher.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Mapping

REGISTRY_SCHEMA = "cathedral_teacher_registry_v1"

# Purposes a teacher may be approved for. Distillation is deliberately separate
# from plain inference: many licences permit the latter and forbid the former.
PURPOSE_INFERENCE = "inference"
PURPOSE_DISTILLATION = "distillation_training_data"
PURPOSES = frozenset({PURPOSE_INFERENCE, PURPOSE_DISTILLATION})


class TeacherNotPermitted(ValueError):
    """Raised whenever a teacher may not be used. Carries a machine-readable reason."""

    def __init__(self, reason: str, teacher_id: str) -> None:
        super().__init__(f"{reason}: {teacher_id}")
        self.reason = reason
        self.teacher_id = teacher_id


@dataclass(frozen=True)
class TeacherRecord:
    """One reviewed teacher.

    `teacher_id` is `provider/model/version` — version included, because a
    licence review of `moonshot/kimi/k2` says nothing about `k3`.
    """

    teacher_id: str
    licence_digest: str
    licence_uri: str
    reviewed_at: datetime
    review_expires_at: datetime
    reviewer: str
    permitted_purposes: frozenset[str] = field(default_factory=frozenset)
    commercial_use: bool = False
    competing_model_training: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        if len(self.teacher_id.split("/")) != 3:
            raise ValueError(
                f"teacher_id must be provider/model/version, got {self.teacher_id!r}"
            )
        if not self.licence_digest.startswith("sha256:"):
            raise ValueError("licence_digest must be a sha256: digest")
        if self.review_expires_at <= self.reviewed_at:
            raise ValueError("review_expires_at must be after reviewed_at")
        if not self.reviewer:
            raise ValueError("a record must name its reviewer")
        unknown = self.permitted_purposes - PURPOSES
        if unknown:
            raise ValueError(f"unknown purposes: {sorted(unknown)}")


def licence_digest(text: bytes) -> str:
    """Digest of licence text as published. Compare before trusting a review."""
    return "sha256:" + hashlib.sha256(text).hexdigest()


class TeacherRegistry:
    """The allowlist. Unknown teacher, stale review, or wrong purpose → refused."""

    def __init__(self, records: Mapping[str, TeacherRecord] | None = None) -> None:
        self._records: dict[str, TeacherRecord] = dict(records or {})

    def add(self, record: TeacherRecord) -> None:
        self._records[record.teacher_id] = record

    def get(self, teacher_id: str) -> TeacherRecord | None:
        return self._records.get(teacher_id)

    def assert_permitted(
        self,
        teacher_id: str,
        *,
        purpose: str,
        at: datetime,
        published_licence: bytes | None = None,
    ) -> TeacherRecord:
        """Authorise a teacher for a purpose, or raise.

        `published_licence`, when supplied, is the licence text as fetched today.
        Passing it turns the pinned digest from documentation into an enforced
        check, and callers on the training path should always pass it.
        """
        if purpose not in PURPOSES:
            raise TeacherNotPermitted("unknown_purpose", teacher_id)

        record = self._records.get(teacher_id)
        if record is None:
            # The default answer for anything unreviewed is no.
            raise TeacherNotPermitted("teacher_not_in_registry", teacher_id)

        if at < record.reviewed_at:
            raise TeacherNotPermitted("review_not_yet_effective", teacher_id)
        if at >= record.review_expires_at:
            raise TeacherNotPermitted("review_expired", teacher_id)

        if purpose not in record.permitted_purposes:
            raise TeacherNotPermitted(f"purpose_not_permitted_{purpose}", teacher_id)

        if purpose == PURPOSE_DISTILLATION and not record.competing_model_training:
            # Distilling a student that competes with the teacher is precisely
            # what the restrictive clauses in these licences target.
            raise TeacherNotPermitted("competing_model_training_forbidden", teacher_id)

        if published_licence is not None:
            if licence_digest(published_licence) != record.licence_digest:
                raise TeacherNotPermitted("licence_text_changed_since_review", teacher_id)

        return record

    def is_permitted(self, teacher_id: str, *, purpose: str, at: datetime) -> bool:
        try:
            self.assert_permitted(teacher_id, purpose=purpose, at=at)
        except TeacherNotPermitted:
            return False
        return True

    def as_policy(self) -> dict[str, object]:
        """Publishable policy document. Contains no secrets."""
        return {
            "schema": REGISTRY_SCHEMA,
            "teachers": [
                {
                    "teacher_id": r.teacher_id,
                    "licence_digest": r.licence_digest,
                    "licence_uri": r.licence_uri,
                    "reviewed_at": r.reviewed_at.astimezone(UTC).isoformat(),
                    "review_expires_at": r.review_expires_at.astimezone(UTC).isoformat(),
                    "reviewer": r.reviewer,
                    "permitted_purposes": sorted(r.permitted_purposes),
                    "commercial_use": r.commercial_use,
                    "competing_model_training": r.competing_model_training,
                    "notes": r.notes,
                }
                for r in sorted(self._records.values(), key=lambda r: r.teacher_id)
            ],
        }
