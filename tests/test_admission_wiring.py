"""Phase 1 launch-readiness: a scored batch may only draw admitted tasks.

Ties together the three defenses so the anti-gaming design is enforced at the draw,
not just available as a function:

* `PooledTask.admitted` + `private_holdout` — an un-admitted task never reaches a
  scored batch;
* `arvo:3938` is gone from the served subset;
* an attested service refuses to credit synthetic (public-computable) tasks.
"""
from __future__ import annotations

import datetime as dt

import pytest

from cathedral_distill.cybergym import Level
from cathedral_distill.cybergym_batch import (
    BatchError,
    PooledTask,
    TaskPool,
    draw_batch,
)

_T0 = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


def _task(task_id: str, *, disclosed_days: int, admitted: bool = True) -> PooledTask:
    return PooledTask(
        task_id=task_id,
        level=Level.level2,
        binary_digest="sha256:" + "ab" * 32,
        disclosed_at=_T0 + dt.timedelta(days=disclosed_days),
        admitted=admitted,
    )


class TestScoredDrawFiltersAdmission:
    def _pool(self):
        return TaskPool([
            _task("arvo:100", disclosed_days=10, admitted=True),
            _task("arvo:3938", disclosed_days=11, admitted=False),  # degenerate
            _task("arvo:200", disclosed_days=12, admitted=True),
        ])

    def test_an_unadmitted_task_is_never_drawn(self):
        pool = self._pool()
        cutoff, as_of = _T0 + dt.timedelta(days=5), _T0 + dt.timedelta(days=30)
        # Draw the whole admitted set repeatedly; the degenerate task must never appear.
        for i in range(20):
            batch = draw_batch(pool, size=2, nonce=f"n{i}", as_of=as_of, cutoff=cutoff)
            assert "arvo:3938" not in batch.task_ids

    def test_disclosure_and_admission_are_both_required(self):
        """A fresh (post-cutoff) but un-admitted task is still excluded — the two
        gates close different holes and both apply to a scored draw."""
        pool = TaskPool([
            _task("arvo:9001", disclosed_days=20, admitted=False),
            _task("arvo:9002", disclosed_days=20, admitted=True),
        ])
        cutoff, as_of = _T0 + dt.timedelta(days=5), _T0 + dt.timedelta(days=30)
        batch = draw_batch(pool, size=1, nonce="x", as_of=as_of, cutoff=cutoff)
        assert batch.task_ids == ("arvo:9002",)

    def test_a_wholly_unadmitted_holdout_says_so(self):
        """The failure names the real cause instead of reporting an exhausted holdout."""
        pool = TaskPool([
            _task("arvo:8001", disclosed_days=10, admitted=False),
            _task("arvo:8002", disclosed_days=11, admitted=False),
        ])
        cutoff, as_of = _T0 + dt.timedelta(days=5), _T0 + dt.timedelta(days=30)
        with pytest.raises(BatchError, match="no task in the pool passed corpus admission"):
            draw_batch(pool, size=1, nonce="x", as_of=as_of, cutoff=cutoff)


class TestAdmitPoolBridge:
    def test_admit_pool_stamps_the_gate_verdict(self):
        from cathedral_distill import corpus_admission as ca

        tasks = [_task("arvo:good", disclosed_days=10),
                 _task("arvo:bad", disclosed_days=11)]

        def backend(task_id, poc, mode, **kwargs):
            # arvo:bad crashes on anything (degenerate); arvo:good only on its ref.
            if task_id == "arvo:bad":
                return 1 if mode != "fix" else 0
            return 1 if poc == b"real" and mode != "fix" else 0

        def run(argv, **kwargs):
            import subprocess
            poc = b"real" if "cat" in argv else b""
            rc = 0 if ("cat" in argv or "manifest" not in argv) else 1
            # "not public" must be the registry's answer, not a bare failure: a
            # non-zero exit with no recognised not-found message is a probe
            # error, which refuses admission outright (issue #78).
            stderr = b"manifest unknown" if rc else b""
            return subprocess.CompletedProcess(argv, rc, stdout=poc, stderr=stderr)

        refused = []
        out = ca.admit_pool(tasks, _run=run, _backend=backend,
                            on_refused=lambda tid, a: refused.append(tid))
        by_id = {t.task_id: t.admitted for t in out}
        assert by_id == {"arvo:good": True, "arvo:bad": False}
        assert refused == ["arvo:bad"]


class TestSyntheticCreditInvariant:
    """The invariant lives in the constructor, so it is tested by constructing.

    All the unrelated required kwargs are passed as placeholders: the synthetic
    guard fires near the top of __init__, before any of them is used, so their
    values never matter to this assertion.
    """

    def _construct(self, **over):
        from cathedral_distill.cybergym_service import CyberGymService

        base = dict(
            holdout=None, chain=None,
            backend=None, corpus_store=None, score_store=None,
            validator_hotkey="5X", private_key=None, signing_key_id="k",
            batch_size=1, cutoff=None, as_of=None,
        )
        base.update(over)
        return CyberGymService(**base)

    def test_an_attested_service_refuses_to_credit_synthetic(self):
        from cathedral_distill.cybergym_service import ProtocolError

        with pytest.raises(ProtocolError, match="computable from"):
            self._construct(attestation_policy=object(),
                            credit_synthetic_tasks=True)

    def test_a_test_may_acknowledge_gameable_synthetic_explicitly(self):
        """The escape hatch: an attested test that scores synthetic ON PURPOSE
        must say so, and then it is allowed."""
        from cathedral_distill.cybergym_service import ProtocolError

        # Construction reaches the next required gate.  If the synthetic-credit
        # guard regresses, its "computable from" refusal appears instead.
        with pytest.raises(ProtocolError, match="durable solve store"):
            self._construct(attestation_policy=object(),
                            credit_synthetic_tasks=True,
                            acknowledge_synthetic_is_gameable=True)

    def test_the_dev_path_may_still_grade_synthetic(self):
        from cathedral_distill.cybergym_service import ProtocolError

        # attestation_required=False is the dev oracle; the synthetic guard must NOT
        # fire. Construction reaches the next required anti-gaming gate instead.
        with pytest.raises(ProtocolError, match="anti-gaming gate policy"):
            self._construct(attestation_required=False,
                            solve_durability_required=False,
                            credit_synthetic_tasks=True)


class TestLoadHoldoutEnforcesAdmission:
    """The reviewer's point: the invariant must hold on the PRODUCTION ingest path
    (load_holdout -> draw_batch), not only in the isolated gate. A manifest entry is
    scoreable only if it explicitly records that admission passed."""

    def _entry(self, task_id, *, admitted, disclosed="2026-07-27T00:00:00Z"):
        e = {"task_id": task_id, "level": 0, "binary_digest": "sha256:" + "ab" * 32,
             "disclosed_at": disclosed}
        if admitted is not None:
            e["admitted"] = admitted
        return e

    def test_a_manifest_entry_without_admission_cannot_be_drawn(self):
        from cathedral_distill.cybergym_holdout import load_holdout

        # arvo:3938 loaded from an ordinary manifest, no admitted field -> fail closed.
        h = load_holdout([self._entry("arvo:3938", admitted=None)])
        assert h.pool.admitted_count() == 0
        with pytest.raises(BatchError, match="no task in the pool passed corpus admission"):
            draw_batch(h.pool, size=1, nonce="x",
                       as_of=dt.datetime(2026, 7, 27, 12, tzinfo=dt.timezone.utc),
                       cutoff=dt.datetime(2026, 7, 20, 12, tzinfo=dt.timezone.utc))

    def test_an_explicitly_admitted_entry_is_drawable(self):
        from cathedral_distill.cybergym_holdout import load_holdout

        h = load_holdout([self._entry("arvo:100", admitted=True)])
        batch = draw_batch(h.pool, size=1, nonce="x",
                           as_of=dt.datetime(2026, 7, 27, 12, tzinfo=dt.timezone.utc),
                           cutoff=dt.datetime(2026, 7, 20, 12, tzinfo=dt.timezone.utc))
        assert batch.task_ids == ("arvo:100",)

    def test_admitted_must_be_a_boolean(self):
        from cathedral_distill.cybergym_holdout import HoldoutError, load_holdout

        with pytest.raises(HoldoutError, match="admitted .* must be a boolean"):
            load_holdout([self._entry("arvo:1", admitted="yes")])

    def test_a_mixed_manifest_draws_only_the_admitted_task(self):
        from cathedral_distill.cybergym_holdout import load_holdout

        h = load_holdout([self._entry("arvo:1", admitted=False),
                          self._entry("arvo:2", admitted=True)])
        for i in range(10):
            batch = draw_batch(h.pool, size=1, nonce=f"n{i}",
                               as_of=dt.datetime(2026, 7, 27, 12, tzinfo=dt.timezone.utc),
                               cutoff=dt.datetime(2026, 7, 20, 12, tzinfo=dt.timezone.utc))
            assert batch.task_ids == ("arvo:2",)
