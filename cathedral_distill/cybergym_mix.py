"""Blend CyberGym task sources by a configured ratio, plus an off-reward canary.

Last turn wired the nonce-seeded synthetic generator into the live service as an
alternative to the disclosure-timed real corpus. This is the next step from the
task-mixture design: run *both* at once in a configured ratio, and add a public
"canary" channel that probes miner liveness without ever touching reward.

Two pieces, each deliberately touching neither `score_batch` nor the receipt
grammar (the receipt re-derives `earned_units` from `Σ count × level_weight`, a
pure function of the scored batch — so a reward *cap* on a subset of tasks would
be a schema change; instead each mechanism is structured to avoid needing one):

  * **`MixedTaskSource`** — a draw-capable source (same `.draw`/`.context_provider`
    /`.backend` interface a `TaskPool` or `SyntheticTaskSource` exposes) that
    deterministically apportions a batch across several sub-sources by weight, so
    a validator can run e.g. 75% generated + 25% recent-real. Every task it yields
    is a legitimate, un-cheatable reward task; the blend changes *which* fresh
    challenges a miner sees, not how they score. The apportionment and each
    sub-source's sub-nonce are derived from the batch nonce, so two independent
    validators draw the byte-identical mixed batch with no coordination.

  * **`probe_liveness`** — the public-canary check. Public CyberGym tasks (whose
    answers are in the public dataset, i.e. lookup-farmable) are dispatched on a
    SEPARATE channel that verifies the miner can complete a known workflow and
    returns a `LivenessReport` — no receipt, no `earned_units`, no scores row. So
    a public task can *never* inflate reward (a stronger property than "capped at
    5%"), while the divergence between a miner's canary pass-rate and its hidden
    scored pass-rate is exactly the lookup-database tell.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from cathedral_distill.cybergym_batch import (
    MAX_BATCH,
    Batch,
    BatchError,
    batch_id_for,
    derive_batch_nonce,
)
from cathedral_distill.cybergym_verifier import verify_poc

MIX_DOMAIN = b"cathedral-cybergym-mix-subnonce-v1\x00"


class MixError(ValueError):
    """Raised when a task mix cannot be composed or drawn. Fails closed."""


@runtime_checkable
class DrawSource(Protocol):
    """What every task source (`TaskPool`, `SyntheticTaskSource`, another
    `MixedTaskSource`) exposes — the polymorphic interface `dispatch`/`run_epoch`
    already call through."""

    def draw(self, *, size: int, nonce: str, as_of: Any, cutoff: Any) -> Batch: ...


@dataclass(frozen=True)
class SourceSpec:
    """One member of a mix: a draw source, its relative weight, and a stable key.

    `key` is a unique, stable label that seeds this source's sub-nonce — change
    it and the source draws a different (still deterministic) sub-batch, so keys
    are part of the mechanism config, not cosmetic. `weight` is a relative draw
    share (a positive integer); the mix apportions each batch's slots in
    proportion to weights.
    """

    key: str
    source: Any
    weight: int

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key:
            raise MixError("a source spec needs a non-empty key")
        if isinstance(self.weight, bool) or not isinstance(self.weight, int) or self.weight < 1:
            raise MixError(f"source {self.key!r} weight must be a positive integer")
        if not hasattr(self.source, "draw"):
            raise MixError(f"source {self.key!r} is not draw-capable (no .draw)")


def _sub_nonce(nonce: str, key: str) -> str:
    """A per-source nonce, domain-separated from the batch nonce and the key.

    Keeps the `cgnonce-sha256:` shape so any sub-source that inspects the nonce
    (e.g. the synthetic generator's id tail) sees a well-formed value, and is a
    deterministic function of (nonce, key) so every validator derives it identically.
    """
    material = MIX_DOMAIN + nonce.encode("utf-8") + b"\x00" + key.encode("utf-8")
    return "cgnonce-sha256:" + hashlib.sha256(material).hexdigest()


def apportion(size: int, specs: Sequence[SourceSpec], nonce: str) -> list[int]:
    """Split `size` slots across `specs` in proportion to weight. Deterministic.

    Largest-remainder (Hamilton) apportionment: each spec gets `floor(size·wᵢ/W)`,
    then the leftover slots go to the specs with the largest fractional remainder,
    ties broken by a nonce-keyed hash so the result is exact (sums to `size`) and
    identical on every validator. Returns counts aligned to `specs` order.
    """
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise MixError("mix draw size must be a non-negative integer")
    total = sum(s.weight for s in specs)
    if total <= 0:
        raise MixError("mix has no positive weight")
    base = [size * s.weight // total for s in specs]
    # Exact integer remainder for spec i: size·wᵢ − baseᵢ·W  ==  (size·wᵢ) mod W.
    remainder = [(size * s.weight) - base[i] * total for i, s in enumerate(specs)]
    leftover = size - sum(base)
    # Rank by (remainder desc, deterministic hash desc) and hand +1 to the top `leftover`.
    order = sorted(
        range(len(specs)),
        key=lambda i: (
            remainder[i],
            hashlib.sha256(MIX_DOMAIN + nonce.encode() + b"\x00" + specs[i].key.encode()).digest(),
        ),
        reverse=True,
    )
    for i in order[:leftover]:
        base[i] += 1
    return base


class MixedTaskSource:
    """A weighted blend of draw sources, itself a drop-in draw source.

    `MixedTaskSource(specs)` satisfies the same `.draw`/`.context_provider`/
    `.backend` interface as `TaskPool` and `SyntheticTaskSource`, so it drops
    straight into `CyberGymService(holdout=Holdout(pool=mix, ...), backend=mix.backend)`
    and into `run_epoch(pool=mix, ...)` unchanged. Every sub-source is a
    reward-bearing, un-cheatable challenge source; the blend only changes the mix
    of fresh challenges a miner faces.

    Determinism: the per-batch apportionment and every sub-source's sub-nonce are
    derived from the batch nonce alone, so two independent validators drawing for
    the same (miner, model, epoch) produce the byte-identical mixed batch — the
    same two-validator-consensus property a single source has. Per-draw origin
    (which sub-source produced each task) is remembered in memory to route
    `.context_provider`/`.backend`, valid for the service's one-epoch lifetime,
    exactly as `SyntheticTaskSource` remembers its generated bugs.
    """

    def __init__(self, specs: Sequence[SourceSpec]) -> None:
        specs = list(specs)
        if not specs:
            raise MixError("a mix needs at least one source")
        keys = [s.key for s in specs]
        if len(set(keys)) != len(keys):
            raise MixError("source keys must be unique within a mix")
        # Canonical order by key: apportionment and iteration are order-independent.
        self._specs: tuple[SourceSpec, ...] = tuple(sorted(specs, key=lambda s: s.key))
        self._by_key = {s.key: s for s in self._specs}
        self._origin: dict[str, str] = {}  # task_id -> owning spec.key

    @property
    def specs(self) -> tuple[SourceSpec, ...]:
        return self._specs

    def draw(self, *, size: int, nonce: str, as_of: Any = None, cutoff: Any = None) -> Batch:
        if isinstance(size, bool) or not isinstance(size, int) or size < 1:
            raise MixError("mix draw size must be a positive integer")
        if size > MAX_BATCH:
            raise MixError(f"mix draw size {size} exceeds MAX_BATCH ({MAX_BATCH})")
        if not nonce:
            raise MixError("a mix draw requires a nonce")
        counts = apportion(size, self._specs, nonce)
        tasks = []
        seen: set[str] = set()
        for spec, count in zip(self._specs, counts):
            if count == 0:
                continue
            try:
                sub = spec.source.draw(
                    size=count, nonce=_sub_nonce(nonce, spec.key), as_of=as_of, cutoff=cutoff
                )
            except MixError:
                raise
            except Exception as exc:
                # Normalise every sub-source failure (a corpus BatchError, or a
                # TypeError from a corpus source reaching `None > None` when
                # as_of/cutoff were omitted for a synthetic-shaped call) to one
                # fail-closed MixError, so a caller sees a consistent error type.
                raise MixError(f"source {spec.key!r} could not draw {count} tasks: {exc}") from exc
            if len(sub.tasks) != count:
                # A source that can't fill its apportioned share must fail the
                # whole draw, not silently yield a short batch (which would break
                # the configured ratio and the size contract).
                raise MixError(
                    f"source {spec.key!r} returned {len(sub.tasks)} tasks, expected {count}"
                )
            for task in sub.tasks:
                if task.task_id in seen:
                    # Two sub-sources produced the same task_id in THIS draw — the
                    # mix cannot commit an ambiguous batch. Distinct source keys
                    # give distinct sub-nonces; this only fires on a genuine
                    # id-space collision, which must fail closed, not silently drop.
                    raise MixError(f"task id collision across mix sources: {task.task_id}")
                prior = self._origin.get(task.task_id)
                if prior is not None and prior != spec.key:
                    # Cross-DRAW collision (the per-draw `seen` set only covers one
                    # draw): a task_id this instance previously routed to a
                    # different sub-source must never be silently re-owned, or a
                    # later miner's `.backend`/`.context_provider` would resolve to
                    # the wrong source. Same-key recurrence (a stable corpus id
                    # re-drawn) is fine.
                    raise MixError(
                        f"task {task.task_id} was drawn from source {prior!r} earlier "
                        f"and now from {spec.key!r}"
                    )
                seen.add(task.task_id)
                self._origin[task.task_id] = spec.key
                tasks.append(task)
        ordered = tuple(sorted(tasks, key=lambda t: t.task_id))
        return Batch(
            batch_id=batch_id_for(nonce, [t.task_id for t in ordered]),
            nonce=nonce,
            tasks=ordered,
        )

    def origin(self, task_id: str) -> str | None:
        """Which sub-source key produced `task_id` (None if never drawn here)."""
        return self._origin.get(task_id)

    def context_provider(self, task_id: str) -> Mapping[str, str]:
        """Route the level-gated context to whichever sub-source owns the task."""
        key = self._origin.get(task_id)
        if key is None:
            return {}
        source = self._by_key[key].source
        provider = getattr(source, "context_provider", None)
        if provider is None:
            return {}
        return dict(provider(task_id))

    def artifact(self, task_id: str):
        """Route the vulnerable-program artifact to the owning sub-source. Returns
        None for an unknown task or a source that delivers no inline artifact (a
        corpus source, whose binary is fetched out of band by its digest)."""
        key = self._origin.get(task_id)
        if key is None:
            return None
        source = self._by_key[key].source
        provider = getattr(source, "artifact", None)
        return provider(task_id) if provider is not None else None

    def backend(self, task_id: str, poc: bytes, mode: str) -> int:
        """Route the differential check to the owning sub-source's backend.

        A sub-source exposes its backend either as a bound `.backend(task_id,
        poc, mode)` method (the synthetic source) or, for a corpus pool, via an
        injected process backend the mix is constructed with. An unknown task
        returns the clean code — a task the mix never drew can never be scored a
        solve through it.
        """
        key = self._origin.get(task_id)
        if key is None:
            return _CLEAN
        source = self._by_key[key].source
        backend = getattr(source, "backend", None)
        if backend is None:
            raise MixError(
                f"source {key!r} has no .backend; construct it with a backend, or "
                "score the mix through an explicitly injected per-source backend"
            )
        return int(backend(task_id, poc, mode))


_CLEAN = 0  # cybergym.CRASH_CLEAN_CODES member — "did not crash"


class CorpusSource:
    """Adapt a real disclosure-timed `TaskPool` into the unified draw/context/
    backend trio a mix routes through.

    The synthetic source bundles all three; a raw `TaskPool` does not — its
    per-task context lives in the loaded `Holdout` manifest and its differential
    backend (the CyberGym `reproduce` runner over the ~130 GB binaries) is
    injected. This wraps a pool + its manifest context + its injected backend
    into one object, so `SourceSpec(source=CorpusSource(...))` blends real ARVO/
    OSS-Fuzz tasks alongside synthetic ones with no special-casing in the mix.
    """

    def __init__(self, pool: Any, *, context: Mapping[str, Mapping[str, str]] | None = None,
                 backend=None) -> None:
        if not hasattr(pool, "draw"):
            raise MixError("CorpusSource needs a draw-capable pool")
        self._pool = pool
        self._context = dict(context or {})
        self._backend = backend

    def draw(self, *, size: int, nonce: str, as_of: Any, cutoff: Any) -> Batch:
        return self._pool.draw(size=size, nonce=nonce, as_of=as_of, cutoff=cutoff)

    def context_provider(self, task_id: str) -> Mapping[str, str]:
        return dict(self._context.get(task_id, {}))

    def artifact(self, task_id: str):
        """A real corpus task's program is its prebuilt binary, fetched out of band
        by `binary_digest` (the ~130 GB dataset) — not delivered inline. Returns
        None so the mix reports "no inline artifact" rather than inventing one."""
        return None

    def backend(self, task_id: str, poc: bytes, mode: str) -> int:
        if self._backend is None:
            raise MixError("CorpusSource was constructed without a differential backend")
        return int(self._backend(task_id, poc, mode))


class PublicCanarySource:
    """A canary source that draws from a `TaskPool`'s PUBLIC (retired, freely-
    trainable, lookup-farmable) set — never its reward-eligible private holdout.

    This is the corpus-backed source `probe_liveness` should be handed: a raw
    `TaskPool.draw` selects from the *private* holdout, so pointing the canary at
    a bare pool would probe (and burn) reward-eligible tasks. This wraps the
    pool's `draw_public` instead, so solving a canary genuinely proves liveness
    over already-public tasks that carry no reward. (A `SyntheticTaskSource` is
    also a valid canary — self-checking, generated, reward-free — for a
    corpus-free deployment.)
    """

    def __init__(self, pool: Any, *, context: Mapping[str, Mapping[str, str]] | None = None,
                 backend=None) -> None:
        if not hasattr(pool, "draw_public"):
            raise MixError("PublicCanarySource needs a pool exposing draw_public (a TaskPool)")
        self._pool = pool
        self._context = dict(context or {})
        self._backend = backend

    def draw(self, *, size: int, nonce: str, as_of: Any = None, cutoff: Any = None) -> Batch:
        return self._pool.draw_public(size=size, nonce=nonce, cutoff=cutoff)

    def context_provider(self, task_id: str) -> Mapping[str, str]:
        return dict(self._context.get(task_id, {}))

    def artifact(self, task_id: str):
        """Public canary tasks are real: their binary is fetched out of band by
        digest, not delivered inline (see `CorpusSource.artifact`)."""
        return None

    def backend(self, task_id: str, poc: bytes, mode: str) -> int:
        if self._backend is None:
            raise MixError("PublicCanarySource was constructed without a differential backend")
        return int(self._backend(task_id, poc, mode))


# --------------------------------------------------------------------------- #
# The public-canary liveness channel — dispatched + verified, never rewarded
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class LivenessReport:
    """The outcome of a canary probe: how many known-answer public tasks a miner
    solved. Carries NO work units and produces no receipt — a public task can
    never move a reward. The gap between this and a miner's hidden scored
    pass-rate is the lookup-database tell (aces public, fails generated)."""

    miner_hotkey: str
    dispatched: int
    solved: int

    def __post_init__(self) -> None:
        if self.dispatched < 0 or self.solved < 0 or self.solved > self.dispatched:
            raise MixError("liveness report counts are inconsistent")

    @property
    def pass_rate(self) -> Decimal:
        if self.dispatched == 0:
            return Decimal(0)
        return (Decimal(self.solved) / Decimal(self.dispatched)).quantize(Decimal("0.0001"))

    def meets(self, min_pass_rate: Decimal) -> bool:
        """Whether the miner cleared a liveness floor (alive + correctly configured)."""
        return self.pass_rate >= Decimal(min_pass_rate)


def probe_liveness(
    source: Any,
    chain: Any,
    *,
    miner_hotkey: str,
    model_commitment: str,
    pocs: Mapping[str, bytes],
    backend,
    size: int,
    as_of: Any = None,
    cutoff: Any = None,
) -> LivenessReport:
    """Dispatch a canary batch to one miner and verify its PoCs — off the reward
    path. Same per-miner nonce discipline as a scored batch (so it's fresh and
    un-predictable per miner), same differential check, but the result is a
    `LivenessReport`, never a signed receipt or a `cybergym_scores` row. Public,
    lookup-farmable tasks belong here precisely because solving them proves
    liveness without earning anything.

    `source` MUST draw public (reward-free) tasks — a `PublicCanarySource` (which
    draws a `TaskPool`'s public set, never its private holdout) or a
    `SyntheticTaskSource`. Passing a bare `TaskPool` would draw the *private*
    reward-eligible holdout onto this off-reward channel; that stays reward-free
    (this function never scores), but it wastes holdout tasks, so use a public
    source.
    """
    nonce = derive_batch_nonce(
        block=chain.block, block_hash=chain.block_hash, network=chain.network,
        netuid=chain.netuid, source_epoch=chain.source_epoch,
        miner_hotkey=miner_hotkey, model_commitment=model_commitment,
    )
    batch = source.draw(size=size, nonce=nonce, as_of=as_of, cutoff=cutoff)
    solved = 0
    for task in batch.tasks:
        poc = pocs.get(task.task_id)
        if poc is None:
            continue
        if verify_poc(task, poc, backend).solved:
            solved += 1
    return LivenessReport(miner_hotkey=miner_hotkey, dispatched=len(batch.tasks), solved=solved)


__all__ = [
    "MixError", "DrawSource", "SourceSpec", "apportion", "MixedTaskSource",
    "CorpusSource", "PublicCanarySource", "LivenessReport", "probe_liveness", "MIX_DOMAIN",
]
