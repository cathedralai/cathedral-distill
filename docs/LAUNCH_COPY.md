# Launch copy

Ready-to-post copy for the SN39 launch. Grounded in the built mechanism; unbuilt
pieces are flagged so nothing here over-promises. Tighten the netuid claim before
posting: public subnet trackers list netuid 39 under a different project, so the
on-chain netuid must be confirmed before any of this copy ships externally.

---

## X / Twitter — launch thread

**1/**
Benchmarks are burned. Labs train on them, so the score stops measuring anything.

Cathedral SN39 scores a physical fact instead: a working exploit the validator
*runs*. No judge model. No self-reported number.

🧵

**2/**
The task: given an already-patched, publicly-disclosed bug, produce a PoC — a
byte-string input — that

  ✅ crashes the vulnerable build
  ❌ does NOT crash the patched build

That differential is the whole anti-gaming design. A generic segfault fails. You
have to hit *the specific bug the patch fixed*.

**3/**
Producing the exploit is expensive. Checking it is a millisecond binary run.

It's a witness in the exact sense SAT uses — hard to produce, trivial and
deterministic to verify. That asymmetry is why the score can't be faked.

**4/**
Difficulty = how much you're told.

  level0: vulnerable code only — find *and* exploit, blind
  level3: here's the patch diff — weaponise it

Blind discovery is near-un-memorisable, so it pays most (8× vs 1×).

**5/**
Why you can't pre-train on the test:

You commit your model hash on-chain BEFORE the batch exists. The batch is drawn
with a nonce from a block finalized AFTER your commit. You can't train on tasks
you couldn't know.

**6/**
Every verified PoC + its reasoning trace becomes an open, uncontaminated training
corpus. Today's champion is tomorrow's public data. The frontier ratchets.

The exploits aren't the product. The verified dataset is.

**7/**
Status: the mechanism, the real ARVO/OSS-Fuzz backend, and Intel-TDX attested
verification are built and tested (1193 tests) — proven on real bugs,
including a real ARVO bug solved inside a TDX enclave. The full corpus at scale and
the on-chain weight flip are the remaining work — in the open, documented.

**8/**
Autonomous exploit discovery just crossed the line — XBOW topped HackerOne's US
board in 2025; CyberGym agents tripled their PoC success in one gen.

The open question is who owns the *verified data* that trains it. That's us.

Docs → [repo link]  •  Mine → [arena link]

---

## Discord / Telegram — pinned announcement

**Cathedral SN39 — verified vulnerability discovery is live in the open.**

You mine by producing proof-of-concept exploits for already-patched, disclosed
bugs. Each epoch you get a sealed batch your model has never seen. Your job: make
it emit a PoC that **crashes the vulnerable build and spares the patched one.**
The validator runs it — that's the whole score. No judge model, no opinion.

- **Scored on:** `Σ weight[level] × solved` — level0 (blind) 8×, down to level3
  (patch given) 1×. Paired against the reigning champion on your exact batch.
- **Bonus:** up to +30% for a real, licensed reasoning trace — it becomes open
  training data. Padded traces earn nothing (structural, model-free floor).
- **Can't game it:** commit-then-challenge sealing means the batch is drawn after
  your model is locked. Public ARVO/OSS-Fuzz tasks are for practice only.
- **Reference miner:** an aligned coding model (e.g. Qwen3-8B, Apache-2.0, single
  16 GB GPU) + an agent loop + the task runner + a trace logger. Improve from
  there.

**Status:** mechanism, real ARVO/OSS-Fuzz backend, and Intel-TDX attestation built
and tested (1193 tests), proven on real bugs. Live participation still needs the full
corpus at scale + the on-chain weight-registration flip — integration in progress,
tracked openly.

Read the mining guide → `docs/MINING.md`
Read how validation works → `docs/VALIDATING.md`

⚠️ Authorized security research only. Targets are patched and disclosed; a task
exists *because* a fix exists. Don't represent the models or corpus as tools for
attacking live systems.

---

## FAQ

**Is this attacking live systems?**
No. Every target is an already-patched, publicly-disclosed vulnerability.
Verification *requires* the patched build to exist. It's authorized security
research — the point is verifiable defensive capability, not zero-days.

**Do I have to discover unknown bugs?**
No unpublished zero-days. The bug is known and fixed; your model has to *produce a
working exploit for it* — at level0, without being shown where it is.

**What exactly do I submit?**
A registry line (identities + digests, never your recipe), the PoC bytes, and an
optional reasoning trace. The validator runs the PoC against both builds and
scores the differential.

**How is this different from Snyk / Semgrep / CodeQL?**
Those emit *alerts* — ranked guesses that a pattern might be vulnerable, with
famously high false-positive rates. Cathedral emits a *proof* — an input that
actually crashes the vulnerable build. Proof of exploitability is the one thing
pattern-matchers structurally can't produce. See
[COMPETITIVE_LANDSCAPE.md](COMPETITIVE_LANDSCAPE.md).

**How is this different from Bitsec (SN60)?**
Bitsec scores by *similarity* of predicted vulnerability categories to a label.
Cathedral scores by *execution* — a crash the validator re-runs. No partial
credit for sounding right.

**Can I just call a frontier API / use any model?**
Yes — the validator only checks the PoC, not how you made it. But whatever you
commit is what's fingerprinted on-chain and scored; you can't swap it after the
batch is drawn, and in the attested lane the run is sealed — a real Intel-TDX quote
binds the run — so the committed model is provably the one that ran.

**Why can't I train on the answers?**
Commit-then-challenge: your model hash is committed before the batch nonce
exists. The scored batch is drawn from vulns disclosed *after* your commit. Public
tasks are development data only.

**What do I actually earn?**
King-of-the-hill emission — hold the frontier, keep earning; a challenger must
beat you re-scored on the same batch, by a margin. A stale or contaminated crown
burns rather than pays. Contractual 10% burn floor.

**Is it built?**
The mechanism, the real ARVO/OSS-Fuzz backend, and Intel-TDX attested verification
are — 1193 tests, proven on real bugs (including a real ARVO bug solved
inside a TDX enclave). The full corpus at scale (~130 GB+) and a Bittensor axon are
the remaining integration work, tracked openly. It runs end-to-end as a service.

**What's the Arena?**
A *proposed* product: a CTF-style workspace where you solve challenges in a sealed
Cathedral environment and get a result-bound receipt + leaderboard position. The
underlying mechanism (sealed batches, differential verification, receipts,
scores) is built; the Arena UX and the free/paid compute funnel are **to build.**
See [`site/arena.html`](../site/arena.html).
