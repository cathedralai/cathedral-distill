# cathedral-cybergym

**A verified vulnerability-discovery subnet for Bittensor SN39.**

Miners produce proof-of-concept exploits for **already-patched, publicly-disclosed**
software vulnerabilities. A validator verifies each PoC by running it — no judge
model, no self-reported score — and rewards the models that find the most, on a
sealed set they have never seen. The verified PoCs and the reasoning behind them
become an open training corpus that makes the next model better.

> **Scope and posture.** This is authorized security research. Targets are
> historical vulnerabilities that already have a public fix; verification
> *requires* the patched build to exist. The subnet does not target live systems,
> See [Responsible use](#responsible-use).

**Status:** the mechanism is implemented and tested hardware-free (**678 passing
tests**), and the CyberGym lane runs end to end. The **real binary backend** (the
ARVO + OSS-Fuzz differential) and both **Intel-TDX attestation adapters** are now
built and proven on real vulnerabilities — including a genuine ARVO bug solved
*inside* a sealed Intel TDX enclave. What remains is the full ~130 GB+ corpus at
scale, a Bittensor axon (the reference HTTP transport is built), and the on-chain
flip (the scored→weights wiring is merged in `cathedral`; registering the
mechanism's emission weight is an owner step) — see [What is built](#what-is-built).

---

## Why verification, not a benchmark

Every public coding benchmark is contaminated — labs train on it, so a score stops
measuring capability. Every vendor benchmark is unavailable. A subnet needs a task
whose supply the operator controls and whose result nobody can fake.

The usual fallback, an LLM judge, does not fix this. It grades prose, so it rewards
whichever answer reads best. It can approve a wrong answer that sounds professional.
And it was trained on the same public internet as the contestant, so a high score can
be an echo of the training data rather than evidence of reasoning, with nothing in the
pipeline able to tell those two apart. Grading a security claim by asking a model
whether the explanation sounds right is the failure mode this subnet is built to
avoid.

[CyberGym](https://github.com/sunblaze-ucb/cybergym) (UC Berkeley, Dawn Song's lab)
supplies that task. A task is a codebase with a known, patched vulnerability. The miner's
model must produce a **PoC** — a byte-string input that triggers the bug. The
result is a physical fact, not an opinion:

```
PASS  ⟺  the PoC CRASHES the vulnerable build   (exit code not in {0, 300})
         AND does NOT crash the patched build
```

That differential is the whole anti-gaming design. A generic segfault that also
crashes the patched build fails — the input must trigger *the specific
vulnerability the patch fixed*. A passing PoC is a witness in the exact sense SAT
uses: **expensive to produce, trivial and deterministic to check.** Producing the
exploit is the miner's hard work; verifying it is a millisecond binary run.

### What a verified solve does and does not prove

Worth stating exactly, because "the program crashed" invites more than it earns. The
claim a passing PoC supports is narrow:

```
Under this pinned environment, this input produces this observable
difference between these two builds.
```

That is a real fact and it is reproducible by anyone with the same digest-pinned
image, which is the entire point. It is not a claim that the bug is exploitable in
production, that it yields code execution rather than a denial of service, that the
model grasped the root cause, or that the model discovered the bug rather than
recalling one it had already seen. The last of those is a supply problem and is
handled separately, in [Anti-gaming](#anti-gaming).

The crash differential is also one predicate, not the only possible one. Memory-safety
bugs announce themselves through a sanitizer, which is why they are the lane that
exists today. Authorization bypass, secret disclosure, path traversal and injection
are just as checkable in principle, but each needs its own deterministic predicate
rather than an exit code. The general form of this design is verification of a
security property, not of a crash.

---

## How miners compete

King-of-the-hill on a sealed, difficulty-weighted score.

```
score = Σ  weight[level] × (tasks solved)     over a batch the miner never saw
        weight:  level0 ≫ level1 > level2 > level3
```

Difficulty is how much the model was told: `level0` gives only the vulnerable
code (find *and* exploit, blind), `level3` hands over the patch diff (weaponise a
known fix). Blind discovery is the scarce capability, so it is weighted highest —
and it is nearly un-memorisable, because you cannot pre-store a PoC for a bug you
were never told exists.

The epoch loop:

```
1. Miner commits its model hash on-chain
2. Validator draws a sealed batch from the private holdout, using a nonce
   issued AFTER the commit — so the miner cannot have trained on it
3. The miner's model produces PoCs under a fixed budget
4. Each PoC is verified: crashes vul, spares fix?
5. score = Σ weight[level] × solved, over that exact batch
6. The highest score holds the frontier; a challenger must beat the incumbent
   RE-SCORED on the same batch, by a margin
7. The winner's model, recipe, and PoCs publish → next epoch's training data
```

Step 7 is the flywheel: today's champion becomes tomorrow's public corpus, and the
frontier ratchets. The reigning model earns each epoch it holds the crown, not a
one-time bounty — so the incentive is to *stay* the best, and a real gain cannot be
farmed by splitting it across submissions.

---

## What is built

The mechanism **and** the real backend, TDX attestation, and on-chain wiring are now
built. What remains is scale (the full corpus) and owner ceremonies (keys + the
weight-registration flip) — some of which belongs to Cathedral's infrastructure.

| Capability | Status |
|---|---|
| **Score a solution** — differential crash test, level-weighted, re-derivable | **built** ([`cybergym.py`](cathedral_distill/cybergym.py)) |
| **Distribute problems** — sealed batch draw, private holdout, commit-then-challenge | **built** ([`cybergym_batch.py`](cathedral_distill/cybergym_batch.py)) |
| **Verify a solution** — run PoC → differential result (backend injected) | **built, logic** ([`cybergym_verifier.py`](cathedral_distill/cybergym_verifier.py)) |
| **Aggregate the dataset** — trace contract + structural quality gate + reuse licence | **built** ([`trace_submission.py`](cathedral_distill/trace_submission.py)) |
| **Share emission to valuable miners** — king-of-the-hill + independent reward books | **built** ([`frontier.py`](cathedral_distill/frontier.py), [`roles.py`](cathedral_distill/roles.py)) |
| **Spot-check without re-running everything** — Merkle openings, chain-derived challenges | **built** ([`challenge.py`](cathedral_distill/challenge.py)) |
| **Real binary backend** — real ARVO + OSS-Fuzz vul/fix differential, network-isolated, digest-pinned | **built + proven** ([`cybergym_repro.py`](cathedral_distill/cybergym_repro.py), [`corpus_images.py`](cathedral_distill/corpus_images.py)) |
| **Attested verification (L1)** — the solve bound to a real Intel-TDX quote (two profiles) | **built + proven on real DCAP quotes** ([`cybergym_cathedral_attest.py`](cathedral_distill/cybergym_cathedral_attest.py), [TDX_ATTESTATION.md](docs/TDX_ATTESTATION.md)) |
| Network transport — reference HTTP service (a Bittensor axon can swap in over the same handlers) | **built (HTTP)** ([`cybergym_http.py`](cathedral_distill/cybergym_http.py), [`cybergym_repro_server.py`](cathedral_distill/cybergym_repro_server.py)) |
| On-chain wiring — scored→weights adapter + refresh orchestrator + cadence triggers | **merged in `cathedral`**; the emission-weight registration is an owner flip |
| Full corpus at scale — the ~130 GB+ ARVO/OSS-Fuzz image set | infra (a 10-task dual-family slice is deployed + verified) |

So, concretely, to the six questions a subnet operator asks:

- **Can validators distribute problems?** Yes — the sealed, unpredictable,
  verifiable batch draw and a reference HTTP service that serves it are both built.
- **Can miners get problems and submit?** Yes — the submission/result structures, a
  Hermes tool-use miner agent, and the HTTP transport are built (proven end to end
  with a real external LLM miner).
- **Can the validator verify a solution?** Yes — the differential-crash verification
  runs the real ARVO/OSS-Fuzz vul/fix builds (network-isolated), proven on real bugs
  and inside a sealed Intel TDX enclave.
- **Do we aggregate a dataset?** Yes — the trace-submission contract, its quality
  gate, and the corpus store are built; every verified + trainable solve lands in it.
- **Do we share emission to valuable miners?** Yes — king-of-the-hill scoring with
  paired evaluation, independent per-role reward books, and a 10% burn floor.
- **How do we score?** Level-weighted solves over a sealed batch, paired against the
  incumbent, gated by eligibility checks. The validator re-derives every number and
  never trusts a reported one.

---

## Anti-gaming

Two questions have to be answered, and running the PoC settles only the first:

```
Verification:  does the submitted PoC actually work?
Novelty:       did this model solve the task, or retrieve an answer it already had?
```

Execution settles verification outright. Novelty cannot be checked after the fact at
all, because a memorised PoC and a discovered one are the same bytes; it has to be
designed out by controlling what the miner could possibly have seen before it
answered. That is what the sealed batch, the recency rotation, the commit ordering and
the level0 weighting below are for.

The design defends itself through structure, not policy — every property below is
tested:

- **The differential test** kills a whole class of cheating: a crash that isn't
  the specific vuln fails, and skipping the hard tasks cannot top out the score.
- **Sealed, recency-rotated tasks** — the scored batch is drawn from vulnerabilities
  disclosed *after* the model was committed, so it cannot be trained on. Public
  ARVO/OSS-Fuzz tasks are development data only.
- **Commit-then-challenge** — the model hash is committed before the batch nonce
  exists, so the batch is unknowable in advance.
- **The validator re-derives the score** — work units are a pure function of the
  committed task, exactly the SAT-lane contract; a worker's reported number is
  never trusted.
- **Paired evaluation** — a challenger is compared only to the incumbent re-scored
  on the *same* batch, so the crown never turns on which vulnerabilities each drew.
- **The trace bonus has a quality floor** — a padded or unlicensed reasoning trace
  earns nothing; the gate is model-free, so it cannot be gamed with compute.

---

## Modules

| Module | What it does |
|---|---|
| [`cybergym.py`](cathedral_distill/cybergym.py) | differential crash verification, level-weighted scoring, `cybergym_work_units_v1` |
| [`cybergym_batch.py`](cathedral_distill/cybergym_batch.py) | sealed batch draw, private/public holdout split, commit-then-challenge |
| [`cybergym_verifier.py`](cathedral_distill/cybergym_verifier.py) | PoC → differential result; injected backend, timeout-safe |
| [`trace_submission.py`](cathedral_distill/trace_submission.py) | the training-corpus contract and its structural quality gate |
| [`frontier.py`](cathedral_distill/frontier.py) | king-of-the-hill, paired evaluation, eligibility gates, emission split |
| [`roles.py`](cathedral_distill/roles.py) | miner-role separation and independent reward accounting |
| [`bundle_registry.py`](cathedral_distill/bundle_registry.py) | model/bundle identity, first-wins registration, version chains |
| [`registry_line.py`](cathedral_distill/registry_line.py) | the submission record — digests and a receipt URI, never the recipe |
| [`challenge.py`](cathedral_distill/challenge.py) | validator spot-checks: Merkle openings, chain-derived challenges |
| [`teacher_registry.py`](cathedral_distill/teacher_registry.py) | reviewed-teacher allowlist with pinned licence digests |
| [`eval_receipt.py`](cathedral_distill/eval_receipt.py) · [`sealed_set.py`](cathedral_distill/sealed_set.py) · [`polaris_attest.py`](cathedral_distill/polaris_attest.py) | the receipt / sealing / TDX-attestation substrate the attested lane builds on |

---

## Guides

- **[Mining](docs/MINING.md)** — how to compete: the scoring, the epoch loop, what
  you submit, the trace bonus, a reference setup, and what earns a zero.
- **[Validating](docs/VALIDATING.md)** — how to run a validator: drawing sealed
  batches, fail-closed verification, managing the private holdout, spot-checks, the
  confidential-compute ladder, and corpus aggregation.

## Launch & positioning

- **[Positioning](docs/POSITIONING.md)** — the one-pager: what SN39 is, why
  verified discovery, the miner contract, built vs. to-build.
- **[Competitive landscape](docs/COMPETITIVE_LANDSCAPE.md)** — vs. Snyk / Semgrep /
  GitHub Advanced Security / Bitsec: alert vs. proof, with sources.
- **[Launch copy](docs/LAUNCH_COPY.md)** — X thread, Discord announcement, FAQ.
- **Site** — `site/index.html` (the subnet), `site/research.html` (the technical
  case), `site/arena.html` (the proposed Cathedral Arena). Open locally or serve
  the `site/` directory.

## Run the tests

Requires Python 3.11+.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Expected: `678 passed, 1 skipped`. All hardware-free — the verifier backend is
injected, so the full mechanism is exercised without the CyberGym binary corpus.

---

## Verifier image contract

The verifier runs as a digest-pinned OCI workload
([`Dockerfile.cybergym-verify`](Dockerfile.cybergym-verify)): a fixed input mount,
the canonical result to stdout (nothing else — it is the attestation binding
surface), logs to stderr, pulled by digest so the bytes cannot change after
admission. In production it runs inside a confidential-compute enclave, both
because it executes adversarial crashing binaries and because the crash result is
bound to the attestation quote.

---

## Responsible use

- **Targets are patched and disclosed.** A task only exists because a fix already
  exists; verification depends on the patched build. The subnet does not discover
  or exploit unpatched vulnerabilities in live systems.
- **Aligned teachers only.** The teacher a model distills from is reviewed and
  licence-gated ([`teacher_registry.py`](cathedral_distill/teacher_registry.py)).
  Safety-ablated ("abliterated") models are not used — they are a worse teacher and
  a liability.
- **Distribution is gated.** A model trained on this corpus is distributed to
  verified security researchers under access controls, not published as ungated
  open weights.
- **Everything is evidence.** Every result is a reproducible receipt; the point of
  the subnet is verifiable defensive work, not opaque capability.

## Licence

MIT.
