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
> and models trained on its corpus are distributed under access controls, never as
> ungated open weights. See [Responsible use](#responsible-use).

**Status:** the scoring, sealing, verification, and reward mechanism is implemented
and tested hardware-free (**198 tests**). The network transport, the real binary
backend, and the on-chain wiring are the remaining integration work — see
[What is built](#what-is-built).

---

## Why verification, not a benchmark

Every public coding benchmark is contaminated — labs train on it, so a score stops
measuring capability. Every vendor benchmark is unavailable. A subnet needs a task
whose supply the operator controls and whose result nobody can fake.

[CyberGym](https://github.com/sunblaze-ucb/cybergym) (UC Berkeley, Dawn Song's lab)
provides it. A task is a codebase with a known, patched vulnerability. The miner's
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

The mechanism is complete and tested. The integration layer that turns it into a
live subnet is not — and some of it (the dataset, the confidential-compute
attestation) belongs to Cathedral's infrastructure, not this repo.

| Capability | Status |
|---|---|
| **Score a solution** — differential crash test, level-weighted, re-derivable | **built** ([`cybergym.py`](cathedral_distill/cybergym.py)) |
| **Distribute problems** — sealed batch draw, private holdout, commit-then-challenge | **built** ([`cybergym_batch.py`](cathedral_distill/cybergym_batch.py)) |
| **Verify a solution** — run PoC → differential result (backend injected) | **built, logic** ([`cybergym_verifier.py`](cathedral_distill/cybergym_verifier.py)) |
| **Aggregate the dataset** — trace contract + structural quality gate + reuse licence | **built** ([`trace_submission.py`](cathedral_distill/trace_submission.py)) |
| **Share emission to valuable miners** — king-of-the-hill + independent reward books | **built** ([`frontier.py`](cathedral_distill/frontier.py), [`roles.py`](cathedral_distill/roles.py)) |
| **Spot-check without re-running everything** — Merkle openings, chain-derived challenges | **built** ([`challenge.py`](cathedral_distill/challenge.py)) |
| Real binary backend — CyberGym `reproduce` over the ~130 GB corpus | to build (needs the dataset) |
| Network transport — Bittensor synapse/axon, task serving, PoC submission | to build |
| On-chain wiring — the CyberGym lane in `cathedralconfidential`, weight setting | to build |
| Attested verification (L1) — the crash result bound to a TDX quote | to build (the `cathedralconfidential` lane) |

So, concretely, to the six questions a subnet operator asks:

- **Can validators distribute problems?** The sealed, unpredictable, verifiable
  batch draw is built. Serving it over the network is not.
- **Can miners get problems and submit?** The submission and result structures are
  built. The miner client and transport are not.
- **Can the validator verify a solution?** The differential-crash verification
  logic is built and tested; wiring it to the real binaries needs the dataset.
- **Do we aggregate a dataset?** The trace-submission contract and its quality gate
  are built; the corpus store and curation are not.
- **Do we share emission to valuable miners?** Yes — king-of-the-hill scoring with
  paired evaluation, independent per-role reward books, and a 10% burn floor.
- **How do we score?** Level-weighted solves over a sealed batch, paired against the
  incumbent, gated by eligibility checks. The validator re-derives every number and
  never trusts a reported one.

---

## Anti-gaming

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

## Run the tests

Requires Python 3.11+.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Expected: `198 passed`. All hardware-free — the verifier backend is injected, so
the full mechanism is exercised without the CyberGym binary corpus.

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
