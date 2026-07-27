# cathedral-distill

**Sealed evaluation and frontier scoring for the Cathedral distillation track.**

Cathedral's confidential-compute mechanism proves that a machine is genuine and
that work ran on it. This package adds the layer above: turning that verified
execution into **measured model capability** that a validator can score without
trusting the miner.

Training miners produce specialised student models. Cathedral evaluates them
inside a separate enclave against a **sealed** held-out set the miner never sees,
emits a signed receipt binding the checkpoint to its score, and rewards only the
model that holds the verified performance frontier.

The design extends Cathedral's existing stance one step:

> Attestation is admission. Verified work is the score.
> **Sealing is admission for evaluation. Holding the frontier is the score.**

**Status:** hardware-free reference implementation. 150 tests pass locally.
Nothing here is scored on chain yet — see
[What is proven today](#what-is-proven-today).

---

## The problem this solves

A distillation competition dies of **evaluation contamination**. If students
train on teacher output and the evaluation is drawn from a similar distribution,
miners train on the test, and the score stops measuring capability.

Attestation alone does not fix this. It proves the evaluation *ran*; it says
nothing about whether the set was clean.

Sealing does. The set travels as ciphertext, its data key is released only into an
attested enclave, and the miner learns nothing but its own score. Three further
controls bound what leaks anyway:

- **Shard rotation** — the live holdout moves deterministically per epoch, so
  leakage through repeated scoring decays instead of accumulating.
- **Canaries** — items answerable only by having read the sealed set. A miner
  scoring well on those has seen the test.
- **One authorised run per nonce and epoch** — a validator issues the nonce, and
  the receipt binds it with the epoch and block window, so a second attempt earns
  nothing.

---

## Two enclaves

Training code is adversarial by assumption, and the sealed set is the asset it
most wants. If the fine-tune and the evaluation share an enclave, the training
recipe becomes an exfiltration path — and a single leak retroactically invalidates
every score on that track, including scores already paid.

```
   ENCLAVE A · train                    ENCLAVE B · evaluate
   ─────────────────                    ────────────────────
   recipe secret                        sealed set secret
   no eval-set key                      no recipe access
           │                                     ▲
           └────────── checkpoint digest ─────────┘
                    (the only thing that crosses)
```

`sealed_set.py` wraps each data key to a per-enclave X25519 key and records
`application_key_sha256`, so a set opens only inside an enclave that was
*attested with* that exact application key. Holding the key is not enough.

Separately, the **evaluating operator must not be the miner being evaluated**.
Confidential computing keeps the set unreadable even from the host, but an
operator who controls the machine can re-run the evaluation and submit only its
best result. `roles.py` compares coldkeys — not hotkeys, which are cheap to mint.

---

## Scoring: hold the frontier

Emissions recur every epoch; "improvement over baseline" is a one-time quantity.
Paying for deltas makes it rational to split one real gain into several small
releases and collect repeatedly.

So nothing is paid for a delta. Each track has a reigning champion who earns for
**holding** the frontier, and the crown moves only when a challenger clears every
gate and beats the incumbent by a margin. This mirrors the `sat-king`
king-of-the-hill pattern already used for SAT.

- **Ties keep the incumbent.** Otherwise the cheapest attack is resubmitting the
  champion's checkpoint for an identical score and a free crown.
- **A margin is required** (default `0.005`). Without one, evaluation noise flips
  the crown every epoch and nobody can build on holding it.

### Eight gates, all boolean, all required

```
attested_receipt · teacher_permitted · reproduced · within_cost_ceiling
no_contamination · within_latency_budget · registered_bundle
independent_evaluator
```

A failed gate makes the score irrelevant — it is not a penalty term to trade off.
Any criterion a validator cannot independently derive must not be a weight,
because a weight that cannot be derived is a weight attacked by attacking the
measurement. `within_latency_budget` is a gate for the same reason: a model that
scores well but cannot serve inside its target envelope is not useful.

An empty frontier pays **everything to burn**, matching the mechanism's existing
stance for an empty verified set.

---

## Roles

| Role | Supplies | Rewarded for |
|---|---|---|
| **Model Training Miner** | student models from its own recipe | holding the frontier |
| **Compute Serving Miner** | attested capacity | verified customer usage |
| **Cathedral Validator** | measurement and scoring | correct verification |

One participant may hold both miner roles. The two rewards are computed from
per-role books that no code path reads across, so a participant's hardware cannot
raise their model score and their model's success cannot raise their serving
reward. Holding both roles yields the sum of two independent amounts, never a
bonus.

There is deliberately **no separate recipe-maintainer reward** in v1: a training
miner owns its complete bundle — teacher configuration, recipe, dataset pipeline,
fine-tuning config, checkpoint — and is paid for the result. Splitting ownership
from execution would require component attribution, which means ablation runs,
which multiplies the most expensive stage of the pipeline.

---

## Submitting: the registry line

A pull request never carries the recipe. It carries a **registry line** —
identities, digests, and a URI. The proof is the attested receipt at that URI,
verified automatically. The PR is the leaderboard, not the evidence.

```json
{"schema":"cathedral_registry_line_v1","miner_hotkey":"5...","track":"hermes-extract-v0",
 "checkpoint_digest":"sha256:...","recipe_digest":"sha256:...",
 "receipt_uri":"https://...","version":"1.0.0","signature":"..."}
```

The strict key set is the leak protection: an unexpected field is a parse error,
not ignored data, so prompts and dataset rows cannot be smuggled into a field
nobody validates.

`recipe_digest` commits a miner to one exact recipe — making "that isn't what I
ran" refutable — while revealing nothing about its contents.

---

## Modules

| Module | What it does |
|---|---|
| [`eval_receipt.py`](cathedral_distill/eval_receipt.py) | `cathedral_ml_eval_receipt_v1`, a sibling of the inference receipt |
| [`sealed_set.py`](cathedral_distill/sealed_set.py) | AES-GCM sealing, per-enclave key wrap, shard rotation, canaries |
| [`grader.py`](cathedral_distill/grader.py) | Deterministic grading, pluggable registry, no model judges a model |
| [`frontier.py`](cathedral_distill/frontier.py) | King-of-the-hill, the eight gates, emission split |
| [`bundle_registry.py`](cathedral_distill/bundle_registry.py) | Bundle identity, first-wins registration, version chains |
| [`registry_line.py`](cathedral_distill/registry_line.py) | The submission artifact and its registry |
| [`roles.py`](cathedral_distill/roles.py) | Role separation and independent reward accounting |
| [`polaris_attest.py`](cathedral_distill/polaris_attest.py) | Binds a receipt to a TDX quote |
| [`teacher_registry.py`](cathedral_distill/teacher_registry.py) | Reviewed teacher allowlist |
| [`challenge.py`](cathedral_distill/challenge.py) | Validator spot-checks: Merkle openings, chain-derived challenges, detection budgeting |
| [`evalset.py`](cathedral_distill/evalset.py) | `hermes-extract-v0`: deterministic extraction set with minted canaries |
| [`runner.py`](cathedral_distill/runner.py) | The enclave eval runner; stdout carries exactly the receipt bytes |
| [`teacher.py`](cathedral_distill/teacher.py) | Provider-agnostic teacher client; licence-gated corpus with logprobs from row one |

### Receipts
`cathedral_ml_eval_receipt_v1` is a deliberate sibling of
`cathedral_ml_inference_receipt_v1`: the same domain-separated hashing, the same
64-byte `report_data` split into identity and execution halves, the same
`Decimal`-not-float discipline, and the same exact-key-set strictness. It reuses
the model and runtime key sets verbatim, so a checkpoint named in an eval receipt
is byte-identical to the same checkpoint named in an inference receipt.

- **Score is derived, never asserted.** A receipt whose score disagrees with its
  own item counts is rejected.
- **Partial runs are rejected.** Grading part of a set is not a score.
- **Unattested receipts are valid but earn zero.** `creditable_as_verified_work()`
  is separate from `validate_receipt()` on purpose.

### Grading
Determinism is a security property, not a nicety: the grader digest is pinned in
the receipt and the score is bound into the quote. No LLM judge is used anywhere —
a model judge is a scoring surface miners optimise against, and it makes the score
depend on a third model nobody pinned. Grading uses `casefold()` rather than
`lower()` and NFKC normalisation, because locale-dependent casing is a
reproducibility bug waiting to happen on someone else's machine.

The grader is tolerant about *packaging* — small instruction-tuned models wrap
JSON in fences and prose far more than large ones, and penalising that would
measure formatting compliance instead of capability. It is strict about *shape*: a
top-level array fails explicitly rather than being silently unwrapped, because
reaching inside it would grade an arbitrary element.

### Teacher allowlist
A miner must never assert that its own teacher's licence permits distillation.
Cathedral publishes signed receipts, and a receipt proving a licence-violating
distillation occurred is evidence against Cathedral. So permission lives in a
reviewed registry, and a teacher absent from it is refused.

Licences are pinned by digest — if the published text no longer matches what was
reviewed, the review is stale and the teacher is refused until re-reviewed.
Reviews expire. `teacher_id` must be `provider/model/version`, because a review of
one version says nothing about the next.

---

## Measured result

A complete distillation loop on the `hermes-extract-v1` track, all numbers from
receipts in [`docs/benchmarks/`](docs/benchmarks/):

| Run | Score | p50 latency | Train time |
|---|---:|---:|---:|
| `Qwen3-4B-Instruct-2507` base | 15/32 — 46.9% | 2,573 ms | — |
| Student · answer-only | 20/32 — 62.5% | **2,387 ms** | 91 s |
| **Student · reasoning** | **28/32 — 87.5%** | 25,201 ms | 278 s |

Training on the teacher's chain-of-thought was worth roughly three times the
gain of training on its answers alone. The reasoning student is also **10×
slower**, so under a CPU serving budget it wins on quality and fails
`within_latency_budget` — the trade-off the gate exists to arbitrate, now a
measured quantity.

Two full runs of the base model produced byte-identical `items_root` values, so
the **`reproduced` gate passes**. Full write-up, including what these receipts
do *not* prove: [`docs/BENCHMARK.md`](docs/BENCHMARK.md).

## What is proven today

- All modules pass **205 local tests**, hardware-free, including one end-to-end
  test that walks the entire path: build set → seal → open → run → grade →
  receipt → attestation binding → validation → validator spot-check → registry
  line → frontier crown → emission share.
- Receipt validation, sealing, quote binding, deterministic grading, teacher
  allowlisting, bundle registration, submission intake, gate evaluation and
  frontier judging are implemented and covered.
- Attestation binding is exercised through the real verification recipe using the
  offline client, which computes identical `report_data`.
- The core economic property is tested directly: splitting one gain into several
  submissions yields the same champion and the same emission share as submitting
  the best result once.

## What is NOT proven

- **The benchmark above is unattested.** Those runs happened on an ordinary GPU
  box; `attestation.kind` is `"none"` and `creditable_as_verified_work()` returns
  `False` for every one of them. Under the mechanism they would earn zero.
- **Attestation-gated key release is disabled upstream.** The sealed-evaluation
  design matches the published key-release contract but cannot be described as
  live.
- **No live attested run.** Only the offline path has been exercised.
- **Nothing is wired to chain** — no score class, no weight vector.
- Confidential GPU acceptance remains pending upstream, so evaluation targets
  confidential CPU.

---

## Run locally

Requires Python 3.11+.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Expected: `205 passed`.

| Test file | Tests |
|---|---:|
| `test_bundle_and_frontier.py` | 38 |
| `test_grader.py` | 29 |
| `test_registry_line.py` | 25 |
| `test_roles.py` | 19 |
| `test_eval_receipt.py` | 14 |
| `test_sealed_set.py` | 14 |
| `test_polaris_attest.py` | 11 |

---

## Container contract

The evaluation runner follows the `sat-king` shape, because the attestation binds
`sha256(image_digest ‖ sha256hex(stdout))`:

- a fixed input mount path and a self-contained entrypoint;
- **stdout is a cryptographic surface, not a log** — the canonical receipt and
  nothing else goes to stdout; every diagnostic goes to stderr;
- pull by digest, never by tag, so the bytes cannot change after admission.

---

## Verifying a score without re-running the evaluation

A validator cannot re-run every evaluation, must not hold the sealed set, and
cannot take the miner's word. Verification is therefore layered, cheapest first:

1. **Structural** — the score must equal the receipt's own item counts.
2. **Attestation** — the quote verifies, `report_data` reconstructs from the
   receipt, the eval image is allowlisted.
3. **Merkle spot-check** (`challenge.py`) — challenge indices derive from a block
   hash that did not exist when the receipt was committed, so a miner cannot
   know in advance which items will be opened. The miner reveals those items
   with openings against `items_root`; the validator re-grades exactly those
   locally. Declining to open an item is a failure, not an omission.
4. **Independent re-run** — occasional full re-evaluation on other attested
   hardware (the `reproduced` gate).

Cheating on `m` of `n` items survives a `k`-item challenge with hypergeometric
probability; `detection_probability` makes the budget explicit, and
`leakage_after` bounds how much of a shard spot-checks may burn before rotation.

## Roadmap

- Two-enclave split on attested hardware
- Frontier score class wired to weights
- Serving-miner routing and per-track leaderboards
- Retired-shard publication, making sealed sets retroactively auditable

## Licence

MIT.
