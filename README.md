# cathedral-distill

**Sealed evaluation and frontier scoring for the Cathedral distillation track.**

Cathedral's confidential-compute mechanism proves that a machine is genuine and
that work ran on it. This package adds the layer above: turning verified
execution into **measured model capability** that a validator can score without
trusting the miner.

Training miners produce specialised student models. Cathedral evaluates them
against a **sealed** held-out set the miner never sees, in an enclave separate
from the one that trained them, emits a signed receipt binding the checkpoint to
its score, and rewards only the model that holds the verified frontier.

The design extends Cathedral's existing stance one step:

> Attestation is admission. Verified work is the score.
> **Sealing is admission for evaluation. Holding the frontier is the score.**

**Status:** reference implementation with a measured distillation result.
**233 tests** pass locally, and a full loop — corpus → fine-tune → sealed eval →
receipts — has been run end to end. Nothing is scored on chain yet. See
[What is proven today](#what-is-proven-today) and
[Known gaps](#known-gaps).

---

## Measured result

A complete distillation loop on the `hermes-extract-v1` track. Every number
comes from a receipt in [`docs/benchmarks/`](docs/benchmarks/):

| Run | Score | p50 latency | Train time |
|---|---:|---:|---:|
| `Qwen3-4B-Instruct-2507` base | 15/32 — 46.9% | 2,573 ms | — |
| Student · answer-only | 20/32 — 62.5% | **2,387 ms** | 91 s |
| **Student · reasoning** | **28/32 — 87.5%** | 25,201 ms | 278 s |

Training on the teacher's chain-of-thought was worth roughly **three times** the
gain of training on its answers alone (+13 items vs +5). The reasoning student
is also **10× slower**, so on a CPU serving envelope it wins on quality and
fails `within_latency_budget` — the trade-off that gate exists to arbitrate, now
a measured quantity rather than an argument.

Two full runs of the base model produced byte-identical `items_root` values, so
the **`reproduced` gate passes**. Full write-up, including what these receipts
do *not* prove: [`docs/BENCHMARK.md`](docs/BENCHMARK.md).

---

## The problem this solves

A distillation competition dies of **evaluation contamination**. If students
train on teacher output and the evaluation is drawn from a similar distribution,
miners train on the test and the score stops measuring capability.

Attestation alone does not fix this. It proves the evaluation *ran*; it says
nothing about whether the set was clean.

Sealing does. The set travels as ciphertext, its data key is released only into
an attested enclave, and the miner learns nothing but its own score. Three
further controls bound what leaks anyway:

- **Shard rotation** — the live holdout moves deterministically per epoch, so
  leakage through repeated scoring decays instead of accumulating.
- **Canaries** — items answerable only by having read the sealed set. A miner
  scoring well on those has seen the test.
- **One authorised run per nonce and epoch** — the validator issues the nonce and
  the receipt binds it with the epoch and block window, so a second attempt earns
  nothing.

---

## Two enclaves

Training code is adversarial by assumption, and the sealed set is the asset it
most wants. If the fine-tune and the evaluation share an enclave, the training
recipe becomes an exfiltration path — and a single leak retroactively invalidates
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
**holding** the frontier, and the crown moves only when a challenger clears
every gate and beats the incumbent by a margin. This mirrors the `sat-king`
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

A failed gate makes the score irrelevant — it is not a penalty term to trade
off. Any criterion a validator cannot independently derive must not be a weight,
because a weight that cannot be derived is a weight attacked by attacking the
measurement.

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
per-role books that no code path reads across, so a participant's hardware
cannot raise their model score and their model's success cannot raise their
serving reward. Holding both roles yields the sum of two independent amounts,
never a bonus.

There is deliberately **no separate recipe-maintainer reward** in v1: a training
miner owns its complete bundle — teacher configuration, recipe, dataset
pipeline, fine-tuning config, checkpoint — and is paid for the result. Splitting
ownership from execution would require component attribution, which means
ablation runs, which multiplies the most expensive stage of the pipeline.

---

## Submitting: the registry line

A pull request never carries the recipe. It carries a **registry line** —
identities, digests, and a URI. The proof is the attested receipt at that URI,
verified automatically. The PR is the leaderboard, not the evidence.

```json
{"schema":"cathedral_registry_line_v1","miner_hotkey":"5...","track":"hermes-extract-v1",
 "checkpoint_digest":"sha256:...","recipe_digest":"sha256:...",
 "receipt_uri":"https://...","version":"1.0.0","signature":"..."}
```

The strict key set is the leak protection: an unexpected field is a parse error,
not ignored data, so prompts and dataset rows cannot be smuggled into a field
nobody validates. `recipe_digest` commits a miner to one exact recipe — making
"that isn't what I ran" refutable — while revealing nothing about its contents.

---

## Verifying a score without re-running the evaluation

A validator cannot re-run every evaluation, must not hold the sealed set, and
cannot take the miner's word. Verification is layered, cheapest first:

1. **Structural** — the score must equal the receipt's own item counts.
2. **Attestation** — the quote verifies, `report_data` reconstructs from the
   receipt, the eval image is allowlisted.
3. **Merkle spot-check** (`challenge.py`) — challenge indices derive from a block
   hash that did not exist when the receipt was committed, so a miner cannot
   know in advance which items will be opened. It reveals those items with
   openings against `items_root`; the validator re-grades exactly those locally.
   Declining to open an item is a failure, not an omission.
4. **Independent re-run** — occasional full re-evaluation on other attested
   hardware (the `reproduced` gate).

Cheating on `m` of `n` items survives a `k`-item challenge with hypergeometric
probability; `detection_probability` makes the budget explicit, and
`leakage_after` bounds how much of a shard spot-checks may burn before rotation.

---

## Modules

| Module | What it does |
|---|---|
| [`eval_receipt.py`](cathedral_distill/eval_receipt.py) | `cathedral_ml_eval_receipt_v1`, a sibling of the inference receipt |
| [`sealed_set.py`](cathedral_distill/sealed_set.py) | AES-GCM sealing, per-enclave key wrap, shard rotation, canaries |
| [`grader.py`](cathedral_distill/grader.py) | Deterministic grading, pluggable registry, no model judges a model |
| [`frontier.py`](cathedral_distill/frontier.py) | King-of-the-hill, the eight gates, emission split |
| [`challenge.py`](cathedral_distill/challenge.py) | Validator spot-checks: Merkle openings, chain-derived challenges, detection budgeting |
| [`roles.py`](cathedral_distill/roles.py) | Role separation and independent reward accounting |
| [`bundle_registry.py`](cathedral_distill/bundle_registry.py) | Bundle identity, first-wins registration, version chains |
| [`registry_line.py`](cathedral_distill/registry_line.py) | The submission artifact and its registry |
| [`teacher_registry.py`](cathedral_distill/teacher_registry.py) | Reviewed teacher allowlist with licence digests pinned |
| [`polaris_attest.py`](cathedral_distill/polaris_attest.py) | Binds a receipt to a TDX quote |
| [`teacher.py`](cathedral_distill/teacher.py) | Provider-agnostic teacher client; licence-gated corpus with logprobs and reasoning traces |
| [`runner.py`](cathedral_distill/runner.py) | The enclave eval runner; stdout carries exactly the receipt bytes |
| [`evalset.py`](cathedral_distill/evalset.py) · [`evalset_v1.py`](cathedral_distill/evalset_v1.py) | Extraction tracks — v0 clean documents, v1 hardened bundles |
| [`trace.py`](cathedral_distill/trace.py) | `cathedral_trace_v1` — desktop traces as corpus *and* eval set |

### Notes on a few

**Receipts.** A deliberate sibling of `cathedral_ml_inference_receipt_v1`: same
domain-separated hashing, same 64-byte `report_data` split into identity and
execution halves, same `Decimal`-not-float discipline. Score is derived from
item counts, never asserted. Partial runs are rejected. Unattested receipts are
valid but earn zero — `creditable_as_verified_work()` is separate from
`validate_receipt()` on purpose.

**Grading.** Determinism is a security property: the grader digest is pinned in
the receipt and the score is bound into the quote. No LLM judge is used
anywhere — a model judge is a scoring surface miners optimise against, and it
makes the score depend on a third model nobody pinned. `runtime.decode_digest`
pins the sampling parameters, so the same checkpoint under different settings is
a distinguishable measurement rather than a contradiction.

**Teacher allowlist.** A miner must never assert that its own teacher's licence
permits distillation. Licences are pinned by digest — if the published text no
longer matches what was reviewed, the review is stale and the teacher is refused.
Reviews expire. `teacher_id` must be `provider/model/version`, because a review
of one version says nothing about the next.

---

## Tracks

| Track | Status | Grading |
|---|---|---|
| `hermes-extract-v0` | superseded — too easy (a 3B model scored 31/32) | schema exact-match |
| `hermes-extract-v1` | **current** — distractors, authority rule, noise | schema exact-match on the authoritative document |
| computer-use traces | schema built, generation not yet wired | next-action match against frozen traces |

`hermes-extract-v1` bundles several on-topic notices from different issuers and
dates, states an explicit authority rule (source class outranks date; date
breaks ties within class), adds off-topic noise, and requires the *authoritative*
document's content hash copied verbatim. Extracting the wrong document produces
well-formed, plausible, failing answers — which is the point.

The [`agent/`](agent/) directory holds a Hermes profile forked from the
regulatory baseline into a **desktop operator**: `computer-use-linux` MCP tools,
an `Action` output schema, and a trace recorder. `trace.py` is what makes
computer use measurable at all — the desktop runs **once** during generation,
where a flaky episode simply fails its predicate and is discarded, and
evaluation replays **frozen observations** instead. One artifact serves as both
the training corpus and the sealed eval set.

---

## What is proven today

- All modules pass **233 local tests**, hardware-free, including an end-to-end
  test that walks the entire path: build set → seal → open → run → grade →
  receipt → attestation binding → validation → spot-check → registry line →
  frontier crown → emission share.
- A real distillation loop has been run: 138-row corpus from a reasoning
  teacher, two LoRA students, four sealed evaluations, all receipts published.
- Two complete runs of the same checkpoint produced byte-identical `items_root`,
  so the `reproduced` gate is satisfiable.
- The core economic property is tested directly: splitting one gain into several
  submissions yields the same champion and the same emission share as submitting
  the best result once.

## What is NOT proven

- **The published benchmark is unattested.** Those runs happened on an ordinary
  GPU box; `attestation.kind` is `"none"` and `creditable_as_verified_work()`
  returns `False` for every one. Under the mechanism they would earn zero.
- **Attestation-gated key release is disabled upstream.** The sealed-evaluation
  design matches the published key-release contract but cannot be described as
  live.
- **Nothing is wired to chain** — no score class, no weight vector.
- **Computer-use traces have never been generated.** The schema and agent
  profile exist; the recorder, desktop image, and task queue do not.
- Confidential GPU acceptance remains pending upstream, so evaluation targets
  confidential CPU.

## Known gaps

- **Paired re-evaluation is missing.** A champion's score is frozen from when it
  was crowned, so once `rotate_holdout` moves the shards, champion and challenger
  are compared on *different items*. The fix is to re-score the incumbent
  whenever the item set rotates. This is a correctness bug and should close
  before miners exist.
- **`min_margin` is not statistically grounded.** On a 32-item set the sampling
  noise on a proportion is far larger than the default 0.005 margin. Paired
  scoring and a continuous metric would both help; neither is implemented.

---

## Run locally

Requires Python 3.11+.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Expected: `233 passed`.

| Test file | Tests |
|---|---:|
| `test_bundle_and_frontier.py` | 38 |
| `test_grader.py` | 29 |
| `test_registry_line.py` | 25 |
| `test_challenge.py` | 20 |
| `test_evalset_teacher.py` | 20 |
| `test_roles.py` | 19 |
| `test_trace.py` | 17 |
| `test_eval_receipt.py` | 14 |
| `test_sealed_set.py` | 14 |
| `test_polaris_attest.py` | 11 |
| `test_evalset_v1.py` | 11 |
| `test_pipeline.py` | 9 |

### Reproducing the benchmark

```bash
python3 scripts/make_corpus.py --track v1 --rows 160 --teachers teachers.json \
    --out corpus.jsonl
python3 scripts/train_lora.py --corpus corpus.jsonl --mode reasoning \
    --base Qwen/Qwen3-4B-Instruct-2507 --out out/reasoning --grad-checkpoint
python3 -m cathedral_distill.runner --items items.json --decode-params decode.json ...
```

Large-vocabulary models need `--grad-checkpoint` at long context: Qwen3's 151k
vocabulary makes the cross-entropy logits, not the activations, the memory
ceiling — several GiB per sequence for the loss alone.

---

## Container contract

The evaluation runner follows the `sat-king` shape, because the attestation
binds `sha256(image_digest ‖ sha256hex(stdout))`:

- a fixed input mount path and a self-contained entrypoint;
- **stdout is a cryptographic surface, not a log** — the canonical receipt and
  nothing else goes to stdout; every diagnostic goes to stderr;
- pull by digest, never by tag, so the bytes cannot change after admission.

---

## Roadmap

**Correctness first:** paired re-evaluation, and a statistically grounded margin.

**Then:** attested evaluation on confidential hardware; the frontier score class
wired to weights; trace generation for the computer-use track; retired-shard
publication, making sealed sets retroactively auditable.

**Under consideration:** a kernel-optimisation track. Compile-and-time
verification has the same asymmetry that makes SAT work — expensive to produce,
cheap to check — and unlike every other candidate workload it *requires* the
attested GPU, because a timing claim from an untrusted machine is not evidence.

## Licence

MIT.
