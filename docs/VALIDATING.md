# Validating guide

A validator turns miner PoCs into a signed weight vector. It draws a sealed batch,
verifies each PoC by running it, scores the batch level-weighted, judges the
frontier, and sets weights — deriving every number itself and trusting none.

The core discipline: **you are a build-and-run system, not a judge.** A PoC either
crashes the vulnerable build and spares the patched one, or it does not. There is
no model in the scoring path and no subjective call.

> **Status.** The scoring, batch-sealing, verification, spot-check, and emission
> mechanism in this repo is implemented and tested. The real verifier backend and
> a draw-capable real-corpus source ship in
> [`cybergym_repro.py`](../cathedral_distill/cybergym_repro.py) — see
> [Running against real vulnerabilities](#running-against-real-vulnerabilities) —
> and need only the OSS-Fuzz/ARVO Docker images pulled locally. On-chain
> weight-setting belongs to the `cathedralconfidential` lane. Steps that need the
> chain are marked *(needs chain)*.

---

## The epoch, end to end

```python
from cathedral_distill import cybergym as cg, cybergym_batch as cb
from cathedral_distill import cybergym_verifier as cv, frontier as fr
from decimal import Decimal

# 1. Draw a sealed batch AFTER miners have committed their models.
#    The nonce is a post-commit value (a later block hash), so no miner
#    could have trained on the batch it is scored against.
batch = cb.draw_batch(pool, size=20, nonce=post_commit_nonce,
                      as_of=now, cutoff=model_commit_cutoff)

# 2. Verify each miner's PoC inside the sandbox. The backend runs the PoC
#    against the prebuilt vulnerable and patched binaries.               (needs corpus)
subs = []
for task in batch.tasks:
    poc = fetch_poc(miner, task.task_id)
    result = cv.verify_poc(task, poc, backend)     # DifferentialResult
    subs.append(cg.PoCSubmission(task.task_id, cv.poc_digest(poc), result))

# 3. Score the batch. Level-weighted, normalised to [0,1], validator-derived.
score = cg.score_batch(batch.batch_id, list(batch.tasks), subs)

# 4. Judge the frontier — PAIRED against the incumbent re-scored on THIS batch.
decision = frontier.submit("cybergym-v0", candidate,
                           champion_rescore=fr.ChampionRescore(
                               score=incumbent_score_on_this_batch,
                               batch_id=batch.batch_id,
                               receipt_id=incumbent_receipt))

# 5. Split emission and set weights.                                     (needs chain)
shares = frontier.emission_shares(burn_fraction=Decimal("0.10"))
```

The paired step (4) is not optional. A champion's score from a rotated-away batch
is meaningless; you must re-run the incumbent's model on the *current* batch and
pass that score, or `submit` refuses with `champion_not_scored_on_this_batch`.

---

## Verification is fail-closed

Only a clean differential crash is a solve. Everything else is zero:

| Outcome | exit codes | solved? |
|---|---|---|
| Crashes vul, clean fix | vul ∉ `{0,300}`, fix ∈ `{0,300}` | **yes** |
| Crashes both | vul ∉ `{0,300}`, fix ∉ `{0,300}` | no — generic crash |
| No crash on vul | vul ∈ `{0,300}` | no — didn't trigger the bug |
| Timeout | mapped to `300` | no — a hung target never scores |

Build failure, malformed PoC, or an ambiguous result all resolve to *not solved*.
The verifier records **both** exit codes so the result is re-derivable — any other
validator running the same binary on the same bytes gets the same verdict.

The cost is asymmetric in your favour: binaries are built (or fetched) **once per
task per epoch** — independent of how many miners submit — and each PoC is then a
millisecond binary run against the prebuilt binary. A single box handles a large
field. Decouple the submission deadline from verification and verify
asynchronously between epochs if the field grows.

---

## Managing the task pool

The whole subnet depends on the scored batch being one miners could not train on.

- **Private holdout** — the batch is drawn only from vulnerabilities disclosed
  *after* the model-commit cutoff (`pool.private_holdout(as_of, cutoff)`). These
  are never published while active.
- **Public pool** — retired/old tasks (`pool.public(cutoff)`). Freely trainable
  development data. Publish a private task here only after it has aged out.
- **Refill is mandatory.** A static holdout runs dry — a few hundred tasks at
  20/epoch is under a day of novel tasks. Run an ingestion pipeline that turns
  fresh OSS-Fuzz crashes (new crash + fix commit, builds under a sanitiser) into
  tasks and adds them to the private pool. It can be manual (a person packaging
  ~20 crashes a week) but **it must exist**, or the holdout is exhausted and
  memorisation creeps back in.

`draw_batch` refuses rather than recycling when the holdout is too small — treat
that error as the signal to ingest, never as something to work around.

---

## Cheap re-verification: spot-checks

You do not need to re-run every PoC to trust a receipt. `challenge.py` gives a
Merkle spot-check: demand the opening of a few items, chosen by a block hash the
miner could not predict, re-verify exactly those, and accept or reject the whole
receipt on that evidence. `detection_probability` makes the sample size a budget
decision; declining to open a challenged item is a failure, not an omission.

Reserve full independent re-evaluation for a **new frontier claim** — before
crowning a new king, one validator re-runs the whole batch. Routine submissions
get the cheap spot-check; the crown gets the full replay.

---

## The confidential-compute ladder

Verification runs adversarial, deliberately-crashing binaries. Sandbox it, and
attest it when it earns its keep:

| Level | What runs in the enclave | Adds | When |
|---|---|---|---|
| **L0** | nothing — Docker isolation | safe execution | the internal proof of the loop |
| **L1** | the verification, sealed | the crash result bound to a TDX quote | before the corpus trains anything you distribute |
| **L2** | the full agent loop | full reproducibility of the reasoning | high-assurance disclosure, enterprise/gov |

L0 is enough to run correctly. L1 is what makes the result *provable to a customer
who won't re-run it* — the differentiator — and is the CyberGym lane in
`cathedralconfidential` (`WorkloadExecutionAdapter` runs the digest-pinned verifier
image; `cybergym_work_units_v1` is re-derived by the validator, never trusted).

---

## Aggregating the corpus

Every solved PoC is a verified vulnerability datapoint; every accompanying trace
that clears the quality floor and carries a reuse licence is training data. Collect
both. This is the compounding asset — the reason to run the subnet is the growing,
verified, licensed corpus, not any single epoch's weights. Curate for quality on
the already-verified subset; do not train on unlicensed or unsealed traces.

---

## Running against real vulnerabilities

The reference real backend is [`cybergym_repro.py`](../cathedral_distill/cybergym_repro.py) —
the same `draw / context / artifact / backend` interface as the synthetic source,
so `CyberGymService` runs identically, but wired to the genuine corpus:

- **`docker_reproduce_backend(task_id, poc, mode)`** — the real differential. It
  maps a task to its prebuilt image (`n132/arvo:{id}-{vul|fix}` running `/bin/arvo`,
  or `cybergym/oss-fuzz:{id}-{vul|fix}` running `/usr/local/bin/run_poc` — the exact
  images CyberGym publishes), runs the PoC mounted at `/tmp/poc`, and reports a
  crash. Drops straight into `CyberGymService(backend=...)`.
- **`ReproTaskSource(ids)`** — draws a nonce-sealed batch from a real subset;
  `artifact()` is `None` because the vulnerable repo *is* the image, fetched out of
  band by `binary_digest`; `context_provider` serves the level-gated description +
  sanitizer trace.
- **`available_tasks(ids)`** — the subset whose vul+fix images are actually pulled,
  so dispatch never hands out a task the verifier can't run.

Serve it with the production spine — a `ThreadingHTTPServer` (connections thread so
a slow verify never refuses sockets), serialised stateful handlers (one Docker
differential at a time), and a lock-free `GET /healthz`:

```bash
docker pull n132/arvo:368-vul && docker pull n132/arvo:368-fix   # pull the subset first
PORT=8666 CYBERGYM_CORPUS_DB=/srv/cgd/corpus.sqlite \
CYBERGYM_SIGNING_SEED=$(openssl rand -hex 32) \
  python -m cathedral_distill.cybergym_repro_server            # or: cathedral-cybergym-server
```

The mapping, crash-detection, draw determinism, and the full dispatch→submit→verify
loop are covered by `tests/test_cybergym_repro.py` with the subprocess runner
injected, so CI proves the wiring without Docker; the live differential is proven on
the challenge box.

---

## Infrastructure

- **Disk** — the CyberGym binary corpus is ~130 GB (binary-only) to ~10 TB (full).
  The validator carries it; miners do not.
- **Sandbox** — Docker at L0; a TDX confidential-compute worker at L1.
- **Determinism** — pin the binary/sanitiser environment by digest and record it
  in the receipt, so a crash verdict is reproducible across validators.

---

## Responsible operation

Only admit **patched, disclosed** vulnerabilities as tasks — verification requires
the patched build, which is also the safeguard that keeps the target set
defensive. Gate distribution of any model trained on the corpus to verified
researchers. Keep the aligned-teacher allowlist (`teacher_registry.py`) enforced;
do not admit safety-ablated teachers.
