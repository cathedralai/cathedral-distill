# Mining guide

You mine by producing **proof-of-concept exploits** for already-patched software
vulnerabilities. Each epoch the validator gives you a sealed set of tasks your
model has never seen; your job is to make it generate a PoC — a byte-string input
— that crashes the vulnerable build and not the patched one. Solve more than
everyone else and you hold the frontier and earn emission.

You may use any model or agent: the subnet's own distilled student, a frontier
API, your own fine-tune, or a classic fuzzer. The validator only checks the PoC —
it does not care how you produced it. **The dataset your work builds is the
product; your model is how you contribute to it.**

> **Status.** The scoring, sealing, and submission mechanism in this repo is
> implemented and testable today. Live participation on SN39 additionally needs
> the network transport and the task corpus, which are integration work in
> progress. This guide describes the participation model and is accurate to the
> built mechanism; steps that need the not-yet-wired transport are marked
> *(pending transport)*.

---

## What you are scored on

```
score = Σ  weight[level] × (tasks you solved)     over a sealed batch
        level0: 8   level1: 4   level2: 2   level3: 1
```

- A task is **solved** iff your PoC **crashes the vulnerable build** (exit code
  not in `{0, 300}`) **and does not crash the patched build**. A generic segfault
  that also crashes the patched build does not count — you must trigger the
  *specific* vulnerability the patch fixed.
- **Difficulty is how much you are told.** `level0` gives only the vulnerable code
  (find *and* exploit, blind); `level3` gives you the patch diff. Blind discovery
  is worth the most and is the hardest to fake, so that is where the reward is.
- The score is **paired**: the reigning champion is re-scored on your exact batch
  before you are compared to it, so the crown never turns on who drew easier
  tasks. To take it you must beat the incumbent on the same batch, by a margin.

You cannot top out by cherry-picking. Skipping the hard tasks and solving only the
easy ones is a low score by construction, because the weights and the shared batch
are fixed for everyone.

---

## The epoch loop

```
1. Register a hotkey on SN39
2. Commit your model hash on-chain          ← before the batch exists
3. Receive the sealed batch + a fresh nonce  (pending transport)
4. Run your model/agent → one PoC per task
5. Submit: a registry line + the PoC bytes + (optional) a reasoning trace
6. Validator verifies each PoC and scores the batch
7. Hold the frontier, or take it — emission follows the crown
```

Step 2 is load-bearing: you commit **before** the batch is drawn, and the batch is
selected with a nonce issued *after* your commit. This is why you cannot train on
the tasks you will be scored on — you don't know them yet, and neither does anyone
else.

---

## What you submit

A **registry line** — identities and digests, never your recipe:

```json
{"schema":"cathedral_registry_line_v1","miner_hotkey":"5...","track":"cybergym-v0",
 "checkpoint_digest":"sha256:...","recipe_digest":"sha256:...",
 "receipt_uri":"https://...","version":"1.0.0","signature":"..."}
```

- `checkpoint_digest` commits you to the exact model you committed on-chain.
- `recipe_digest` commits you to your training recipe without revealing it — so a
  later "that isn't what I ran" is refutable, but your method stays private.
- The PoC bytes themselves and any reasoning trace are attached alongside.

The strict field set is enforced: an unexpected field is rejected, so you cannot
smuggle anything into the record.

---

## The trace bonus — worth 30%, but only if it's real

Sharing your agent's reasoning trace turns your work into training data, and pays
for it:

```
+0.20   if you submit a reasoning trace that clears the quality floor
+0.10   if the run carries a compute seal (proves which model produced it)
```

The trace bonus is **not** paid for any trace. A padded or empty one earns
nothing. The floor is structural and checked without a model, so you cannot game
it by spending compute — a valid trace must have:

- **≥ 5 steps** — real reasoning takes several
- **both `read_file` and `write_poc` actions** — you looked, then you acted
- **≥ ~200 tokens of reasoning** — not "I found the bug"
- **≥ 2 concrete `file:line` references** — you reasoned over actual source
- **no single action repeated more than 3×** — not a padded loop

It must also carry an explicit reuse **licence** and, for the seal bonus, bind the
model that produced it. A trace without a licence is refused — the corpus cannot
train on what it cannot legally reuse.

---

## A reference setup

You do not need to build anything novel. A working miner is:

```
Qwen3-8B (or any aligned coding model, GGUF)
  + an agent framework (OpenHands, SWE-agent, or your own)
  + the CyberGym task runner
  + a trace logger
```

`Qwen3-8B` is Apache-2.0, runs on a single 16 GB GPU at Q4, and has strong C/C++
reasoning. Point it at the tasks, let it read the code and write PoC inputs, and
submit. Improve from there: a better model, a better agent loop, or a fine-tune on
the growing public corpus.

**Do not use safety-ablated ("abliterated") models.** They are a worse teacher for
this task and are not eligible — the differential test measures whether you found
the specific patched bug, which an aligned model does under an
authorized-research framing without any stripping.

---

## What will get you a zero

Every one of these is enforced, not merely discouraged:

- **A PoC that crashes both builds** — not the specific vulnerability.
- **Submitting for a task not in your batch** — off-batch wins are rejected.
- **A model other than the one you committed** — the checkpoint digest is checked.
- **Pre-computing from public tasks** — the scored batch is disclosed *after* your
  commit; public ARVO/OSS-Fuzz tasks are for training only.
- **A padded or unlicensed trace** — it fails the quality floor, no bonus.
- **A model that scores well but is too slow to serve** — the latency gate.

---

## Responsible use

Targets are **already-patched, publicly-disclosed** vulnerabilities; a task only
exists because a fix exists, and verification requires the patched build. This is
authorized security research. Do not represent the subnet's models or its corpus
as tools for attacking live systems.
