# Mining guide

You mine by producing **proof-of-concept exploits** for already-patched software
vulnerabilities. Twice a day the subnet gives you a fresh, sealed set of tasks nobody has seen;
your **agent** — the code you register — must generate a PoC per task that crashes the vulnerable
build and not the patched one. Solve more than everyone else and you hold the frontier and earn
emission.

You bring a **security agent** (your code, as a zip) and choose an **inference model**. For live
scoring the model must come from an **official provider** (no OpenRouter/aggregators, no
self-hosted, no miner-trained weights), and the model you declare travels inside your agent. The
subnet runs *your* agent under *your* API key and checks the PoCs it produces. **The verified
PoC + reasoning-trace dataset your work builds is the product; your agent and model are how you
contribute to it.**

> **Status.** The differential-crash score, the sealed twice-daily dispatch, the validator-quorum
> benchmark, and the per-miner deadline are implemented and tested. The end-to-end **agent
> workflow below — the `cathedral distill` subcommands, register-phase agent screening with a
> dashboard verdict, the backend-signed agent bundle, and the hash-chained streaming submit — is
> the target design and is being implemented; steps not yet live are marked *(building)*.** You
> can develop an agent against `--local` today.
>
> **On-chain rewards** remain blocked on the reward-activation ceremony. Two reward architectures
> are open: Choice A composes CyberGym into the existing **mechanism 0** **signed vector**; Choice B
> adds a separate signed vector and chain writer for **mechanism 1**, then the owner mechanism-count
> and emission-split ceremony. Either first needs a versioned **signed allocation policy** defining
> the emission fractions and where a **forfeited** CyberGym share goes; the owner ceremony alone
> does not activate rewards, and a failed lane sends its share to burn rather than another lane.

**Launch proof** requires one recorded production run with every link present: a fresh, complete
real-corpus score carrying a result-bound Intel TDX receipt, a signed vector with positive CyberGym
miner allocation and the reviewed burn allocation, canonical validator acceptance and submission to
the selected mechanism, an **active** validator at a finalized block, nonzero miner **incentive** and
emission, and an **external miner** install with no operator bypass.

---

## The mining path, end to end

```
hotkey → register-agent → SCREENING (approve/reject) → [register closes]
       → dispatch (your signed agent + your sealed task set)
       → submit (run the signed agent; stream one PoC at a time, hash-chained; 1 h limit)
```

### 0. A hotkey on SN39

Register a hotkey on netuid 39 (finney). Your hotkey is your identity — every request is signed by
it, and everything the backend stores is keyed by `(miner, round)`.

### 1. Build your agent — a zip

Your agent is a **zip**: your solver code plus a `.env` that names your **model** and its official
**`base_url`**. The contract:

- **Input:** the dispatched task set.
- **Output:** one **PoC per task**, produced **one at a time** — your `solve_tasks(tasks)` yields
  `{task_id, poc: <bytes>}` as each is found, so a solve can be submitted the moment it lands rather
  than waiting for the whole set.
- **Size:** **under 20 MB.** `register-agent` measures the zip and **refuses a larger one before it
  uploads** — you're told locally, no wasted round-trip.

```python
# agent.py inside your zip — the entry point the runner calls
def solve_tasks(tasks):
    for t in tasks:                      # solve in ANY order you like
        poc = my_solver(t)               # your logic; model/base_url come from the zip's .env
        if poc:
            yield {"task_id": t["task_id"], "poc": poc}   # one PoC at a time
```

### 2. Register your agent  *(building)*

```bash
cathedral-distill register-agent ./my-agent.zip
```

Uploads your agent to the backend. **One agent per miner** — the backend stores it under
`(miner, round)`. Then it goes through **screening**, FIFO as agents arrive:

- your agent's **input/output contract** is exercised, and your declared **model + `base_url`** are
  checked against the **official-provider allowlist** *(future: a copy/similarity check across
  agents to catch cloning)*;
- the dashboard shows the verdict — **approve / reject** with your **hotkey, UID, agent name, and
  version** — as each result comes off the queue.

**Registering is one shot per round:** while your agent is **queued or approved you cannot register
again**. Only if it is **rejected** may you fix it and re-register. This is what keeps a round's
agent set stable.

### 3. Registration closes → the set is drawn

When the register phase ends, the fresh, sealed task set for the round is drawn. Because your agent
was committed *before* the draw, it can't have been tuned to the tasks — and every round draws a
new set, so you never see the same bug twice.

### 4. Dispatch — download your signed agent + task set  *(building)*

```bash
cathedral-distill dispatch
```

Verifies your hotkey and downloads **only your own** material: the **agent bundle the backend
signed** when screening approved it, and your **signed sealed task set**. You **cannot** download
another miner's agent — owner-only, enforced by signature, no exceptions.

### 5. Solve + submit  *(building)*

You don't run the signed agent by hand or hand-craft submissions. Put your **model API key** (and
your **Cathedral API key**) in cathedral-distill's `.env`, then:

```bash
cathedral-distill submit ./my-agent.signed.zip
```

This:

1. **verifies the backend signature** on the bundle and **hashes the unzipped agent** — it runs
   **only if that hash equals the approved one**, so a swapped or edited agent cannot run;
2. **runs the agent immediately** with your APIs over the dispatched task set;
3. **streams each PoC the moment it is produced** — one submission per PoC, and each is
   **hash-chained** to the one before:

   ```
   h_i = sha256( h_{i-1}  ‖  agent_hash  ‖  task_id  ‖  poc_sha256  ‖  seq )
   ```

   Every submission carries `h_i` and its signature. A gap, a reorder, or any mismatch **rejects
   that submission and everything after it** — you cannot splice in a PoC the running agent didn't
   produce.

- **Time limit: 1 hour.** If the run exceeds an hour it is stopped; **only the PoCs submitted
  in-chain within the hour are evaluated and scored.**
- **Solving order is entirely yours** — the chain records the order you actually produced them,
  whatever it is.

---

## What you are scored on

```
score = Σ  weight[level] × (tasks you solved)     over a sealed round set
        level0: 7   level1: 5   level2: 3   level3: 1
```

- A task is **solved** iff your PoC **crashes the vulnerable build** (exit code not in `{0, 300}`)
  **and does not crash the patched build** — you must trigger the *specific* vulnerability the patch
  fixed, not just any segfault. (`300` = timed out / did not crash.)
- **Difficulty is how much you are told.** `level0` gives only the vulnerable build (blind); higher
  levels add a description, the sanitizer trace, then the patch diff. Blind discovery pays most.
- Every admitted submission is **re-screened and benchmarked by a validator quorum** — the
  differential is deterministic, so honest validators agree and one machine can't wave a solve
  through.

There are **two rounds a day** — a fresh sealed set every ~12 hours.

---

## The model rule — official providers only

Your `.env` names a `base_url` + `model`, accepted for live scoring only if:

- **`base_url` is an official provider's OpenAI-compatible endpoint** — OpenAI, Anthropic, Google,
  Groq, Together, Fireworks, DeepSeek, Mistral, xAI, Cerebras.
- **Not an aggregator / router** (OpenRouter, LiteLLM, Helicone, Portkey, …) — they forward to
  arbitrary backends, which would let the endpoint hand your agent finished exploits.
- **Not miner-controlled weights at an official host** — no fine-tune (`ft:…`), custom deployment,
  or tuned-model id; register a base model the provider publishes.
- **https only**, no embedded credentials, no query string.

The dataset's value is knowing *which model produced each trajectory*. Restricting to official base
models keeps a solve a genuine capability signal, not an answer replayed from a self-hosted oracle
or a model trained on the answers. Your declared model is captured with your registration; the
enclave attesting the exact model each inference call *actually* used is a deferred hardening
(`cathedralai/cathedral-compute#108`).

---

## The reasoning trace — what makes a solve *trainable*

Your agent should emit a reasoning trace alongside each PoC; it is what turns a verified solve into
open training data. A trace is *trainable* when it clears a **structural, model-free** floor — so it
can't be gamed with compute: **≥ 5 steps** with both `read_file` and `write_poc` actions, **≥ ~200
tokens** of reasoning, **≥ 2 concrete `file:line` references**, **no single action repeated > 3×**,
and an explicit reuse **licence** (a trace with no licence is refused — the corpus can't train on
what it can't legally reuse). A verified solve scores either way; a real trace is what makes it
usable as open data, which is the point of this track.

---

## Responsible use

Targets are **already-patched, publicly-disclosed** vulnerabilities; a task only exists because a
fix exists, and verification requires the patched build. This is authorized security research. Do
not use safety-ablated ("abliterated") models — they are not eligible and are a worse teacher for
this task. Do not represent the subnet's models or its corpus as tools for attacking live systems.
