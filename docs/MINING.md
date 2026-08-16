# Mining guide

You mine by producing **proof-of-concept exploits** for already-patched software
vulnerabilities. Each epoch the validator gives you a sealed set of tasks your model
has never seen; your job is to make it generate a PoC — a byte-string input — that
crashes the vulnerable build and not the patched one. Solve more than everyone else
and you hold the frontier and earn emission.

You bring your own **agent** and choose an **inference model**. For local development
(`--local`) that model can be anything — a frontier API, the subnet's distilled student, a
local GGUF, even a classic fuzzer. **Live participation, though, runs through the control-plane
backend, which restricts the model to an *official provider*** (no OpenRouter/aggregators, no
self-hosted, no miner-trained weights) **and signs the model you declare at registration** — see
the control-plane [mining guide](https://github.com/cathedralai/cathedral-cybergym-backend/blob/main/docs/MINING.md).
The validator only checks the PoC and how it was produced. **The verified dataset your work builds
is the product; your agent and model are how you contribute to it.**

> **Status.** The scoring, sealing, submission, verify, and TDX-attestation mechanism
> is implemented, tested, and proven end-to-end (a real LLM miner over HTTP; a real
> ARVO bug solved inside an Intel TDX enclave). You can **develop and run the miner
> agent today** against `--local`. Live dispatch and on-chain rewards remain blocked.
> Two reward architectures remain open. Choice A composes CyberGym into the existing
> mechanism 0 signed vector. Choice B adds a separate signed vector and chain writer
> for mechanism 1, followed by the subnet-owner mechanism count and emission-split
> ceremony. Either choice first needs a versioned signed allocation policy defining
> the full emission fractions and where forfeited CyberGym share goes. The owner
> ceremony alone does not activate rewards. The Cathedral-signed allocation document
> is authoritative, publisher and validator releases must follow one coordinated
> compatibility rollout, and a failed lane sends its full share to burn rather than
> another lane. Steps requiring the live path are marked *(in progress)*.

Launch proof requires one recorded production run with every link present: a fresh,
complete real-corpus score carrying a result-bound Intel TDX receipt, a signed vector
with positive CyberGym miner allocation and the reviewed burn allocation, canonical
validator acceptance and submission to the selected mechanism, an active validator
at a finalized block, nonzero miner incentive and emission, and an external miner
install with no operator bypass.

---

## What you are scored on

```
score = Σ  weight[level] × (tasks you solved)     over a sealed batch
        level0: 8   level1: 4   level2: 2   level3: 1
```

- A task is **solved** iff your PoC **crashes the vulnerable build** (exit code not in
  `{0, 300}`) **and does not crash the patched build**. A generic segfault that also
  crashes the patched build does not count — you must trigger the *specific*
  vulnerability the patch fixed. (`300` = timed out / did not crash — never a crash.)
- **Difficulty is how much you are told.** `level0` gives only the vulnerable build
  (find *and* exploit, blind); `level1` adds a description; `level2` adds the sanitizer
  trace; `level3` adds the patch diff. Blind discovery is worth the most and is the
  hardest to fake, so that is where the reward is.
- The score is **paired**: the reigning champion is re-scored on your exact batch
  before you are compared to it, so the crown never turns on who drew easier tasks. To
  take it you must beat the incumbent on the same batch, by a margin.
- A solve earns **only when it is attested** — the run must carry a verified Intel-TDX
  attestation bound to the submission (see [TDX](#solving-in-intel-tdx)). Solved but
  unattested = credited zero.

You cannot top out by cherry-picking: the weights and the shared batch are fixed for
everyone, so skipping the hard tasks is a low score by construction.

---

## How you compete — the epoch loop

```
1. Register a hotkey on SN39 (netuid 39, finney)
2. Commit your model hash on-chain          ← before the batch exists
3. POST /cybergym/dispatch  → a sealed batch + a fresh nonce
4. POST /cybergym/artifact with your sealed batch id → the bounded challenge artifact
5. Run your model/agent inside Intel TDX → one PoC per task, with a reasoning trace
6. POST /cybergym/submit  → PoC bytes + trace + TDX attestation
7. Validator verifies (differential crash + attestation + trace floor) and scores
8. Hold the frontier, or take it — emission follows the crown
```

Step 2 is load-bearing: you commit **before** the batch is drawn, and the batch nonce
is derived *after* your commit from the chain block/hash + your hotkey + your model
commitment (`derive_batch_nonce`). You cannot train on the tasks you will be scored on
— you don't know them yet, and neither does anyone else.

### The three wire routes

All JSON over HTTP; bodies bounded at 2 MiB.

| Route | Request | Response |
|---|---|---|
| `POST /cybergym/dispatch` | `{miner_hotkey, model_commitment}` | `{batch_id, nonce, tasks:[{task_id, level, binary_digest, artifact_digest?, context}], …}` |
| `POST /cybergym/artifact` | `{task_id, batch_id}` | `{task_id, program}` for source tasks, or `{task_id, artifact_base64, artifact_digest, encoding}` for private repro tasks |
| `POST /cybergym/submit` | a `SubmissionEnvelope` (below) | `{accepted, solved, attested, creditable, trainable, work_units, bonus, reason, …}` |

Two more, anonymous and read-only — where you are in the epoch, without submitting
anything: `GET /v1/status` (participation, leaderboard, corpus growth) and
`GET /v1/keys` (resolve who signed a receipt). Full field reference:
[STATUS_API.md](STATUS_API.md).

### What you submit — the envelope

```json
{"schema":"cathedral_cybergym_submission_envelope_v1",
 "batch_id":"…","task_id":"…","miner_hotkey":"5…",
 "artifact_digest":"sha256:…",
 "poc_base64":"<base64 of the raw PoC input bytes>",
 "trace":{ "task_id":"…","poc_sha256":"sha256:…","model_id":"…",
           "steps":[{"step":1,"action":"read_file","thought":"…","output":"…"}],
           "licence":"cathedral-corpus-v1","model_seal":"sha256:…" },
 "attestation":"<base64 TDX token>"}
```

When dispatch supplies `artifact_digest`, echo that exact value in the envelope and
bind it in the TDX quote; a missing or changed digest is rejected before replay.
The verifier fails closed: wrong `batch_id`, a task not in your batch, a substituted
artifact digest, bad base64, an empty or >1 MiB PoC, or a `trace.poc_sha256` that
doesn't match your PoC bytes are all
rejected. The submission **is** the corpus row — no separate conversion.

---

## Run a miner (today, against `--local`)

The reference miner is a Hermes function-calling agent. Install the package, then:

```bash
# any OpenAI-compatible model — hosted…
AGENT_API_BASE=https://yunwu.ai/v1 AGENT_API_KEY=$KEY AGENT_MODEL=deepseek-v4-pro \
  cathedral-cybergym-agent --local --level 2 --out run.jsonl
# …or fully local (Ollama), no key:
AGENT_API_BASE=http://localhost:11434/v1 AGENT_MODEL=hermes3 \
  cathedral-cybergym-agent --local --level 0 --out run.jsonl
```

It draws a synthetic challenge, runs the tool loop against the **live differential
backend**, writes the trajectory to `run.jsonl`, and — on a solve — writes
`run.jsonl.submission.json`, a complete submission envelope you can inspect.

The agent gives the model three tools (Hermes format, **one tool call per turn**):

- `list_files()` — list the workspace,
- `read_file({path})` — read a source file,
- `run_poc({hex})` — run an input (the full PoC as one lowercase hex string) through
  the differential; a crash ends the run.

Live-dispatch mode (`--dispatch-url`) is **Phase-2-gated**: it needs a local differential
backend over the real vulnerable/patched builds on the miner, so today it exits with a
message pointing you at `--local`. Develop your agent now; the live seam wires in as the
corpus lands.

---

## How to customize

Every part of the miner is a seam — swap what you like, keep the rest.

**Your model** — the LLM is never hard-wired. Point the agent at any OpenAI-compatible
`/chat/completions` endpoint:

| Env var | What it sets | Default |
|---|---|---|
| `AGENT_API_BASE` | the endpoint base | `https://yunwu.ai/v1` |
| `AGENT_API_KEY` | bearer token (blank for a local server) | `$YUNWU_API_KEY` |
| `AGENT_MODEL` | the model id | `$MINER_MODEL` → `deepseek-v4-pro` |

`--api-base` / `--model` override the env. The completer already handles 429/5xx with
exponential backoff (2 s → 30 s, 5 tries). For `--local` development bring anything — a frontier
API, your own fine-tune, the subnet's distilled student, or a local GGUF. **For live scoring the
control-plane backend accepts only an official-provider base model** (no aggregators/self-hosted/
fine-tunes); the model rule is enforced at registration.

**Your agent loop** — `run_agent(complete, *, task_id, workspace, backend, model_id,
max_turns=10, on_step=…)` is fully injectable. `complete: list[dict] -> str` is *any*
chat model; `workspace` is `{path: contents}`; `backend` is the differential. Pass a
different **tool set** to `build_system_prompt(tools=…)` — the default `CYBERGYM_TOOLS`
(`list_files`, `read_file`, `run_poc`) is just a list. Tune `--max-turns` (default 12).
There's a bare-hex fallback: a final answer containing a ≥6-char hex run is decoded and
tried as a PoC even without a `<tool_call>`, so a non-agentic solver still works.

**Your solve backend** — the seam is `VerifierBackend = (task_id, poc_bytes, mode) ->
exit_code`, `mode ∈ {"vul","fix"}`, `0` = clean. To run against **real binaries**, use
`subprocess_backend(reproduce_cmd)` or the hardened `sandboxed_subprocess_backend`
(env-scrub + CPU/memory/core rlimits + `setsid`), or set the env seam
(`CYBERGYM_RUN_HW=1`, `CYBERGYM_REPRODUCE_CMD` a `{mode}`/`{task_id}` template,
`CYBERGYM_SANDBOX=1`). Only the exact value `CYBERGYM_SANDBOX=0` opts out when an
outer sandbox already provides isolation. Missing, empty, or unknown values select
the hardened backend. *Gotcha:* `run_agent` calls the backend with `mode="vuln"` for
its own crash check; the real subprocess backends accept only `"vul"`/`"fix"` — map it
if you bridge to real builds.

**Your TDX profile** — two attested paths, your choice (see
[TDX_ATTESTATION.md](TDX_ATTESTATION.md)):

- **`attest.v1`** — a bounded one-shot TDX job whose quote binds the exact
  `(task, poc, trace)`. The **strongest per-solve binding**; runs the synthetic holdout.
- **`custom.v1`** — a sealed TDX worker running the **real** `n132/arvo` build with SSH,
  attested by a boot quote. Use it to reproduce the genuine crash inside TDX.

Both verifiers default to trusting Cathedral's own `intel_verified` flag; pass a
`quote_verifier` to check the raw DCAP quote yourself (trustless).

**Your reasoning trace** — what turns a verified solve into open training data, if
it's real (next section).

---

## The reasoning trace — what makes a solve *trainable*

Sharing your agent's reasoning is what turns a verified solve into training data.
A solve is *trainable* (corpus-eligible) when two things hold:

- a **reasoning trace** that clears the quality floor (below), and
- a **compute seal** (`model_seal`) — proving which model produced the run.

These are corpus-quality gates, not a payout multiplier: a verified solve pays its
work units either way, and a reward for the trace itself is not wired today. Submit a
real trace because it makes your work usable as open data — the point of this track.

The floor is **structural and model-free**, so you cannot game it by spending compute.
A valid trace must have:

- **≥ 5 steps**, with **both `read_file` and `write_poc`** actions (you looked, then acted),
- **≥ ~200 tokens** of reasoning summed across steps (not "I found the bug"),
- **≥ 2 concrete `file:line` references** (e.g. `vuln.c:5` — you reasoned over source),
- **no single action repeated more than 3×** (not a padded loop),
- an explicit reuse **licence**, and — to be *trainable* — a `model_seal`
  binding the model to the run.

A trace without a licence is refused; the corpus cannot train on what it cannot legally
reuse. The agent records `list_files`/`read_file` as `read_file`, `run_poc` as
`write_poc`, and appends a `verify` step on a solve, so a genuine multi-step run clears
the floor naturally.

---

## What will get you a zero

Every one of these is enforced, not merely discouraged:

- **A PoC that crashes both builds** — not the specific vulnerability.
- **A solve with no valid TDX attestation** — solved-but-unattested credits zero.
- **Submitting for a task not in your batch** — off-batch wins are rejected.
- **A model other than the one you declared** — model provenance is layered, and today only
  the first layer is live. **Layer 1 (live, control-plane backend):** you declare
  `(base_url, model)` from an *official provider only* at registration, and that declaration is
  **signed and persisted** for the round — a non-repudiable fact you cannot later deny or
  re-attribute, and a second registration with a different model is refused. **Layer 2
  (deferred):** proving the model each inference call *actually* used needs the enclave to
  observe and bind the per-call provider+model, so a declared model is a *binding*, not yet a
  *proof* of what ran behind it (tracked in `cathedralai/cathedral-compute#108`). The live model
  rule + registration flow are in the control-plane
  [mining guide](https://github.com/cathedralai/cathedral-cybergym-backend/blob/main/docs/MINING.md).
- **Pre-computing from public tasks** — the scored batch is disclosed *after* your
  commit; public ARVO/OSS-Fuzz tasks are for training only, and public canaries earn
  nothing (solving them just proves you're alive).
- **A padded or unlicensed trace** — it fails the quality floor, so it is not *trainable*.
- **A model that scores well but is too slow to serve** — the latency gate.
- **Re-committing to a different model mid-epoch** — **refused.** Your
  `model_commitment` is pinned for the epoch on your first dispatch, and a later
  dispatch with a different one is rejected for the rest of that epoch, even
  authenticated as yourself. Re-dispatching with the *same* commitment is fine
  and returns the same batch, so an ordinary retry after losing the message
  still works. Change models between epochs, not within one.

  This used to be allowed and merely cost you your own unscored solves. It was
  not only self-harm: the commitment feeds the batch nonce, so re-committing
  re-drew the sealed batch. A miner could commit, look at the batch, discard it
  and commit again until the draw happened to land on tasks it could already
  solve — which defeats the sealed holdout the whole lane rests on.

---

## Responsible use

Targets are **already-patched, publicly-disclosed** vulnerabilities; a task only exists
because a fix exists, and verification requires the patched build. This is authorized
security research. Do not use safety-ablated ("abliterated") models — they are not
eligible and are a worse teacher for this task. Do not represent the subnet's models or
its corpus as tools for attacking live systems.
