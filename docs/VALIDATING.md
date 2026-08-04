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

- **`docker_reproduce_backend(task_id, poc, mode, manifest=...)`** — the real
  differential. It executes the task's immutable vulnerable/fixed
  `repository@sha256:...` references, never a mutable tag, and accepts only the
  configured sanitizer plus expected process-death evidence.
- **`ReproTaskSource(manifest)`** — draws a nonce-sealed batch from a private
  per-epoch manifest. Its evidence digest commits task metadata and both image
  identities; `artifact()` remains `None` and `context_provider` serves level-gated
  context.
- **`available_tasks(manifest)`** — verifies that every exact pinned image needed
  by a manifest is local before the server starts.

Serve it with the production spine — a `ThreadingHTTPServer` (connections thread so
a slow verify never refuses sockets), serialised stateful handlers (one Docker
differential at a time), and a lock-free `GET /healthz`:

```bash
# Pull + inspect the vul+fix pair and create the validator-held private epoch
# manifest. A re-pull cannot alter its `@sha256` references:
cathedral-cybergym-pull --tasks arvo:368 arvo:10400 --source-epoch 21 \
  --disclosed-at 2026-08-04T12:00:00Z --out /srv/cgd/private-repro-manifest.json
PORT=8666 CYBERGYM_CORPUS_DB=/srv/cgd/corpus.sqlite \
CYBERGYM_CORPUS_MANIFEST=/srv/cgd/private-repro-manifest.json \
CYBERGYM_SIGNING_SEED=$(openssl rand -hex 32) \
  python -m cathedral_distill.cybergym_repro_server            # or: cathedral-cybergym-server
```

`corpus_images.py` rejects an unpinned pair and writes a private manifest with exact
vulnerable/fixed digests and disclosure time. The server refuses tag-only or partial
manifests. The verify container is networkless, non-root, capability-free and
read-only; Docker's default seccomp profile remains enabled.

The mapping, crash-detection, draw determinism, and the full dispatch→submit→verify
loop are covered by `tests/test_cybergym_repro.py` with the subprocess runner
injected, so CI proves the wiring without Docker; the live differential is proven on
the challenge box.

---

## Live status for a dashboard

`GET /v1/status` is a public, anonymous read of what this validator can currently
attest to: the epoch and its state, the authorized block window, the signing key
a receipt resolves against, participation counts, and the scored leaderboard.
`cathedral_distill.status.build_status` builds it; the route is served by both
`make_server` and `make_threaded_server`, alongside `GET /healthz`.

```bash
curl -s http://127.0.0.1:8080/v1/status | python -m json.tool
```

```
epoch        source_epoch, network, netuid, state, valid_from_block/valid_until_block
signer       validator_hotkey, signing_key_id, signing_public_key_digest
             manifest_digest  (the FULL manifest's digest, not its contents)
participation committed, pending, scored, unscorable, durable_solves
leaderboard  scored_miners, total_earned_units, top[{rank, miner_hotkey, earned_units}]
```

What it deliberately does **not** publish: `batch_size`, `cutoff`, `as_of`, the
level weights, and the gate policy. Those are in `epoch_manifest()`, and they are
exactly what would let a miner time and shape a submission for maximum credit
while the epoch is open. `manifest_digest` is published instead, so anyone holding
the manifest can confirm which one this validator is running without the endpoint
handing out the draw parameters. A field added to the manifest later stays private
until it is added to `status._PUBLIC_MANIFEST_KEYS`.

Operational notes:

- **Read-only.** It calls no mutating handler; a public read cannot touch an epoch.
- **Cached 5s.** The reads hit the same SQLite the submit path writes, so the work
  an anonymous caller can provoke is bounded by the TTL, not by their request rate.
  On the threaded server the build takes the same lock the POST handlers use, so
  an uncached status read can queue behind a slow verify — use `/healthz`, which is
  lock-free, for liveness probing.
- **Fails soft per section.** An unreadable store reports
  `{"available": false, "detail": …}` for that section and the rest still serves.
- **CORS is open on this route only.** The mutating POST routes stay same-origin,
  because a browser that could drive dispatch/submit cross-site would let any page
  a miner visits act as that miner.
- **Same-origin is a BROWSER control, not authentication.** It stops a web page
  driving these routes; it stops nothing that can open a socket. By default the
  three mutating POST routes have **no server-side caller authentication**, so
  anyone who can reach the port can dispatch and submit as any `miner_hotkey`.
  Bind them to loopback (or behind an authenticating proxy) unless you have
  supplied an `authenticator` and set `require_authentication=True` — see
  "Authenticating the mutating routes" below.
- The site's opt-in **Live** section consumes exactly this payload; see
  [`../site/README.md`](../site/README.md).

## Authenticating the mutating routes

`/cybergym/dispatch`, `/cybergym/artifact` and `/cybergym/submit` change state.
`CyberGymService` takes an `authenticated_caller` — the identity the TRANSPORT
proved, never a value from the request body — and refuses a dispatch whose caller
is not the miner it names.

`make_handler` and `make_threaded_server` take two arguments that make that seam
usable:

| Argument | Effect |
|---|---|
| `authenticator(headers, body) -> str \| None` | returns the proven caller identity, or `None` |
| `require_authentication=True` | a request with no identity gets **401**, and never reaches the service |

Both default to off on the loopback-only development path. The server helpers now
refuse a non-loopback bind unless `require_authentication=True`; an authenticator
that raises is treated as "no identity" rather than a 500, so a broken verifier
fails closed.

**The identity mechanism is deliberately not chosen here.** A Bittensor axon's
verified `dendrite.hotkey`, a bearer per miner, or a signature over the canonical
request bytes are all workable, and which is right depends on the deployment shape
(cathedral-distill#33 part B). Supplying one is what lets these routes bind
anywhere other than loopback.

## Serving the key registry — `GET /v1/keys`

A receipt carries a `signing_key_id`; the root-signed key registry is what turns that
into a public key. Until consumers can fetch one, **no live receipt has a resolvable
signer**. Serve it alongside the other routes:

```python
from cathedral_distill.served_keys import ServedKeyRegistry

registry = ServedKeyRegistry("/etc/cathedral/registry.signed.json",
                             {"root": root_pub_bytes})
server = make_threaded_server(service, port=8080, key_registry=registry)
```

The trust is the root signature and the anchored `root.pub`, not the transport, so
serving it from a validator is safe. What this adds over a static file server is that
it refuses to hand out anything its own consumers would reject:

- **Verified before served**, on every load, against the anchored root. The root is a
  required constructor argument: a relay that cannot verify what it relays cannot tell
  a rotation from a mistake, and an unverifiable registry served here fails at every
  consumer at once instead of once here with a reason.
- **Verbatim bytes**, with an `ETag` of the registry digest and `304` on
  `If-None-Match`. `registry_digest` hashes the raw bytes, so re-serialising the JSON
  would change the published digest even where the signature still verified.
- **Rotation without a restart** — replace the file and the next request re-reads and
  re-verifies. A replacement that does not verify leaves the previous good registry
  serving and reports why.

> **⚠ It goes stale in 24 hours, whatever `valid_until` says.**
> `verify_key_registry` bounds `generated_at + max_age_seconds` (default `86400`)
> *independently* of the registry's validity window. A registry signed with a
> year-long `valid_until` is refused by every default-configured fetcher the next day
> (`key registry is too stale`). **Re-sign and re-serve daily.** Once stale,
> `GET /v1/keys` returns 503 naming the deadline rather than serving bytes nobody
> will accept, and `GET /v1/status` carries a `key_registry` block with `state`
> (`served` / `stale` / `unverified`), `digest`, `generated_at` and `fresh_until` — so
> `epoch.signing_key_id` and the registry that resolves it can be checked together in
> one request.

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
