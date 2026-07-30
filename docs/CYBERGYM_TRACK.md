# CyberGym track — validator flow

CyberGym is SN39's verified vulnerability-discovery workload. A miner commits a
model, is issued a sealed batch of already-patched vulnerabilities it could not
have trained on, and submits a **PoC** (a byte-string input) per task. The
validator verifies each PoC by a **differential crash test** and pays for the
scarce capability of finding the bug, not for a judge model's opinion.

    solved  ⟺  the PoC crashes the vulnerable build
               AND does not crash the patched build

This document is the validator side: how one epoch goes from committed models to
a signed, auditable contribution in the SN39 feed. CyberGym is a **separate
mechanism** — it does not live inside `cathedralconfidential` (the Intel-TDX CPU
compute mechanism); the two compose through the router in `cathedralai/cathedral`.

## The epoch loop

`cybergym_validator.run_epoch` runs the whole path hardware-free (the crash
backend is injected); production swaps in the real binaries and a submission
transport, and nothing else changes.

1. **Anchor the nonce to the chain, after commitment.**
   `cybergym_batch.derive_batch_nonce` derives the batch-draw nonce under a
   domain separator from the finalized block + hash, the audience, the epoch,
   the miner, and the digest of the model the miner committed *before* that
   block. So the miner cannot have trained on the drawn set, and every validator
   reproduces the identical nonce.

2. **Draw the sealed batch from a fresh, un-cheatable source.**
   Every source exposes one `.draw(size, nonce, …) → Batch` interface, so the
   epoch loop is source-agnostic:
   - `cybergym_batch.TaskPool` — real ARVO/OSS-Fuzz tasks from the **private
     holdout** (disclosed after the cutoff the committed model predates), ranked
     by a nonce-keyed hash; an exhausted holdout refuses rather than recycles.
     Its answers are public once disclosed, so freshness depends on an external
     disclosure feed.
   - `cybergym_synthetic.SyntheticTaskSource` — bugs **generated from the nonce**,
     so a challenge did not exist in *any* public dataset until the nonce created
     it: no lookup, no disclosure lag, unlimited supply. **Not rewardable today**:
     the delivered artifact renders the magic guard and the buffer size in
     plaintext, so a no-model regex extractor solves 8/8 level-0 tasks. Generated
     tasks are dispatched and graded, and earn nothing (see step 6).
   - `cybergym_mix.MixedTaskSource` — a **deterministic weighted blend** of the
     above (e.g. 75% generated + 25% recent-real), apportioned and sub-nonced from
     the batch nonce so two validators still draw the byte-identical mixed batch.

   Whatever the source, the nonce binds the miner's committed model, so the miner
   cannot have trained on the drawn set and every validator reproduces it.

   *Public canaries* (whose answers are public, hence lookup-farmable) never enter
   this scored batch. `cybergym_mix.probe_liveness` dispatches them on a **separate,
   off-reward channel** (`PublicCanarySource` draws a pool's *public* set, never the
   private holdout) that returns a `LivenessReport` — no receipt, no work units. A
   public task can therefore prove a miner is alive/configured but can never move a
   reward, and a lookup-database miner reveals itself by acing canaries while failing
   the generated batch.

3. **Verify each PoC.** `cybergym_verifier.verify_poc` runs the PoC against both
   builds and reads the exit codes (`{0,300}` = clean, anything else = a
   sanitiser crash). `solved` is a physical fact any validator re-derives.

4. **Score the batch.** `cybergym.score_batch` produces a level-weighted total
   (level0 blind discovery weighs most), normalized to `[0,1]`, with a Merkle
   `items_root` over every graded task (solved *and* unsolved), so a validator
   can spot-check either. Work units are re-derived from the committed task,
   never a worker-reported number.

5. **Sign a receipt.** `cybergym_receipt.build_receipt` emits a
   `cathedral_cybergym_receipt_v1` — a sibling of the eval receipt, with the same
   disciplines (canonical JSON, exact key sets, decimal strings, domain-separated
   `receipt_id`, Ed25519 signature). It binds *which* batch, *which* miner,
   *which* epoch, and *what* was claimed. `verify_receipt` re-derives the
   rewardable `work_units` from `per_level_solved × level_weights`, so the earned
   units are checkable from the receipt alone before scoring.

6. **Gate, then persist the verified score.** The write to `cybergym_scores` *is*
   the reward, so the anti-gaming gates run immediately before it, in `run_epoch`
   (`EmissionGatePolicy` / `evaluate_emission_gates`). A gate evaluated anywhere
   else, in `derive_cybergym_candidate` or in `Frontier.submit`, is not on this path
   and does not stop a payment. Required by default and fail-closed:
   `registered_bundle` (the commitment is registered *by this miner*) and
   `no_contamination` (the registration pre-dates the draw). Configurable and OFF by
   default, each an explicit owner decision: `reproduced` (needs a peer validator's
   receipt for the same `batch_id`/`items_root` under a different validator hotkey,
   which a single-validator deployment cannot produce) and `independent_evaluator`
   (structurally unsatisfiable while the operator *is* the evaluator). A miner
   failing any required gate is still scored, signed and returned for audit, but its
   row is not written, so it earns nothing and its share burns. `run_epoch` and
   `CyberGymService` refuse to run without a gate decision; `gates_required=False`
   is the dev opt-out and warns loudly.

   `CyberGymScoreStore.record` then writes the level-weighted earned units keyed by
   `(miner_hotkey, epoch)`, transactionally and idempotently; a conflicting re-score
   is refused rather than silently overwriting a published frontier.

   **Synthetic tasks are graded but NOT rewarded** (`credit_synthetic_tasks=False`,
   the default). `cybergym_synthetic.render_source` prints the 4-byte magic guard and
   the exact `char buf[N]` size in plaintext, and the artifact route serves that
   source at every level including level 0, so a no-model extractor with two regexes
   solves 8/8 level-0 tasks (measured). Their solves are excluded from the scored
   submissions, so the receipt itself reports zero units for them.
   `credit_synthetic_tasks=True` is an explicit unsafe-for-rewards override, and it
   changes the derived `items_root`, so every validator must agree on it exactly as
   they agree on `level_weights`.

7. **Compose the feed.** `cybergym_receipt.lane_contribution` yields
   `(miner_hotkey, receipt_id, work_units)`, which `lane_feed.compose_vector`
   composes into the one signed SN39 vector alongside the compute lane, with the
   contractual 10% burn.

## The miner↔validator protocol

`cybergym_protocol.py` is the delivery loop — pure and transport-agnostic, so a
real HTTP/axon shim is a thin wrapper over these functions and the binaries plug
in behind the injected backend.

1. **Dispatch** — `dispatch → DispatchMessage` (validator → miner). Draws the
   miner's sealed batch (nonce bound to its committed model) and serves only the
   **level-appropriate context**: level 0 gets the vulnerable build alone, level 3
   also gets the patch (`LEVEL_CONTEXT_FIELDS`). Deterministic and identical
   across validators.
2. **Submit** — `SubmissionEnvelope` (miner → validator). `{batch_id, task_id,
   poc_base64, trace, attestation}`, where `trace` is a
   `cathedral_trace_submission_v1` document and `attestation` is a base64
   `cathedral_cc_attestation_v1` Intel-TDX token (see the attestation gate below).
   `from_json` validates it fail-closed.
3. **Verify + score** — `process_submission`. Binds the trace to the exact PoC and
   the challenged task, runs the differential crash test (`solved` ⟺ crashes the
   vulnerable build, not the patched one), verifies the **Intel-TDX attestation**
   (`attested`), applies the structural trace floor, and scores: level-weighted
   `derived_work_units` (validator-derived, never miner-claimed) plus the
   trace/seal bonus. A solve is *creditable* only when **`solved` AND `attested`**;
   off-batch, wrong-batch, digest-mismatch, and malformed traces are refused; an
   unsolved or unattested PoC earns zero; a solved-but-thin trace scores nothing
   extra and never enters the corpus.
4. **Corpus** — `CyberGymCorpusStore`. A verified + trainable + licenced + sealed
   row is written as the trajectory **verbatim** — the submission format *is* the
   dataset format, so a verified solution compounds into training data with no
   transformation.

The trace floor (`trace_submission.check_trace_quality`) is structural and
model-free: ≥ 5 steps, `read_file` + `write_poc`, ≥ 200 reasoning tokens, ≥ 2
`file:line` references, and no padded loops — cheap on every submission and
un-gameable by spending compute.

## The Intel-TDX attestation gate

A verified PoC proves *a* bug was found; it does not prove *this* miner found it,
in an attested run, rather than outsourcing the analysis or replaying another
miner's work (the SparkProof **SEC-5** gap). So the CyberGym miner **must run its
bug-finding agent inside an Intel TDX CPU enclave** and attach a TDX attestation to
every submission; a solve earns work units **only** when that attestation verifies
and is bound to the exact submission (`cybergym_attest`).

- **Binding.** `report_data = sha256("cathedral-cybergym-attest-v1␀" ‖ batch_id ‖
  task_id ‖ poc_sha256 ‖ trace_id ‖ miner_hotkey)`. The enclave commits this into
  the TDX quote; the validator re-derives it and requires the match. Because it
  binds the batch (→ chain nonce → block + committed model), the task, the PoC,
  **the trajectory** (`trace_id` content-addresses the trace), and the miner, an
  attestation cannot be replayed for a different task/PoC, lifted from another
  miner, reused across epochs, or paired with a fabricated out-of-enclave trace.
- **Verification.** `verify_submission_attestation` reuses `attestation.verify_attestation`
  (trusted-root Ed25519 signature, pinned measurement allow-list, `report_data`
  nonce binding, freshness — all fail-closed) and additionally requires
  `tee == intel_tdx` (an AMD SEV-SNP quote is refused for this track).
- **Enforcement is mandatory and fail-closed.** `CyberGymService` refuses to start
  without an attestation policy unless the operator *explicitly* opts out
  (`attestation_required=False`) for the hardware-free dev/test path — and warns
  loudly when it does. Only *creditable* (solved ∧ attested) PoCs enter the reward
  pool `run_epoch` scores, so a forgotten kwarg can never silently credit
  unattested work.

The hardware-free reference uses a normalized Ed25519-signed token standing in for
a real Intel DCAP quote; production ingests Cathedral's live `tee_attestation`
(`tdx-1.5` `quote_b64` + collateral), where the submission binds through the
attested **workload** digests (input task + output PoC/trace).

## Auditing a receipt

Any validator, given a `cathedral_cybergym_receipt_v1`, checks — before it
counts:

1. **Structure** — exact key sets; unknown or missing fields fail closed.
2. **`receipt_id`** — recomputed from the canonical body; must match.
3. **Signature** — Ed25519 over the canonical body minus `signature`.
4. **Replay** — `source_epoch` must equal the authorized epoch.
5. **Work units** — `earned_units == Σ per_level_solved[level] × level_weights[level]`,
   `solved_tasks ≤ graded_tasks`, `score == earned/max`.

Re-running the differential crash test to confirm the individual `solved`
verdicts is the separate spot-check (it needs the binaries); the receipt binds
everything else.

## Consumed by

`cathedralai/cathedral` PR #409 (the CyberGym mechanism adapter) reads
`SELECT miner_hotkey, score FROM cybergym_scores WHERE epoch=?` and maps each
hotkey to its uid via the metagraph snapshot, with no router change. The store
above is its writer.

## Implemented vs. tracked (issue #4)

**Implemented and tested** (hardware-free): the chain-anchored nonce, sealed
batch draw + commitment, the **level-gated dispatch**, the **submission
envelope**, differential-crash verification + the **structural trace floor**,
level-weighted scoring with the trace/seal bonus, the **verified-solution corpus
writer**, the signed receipt (build/verify/tamper) resolved through an anchored
key registry, the durable score store, `derive_cybergym_candidate` (gates from a
verified receipt, never asserted booleans), and the full epoch loop into the feed.

The lane now also **runs end to end as a service**: `cybergym_holdout.load_holdout`
ingests a disclosed-vulnerability manifest into the drawable `TaskPool` (with the
level-gated context), `cybergym_service.CyberGymService` serves each miner its
sealed batch and accepts POSTed submissions (dispatch → verify → corpus → score →
persist), `cybergym_http` is a dependency-free stdlib HTTP binding of the two
routes, and `cybergym_service.compose_scores_lane` turns the persisted
`cybergym_scores` into a `lane_feed` contribution. The whole loop is exercised over
a live HTTP server against the injected crash backend in `tests/test_cybergym_service.py`.

The **task-source layer** is also complete: the nonce-seeded `SyntheticTaskSource`
is wired into the live service (`tests/test_cybergym_synthetic_service.py`), and
`cybergym_mix` adds the deterministic weighted blend + the off-reward public-canary
channel (`tests/test_cybergym_mix.py`), so a validator can run generated +
recent-real in a configured ratio and probe liveness on public tasks without ever
letting a lookup-farmable task earn a reward.

> **The generated source is not yet "un-cheatable" in the sense that matters for
> reward.** Its answer is absent from every public dataset, which was the claim, but
> it is present in the artifact the validator itself delivers: the rendered
> pseudo-C states the magic guard and the buffer size, so the task is solvable with
> two regexes and no model (8/8 at level 0, `tests/test_cybergym_synthetic_reward.py`).
> Generated tasks are therefore **non-rewarding by default**. Closing the oracle
> (delivering a compiled artifact, or a source that does not state the trigger
> parameters) is what would make them rewardable, and that is tracked, not done.

**Crash recovery.** Accepted solves are written through to
`cybergym_scores.CyberGymSolveStore` as they are accepted and rehydrated at
construction, so a restart mid-epoch resumes with the same scoring input and scores
byte-identically (`run_epoch` re-draws each batch from the chain-anchored nonce, so
the commitment plus the PoC bytes are the whole input). A running service requires
the store. Where recovery is impossible, `compose_lane` **refuses to publish** and
names the miners it cannot account for, rather than composing an empty lane that is
indistinguishable from an epoch nobody solved. Dispatch messages are still
in-memory: after a restart a miner re-requests its batch (same commitment, same
nonce, same batch) before it can submit again.

**Tracked** (needs infrastructure or a cross-repo decision, not local code): the
real vul/fix binary backend + the ~130 GB CyberGym dataset (plugs in behind the
injected `cybergym_verifier.subprocess_backend`; only binaries/dataset remain); the
production holdout **refill** feed of fresh disclosures (the ingestion loader is
built; the source of new vulns is infrastructure); and merging `cathedralai/cathedral`
PR #409 plus a live weight-set caller so persisted scores set weights on chain.
