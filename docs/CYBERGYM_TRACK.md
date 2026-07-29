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

2. **Draw the sealed batch from the private holdout.**
   `cybergym_batch.draw_batch` selects `size` tasks disclosed after the cutoff
   the committed model predates, ranked by a nonce-keyed hash. Same pool + nonce
   → same batch; an exhausted holdout refuses rather than recycles.

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

6. **Persist the verified score.** `cybergym_scores.CyberGymScoreStore.record`
   writes the level-weighted earned units to the `cybergym_scores` table keyed by
   `(miner_hotkey, epoch)`, transactionally and idempotently; a conflicting
   re-score is refused rather than silently overwriting a published frontier.

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
   poc_base64, trace}`, where `trace` is a `cathedral_trace_submission_v1`
   document. `from_json` validates it fail-closed.
3. **Verify + score** — `process_submission`. Binds the trace to the exact PoC and
   the challenged task, runs the differential crash test (`solved` ⟺ crashes the
   vulnerable build, not the patched one), applies the structural trace floor, and
   scores: level-weighted `derived_work_units` (validator-derived, never
   miner-claimed) plus the trace/seal bonus. Off-batch, wrong-batch,
   digest-mismatch, and malformed traces are refused; an unsolved PoC earns zero;
   a solved-but-thin trace scores the exploit but earns no trace bonus and never
   enters the corpus.
4. **Corpus** — `CyberGymCorpusStore`. A verified + trainable + licenced + sealed
   row is written as the trajectory **verbatim** — the submission format *is* the
   dataset format, so a verified solution compounds into training data with no
   transformation.

The trace floor (`trace_submission.check_trace_quality`) is structural and
model-free: ≥ 5 steps, `read_file` + `write_poc`, ≥ 200 reasoning tokens, ≥ 2
`file:line` references, and no padded loops — cheap on every submission and
un-gameable by spending compute.

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

**Tracked** (needs infrastructure or a cross-repo decision, not local code): the
real vul/fix binary backend + the ~130 GB CyberGym dataset (plugs in behind the
injected `cybergym_verifier.subprocess_backend`; only binaries/dataset remain); the
production holdout **refill** feed of fresh disclosures (the ingestion loader is
built; the source of new vulns is infrastructure); and merging `cathedralai/cathedral`
PR #409 plus a live weight-set caller so persisted scores set weights on chain.
