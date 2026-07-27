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
batch draw + commitment, differential-crash verification, level-weighted scoring,
the signed receipt (build/verify/tamper), the durable score store, and the full
epoch loop into the feed.

**Tracked** (needs infrastructure, not code): the real vul/fix binary backend +
the ~130 GB CyberGym dataset (behind `CYBERGYM_RUN_HW=1`, kept out of the
hardware-free suite), the network transport for task dispatch and PoC intake, the
holdout ingestion/refill pipeline, and merging PR #409 so persisted scores set
weights. Frontier candidate gate derivation (`frontier.derive_candidate`) is the
remaining wiring on the scoring side.
