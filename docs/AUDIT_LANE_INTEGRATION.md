# The audit lane: integration contract

**Status: proposal, not wired in.** `cathedral_distill/cybergym_audit.py` is a
standalone scorer with its own tests (`tests/test_cybergym_audit.py`). Nothing in
the live scoring or reward path imports it. This document is the plan for how it
*would* plug into the existing spine without disturbing the crash lane — so a
reviewer can judge the seam before any mechanism-version change is made.

## What the lane adds

The shipped crash lane (`cybergym.score_batch`) asks one question per task: does
this PoC reproduce *the specific vulnerability this patch fixed*? The audit lane
asks the open-world question Brumley's talk argues for — *find every bug in this
build* — and scores **precision × recall**, uniquifying PoCs by their sanitiser
**backtrace signature** the way ClusterFuzz / syzkaller bucket duplicates.

Recall stops a model settling for the easiest bug; precision stops it spamming
near-duplicate or junk PoCs. The product means one cannot be bought at the
other's expense. The crash lane is unchanged; this is an additive sibling.

## The reward spine it must ride

Per miner, `cybergym_validator.py` runs exactly this chain today:

```
verify_poc()  →  PoCSubmission  →  score_batch()  →  BatchScore
      (runs inside the attested backend)                 │
                                                         ▼
                                          build_receipt()  (Ed25519-signed;
                                          reward-bearing field = score.work_units)
                                                         │
                                                         ▼
                                     evaluate_emission_gates()  (TDX attestation,
                                          eligibility, freshness, source admission)
                                                         │
                                         pass ──► score_store.record(receipt)
                                                         │
                                                         ▼
                                     lane_contribution(receipt) → frontier
                                              (king-of-the-hill)
```

"Integrating seamlessly" means one thing precisely: the audit lane emits a
`work_units` number through *this same* receipt → gates → frontier pipe, and
every number in the receipt is **re-derivable by a peer validator**. It must not
open a side door around the gates.

## The five seams

### 1. Score → `work_units`
`score_audit` returns `AuditScore.work_units` = `precision × weighted-found-mass`,
already in the crash lane's weight units (a blind `level0` find is worth `8`, a
handed-the-diff `level3` find `1`, same `DEFAULT_LEVEL_WEIGHTS`). The frontier
sums and compares it exactly like `earned_units`. `score` (normalised `[0,1]`)
stays the human-readable headline; `work_units` is the reward-bearing quantity.

### 2. Merkle `items_root`
`AuditScore.items_root` commits one leaf per known bug (found / not-found, and the
confirming PoC) and one per distinct PoC (crashed, signature, differential exit
codes). Same odd-node-promotion Merkle shape as `BatchScore.items_root`, so a
peer validator can spot-check a single claim — a claimed *miss* on the recall
side, or a claimed *find* on the precision side — without re-running the audit.

### 3. A signed receipt variant
`build_receipt` serialises `BatchScore` into a signed body; `verify_receipt`
re-derives it. The audit lane needs an `audit` block (or a sibling schema,
`RECEIPT_SCHEMA_AUDIT_V1`) carrying `precision`, `recall`, `found_bugs`,
`work_units`, and `items_root`, with a matching re-derivation check. Same signing
key, same verify-before-persist discipline. **This is the one piece of new
receipt code required.** `novel_candidates` must NOT enter the signed arithmetic
(see seam 5).

### 4. Pass through the gates unchanged — the load-bearing rule
The audit lane routes through `evaluate_emission_gates` and honours the same
per-task admission filters the crash lane already applies before counting any
find:
- `source_rewardable(task_id)` — a private source without a verified miner
  artifact is excluded.
- synthetic / reversible tasks (`is_synthetic_task`, and the `freshvuln`
  recoverable-artifact rule from #88) are graded, never rewarded.
- **crash-evidence binding (#93).** A find is only credited when the differential
  passes *inside the enclave*, which already enforces the task's bound
  crash-evidence rule (`_is_crash`: expected exit/signal AND a canonical
  sanitiser report). The module mirrors this at its own boundary:
  `AuditPoC.crashed` must be set by the backend under that same rule, and a
  `signature` attached without a bound crash is rejected at construction. So the
  novel-candidate channel cannot be spammed with fake sanitiser strings.

### 5. Novel candidates stay off the reward path
`AuditScore.novel_candidates` (crashing signatures matching no known bug) never
enter `work_units`. They flow to `corpus_admission` on a separate channel —
structurally identical to how synthetic tasks are "graded, never rewarded" today.
This is the quarantine decision, enforced at the receipt boundary rather than by
convention: novelty is treated as *supply* (it grows a later epoch's known set
once it earns a fix build), not as *reward*. It is the decentralised analogue of
a zero-day mining pipeline — the miners' models are the discovery engine — without
paying unverified claims.

## The one mechanism-policy choice

The frontier can either **sum** the audit `work_units` into each miner's
contribution alongside the crash lane, or run the audit lane as an **independent
reward book** (`roles.py`). This is the same fork the README already flags for
reward activation (one composed vector vs. a separate on-chain mechanism), and it
is the only decision that is policy rather than code. Until it is made and the
full allocation contract is signed, this lane stays inert — exactly like the
crash lane's own reward wiring.

## Batch sealing

An audit task is a *build* with a set of known bugs. It seals through the same
commit-then-challenge machinery as the crash lane (`cybergym_batch`): the model
is committed before the batch nonce exists, so the miner cannot know which build
it will audit. Two miners are comparable only on the same sealed build.

## What is NOT in this proposal

- The receipt-schema code of seam 3 (the module produces the numbers; nothing
  signs them yet).
- The `corpus_admission` handoff wiring of seam 5 (the module surfaces
  `novel_candidates`; nothing consumes them yet).
- Any frontier or allocation change.

Each is a deliberate mechanism-version step, gated on the policy choice above.
