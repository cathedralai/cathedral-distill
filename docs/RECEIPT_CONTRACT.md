# Cathedral Distill validation & publishing contract

*Resolves cathedralai/cathedral-distill#3. Compute is the reference lane.*

A rewardable Distill result enters SN39 through the **existing** compute
validation and publishing path — the same assurance receipt and the same signed
SN39 feed. This is not a separate publishing system: the Distill receipt is a
**versioned extension** of `cathedral_assurance_receipt_v2`, and Distill
contributions compose into the one signed vector alongside compute.

> **Cross-repo status — not yet reconciled.** The field-by-field mapping below
> (§1) is real: every shared field carries the same name and meaning as
> `cathedralai/cathedralconfidential`'s actual `cathedral_assurance_receipt_v2`
> (`tests/test_receipt_v2_cross_repo_contract.py` pins and checks this). What is
> **not yet true** is that a Distill receipt, as a whole document, passes that
> repo's own parser: its `evaluation` block is an additive top-level key, and
> `cathedralconfidential`'s parser requires an exact top-level key match with no
> extension point — so it rejects any receipt carrying `evaluation`, the same way
> it rejects the Compute receipt's `platform` key (see `docs/INTEGRATION_CONTRACT.md`
> §"Cross-repo status"). "The same assurance receipt" is the shared-field design,
> not (yet) a receipt that validates against both implementations.

Reference artifacts (`cathedralai/cathedralconfidential`):

- compute receipt fixture — `tests/fixtures/assurance-receipt-v2.json`
- receipt field + verification rules — `docs/RECEIPTS.md`
- signed SN39 feed contract — `tests/test_cross_repo_vector_contract.py`

Deliverables in this repo:

- receipt schema + verifier — [`cathedral_distill/distill_receipt.py`](../cathedral_distill/distill_receipt.py)
- feed composition — [`cathedral_distill/lane_feed.py`](../cathedral_distill/lane_feed.py)
- concrete fixtures — [`tests/fixtures/distill-receipt-v1.json`](../tests/fixtures/distill-receipt-v1.json), [`tests/fixtures/multi-lane-feed.json`](../tests/fixtures/multi-lane-feed.json)
- proof + regeneration — [`tests/test_receipt_contract.py`](../tests/test_receipt_contract.py)

---

## 1. Field-by-field mapping to the compute receipt

**Shared fields — identical name and meaning.** The Distill receipt carries every
top-level field of `cathedral_assurance_receipt_v2`, verbatim. For a Distill
result the "worker" is the *evaluator* machine, the "challenge" is the *evaluation
authorization*, and the "result" is the *score record* — but the field shapes and
the verification semantics are unchanged.

| Field | Compute meaning | Distill meaning (same field) |
|---|---|---|
| `schema` | `cathedral_assurance_receipt_v2` | `cathedral_distill_receipt_v1` |
| `receipt_id` | SHA-256 of the canonical body before `receipt_id`+`signature` | **identical rule** |
| `signing_key_id`, `signature` | registry-anchored Ed25519 over all other fields | **identical rule** |
| `subject_hotkey` | worker the challenge was assigned to | the **miner** whose model was evaluated |
| `epoch_id`, `source_epoch` | local + external epoch | **same** — replay binding is by `source_epoch` |
| `issued_at` | six-fraction-digit UTC | **same** |
| `platform_pseudonym` | source-epoch-scoped hardware pseudonym | pseudonym of the **evaluator** machine |
| `measurement` | approved software measurement | measurement of the **evaluator enclave** |
| `tcb` | vendor TCB (svn/status/advisory/debug/collateral) | **same shape**, of the evaluator |
| `policy_registry_release`, `policy_registry_digest`, `policy_profile_ids` | signed registry snapshot used for admission | **same** |
| `channel` | channel claim status + evidence digest | **same** |
| `work` | `challenge_id`, `manifest_digest`, `result_digest`, `status`, `work_units` | **same shape**: eval-authorization id, eval-job manifest, score-record digest, status, and the rewardable decimal `work_units` |
| `assurance` | four typed claims (channel/hardware/software/work) | **same** — the `work` claim asserts the evaluation ran and verified |
| `lifecycle` | worker state, generation/revision, evidence-expiry, revocation | **same** — v2 admits only an `attested` worker and an `issued` receipt with null revocation |

**Distill-specific extension — one added block.** Everything needed to
independently re-derive the score, and nothing more:

| `evaluation.*` | Meaning |
|---|---|
| `schema` | `cathedral_distill_evaluation_v1` |
| `model_digest`, `tokenizer_digest` | the exact student checkpoint that was evaluated |
| `evalset_digest` | the sealed evaluation set (plaintext digest) it was scored on |
| `evaluator_digest` | the grader/verifier image + code |
| `runtime_digest` | the decode / environment the score is only comparable within |
| `score` | decimal string, e.g. `"0.875"` (one representation for every value) |
| `graded_items`, `passed_items` | integer counts; `passed ≤ graded` enforced |
| `evidence_digest` | digest over the full evaluation evidence bundle |

`work.result_digest` is the score record; `work.work_units` is the rewardable
quantity derived from the score. The `evaluation` block is what lets a verifier
re-derive that number instead of trusting it.

**Proposed shared-field note.** No shared field needed renaming — `subject_hotkey`,
`work.*`, `measurement`, and `platform_pseudonym` all carry over cleanly by
reading "worker" as "evaluator". The only structural change is the additive
`evaluation` block under a new schema id, exactly as the compute contract
prescribes ("a versioned extension, not a parallel format").

---

## 2. Independent verification, before scoring

`verify_receipt` performs, in order, the same checks a compute receipt gets — so a
Distill contribution is admitted on identical evidence:

1. **Structure** — exact key sets; unknown or missing fields fail closed.
2. **`receipt_id`** — recomputed from the canonical body; must match.
3. **Signature** — Ed25519 over the canonical body minus `signature`, against the
   registry-anchored key.
4. **Replay** — `source_epoch` must equal the authorized epoch.
5. **Lifecycle** — state `issued`, revocation reference null (the v2 rule).
6. **Freshness** — `worker_evidence_expires_at` must be in the future; not issued
   ahead of `now`.

Canonical bytes match the compute rule exactly: sorted keys, ASCII escaping,
`,`/`:` separators, no whitespace, **no floats** (scores and work units are
decimal strings), six-fraction-digit UTC timestamps, ≤ 256 KiB.

The test suite exercises each failure: a bumped score breaks `receipt_id`; a
relabelled `receipt_id` breaks the signature; a wrong key, a wrong epoch, expired
evidence, a revocation reference, an unknown field, and a float each fail closed.

---

## 3. The shared feed — the pre-burn composition the publisher signs

`lane_feed.compose_vector` is **not** a competing signed vector. It is the
composition input the production publisher
(`scaffold/publisher/weights.py::build_signed_vector`) turns into the signed
`validated_supply_v2` vector, and the validator applies burn to. So it emits the
grammar that contract requires:

- per-miner rows summing to **1.0 pre-burn**, with `base_component == 0` and
  `weight == external_component` (the validator applies the fixed 10% burn *after*
  mapping hotkeys to uids — rows are never pre-burned to 0.90);
- `burn_snapshot = {burn_uid: null, burn_hotkey, forced_burn_percentage: 10.0}`;
- empty rows (zero supply) when nothing is verified — never a post-burn or
  variable-burn percentage.

The generated [`multi-lane-feed.json`](../tests/fixtures/multi-lane-feed.json)
composes one compute and one Distill contribution:

```
lane                          allocation  audit_root        contribution
cathedral_confidential_tdx    0.45        sha256:…          5ComputeMiner  work_units 3.5
cathedral_distill             0.45        sha256:…          5Miner         work_units 28

pre-burn weights (sum 1.0):  5ComputeMiner 0.5   5Miner 0.5     burn_snapshot 10.0%
```

Each lane records its **audit root** so the publisher can bind the vector back to
the receipts. The composed mass is renormalized to sum 1.0 across all miners with
verified work; a lane with none contributes nothing (the present lanes hold the
1.0). The **signature** and the full `validated_supply`/`confidential_primary`/
`external_scores` policy metadata are the publisher's, not this primitive's —
cross-repo integration with that real builder is tracked in #3 and #4.

---

## 4. Done-when checklist

- [x] A concrete Distill receipt fixture exists — `tests/fixtures/distill-receipt-v1.json`, real Ed25519 signature.
- [x] Its fields map to the compute receipt — §1, shared fields verbatim + one `evaluation` extension.
- [x] The shared feed shows one compute and one Distill contribution — `tests/fixtures/multi-lane-feed.json`.
- [x] The validator independently verifies receipt_id, evidence, freshness, replay, and signature before scoring — `verify_receipt`, tested.

No production activation or weight submission is included, per the issue.
