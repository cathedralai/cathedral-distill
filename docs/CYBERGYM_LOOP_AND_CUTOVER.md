# CyberGym loop + v3 cutover runbook

Every stage of the CyberGym reward path has been exercised end-to-end on the rig
**with attestation disabled** (`CYBERGYM_E2E_ALLOW_UNATTESTED=1`, preview posture).
That proves the path is *functional*; it does not yet prove it is *trustworthy* —
the attested loop (real TDX receipts per solve) is the remaining trust step (§4),
and it is deliberately the last thing before a live cutover, not an afterthought.

This is how to run the loop and, when the reward-path pieces are reviewed, how to
flip the v3 contract live.

## 1. The sustained loop (proven on the arvo-real rig)

Each epoch: **dispatch → miner submits held PoC → verifier differential → score →
credit → close → advance epoch**.

Components:
- **Verifier**: `cybergym_private_v2_server` over a sealed corpus (arvo-real:
  `arvo:900001/3/4/5`, opaque ids, `/tmp/poc` stripped). Launched by the corpus
  `run-server.sh` (sets `CYBERGYM_VALIDATOR_HOTKEY` — the closer must match it).
- **Miner**: `scripts/cybergym_reference_miner.py` — the canary that submits the
  HELD reference PoCs (`references/<opaque>.poc`). `mock_miner` cannot solve a
  sealed corpus (it extracts from the image). The submit contract that must be
  met: envelope `schema=cathedral_cybergym_submission_envelope_v1`, a
  `cathedral_trace_submission_v1` trace (schema + task_id + poc_sha256 +
  `model_id` + `licence` + steps clearing the quality floor: ≥5 steps,
  read_file+write_poc, ≥200 reasoning tokens, ≥2 `file:line` refs), and the
  dispatched `artifact_digest` echoed back.
- **Close/score/export**: `python -m cathedral_distill.cybergym_private_v2_close
  --issued-at <ts>` with the corpus env (incl. `CYBERGYM_SCORE_DB`,
  `DOCKER_CONFIG`, and `CYBERGYM_VALIDATOR_HOTKEY` **matching the server**). It
  refuses to re-score a closed epoch (anti-gaming — correct), so each cycle needs
  a fresh `source_epoch`.

Epoch rolling for the E2E harness: `build_service` now reads
`CYBERGYM_E2E_SOURCE_EPOCH` (default 21) instead of a hardcoded 21, so a wrapper
can bump the manifest `source_epoch` + the env each cycle. Verified: 3 cycles
across epochs 25/26/27, each `4/4 solved` → close `scores {uid250: "8"}, closed`.

**What a "green epoch" here proves — and what it does not.** The **PoC half is
genuinely proven end to end**: the submitted input crashes the vulnerable build
and spares the patched one, under the verifier's differential, on a sealed
corpus the miner cannot read the answer out of. The **trace half is proven only
structurally**: the floor is structural and model-free by design, with the
semantic "did the reasoning lead to the PoC?" check deferred to curation. So if
this canary drives the **#108 five-green-epochs gate**, the gate should record
that it attests the PoC half, not the trace half — a reader of "5 green epochs"
would otherwise reasonably assume both. (Credit: wallscaler's review of #124.)

The reference miner used to *clear* that floor with a fixed, fabricated trace
whose `file:line` refs bore no relation to the dispatched task. It no longer
does: the floor now rejects reasoning padded by repeating one sentence, which is
how that trace met the ≥200 token count. Until the canary is changed to submit
without a trace, or its trace is marked non-rewardable at the source, its
submissions carry **no trace credit at all** — which is the honest version of
what was already true.

## 2. Report → intake → v3 compose

- The exported score report feeds the publisher intake at
  `/v1/cybergym/scores` (producer bearer + HMAC over `canonical_report_bytes`).
  Proven: a report ingested `accepted:true`.
- Under the v3 contract the composer maps it to the uid-keyed CyberGym lane at
  30%. Proven end-to-end in `cathedral-validator` PR #110
  (`test_v3_full_compose_proof`): `build_signed_vector → {163:0.70, 250:0.30}`,
  burn 0.

## 3. The v3 on-chain cutover — the six required settings

The composer applies **no** contract (silent flat-recent fallback) unless the
first flag is set. All six are required together:

```
CATHEDRAL_VALIDATED_SUPPLY_ENABLED=1      # the one that was missing — without it, no contract at all
CATHEDRAL_ALLOCATION_CONTRACT=v3
CATHEDRAL_CYBERGYM_MECHANISM_ENABLED=1
CATHEDRAL_CYBERGYM_WEIGHT_FRACTION=0.30
CATHEDRAL_WEIGHT_POLICY_BURN_HOTKEY=<hotkey>   # BURN_UID must be empty (v3 burns by hotkey only)
# forced burn = 0%   (v3 requires exactly 0)
```

`test_missing_validated_supply_enabled_silently_falls_back` (PR #110) guards
against dropping the flag and silently returning to fallback.

## 4. Remaining for a live launch (reward-path — coordinate + review)

1. Wire the loop's exported reports into the **live** intake with **attestation**
   (the loop runs preview/`ALLOW_UNATTESTED` today). Reward-path → review.
2. Flip the central publisher to v3 with the six settings above. This changes the
   whole subnet's live economics — a coordinated go with the maintainers, with
   PR #110 as the proof it composes correctly, not a unilateral flip.
