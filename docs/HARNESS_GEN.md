# Fuzz-harness generation — the second capability

CyberGym's differential task asks a miner to **reproduce a bug** (a PoC that
crashes the vulnerable build, not the patched one). Harness generation asks a
miner to **write a fuzz harness** (an `LLVMFuzzerTestOneInput` driver) for a
target — the [`google/oss-fuzz-gen`](https://github.com/google/oss-fuzz-gen)
problem. It reuses the entire existing spine — dispatch → submit → verify → score
→ compose → attest → corpus — and adds **one new module** (`harness_gen.py`) plus
a `task_kind` flag. Nothing else changes.

## Why it fits: it maps 1:1 onto oss-fuzz-gen's metrics

oss-fuzz-gen (Google) scores a generated harness on four things; our four gates
are the same, made **objective and validator-re-derivable** (never judged):

| oss-fuzz-gen metric | our gate | signal |
|---|---|---|
| Compilability | **1 · BUILD** | harness compiles + links vs the pinned target (ASan + libFuzzer) → else 0 |
| — | **2 · SANITY** | runs on trivial inputs without crashing, and is not a no-op |
| Runtime coverage / **line-coverage diff vs the existing human-written target** | **3 · COVERAGE** | fuzz with a **pinned seed + fixed run budget** → coverage GAIN over the human OSS-Fuzz harness. A miner is paid only for what it adds *over the human* |
| Runtime crashes | **4 · BUG** | a crash within budget → the crash input is a PoC → the **existing differential verify** (crash-vuln / clean-patch) |

oss-fuzz-gen's own proof this is valuable: **30 real bugs** found by AI-generated
targets, including **CVE-2024-9143**, "only reachable via AI-generated targets" —
that is exactly gate 4's upside.

## The score is deterministic — proven on real data

The graded gate (coverage) is only objective if every validator re-derives the
same number. Run live on a real ARVO/OSS-Fuzz target (`n132/arvo:368` freetype
`ftfuzzer`) under udocker, two runs at the same seed + budget:

```
seed=1 runs=4000  →  RUN A  cov: 310  ft: 540      RUN B  cov: 310  ft: 540   (identical)
```

Same discipline as the crash differential — a fixed seed + fixed budget + pinned
build → a number two validators agree on byte-for-byte. Reusable on the verify
box: `~/cgverify/harness_verify.sh <arvo_id>`.

## Scoring (validator-derived, never miner-claimed)

`harness_gen.derived_harness_units(task, result)` — a pure function:

- `0` unless the harness **builds AND passes sanity**.
- otherwise **normalized coverage gain over the human baseline**, capped at
  `weight` (a no-op harness → ~0; a harness matching the human → ~0; only a
  genuinely better harness earns).
- **+ bug bonus** when the fuzz budget finds a crash (worth more than any
  coverage — a real bug is the point).

Merkle `items_root`, signed receipt, its own `harness_gen_v0` lane composed under
the same signed burn + allocation config → one SN39 vector. The submitted harness
source rides the existing `SubmissionEnvelope` in place of the PoC.

## Anti-cheat — reused wholesale

- **Nonce-sealed target** (bound to the committed model) → can't pre-generate.
- **Validator re-derives coverage** (pinned seed/budget/build) → a claimed number
  is worthless; two validators get byte-identical coverage → consensus.
- **TDX attestation** binds the harness to the enclave that wrote it (SEC-5) → no
  outsourcing (`cybergym_attest`).
- **Un-cheatable holdout** → targets drawn from a private/synthetic set (or
  oss-fuzz-gen's 1300+ benchmarks over 297 projects, nonce-selected).

## Implemented vs. infra

**Implemented + tested** (`harness_gen.py`, 7 tests): the 4-gate scoring model
(`derived_harness_units`, `HarnessTask`, `HarnessResult`), the injected backend
seam (`harness_backend_from_env` — stub for tests, real under `CYBERGYM_RUN_HW`),
the `harness_gen_v0` lane id. Determinism proven live on `ftfuzzer`.

**Infra (the real backend)**: `libfuzzer_backend` should **reuse oss-fuzz-gen's
evaluation runner** (build + run + coverage-diff on the OSS-Fuzz platform) rather
than reinvent it — provisioned onto the attested verify worker with a real fuzz
budget (heavier than a one-shot differential; needs more than the one-shot box).

## The flywheel

Verified harness-writing trajectories land in the corpus verbatim → distill a
**second model: a fuzz-harness generator**, complementing the bug-finder. Two
objectively-scored capabilities, two distilled models, one validator.
