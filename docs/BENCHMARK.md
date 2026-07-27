# Benchmark: distilling a reasoning teacher into a 4B student

**Date:** 2026-07-27 · **Track:** `hermes-extract-v1` · **Items:** 32 (4 canaries)

A single distillation loop, end to end: generate a corpus from a reasoning
teacher, fine-tune a student on it, and score both against a sealed evaluation
set under a pinned decode contract. Every number below comes from a receipt in
[`benchmarks/`](benchmarks/), and every receipt validates against
`cathedral_ml_eval_receipt_v1`.

## Results

| Run | Score | | p50 latency | Train time | Dominant failure |
|---|---:|---|---:|---:|---|
| Base model | 15/32 | 46.9% | 2,573 ms | — | 17× wrong document |
| Student · answer-only | 20/32 | 62.5% | **2,387 ms** | 91 s | 12× wrong document |
| **Student · reasoning** | **28/32** | **87.5%** | 25,201 ms | 278 s | 3× unparsable, 1× wrong document |
| *Teacher (reference)* | *27/32* | *84.4%* | — | — | — |

Base model: `Qwen/Qwen3-4B-Instruct-2507`. Corpus: 138 verified rows
(`sha256:3d3826bb…`). LoRA r=32, 3 epochs, loss on completion tokens only.

## What the numbers say

**Reasoning traces are worth roughly three times the answer-only gain.**
Training on the teacher's final JSON bought +5 items. Training on its
chain-of-thought followed by the same JSON bought +13. The training loss tells
the same story from the other side: answer-only bottomed at **0.021**, which is
a model memorising a short output format, while reasoning settled at **0.408**,
which is a model learning a procedure it cannot shortcut.

**The student exceeded the teacher that taught it.** 28/32 against the teacher's
27/32. This is less surprising than it sounds and worth stating precisely: the
corpus was filtered to rows the teacher got *fully correct*, so the student
learned from a curated 100%-accurate subset of its teacher's behaviour rather
than from the teacher's average behaviour. Distillation from verified
demonstrations can exceed the demonstrator; distillation from raw output cannot.

**Quality and latency moved in opposite directions, and the mechanism cares.**
The answer-only student got *faster* than its base (2,387 ms vs 2,573 ms) —
distillation made it more decisive, cutting hedging before the answer. The
reasoning student is **10× slower**, because it emits its thinking before
answering. Under the frontier's `within_latency_budget` gate on a CPU serving
envelope, the reasoning student wins on quality and would be **rejected on
latency**, while the answer-only student is worse but shippable. That is the
trade-off the gate exists to arbitrate, and it is now a measured quantity rather
than an argument.

**The remaining reasoning failures are formatting, not capability.** Three of
its four misses are `unparsable_json` — the model occasionally fails to close
its `<thinking>` block before emitting the answer. A stop sequence or a light
extraction pass would likely recover most of those, which would put the ceiling
above 30/32.

## Reproducibility

Two complete runs of the base model produced **byte-identical results**:

```
run 1  items_root  sha256:e46cd89232b4da1fb1fec5ee091d1345b91b2dddc313d5835f03af72adb8797b
run 2  items_root  sha256:e46cd89232b4da1fb1fec5ee091d1345b91b2dddc313d5835f03af72adb8797b
```

This matters because an earlier attempt to score through a hosted relay was
**not** reproducible: the same model at temperature 0 with a fixed seed returned
different answers across calls, and five of seven apparent failures passed on
retry. A leaderboard built on that would be measuring the relay, not the model.

Determinism here comes from greedy decoding, a pinned seed, a fixed dtype, and a
resident process — and the parameters are digested into `runtime.decode_digest`,
so two runs of the same checkpoint under different sampling settings are
distinguishable measurements rather than a contradiction.

## What these receipts do and do not prove

They prove that the named checkpoint, under the named decode contract, scored
what is claimed on the named sealed set, and that the score is consistent with
the per-item Merkle root a validator can spot-check.

They prove nothing about where the computation happened. **`attestation.kind` is
`"none"` and `creditable_as_verified_work()` returns `False` for every receipt
here** — these ran on an ordinary GPU box, not inside an enclave. Under the
subnet mechanism they would earn zero. They are engineering evidence, not work.

Identities are placeholders. The `validator_hotkey` and `miner_hotkey` fields
carry obvious non-identities so that nothing in this benchmark can be mistaken
for an on-chain attribution.

## Caveats worth holding

- **138 training rows is small.** The gain is real and measured on a disjoint
  sealed set, but a larger corpus would show whether it generalises or merely
  fits. The corpus generator is resumable and can run overnight.
- **The evaluation documents are synthetic**, generated in the style of the real
  EU AI Act source pool and citing its real URLs. Live pages would break
  determinism. The student therefore learns a *reasoning pattern* — authority
  ranking under conflict — rather than memorised regulation.
- **The teacher reference (27/32) was measured through the relay** and is
  subject to the nondeterminism described above. Treat it as approximate; the
  three local numbers are not.

## Reproducing

```bash
python3 scripts/make_corpus.py --track v1 --rows 160 --teachers teachers.json \
    --out corpus.jsonl
python3 scripts/train_lora.py --corpus corpus.jsonl --mode reasoning \
    --base Qwen/Qwen3-4B-Instruct-2507 --out out/reasoning --grad-checkpoint
python3 -m cathedral_distill.runner --items items.json --decode-params decode.json ...
```

Large-vocabulary models need `--grad-checkpoint` at long context: Qwen3's 151k
vocabulary makes the cross-entropy logits, not the activations, the memory
ceiling — several GiB per sequence for the loss alone.
