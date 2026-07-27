#!/usr/bin/env python3
"""LoRA fine-tune a student on a Cathedral distillation corpus.

Two variants, selected by `--mode`, because which one is better is an empirical
question the receipts should answer rather than an assumption:

- `reasoning` — the target is the teacher's chain-of-thought followed by the
  JSON answer. The student learns *how* sources were ranked. Longer sequences,
  slower at serve time, higher ceiling.
- `answer` — the target is the JSON alone. Shorter sequences, much faster on a
  CPU serving envelope, which is a hard gate in the frontier mechanism.

Loss is computed on completion tokens only. The prompt is context, not
something to memorise: training on it would spend capacity reproducing
regulatory boilerplate the model is *given* at inference.

Determinism is deliberate throughout — fixed seed, no shuffling entropy beyond
that seed, and a recorded `training_manifest.json` carrying the corpus digest,
base model, hyper-parameters, and the resulting adapter digest. A checkpoint
whose provenance cannot be stated is not submittable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    DataCollatorForSeq2Seq,
    Trainer,
    TrainingArguments,
    set_seed,
)

IGNORE = -100


def build_dataset(path: Path, tokenizer, mode: str, max_len: int):
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    examples = []
    skipped = 0
    for row in rows:
        if mode == "reasoning" and row.get("reasoning"):
            target = (
                "<thinking>\n" + row["reasoning"].strip() + "\n</thinking>\n"
                + row["completion"].strip()
            )
        else:
            target = row["completion"].strip()

        # The chat template is applied to the prompt so the student sees the
        # same framing at train and serve time.
        prompt_ids = tokenizer.apply_chat_template(
            [{"role": "user", "content": row["prompt"]}],
            add_generation_prompt=True,
            tokenize=True,
        )
        # transformers 5.x may return a BatchEncoding rather than a list.
        if hasattr(prompt_ids, "get"):
            prompt_ids = prompt_ids["input_ids"]
        if prompt_ids and isinstance(prompt_ids[0], list):
            prompt_ids = prompt_ids[0]
        target_ids = tokenizer(target, add_special_tokens=False)["input_ids"]
        target_ids = target_ids + [tokenizer.eos_token_id]

        input_ids = prompt_ids + target_ids
        if len(input_ids) > max_len:
            skipped += 1
            continue
        # Loss on the completion only: the prompt is given at inference.
        labels = [IGNORE] * len(prompt_ids) + target_ids
        examples.append({"input_ids": input_ids, "labels": labels,
                         "attention_mask": [1] * len(input_ids)})

    print(f"[data] {len(examples)} examples, {skipped} over {max_len} tokens")
    lens = sorted(len(e["input_ids"]) for e in examples)
    if lens:
        print(f"[data] token length p50={lens[len(lens)//2]} "
              f"p95={lens[int(len(lens)*.95)]} max={lens[-1]}")
    return Dataset.from_list(examples)


def digest_dir(path: Path) -> str:
    """Content digest over an adapter directory, for the receipt's weights_digest."""
    hasher = hashlib.sha256()
    for file in sorted(path.rglob("*")):
        if file.is_file():
            hasher.update(file.name.encode())
            hasher.update(file.read_bytes())
    return "sha256:" + hasher.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--base", default="meta-llama/Llama-3.2-3B-Instruct")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--mode", choices=("reasoning", "answer"), required=True)
    parser.add_argument("--epochs", type=float, default=3.0)
    parser.add_argument("--lr", type=float, default=1e-4)
    parser.add_argument("--rank", type=int, default=32)
    parser.add_argument("--max-len", type=int, default=8192)
    parser.add_argument("--seed", type=int, default=39)
    parser.add_argument("--grad-checkpoint", action="store_true",
                        help="trade compute for memory; needed on large-vocab "
                             "models at long context, where the cross-entropy "
                             "logits dominate memory rather than activations")
    args = parser.parse_args()

    set_seed(args.seed)
    random.seed(args.seed)

    tokenizer = AutoTokenizer.from_pretrained(args.base)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    dataset = build_dataset(args.corpus, tokenizer, args.mode, args.max_len)

    model = AutoModelForCausalLM.from_pretrained(
        args.base, dtype=torch.bfloat16, device_map="cuda:0")
    model.config.use_cache = False
    if args.grad_checkpoint:
        model.gradient_checkpointing_enable()
        model.enable_input_require_grads()

    lora = LoraConfig(
        r=args.rank, lora_alpha=args.rank * 2, lora_dropout=0.05,
        bias="none", task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
    )
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=str(args.out / "checkpoints"),
            num_train_epochs=args.epochs,
            per_device_train_batch_size=1,
            gradient_accumulation_steps=8,
            learning_rate=args.lr,
            lr_scheduler_type="cosine",
            warmup_ratio=0.05,
            logging_steps=5,
            save_strategy="no",
            bf16=True,
            gradient_checkpointing=args.grad_checkpoint,
            seed=args.seed,
            data_seed=args.seed,
            report_to=[],
        ),
        train_dataset=dataset,
        data_collator=DataCollatorForSeq2Seq(
            tokenizer, label_pad_token_id=IGNORE, padding=True),
    )
    result = trainer.train()

    adapter_dir = args.out / "adapter"
    model.save_pretrained(str(adapter_dir))
    tokenizer.save_pretrained(str(adapter_dir))

    manifest = {
        "base_model": args.base,
        "mode": args.mode,
        "corpus": str(args.corpus.name),
        "corpus_digest": "sha256:" + hashlib.sha256(
            args.corpus.read_bytes()).hexdigest(),
        "examples": len(dataset),
        "epochs": args.epochs,
        "learning_rate": args.lr,
        "lora_rank": args.rank,
        "max_len": args.max_len,
        "seed": args.seed,
        "train_loss": result.training_loss,
        "adapter_digest": digest_dir(adapter_dir),
    }
    (args.out / "training_manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
