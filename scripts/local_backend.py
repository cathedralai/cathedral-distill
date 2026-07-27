#!/usr/bin/env python3
"""Local inference backend for the eval runner — deterministic by construction.

The relay backend cannot satisfy the `reproduced` gate: the same model, at
temperature 0 with a fixed seed, returned different answers across calls. This
backend exists to remove that variable. Greedy decoding, a fixed seed, a pinned
dtype, and a resident process mean the same checkpoint scores the same number
every time, which is what makes a spot-check or a re-run meaningful.

It serves the runner's contract — prompt on stdin, completion on stdout — but
loading a 4B model per item would cost minutes per eval, so it runs as a small
persistent server instead: the first invocation starts it, subsequent ones talk
to it over a unix socket. `--serve` runs the server in the foreground.

`--adapter` attaches a LoRA adapter, so baseline and student runs differ by one
argument and nothing else.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from pathlib import Path

SOCKET_PATH = "/tmp/cathedral-local-backend.sock"


def load(base: str, adapter: str | None):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(base)
    model = AutoModelForCausalLM.from_pretrained(
        base, dtype=torch.bfloat16, device_map="cuda:0")
    if adapter:
        from peft import PeftModel

        model = PeftModel.from_pretrained(model, adapter)
        model = model.merge_and_unload()  # fold LoRA in, so serving is plain
    model.eval()
    return tokenizer, model


def generate(tokenizer, model, prompt: str, max_new_tokens: int) -> str:
    import torch
    from transformers import set_seed

    set_seed(39)  # pinned: the decode contract in the receipt says seed 39
    # transformers 5.x returns a BatchEncoding here, not a bare tensor.
    encoded = tokenizer.apply_chat_template(
        [{"role": "user", "content": prompt}],
        add_generation_prompt=True, tokenize=True, return_tensors="pt",
        return_dict=True,
    ).to(model.device)
    ids = encoded["input_ids"]
    with torch.no_grad():
        out = model.generate(
            **encoded,
            max_new_tokens=max_new_tokens,
            do_sample=False,          # greedy: no sampling entropy at all
            temperature=None, top_p=None, top_k=None,
            pad_token_id=tokenizer.pad_token_id or tokenizer.eos_token_id,
        )
    return tokenizer.decode(out[0][ids.shape[-1]:], skip_special_tokens=True)


def serve(base: str, adapter: str | None, max_new_tokens: int) -> int:
    tokenizer, model = load(base, adapter)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(4)
    print(f"[backend] ready: {base} adapter={adapter or 'none'}", file=sys.stderr)
    while True:
        conn, _ = server.accept()
        try:
            chunks = []
            while chunk := conn.recv(65536):
                chunks.append(chunk)
                if chunks[-1].endswith(b"\x00"):
                    break
            prompt = b"".join(chunks).rstrip(b"\x00").decode("utf-8")
            if prompt == "__SHUTDOWN__":
                conn.sendall(b"bye\x00")
                break
            reply = generate(tokenizer, model, prompt, max_new_tokens)
            conn.sendall(reply.encode("utf-8") + b"\x00")
        except Exception as exc:  # noqa: BLE001 — a bad item must not kill the server
            import traceback
            print(f"[backend] error: {type(exc).__name__}: {exc}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            try:
                conn.sendall(b"\x00")
            except OSError:
                pass
        finally:
            conn.close()
    return 0


def client() -> int:
    prompt = sys.stdin.read()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(600)
    sock.connect(SOCKET_PATH)
    sock.sendall(prompt.encode("utf-8") + b"\x00")
    chunks = []
    while chunk := sock.recv(65536):
        chunks.append(chunk)
        if chunks[-1].endswith(b"\x00"):
            break
    sys.stdout.write(b"".join(chunks).rstrip(b"\x00").decode("utf-8"))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--base", default="Qwen/Qwen3-4B-Instruct-2507")
    parser.add_argument("--adapter")
    parser.add_argument("--max-new-tokens", type=int, default=2048)
    args = parser.parse_args()
    return serve(args.base, args.adapter, args.max_new_tokens) if args.serve else client()


if __name__ == "__main__":
    raise SystemExit(main())
