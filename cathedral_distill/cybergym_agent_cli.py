"""Run the CyberGym agent from a terminal or VS Code — the miner's entrypoint.

Two modes:
  * `--local`   : generate a synthetic challenge locally and solve it (no server,
                  no keys) — the fast dev loop.
  * `--dispatch-url URL --miner HOTKEY` : dispatch a real batch from a running
                  validator over HTTP, solve each task, and (with `--submit`) POST
                  the submission back.

Model-agnostic and provider-agnostic: the LLM is any OpenAI-compatible
`/chat/completions` endpoint, configured by env — so a miner can point it at a
LOCAL Hermes model (Ollama / vLLM / llama.cpp) or any hosted model:
    AGENT_API_BASE  (e.g. http://localhost:11434/v1  or  https://yunwu.ai/v1)
    AGENT_API_KEY   (bearer token; blank for a local server)
    AGENT_MODEL     (e.g. hermes-3-llama-3.1-8b, deepseek-v4-pro, ...)
Falls back to YUNWU_API_KEY / MINER_MODEL for convenience.

Streams the live trajectory (for the VS Code viewer) and writes the full run to a
JSON file (`--out`), which is the artifact the extension renders and replays.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

from cathedral_distill.cybergym import CyberGymError, validate_synthetic_nonce
from cathedral_distill.cybergym_agent import run_agent
from cathedral_distill.cybergym_protocol import _trace_from_dict
from cathedral_distill.cybergym_synthetic import SyntheticTaskSource, generate_bug
from cathedral_distill.trace_submission import TraceQualityPolicy

ENVELOPE_SCHEMA = "cathedral_cybergym_submission_envelope_v1"


def make_completer(base: str, key: str, model: str, *, max_retries: int = 5):
    """An OpenAI-compatible chat completer with exponential backoff on 429/5xx —
    a real miner hits rate limits, so the agent must ride them, not fail the run."""
    def complete(messages):
        body = json.dumps({"model": model, "messages": messages,
                           "max_tokens": 2000, "temperature": 0}).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "curl/8.5.0"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        delay = 2.0
        for attempt in range(max_retries):
            req = urllib.request.Request(f"{base}/chat/completions", data=body,
                                         method="POST", headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=180) as r:
                    d = json.loads(r.read())
                return d["choices"][0]["message"].get("content") or ""
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 500, 502, 503) and attempt < max_retries - 1:
                    time.sleep(delay)
                    delay = min(delay * 2, 30)
                    continue
                raise
        raise RuntimeError("exhausted retries")
    return complete


def _emit(step, *, jsonl):
    th = " ".join(step["thought"].split())
    out0 = (step["output"].splitlines() or [""])[0]
    print(f"  [{step['step']:>2}] {step['action']:<10} {th[:100]}")
    if out0:
        print(f"       → {out0[:90]}")
    if jsonl:
        print("@STEP " + json.dumps(step), file=jsonl, flush=True)


def solve_one(complete, *, task_id, workspace, backend, miner, model, out_path, max_turns):
    jsonl = open(out_path, "w") if out_path else None
    if jsonl:
        print("@META " + json.dumps({"task_id": task_id, "model": model, "miner": miner}), file=jsonl, flush=True)
    print(f"\n▶ task {task_id}   model={model}")
    res = run_agent(complete, task_id=task_id, workspace=workspace, backend=backend,
                    miner_hotkey=miner, model_id=model, max_turns=max_turns,
                    on_step=lambda s: _emit(s, jsonl=jsonl))
    trainable = None
    if res.solved:
        sub = _trace_from_dict(res.trace)
        trainable = sub.is_trainable(TraceQualityPolicy())
    print(f"  ── solved={res.solved} turns={res.turns} "
          + (f"trainable={trainable} " if res.solved else "") + f"reason={res.reason}")
    if jsonl:
        print("@RESULT " + json.dumps({"solved": res.solved, "turns": res.turns,
              "trainable": trainable, "reason": res.reason}), file=jsonl, flush=True)
        jsonl.close()
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the CyberGym agent (local or against a validator).")
    ap.add_argument("--local", action="store_true", help="generate a synthetic challenge locally (default)")
    ap.add_argument("--dispatch-url", help="validator base URL, e.g. http://127.0.0.1:8973")
    ap.add_argument("--miner", default="5LocalAgent", help="miner hotkey")
    ap.add_argument("--model", default=os.environ.get("AGENT_MODEL") or os.environ.get("MINER_MODEL", "deepseek-v4-pro"))
    ap.add_argument("--api-base", default=os.environ.get("AGENT_API_BASE", "https://yunwu.ai/v1"))
    ap.add_argument("--level", type=int, default=0, help="synthetic level 0-3 (local mode)")
    ap.add_argument("--nonce", default="cli0local", help="synthetic nonce (local mode)")
    ap.add_argument("--max-turns", type=int, default=12)
    ap.add_argument("--out", help="write the trajectory JSONL here (for the VS Code viewer)")
    args = ap.parse_args(argv)

    # Check the nonce HERE, where the operator typed it. Left to task construction
    # it fails as "task_id must be arvo:<n>, ..." -- accurate about the task id and
    # silent about the nonce that produced it (issue #45).
    try:
        validate_synthetic_nonce(args.nonce)
    except CyberGymError as exc:
        print(f"--nonce: {exc}", file=sys.stderr)
        return 2

    key = os.environ.get("AGENT_API_KEY", os.environ.get("YUNWU_API_KEY", ""))
    complete = make_completer(args.api_base, key, args.model)

    if args.dispatch_url:
        # Dispatch mode needs a LOCAL differential backend so the agent can test its
        # PoCs (read → run → observe → refine). That means the real vulnerable/patched
        # builds on the miner box (the ~130 GB corpus / delivered repo) — not the
        # synthetic pseudo-C, which isn't runnable. Until the real-binary path is
        # wired (Phase 2), iterate with --local, which has a live differential backend.
        print("dispatch mode needs the real build corpus on the miner (Phase 2); "
              "use --local to develop the agent now.", file=sys.stderr)
        return 2

    # local mode (default) — full dev loop with a live differential backend
    source = SyntheticTaskSource(levels=(args.level,))
    batch = source.draw(size=1, nonce=args.nonce)
    task = batch.tasks[0]
    _ = generate_bug(args.nonce, 0, level=args.level)  # ground truth exists; agent must not see it
    workspace = {"vuln.c": source.artifact(task.task_id)}
    res = solve_one(complete, task_id=task.task_id, workspace=workspace, backend=source.backend,
                    miner=args.miner, model=args.model, out_path=args.out, max_turns=args.max_turns)
    if res.solved and args.out:
        env = {"schema": ENVELOPE_SCHEMA, "batch_id": batch.batch_id, "task_id": task.task_id,
               "miner_hotkey": args.miner, "poc_base64": base64.b64encode(res.poc).decode(), "trace": res.trace}
        with open(args.out + ".submission.json", "w") as f:
            json.dump(env, f, indent=2)
    return 0 if res.solved else 1


if __name__ == "__main__":
    raise SystemExit(main())
