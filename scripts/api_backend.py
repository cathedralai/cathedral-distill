#!/usr/bin/env python3
"""Runner backend that fronts an OpenAI-compatible endpoint.

The eval runner's contract: prompt arrives on stdin, completion leaves on
stdout, everything else goes to stderr. This makes any relay model usable as a
"student" for harness runs — with the honest caveat that latency measured
through it is relay latency, not CPU-serving latency, and must be labelled as
such wherever the numbers travel.

Model comes from BACKEND_MODEL so the same script serves teacher-ceiling and
student-baseline runs. Deterministic settings: temperature 0, fixed seed.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request


def main() -> int:
    base = os.environ["TEACHER_BASE_URL"].rstrip("/")
    key = os.environ["TEACHER_API_KEY"]
    model = os.environ.get("BACKEND_MODEL") or os.environ["TEACHER_MODEL"]
    prompt = sys.stdin.read()

    request = urllib.request.Request(
        base + "/chat/completions",
        method="POST",
        data=json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "seed": 39,
            "max_tokens": 1024,
        }).encode(),
        headers={"Authorization": f"Bearer {key}",
                 "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as resp:
            payload = json.loads(resp.read().decode())
        sys.stdout.write(payload["choices"][0]["message"]["content"] or "")
        return 0
    except Exception as exc:  # noqa: BLE001 - backend failures grade as empty output
        print(f"[api_backend:{model}] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
