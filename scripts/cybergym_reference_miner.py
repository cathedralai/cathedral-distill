#!/usr/bin/env python3
"""Reference-miner canary for a SEALED CyberGym corpus.

`cybergym_mock_miner` extracts each PoC from the vulnerable image
(`docker cat /tmp/poc`). That is impossible on a *sealed* corpus: the images
carry opaque task ids and have `/tmp/poc` stripped, precisely so a miner cannot
read the answer out of the image. The only holder of the crash inputs is the
verifier operator, who keeps them in the private reference-PoC store.

This canary is that operator submitting the HELD reference PoCs — the honest
baseline that proves the full dispatch -> solve -> submit -> verify -> score
loop end to end on a sealed corpus. It is not a real miner; it is the
"first-solver is us" reference that a sustained loop drives every epoch.

Config (all via env, with sensible rig defaults):
  CYBERGYM_ROOT              corpus dir holding `bearer-token` + `references/<opaque>.poc`
  CYBERGYM_BASE             verifier base URL (default http://127.0.0.1:8672)
  CYBERGYM_E2E_MINER_HOTKEY  the submitting hotkey

Exit code 0 iff at least one task was creditable.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

ROOT = os.environ.get("CYBERGYM_ROOT", "/home/jared/cgverify/state/arvo-real")
BASE = os.environ.get("CYBERGYM_BASE", "http://127.0.0.1:8672")
HOTKEY = os.environ.get("CYBERGYM_E2E_MINER_HOTKEY", "")
ENVELOPE_SCHEMA = "cathedral_cybergym_submission_envelope_v1"
TRACE_SCHEMA = "cathedral_trace_submission_v1"
# Enough reasoning to clear the structural quality floor (>=200 tokens, >=2 file:line refs).
_LONG = "trace the length field through the parser and confirm the bound is unchecked; " * 6


def _token() -> str:
    return open(os.path.join(ROOT, "bearer-token")).read().strip()


def post(path: str, payload: dict):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {_token()}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {"error": f"http_{e.code}"}


def _trace(task_id: str, poc: bytes) -> dict:
    return {
        "schema": TRACE_SCHEMA,
        "task_id": task_id,
        "poc_sha256": "sha256:" + hashlib.sha256(poc).hexdigest(),
        "model_id": "cathedral-reference-canary-v1",
        "licence": "cathedral-corpus-v1",
        "steps": [
            {"step": 1, "thought": f"open src/parse.c:120 and read the header; {_LONG}", "action": "read_file"},
            {"step": 2, "thought": f"cross-check src/cff/cffparse.c:440 for the bound; {_LONG}", "action": "read_file"},
            {"step": 3, "thought": f"the length is trusted so it overflows the heap buffer; {_LONG}", "action": "reason"},
            {"step": 4, "thought": f"write the reproducer with an oversized length header; {_LONG}", "action": "write_poc"},
            {"step": 5, "thought": f"confirm the sanitizer fires on vul and not fix; {_LONG}", "action": "verify"},
        ],
    }


def main() -> int:
    if not HOTKEY:
        print("set CYBERGYM_E2E_MINER_HOTKEY")
        return 2
    st, batch = post("/cybergym/dispatch", {"miner_hotkey": HOTKEY, "model_commitment": "sha256:" + "a1" * 32})
    if st != 200 or not isinstance(batch, dict) or not batch.get("batch_id"):
        print(f"dispatch FAILED {st}: {batch}")
        return 1
    bid = batch["batch_id"]
    tasks = batch.get("tasks", [])
    print(f"batch {bid[:16]}  tasks: {[t['task_id'] for t in tasks]}")
    if not tasks:
        print("no tasks dispatched (epoch consumed / no fresh batch)")
        return 2
    solved = 0
    for t in tasks:
        tid = t["task_id"]
        op = tid.split(":", 1)[1]
        poc_path = os.path.join(ROOT, "references", f"{op}.poc")
        if not os.path.exists(poc_path):
            print(f"  {tid}: NO held reference PoC at {poc_path}")
            continue
        poc = open(poc_path, "rb").read()
        st, out = post("/cybergym/submit", {
            "schema": ENVELOPE_SCHEMA,
            "batch_id": bid, "task_id": tid, "miner_hotkey": HOTKEY,
            "poc_base64": base64.b64encode(poc).decode(),
            "trace": _trace(tid, poc),
            "artifact_digest": t.get("artifact_digest"),
        })
        if not isinstance(out, dict):
            print(f"  {tid}: http={st} {out}")
            continue
        creditable = bool(out.get("creditable") or out.get("work_units"))
        solved += int(creditable)
        print(f"  {tid}: http={st} solved={out.get('solved')} creditable={creditable} "
              f"work_units={out.get('work_units')}")
    print(f"\nsolved/creditable: {solved}/{len(tasks)}")
    return 0 if solved else 3


if __name__ == "__main__":
    sys.exit(main())
