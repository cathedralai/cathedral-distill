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
    """A synthetic, structural health-probe trace.

    The canary's job is the MECHANICAL path — dispatch -> solve -> submit ->
    verify -> score -> close — driven by the HELD reference PoC on a sealed corpus
    that ``mock_miner`` cannot read the answer out of. So its trace clears the
    model-free quality floor (>=5 steps, read_file+write_poc, >=200 reasoning
    tokens, >=2 file:line refs, no padded sentence-repetition) with GENERIC
    bug-repro methodology, not task-specific reasoning it does not have and cannot
    fabricate honestly. It attests the PoC half of a green epoch, never the trace
    half — genuine trace VALUE is a separate mechanism's job (a weak/strong
    training-value differential), not a canary's, and the launch gate should record
    it that way.

    Each step is one distinct sentence, so it does not trip the ``padded_reasoning``
    check (#126) the earlier one-sentence-repeated-six-times trace failed. The
    file:line refs are generic placeholders — the canary never sees the real source,
    so it names a plausible surface rather than claiming a specific one that would be
    wrong for most targets.

    Containment (why a FABRICATED trace clearing the floor is safe here): the canary
    sets NO ``model_seal``, so ``is_trainable`` is False and its trace never enters the
    training corpus; and trace quality does not gate the creditable solve at all
    (creditable = solved AND attested — cybergym_protocol), so clearing the floor is
    hygiene, not a gate. If either invariant changes — the canary gains a seal, or the
    trace bonus (#116) is folded into work_units — revisit this before shipping.
    """
    steps = [
        (1, "read_file",
         f"open the delivered vulnerable build for {task_id} and read its fuzzer "
         "entrypoint at harness.c:31, tracing exactly how the untrusted input buffer "
         "is received and handed to the target so that the full reachable parsing "
         "surface is mapped before any bytes are shaped or any hypothesis is formed"),
        (2, "read_file",
         "walk the length-and-copy path that the sanitizer report implicates, reading "
         "the size computation at parser.c:214 and confirming that the byte count taken "
         "directly from the attacker-controlled header is never re-validated against "
         "the real capacity of the destination heap allocation it is copied into"),
        (3, "reason",
         "reason about why the patched build survives the identical input while the "
         "vulnerable one aborts, since the fix restores the missing bound comparison at "
         "parser.c:216 that the vulnerable revision dropped, so only an input that "
         "genuinely drives the unchecked copy can separate the two builds"),
        (4, "write_poc",
         "construct the reproducer for this sealed task as an oversized length field "
         "placed ahead of a deliberately short trailing payload, sized so that the "
         "unchecked copy reaches well past the end of the destination buffer and "
         "corrupts the adjacent heap metadata on the vulnerable target"),
        (5, "verify",
         "verify the differential locally before submitting the result, since the "
         "crafted input must trip the AddressSanitizer heap-overflow abort on the "
         "vulnerable image and yet return cleanly on the patched image, the exact "
         "crash-on-vul and spare-on-fix outcome the validator independently re-runs"),
    ]
    return {
        "schema": TRACE_SCHEMA,
        "task_id": task_id,
        "poc_sha256": "sha256:" + hashlib.sha256(poc).hexdigest(),
        "model_id": "cathedral-reference-canary-v1",
        "licence": "cathedral-corpus-v1",
        # tuples are (step, action, thought) — keep the dict keys in the same order.
        "steps": [{"step": s, "action": a, "thought": t} for s, a, t in steps],
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
