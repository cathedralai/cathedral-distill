"""Validator-generated synthetic vulnerabilities — the un-cheatable holdout.

Proves the answer is nonce-deterministic (every validator identical), that a
genuine solve (an input crafted from analysing the revealed program) crashes the
vulnerable build and not the patched one, and that a lookup / random PoC — the
public-dataset cheat — earns nothing.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import cybergym_synthetic as syn  # noqa: E402
from cathedral_distill.cybergym_verifier import verify_poc  # noqa: E402

NONCE_A = "cgnonce-sha256:" + "ab" * 32
NONCE_B = "cgnonce-sha256:" + "cd" * 32


def test_generation_is_deterministic_across_validators():
    # two validators, same nonce -> byte-identical bug (same magic, size, trigger)
    a = syn.generate_bug(NONCE_A, 3, level=0)
    b = syn.generate_bug(NONCE_A, 3, level=0)
    assert a == b
    # a different nonce -> a different challenge (not the same magic + size)
    c = syn.generate_bug(NONCE_B, 3, level=0)
    assert (c.magic, c.buffer_size) != (a.magic, a.buffer_size)


def test_the_validators_trigger_solves():
    for i in range(12):  # cover both bug classes and a range of sizes
        bug = syn.generate_bug(NONCE_A, i, level=0)
        assert syn.execute(bug, bug.trigger, patched=False) == syn.CRASH_EXIT   # crashes vul
        assert syn.execute(bug, bug.trigger, patched=True) == syn.CLEAN_EXIT    # clean on fix


def test_lookup_and_random_pocs_do_not_solve():
    bug = syn.generate_bug(NONCE_A, 0, level=0)
    for cheat in (b"", b"A" * 500, b"not-an-exploit", bytes(range(256)),
                  b"WRONG" + b"\xff\xff" + b"A" * 300):   # oversized but wrong magic
        assert syn.execute(bug, cheat, patched=False) == syn.CLEAN_EXIT   # format guard -> no crash


def test_bug_is_solvable_by_analysing_the_revealed_program():
    # A capable miner reads the (revealed) vulnerable source, extracts the magic +
    # buffer size, and crafts a trigger — capability, not lookup.
    bug = syn.generate_bug(NONCE_A, 1, level=0)
    src = syn.render_source(bug, patched=False)
    magic_hex = re.search(r'memcmp\(in, "\\x([0-9a-f]+)", 4\)', src).group(1)
    buf = int(re.search(r"char buf\[(\d+)\]", src).group(1))
    magic = bytes.fromhex(magic_hex)
    # from the source alone, n = buf+1 overflows the missing-check case; n = buf the
    # off-by-one. Try both — analysis narrows it, here we assert one solves.
    crafted = magic + (buf + 1).to_bytes(2, "big") + b"A" * (buf + 1)
    crafted_obo = magic + buf.to_bytes(2, "big") + b"A" * buf
    solved = any(syn.execute(bug, c, patched=False) == syn.CRASH_EXIT
                 and syn.execute(bug, c, patched=True) == syn.CLEAN_EXIT
                 for c in (crafted, crafted_obo))
    assert solved


def test_backend_plugs_into_verify_poc():
    bugs, backend, ctx = syn.generate_holdout(NONCE_A, 4)
    bug = bugs[0]
    task = bug.to_task()
    assert verify_poc(task, bug.trigger, backend).solved is True          # genuine solve
    assert verify_poc(task, b"public-poc-guess", backend).solved is False  # cheat fails
    # the level-gated context reveals the program to analyse and, at L3, the patch
    provided = ctx(bug.task_id)
    assert "memcpy" in provided["description"]
    assert "patched" in provided["patch"]


def test_binary_digest_commits_to_the_exact_program():
    a = syn.generate_bug(NONCE_A, 0, level=0)
    b = syn.generate_bug(NONCE_B, 0, level=0)
    assert a.binary_digest.startswith("sha256:") and a.binary_digest != b.binary_digest
