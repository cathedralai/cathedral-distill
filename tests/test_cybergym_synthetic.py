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
    # per-byte \xNN escapes in the memcmp literal — parse each byte (the program
    # is faithful C, so the escapes are the real 4-byte magic)
    magic = bytes(int(h, 16) for h in re.findall(r'\\x([0-9a-f]{2})', src))
    buf = int(re.search(r"char buf\[(\d+)\]", src).group(1))
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
    # the program to analyse is the always-available ARTIFACT; the level-gated
    # context carries only hints (a vuln description, and at L3 the patch)
    assert "memcpy" in syn.artifact_provider(bugs)(bug.task_id)   # the program
    provided = ctx(bug.task_id)
    assert "overrun" in provided["description"] or "overflow" in provided["description"]  # a hint
    assert "char buf[" not in provided["description"]             # the literal SOURCE is not in the hint
    assert "int parse(" not in provided["description"]
    assert "patched" in provided["patch"]                         # L3 patch hint


def test_binary_digest_commits_to_the_exact_program():
    a = syn.generate_bug(NONCE_A, 0, level=0)
    b = syn.generate_bug(NONCE_B, 0, level=0)
    assert a.binary_digest.startswith("sha256:") and a.binary_digest != b.binary_digest


def test_rendered_program_encodes_the_faithful_4_byte_magic():
    # The served artifact must be faithful C: the memcmp literal must decode to
    # the SAME 4 bytes the backend's execute() enforces (poc[:4] != bug.magic).
    # A single greedy "\xAABBCCDD" escape would collapse to one byte — regression
    # guard for exactly that.
    for i in range(8):
        bug = syn.generate_bug(NONCE_A, i, level=0)
        src = syn.render_source(bug, patched=False)
        escapes = re.findall(r'\\x([0-9a-f]{2})', src)
        assert len(escapes) == 4, f"expected 4 per-byte escapes, got {escapes} in {src!r}"
        assert bytes(int(h, 16) for h in escapes) == bug.magic


def test_rendered_program_compiles_as_valid_c():
    import shutil
    import subprocess
    import tempfile
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:  # pragma: no cover - CI has a C compiler; skip if not
        import pytest
        pytest.skip("no C compiler available")
    bug = syn.generate_bug(NONCE_A, 0, level=0)
    src = syn.render_source(bug, patched=False)
    prog = "#include <stdint.h>\n#include <string.h>\n" + src + "\nint main(void){return 0;}\n"
    with tempfile.TemporaryDirectory() as d:
        c = Path(d) / "s.c"
        c.write_text(prog)
        r = subprocess.run([cc, "-std=c11", "-Werror", "-c", str(c), "-o", str(Path(d) / "s.o")],
                           capture_output=True, text=True)
        # -Werror turns the "hex escape out of range" the greedy bug produced into
        # a failure; faithful per-byte escapes compile clean.
        assert r.returncode == 0, r.stderr
