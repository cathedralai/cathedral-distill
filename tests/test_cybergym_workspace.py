"""Building a REAL agent workspace from an ARVO image, instead of the stub the sealed corpus ships.

The old design blinded tasks to defeat lookup and, in doing so, stripped the source and context a
genuine agent needs. Under the screening design blinding is not the defence, so a task can carry
real material. These tests hold the pure half: recovering the fuzz target from ``/bin/arvo``,
turning it into an input-format hint, and assembling a workspace that carries the source without
ever carrying the answer.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.cybergym_workspace import (  # noqa: E402
    MAX_FILE_BYTES,
    Workspace,
    WorkspaceError,
    build_workspace,
    format_hint,
    parse_arvo_target,
)

# A realistic fragment of a generated /bin/arvo, with the target repeated across branches.
ARVO_SCRIPT = """#!/bin/bash
export SANITIZER=address
export FUZZING_ENGINE=libfuzzer
if [ "$#" -ge 1 ]; then
  if [ "$1" = "run" ]; then
    /out/coder_MNG_fuzzer /tmp/poc
  fi
else
  /out/coder_MNG_fuzzer /tmp/poc
fi
"""

SOURCES = {
    "/src/gm/fuzzing/coder_fuzzer.cc": "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){...}",
    "/src/gm/coders/png.c": "/* MNG/PNG coder */\n" + "int ReadMNGImage(){ /* ... */ }\n" * 50,
}


def _reader(mapping):
    return lambda path: mapping.get(path)


class TestRecoveringTheTarget:
    def test_the_target_is_parsed_from_the_script(self):
        assert parse_arvo_target(ARVO_SCRIPT) == "/out/coder_MNG_fuzzer"

    def test_a_script_without_a_target_fails_closed(self):
        """A task whose target cannot be identified cannot be given a truthful format hint."""
        with pytest.raises(WorkspaceError, match="no /out"):
            parse_arvo_target("#!/bin/bash\necho hello\n")

    def test_the_format_hint_is_the_coder_type(self):
        assert format_hint("/out/coder_MNG_fuzzer") == "MNG"
        assert format_hint("/out/coder_TIFF_fuzzer") == "TIFF"

    def test_a_non_coder_target_has_no_hint_rather_than_a_wrong_one(self):
        assert format_hint("/out/parser_fuzzer") == ""


class TestTheWorkspaceCarriesSourceNotTheAnswer:
    def test_the_harness_comes_before_the_library(self):
        """The agent must see the input format before the code that consumes it — the harness is
        added first and named so it is recognisable."""
        ws = build_workspace(
            "arvo:10400", level=0, arvo_script=ARVO_SCRIPT, read_source=_reader(SOURCES),
            harness_paths=["/src/gm/fuzzing/coder_fuzzer.cc"], source_paths=["/src/gm/coders/png.c"])
        names = list(ws.files)
        assert names[0].startswith("harness_")
        assert "png.c" in names

    def test_the_format_hint_reaches_the_agent_context(self):
        ws = build_workspace(
            "arvo:10400", level=0, arvo_script=ARVO_SCRIPT, read_source=_reader(SOURCES),
            harness_paths=[], source_paths=["/src/gm/coders/png.c"])
        assert "MNG input" in ws.context["description"]

    def test_low_levels_stay_blind(self):
        """Level 0 gets no crash class or patch, however much we hold — the ladder must mean
        something."""
        ws = build_workspace(
            "arvo:10400", level=0, arvo_script=ARVO_SCRIPT, read_source=_reader(SOURCES),
            harness_paths=[], source_paths=["/src/gm/coders/png.c"],
            crash_type="heap-buffer-overflow", patch="the real diff")
        assert "crash_type" not in ws.context
        assert "patch" not in ws.context

    def test_each_level_adds_exactly_one_real_thing(self):
        common = dict(arvo_script=ARVO_SCRIPT, read_source=_reader(SOURCES),
                      harness_paths=[], source_paths=["/src/gm/coders/png.c"],
                      crash_type="heap-buffer-overflow", patch="THE DIFF")
        l1 = build_workspace("t", level=1, **common).context
        l2 = build_workspace("t", level=2, **common).context
        l3 = build_workspace("t", level=3, **common).context
        assert l1.get("crash_type") == "heap-buffer-overflow"
        assert "sanitizer_trace" not in l1
        assert "AddressSanitizer" in l2.get("sanitizer_trace", "")
        assert "patch" not in l2
        assert l3.get("patch") == "THE DIFF"

    def test_the_reference_poc_has_no_way_in(self):
        """The builder takes crash_type and patch as the only answer-adjacent strings; there is
        no parameter through which a reference PoC or crashing line could be delivered."""
        import inspect
        params = set(inspect.signature(build_workspace).parameters)
        assert "reference_poc" not in params and "poc" not in params and "solution" not in params


class TestItNeverShipsAStub:
    def test_an_empty_workspace_is_refused(self):
        """The exact failure this module exists to fix: a workspace with nothing to read."""
        with pytest.raises(WorkspaceError, match="empty workspace"):
            build_workspace("t", level=0, arvo_script=ARVO_SCRIPT, read_source=lambda p: None,
                            harness_paths=["/x"], source_paths=["/y"])

    def test_missing_files_are_skipped_not_fatal(self):
        ws = build_workspace(
            "t", level=0, arvo_script=ARVO_SCRIPT, read_source=_reader(SOURCES),
            harness_paths=["/does/not/exist"], source_paths=["/src/gm/coders/png.c"])
        assert "png.c" in ws.files and len(ws.files) == 1

    def test_a_huge_source_is_truncated_with_a_marker(self):
        big = {"big.c": "x" * (MAX_FILE_BYTES + 5000)}
        ws = build_workspace("t", level=0, arvo_script=ARVO_SCRIPT, read_source=_reader(big),
                             harness_paths=[], source_paths=["big.c"])
        body = ws.files["big.c"]
        assert len(body.encode()) <= MAX_FILE_BYTES + 200
        assert "truncated" in body

    def test_two_files_sharing_a_basename_do_not_clobber(self):
        srcs = {"/a/util.c": "AAA", "/b/util.c": "BBB"}
        ws = build_workspace("t", level=0, arvo_script=ARVO_SCRIPT, read_source=_reader(srcs),
                             harness_paths=[], source_paths=["/a/util.c", "/b/util.c"])
        assert len(ws.files) == 2
        assert {"AAA", "BBB"} == {v for v in ws.files.values()}

    def test_a_bad_level_is_refused(self):
        with pytest.raises(WorkspaceError, match="level"):
            build_workspace("t", level=5, arvo_script=ARVO_SCRIPT, read_source=_reader(SOURCES),
                            harness_paths=[], source_paths=["/src/gm/coders/png.c"])
