"""The intake runbook is copy-pasteable, so its strings are held to the code.

`docs/CYBERGYM_SCORE_INTAKE_RUNBOOK.md` is the document an operator follows while
wiring a real producer to a real validator. Everything in it that a reader would
copy — a command flag, the signature header, the body cap — is a cross-repo
contract string, and the failure mode of drift is not a confusing sentence: it is
a flag that no longer exists, or a header the intake does not read, discovered
while a live lane is burning its share.

`test_doc_contract_strings.py` already holds schema identifiers to the package
for the same reason. This file does the narrower job for the one doc whose whole
purpose is to be executed verbatim.

Prose is not checked. Only the strings a reader would copy.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from cathedral_distill.cybergym_score_report import MAX_BODY_BYTES, body_hmac
from cathedral_distill.operator_cli import build_parser

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "CYBERGYM_SCORE_INTAKE_RUNBOOK.md"
REPORT_SOURCE = ROOT / "cathedral_distill" / "cybergym_score_report.py"

SIGNATURE_HEADER = "X-Cathedral-Cybergym-Signature"

# A fenced block, and the flags used inside one invocation of a subcommand.
_FENCE = re.compile(r"```bash\n(.*?)```", re.DOTALL)
_FLAG = re.compile(r"--[a-z0-9][a-z0-9-]*")


def _runbook() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


def _subcommand_options() -> dict[str, set[str]]:
    """Every long option each `cathedral-cybergym` subcommand actually accepts."""
    options: dict[str, set[str]] = {}
    for action in build_parser()._subparsers._group_actions:  # noqa: SLF001
        for name, sub in action.choices.items():
            options[name] = {
                opt
                for sub_action in sub._actions  # noqa: SLF001
                for opt in sub_action.option_strings
                if opt.startswith("--")
            }
    return options


def _documented_invocations() -> list[tuple[str, set[str]]]:
    """`(subcommand, flags)` for each invocation in the runbook's shell blocks."""
    invocations: list[tuple[str, set[str]]] = []
    for block in _FENCE.findall(_runbook()):
        # One invocation per `cathedral-cybergym <sub>`; line continuations keep
        # the rest of the invocation in the same chunk.
        chunks = block.split("cathedral-cybergym ")[1:]
        for chunk in chunks:
            name = chunk.split()[0]
            invocations.append((name, set(_FLAG.findall(chunk))))
    return invocations


def test_the_runbook_documents_both_operator_commands():
    """Guard the guard: an extraction that finds nothing passes everything below."""
    names = {name for name, _ in _documented_invocations()}
    assert names == {"export-scores", "publish-scores"}, (
        "the runbook no longer shows both halves of the handoff; freezing and "
        f"publishing are separate operations and both must be shown, got {names}"
    )


@pytest.mark.parametrize("index", range(2))
def test_every_documented_flag_is_a_real_flag(index):
    """A flag the CLI does not accept is an instruction that exits non-zero."""
    options = _subcommand_options()
    name, flags = _documented_invocations()[index]
    assert name in options, f"the runbook invokes an unknown subcommand {name!r}"
    unknown = sorted(flags - options[name])
    assert not unknown, (
        f"docs/CYBERGYM_SCORE_INTAKE_RUNBOOK.md passes {unknown} to "
        f"`cathedral-cybergym {name}`, which does not accept them"
    )


def test_the_runbook_names_the_signature_header_the_publisher_sends():
    """One header name, stated in the doc and used by the code that posts."""
    assert SIGNATURE_HEADER in REPORT_SOURCE.read_text(encoding="utf-8"), (
        f"{SIGNATURE_HEADER} is no longer the header publish_score_report sends; "
        "the runbook's transport section is now wrong"
    )
    assert SIGNATURE_HEADER in _runbook()


def test_the_runbook_states_the_prefixed_hex_signature_form():
    """`sha256=<hex>`: the intake strips exactly that prefix before comparing."""
    signature = body_hmac(b"{}", "secret")
    assert signature.startswith("sha256=")
    assert len(signature) == len("sha256=") + 64
    assert "sha256=<hex>" in _runbook(), (
        "the runbook no longer shows the signature's wire form, which is the one "
        "detail a reimplementing producer gets wrong"
    )


def test_the_runbook_states_the_real_body_cap():
    """The cap is enforced on both sides; a wrong number sends a doomed report."""
    grouped = f"{MAX_BODY_BYTES:,}".replace(",", " ")
    assert grouped in _runbook(), (
        f"the runbook does not state the {MAX_BODY_BYTES}-byte intake body cap, "
        "so an operator cannot tell a too-large epoch from a transport fault"
    )
