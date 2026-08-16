"""cathedral-distill miner CLI: the wire-message contract (must match the backend byte-for-byte),
the local <20MB pre-reject, reading the declared model from the agent zip's .env, and subcommand wiring."""
from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import miner_cli as mc  # noqa: E402


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_register_message_matches_the_wire_contract():
    assert mc.register_message("5M", "sha256:aa", 7) == b"cybergym:register:5M:sha256:aa:7"
    # declaring inference but no identity keeps the identity slots as trailing empties (fixed suffix)
    assert (mc.register_message("5M", "sha256:aa", 7, "https://api.openai.com/v1", "gpt-5")
            == b"cybergym:register:5M:sha256:aa:7:https://api.openai.com/v1:gpt-5::")
    # the agent identity (agent_name, version) is bound in the last two slots
    assert (mc.register_message("5M", "sha256:aa", 7, "https://api.openai.com/v1", "gpt-5",
                                "crasher", "3.1")
            == b"cybergym:register:5M:sha256:aa:7:https://api.openai.com/v1:gpt-5:crasher:3.1")
    assert mc.task_message("5M", 7) == b"cybergym:task:5M:7"
    assert mc.submit_message("b", "t", "5M", "sha256:p") == b"cybergym:submit:b:t:5M:sha256:p"
    assert mc.agent_message("5M", 7) == b"cybergym:agent-download:5M:7"


def test_wire_messages_are_byte_identical_to_the_backend():
    """The public client and the private backend MUST build the same signed bytes, or every
    signature fails. Cross-checks against the sibling backend checkout when present."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "cathedral-cybergym-backend"))
    be = pytest.importorskip("cathedral_cybergym_backend.signing")
    for args in [("5M", "sha256:aa", 7),
                 ("5M", "sha256:aa", 7, "https://api.openai.com/v1", "gpt-5"),
                 ("5M", "sha256:aa", 7, "https://api.openai.com/v1", "gpt-5", "crasher", "3.1")]:
        assert mc.register_message(*args) == be.register_message(*args)
    assert mc.task_message("5M", 7) == be.task_message("5M", 7)
    assert mc.submit_message("b", "t", "5M", "sha256:p") == be.submit_message("b", "t", "5M", "sha256:p")


def test_oversize_agent_is_rejected_before_any_upload(tmp_path):
    big = tmp_path / "agent.zip"
    big.write_bytes(b"x" * (mc.MAX_AGENT_BYTES + 1))
    args = SimpleNamespace(agent_zip=str(big), dispatch_url="http://unused", miner="5M",
                           model=None, base_url=None)
    with pytest.raises(mc.MinerCliError) as e:
        mc.cmd_register_agent(args)          # must raise on size BEFORE touching the network
    assert "over the" in str(e.value) and "limit" in str(e.value)


def test_declared_inference_and_identity_are_read_from_the_agent_zip_env():
    raw = _zip({"agent.py": b"# solver\n",
                ".env": b'AGENT_MODEL=deepseek-v4-pro\nAGENT_BASE_URL="https://api.deepseek.com/v1"\n'
                        b'AGENT_NAME=crasher\nAGENT_VERSION=3.1\n'})
    assert mc._declared_from_zip(raw) == {
        "base_url": "https://api.deepseek.com/v1", "model": "deepseek-v4-pro",
        "agent_name": "crasher", "version": "3.1"}
    assert mc._declared_from_zip(_zip({"agent.py": b"x"})) == {   # no .env → nothing declared
        "base_url": "", "model": "", "agent_name": "", "version": ""}


def test_identity_with_a_colon_is_rejected_before_upload():
    import pytest
    with pytest.raises(mc.MinerCliError):
        mc._clean_identity("bad:name", "agent_name")   # ':' is the wire separator


def test_cli_wires_the_three_subcommands():
    p = mc.build_parser()
    assert p.parse_args(["register-agent", "a.zip"]).func is mc.cmd_register_agent
    assert p.parse_args(["dispatch"]).func is mc.cmd_dispatch
    assert p.parse_args(["submit", "a.zip"]).func is mc.cmd_submit


def test_dotenv_loads_without_overriding(monkeypatch, tmp_path):
    monkeypatch.setenv("MINER_HOTKEY", "already-set")
    (tmp_path / ".env").write_text('MINER_HOTKEY=from-file\nCYBERGYM_DISPATCH_URL=http://x\n# c\n')
    mc.load_dotenv(str(tmp_path / ".env"))
    import os
    assert os.environ["MINER_HOTKEY"] == "already-set"          # not overridden
    assert os.environ["CYBERGYM_DISPATCH_URL"] == "http://x"    # loaded
