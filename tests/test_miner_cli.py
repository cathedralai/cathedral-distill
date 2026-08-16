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
    assert mc.agent_message("5M", 7) == be.agent_message("5M", 7)
    assert (mc.agent_bundle_message("finney", 39, 7, "5M", "sha256:aa")
            == be.agent_bundle_message("finney", 39, 7, "5M", "sha256:aa"))


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


def _signed_agent_response(bundle=b"def solve_tasks(t):\n    return []\n", *, network="finney",
                           netuid=39, round_id=7, miner="5M"):
    """Build a genuine /v1/agent response: an Ed25519 key signs the round-bound bundle message."""
    import base64
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    digest = "sha256:" + hashlib.sha256(bundle).hexdigest()
    msg = mc.agent_bundle_message(network, netuid, round_id, miner, digest)
    return {
        "miner_hotkey": miner, "harness_digest": digest, "network": network, "netuid": netuid,
        "round_id": round_id, "harness_bundle": base64.b64encode(bundle).decode(),
        "backend_signature": key.sign(msg).hex(),
        "public_key_base64": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
    }


def _mc_verify(resp, trusted=None, expect_round=None, expect_miner=None):
    return mc._verify_signed_agent(
        resp, trusted if trusted is not None else resp["public_key_base64"],
        expect_round=expect_round if expect_round is not None else resp["round_id"],
        expect_miner=expect_miner if expect_miner is not None else resp["miner_hotkey"])


def test_verify_signed_agent_accepts_a_valid_response():
    pytest.importorskip("cryptography")
    blob = _mc_verify(_signed_agent_response())
    assert blob.startswith(b"def solve_tasks")               # returns the raw bundle bytes


def test_verify_signed_agent_rejects_a_tampered_bundle():
    pytest.importorskip("cryptography")
    import base64
    resp = _signed_agent_response()
    resp["harness_bundle"] = base64.b64encode(b"def solve_tasks(t):\n    return [1]\n").decode()
    with pytest.raises(mc.MinerCliError):                     # digest no longer matches
        _mc_verify(resp)


def test_verify_signed_agent_rejects_a_bad_signature():
    pytest.importorskip("cryptography")
    resp = _signed_agent_response()
    resp["backend_signature"] = "00" * 64                    # wrong signature
    with pytest.raises(mc.MinerCliError):
        _mc_verify(resp)


def test_verify_signed_agent_rejects_a_substituted_pubkey():
    """A genuinely self-consistent artifact whose key is NOT the trusted producer key is refused —
    verification is anchored to the trusted key, not the artifact's own embedded key."""
    pytest.importorskip("cryptography")
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    other = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
    with pytest.raises(mc.MinerCliError):
        _mc_verify(_signed_agent_response(), trusted=other)


def test_verify_signed_agent_rejects_a_replayed_round():
    """A genuinely-signed artifact for a DIFFERENT round than expected is refused (anti-replay is
    anchored to the caller's expected round, not the artifact's own round_id)."""
    pytest.importorskip("cryptography")
    resp = _signed_agent_response(round_id=7)                 # validly signed for round 7
    with pytest.raises(mc.MinerCliError):
        _mc_verify(resp, expect_round=8)                     # but the miner expects round 8


def test_verify_signed_agent_rejects_a_missing_field():
    pytest.importorskip("cryptography")
    resp = _signed_agent_response()
    del resp["backend_signature"]
    with pytest.raises(mc.MinerCliError):                     # clean reject, not a KeyError crash
        _mc_verify(resp)


def test_verify_signed_agent_rejects_a_different_miner():
    """A genuinely-signed bundle for a DIFFERENT miner (same round + trusted key) is refused —
    verification is anchored to your own hotkey."""
    pytest.importorskip("cryptography")
    with pytest.raises(mc.MinerCliError):
        _mc_verify(_signed_agent_response(), expect_miner="5SomeoneElse")


def test_verify_signed_agent_rejects_a_non_numeric_round():
    """A present-but-non-numeric round_id is a clean MinerCliError, not a raw ValueError crash."""
    pytest.importorskip("cryptography")
    resp = _signed_agent_response()
    resp["round_id"] = "not-an-int"
    with pytest.raises(mc.MinerCliError):
        _mc_verify(resp, expect_round=7)
