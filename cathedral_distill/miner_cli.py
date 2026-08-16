"""``cathedral-distill`` — the CyberGym miner CLI (the mining path in three subcommands).

    cathedral-distill register-agent AGENT.zip   upload your agent (code + a .env naming your
                                                 official-provider model/base_url); <20 MB, checked
                                                 before it uploads
    cathedral-distill dispatch                   download your own signed agent + sealed task set
    cathedral-distill submit  SIGNED_AGENT.zip   run the signed agent; stream one PoC at a time,
                                                 hash-chained            [building — phases 4/5]

Config comes from the environment or a local ``.env`` (loaded if present):
``CYBERGYM_DISPATCH_URL`` (the subnet endpoint), ``MINER_HOTKEY``/``MINER_HOTKEY_SEED``, and — for
submit — ``AGENT_API_KEY`` / ``CATHEDRAL_API_KEY``. The declared model + base_url are read from the
agent zip's own ``.env`` (or ``--model`` / ``--base-url``), so what you register is what the agent runs.

This is the miner side of the wire; the register/task/submit messages here are byte-identical to the
backend's canonical signing contract (a test pins the register message).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import os
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

#: An agent bundle over this is rejected LOCALLY, before any upload — the miner is told at once.
MAX_AGENT_BYTES = 20 * 1024 * 1024  # 20 MB


class MinerCliError(Exception):
    """A miner-side error with a message meant for the operator, not a stack trace."""


# --------------------------------------------------------------------------- signing (sr25519 hotkey)
# The canonical wire messages — byte-identical to the backend's signing contract. Each is bound to
# the round so a signature cannot be replayed into a later one.
def register_message(miner_hotkey: str, harness_digest: str, round_id: int,
                     base_url: str = "", model: str = "",
                     agent_name: str = "", version: str = "") -> bytes:
    # byte-identical to the backend: the signature commits the declared inference (base_url, model)
    # AND the agent identity (agent_name, version) as a FIXED 4-field suffix (empties kept), present
    # only when at least one is declared, so what you register is what the dashboard shows.
    base = f"cybergym:register:{miner_hotkey}:{harness_digest}:{round_id}"
    fields = [base_url.strip(), model.strip(), agent_name.strip(), version.strip()]
    return (base + ":" + ":".join(fields)).encode() if any(fields) else base.encode()


def task_message(miner_hotkey: str, round_id: int) -> bytes:
    return f"cybergym:task:{miner_hotkey}:{round_id}".encode()


def agent_message(miner_hotkey: str, round_id: int) -> bytes:
    return f"cybergym:agent-download:{miner_hotkey}:{round_id}".encode()


def submit_message(batch_id: str, task_id: str, miner_hotkey: str, poc_sha256: str) -> bytes:
    return f"cybergym:submit:{batch_id}:{task_id}:{miner_hotkey}:{poc_sha256}".encode()


def _keypair_cls():
    for mod in ("substrateinterface", "bittensor_wallet", "bittensor"):
        try:
            return getattr(__import__(mod, fromlist=["Keypair"]), "Keypair")
        except Exception:
            continue
    raise MinerCliError(
        "no sr25519 Keypair library — pip install substrate-interface (or bittensor-wallet) to sign "
        "as your hotkey")


def sign(secret_seed: str, message: bytes) -> str:
    return _keypair_cls().create_from_seed(secret_seed).sign(message).hex()


# --------------------------------------------------------------------------- config + HTTP
def load_dotenv(path: str = ".env") -> None:
    """Load ``KEY=VALUE`` lines from a local .env into the environment (without overriding what is
    already set), so a miner can keep its endpoint + hotkey seed + API keys in one file."""
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _require(name: str, arg_value: str | None = None) -> str:
    value = arg_value or os.environ.get(name)
    if not value:
        raise MinerCliError(f"{name} is required (set it in the environment, your .env, or the flag)")
    return value


def _http(url: str, payload: dict | None) -> dict:
    data = None if payload is None else __import__("json").dumps(payload).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"content-type": "application/json"} if data else {},
                                 method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            body = r.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise MinerCliError(f"{url} -> HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise MinerCliError(f"cannot reach {url}: {exc.reason}") from exc
    import json
    return json.loads(body) if body else {}


def _current_round(base: str) -> int:
    return int(_http(f"{base.rstrip('/')}/v1/round", None)["round_id"])


#: Max length of the declared identity fields (agent_name, version) — mirrors the backend.
MAX_IDENTITY_LEN = 64


def _clean_identity(value: str, field: str) -> str:
    """Normalise + bound a declared identity field, mirroring the backend so the value the miner
    signs is the value the backend accepts (rejected locally BEFORE any upload)."""
    v = (value or "").strip()
    if len(v) > MAX_IDENTITY_LEN:
        raise MinerCliError(f"{field} exceeds {MAX_IDENTITY_LEN} characters")
    if any(ord(c) < 0x20 or c == ":" for c in v):
        raise MinerCliError(f"{field} must not contain control characters or ':'")
    return v


def _declared_from_zip(raw: bytes) -> dict[str, str]:
    """Read the agent's declared inference (model, base_url) + identity (agent_name, version) from a
    ``.env`` inside the zip, so what is registered is exactly what the agent will run. Missing keys
    come back ''."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise MinerCliError(f"agent is not a valid zip: {exc}") from exc
    out = {"model": "", "base_url": "", "agent_name": "", "version": ""}
    name = next((n for n in zf.namelist() if Path(n).name == ".env"), None)
    if name is None:
        return out
    for line in zf.read(name).decode("utf-8", "replace").splitlines():
        k, _, v = line.strip().partition("=")
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k in ("AGENT_MODEL", "MODEL"):
            out["model"] = v
        elif k in ("AGENT_BASE_URL", "BASE_URL", "AGENT_API_BASE"):
            out["base_url"] = v
        elif k in ("AGENT_NAME", "NAME"):
            out["agent_name"] = v
        elif k in ("AGENT_VERSION", "VERSION"):
            out["version"] = v
    return out


# --------------------------------------------------------------------------- subcommands
def cmd_register_agent(args: argparse.Namespace) -> int:
    """Upload the agent bundle for this round. Size is checked BEFORE the upload."""
    zip_path = Path(args.agent_zip)
    if not zip_path.is_file():
        raise MinerCliError(f"agent zip not found: {zip_path}")
    raw = zip_path.read_bytes()
    if len(raw) > MAX_AGENT_BYTES:
        raise MinerCliError(
            f"agent is {len(raw)/1e6:.1f} MB, over the {MAX_AGENT_BYTES//(1024*1024)} MB limit — "
            "trim it before uploading (nothing was sent)")
    harness_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    declared = _declared_from_zip(raw)
    base_url = args.base_url or declared["base_url"] or os.environ.get("AGENT_BASE_URL", "")
    model = args.model or declared["model"] or os.environ.get("AGENT_MODEL", "")
    if not (base_url and model):
        raise MinerCliError("declare your model — put AGENT_MODEL + AGENT_BASE_URL in the agent's "
                            ".env, or pass --model/--base-url (must be an official provider)")
    # the agent's dashboard identity — optional, but if given it is signed + shown next to your UID.
    # Validated locally (same rules as the backend) so a bad label is caught before any upload.
    agent_name = _clean_identity(args.agent_name or declared["agent_name"], "agent_name")
    version = _clean_identity(args.version or declared["version"], "version")

    base = _require("CYBERGYM_DISPATCH_URL", args.dispatch_url).rstrip("/")
    hotkey, seed = _require("MINER_HOTKEY", args.miner), _require("MINER_HOTKEY_SEED")
    round_id = _current_round(base)
    signature = sign(seed, register_message(hotkey, harness_digest, round_id, base_url, model,
                                            agent_name, version))
    resp = _http(f"{base}/v1/register", {
        "miner_hotkey": hotkey, "harness_digest": harness_digest, "round_id": round_id,
        "harness_bundle": base64.b64encode(raw).decode(), "model": model, "base_url": base_url,
        "agent_name": agent_name, "version": version, "signature": signature})
    label = f" {agent_name} {version}".rstrip() if agent_name else ""
    print(f"registered agent{label} {harness_digest[:19]}… for round {round_id}: "
          f"model={model} ({resp.get('inference', {}).get('provider', '?')}), "
          f"signed={resp.get('signed')}, screen_state={resp.get('screen_state')}. "
          "The approve/reject verdict will show on the dashboard.")
    return 0


def cmd_dispatch(args: argparse.Namespace) -> int:
    """Draw this round's sealed task set and download your own (signed) agent bundle."""
    base = _require("CYBERGYM_DISPATCH_URL", args.dispatch_url).rstrip("/")
    hotkey, seed = _require("MINER_HOTKEY", args.miner), _require("MINER_HOTKEY_SEED")
    round_id = _current_round(base)
    tasks = _http(f"{base}/v1/task", {
        "miner_hotkey": hotkey, "round_id": round_id,
        "signature": sign(seed, task_message(hotkey, round_id))})
    out = Path(args.out or "dispatch.json")
    import json
    out.write_text(json.dumps(tasks, indent=2))
    print(f"dispatched round {round_id}: {len(tasks.get('tasks', []))} tasks -> {out}. "
          "(downloading the backend-SIGNED agent bundle lands in phase 4.)")
    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    """Run the signed agent and stream its PoCs, each hash-chained. (phases 4/5 wire the signature
    verification, the run, and the hash-chain; this validates the bundle you point it at.)"""
    signed = Path(args.signed_agent)
    if not signed.is_file():
        raise MinerCliError(f"signed agent not found: {signed}")
    agent_hash = "sha256:" + hashlib.sha256(signed.read_bytes()).hexdigest()
    print(f"signed agent {agent_hash[:19]}… ready. Running the agent and streaming one hash-chained "
          "PoC at a time (with the 1 h limit) lands in phases 4/5.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cathedral-distill", description="CyberGym miner: register an agent, dispatch, submit.")
    parser.add_argument("--env-file", default=".env", help="config file to load (default: .env)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_reg = sub.add_parser("register-agent", help="upload your agent bundle for this round (<20 MB)")
    p_reg.add_argument("agent_zip", help="path to your agent zip (code + a .env naming model/base_url)")
    p_reg.add_argument("--dispatch-url", help="subnet endpoint (or CYBERGYM_DISPATCH_URL)")
    p_reg.add_argument("--miner", help="your hotkey ss58 (or MINER_HOTKEY)")
    p_reg.add_argument("--model", help="declared model id (else read from the zip's .env)")
    p_reg.add_argument("--base-url", help="declared official-provider base_url (else the zip's .env)")
    p_reg.add_argument("--agent-name", help="a name for your agent, shown on the dashboard "
                       "(else AGENT_NAME in the zip's .env; optional)")
    p_reg.add_argument("--version", help="your agent's version label, shown on the dashboard "
                       "(else AGENT_VERSION in the zip's .env; optional)")
    p_reg.set_defaults(func=cmd_register_agent)

    p_dis = sub.add_parser("dispatch", help="draw your sealed task set + your signed agent")
    p_dis.add_argument("--dispatch-url", help="subnet endpoint (or CYBERGYM_DISPATCH_URL)")
    p_dis.add_argument("--miner", help="your hotkey ss58 (or MINER_HOTKEY)")
    p_dis.add_argument("--out", help="where to write the dispatched set (default: dispatch.json)")
    p_dis.set_defaults(func=cmd_dispatch)

    p_sub = sub.add_parser("submit", help="run your signed agent and stream hash-chained PoCs")
    p_sub.add_argument("signed_agent", help="path to the backend-signed agent bundle from dispatch")
    p_sub.add_argument("--dispatch-url", help="subnet endpoint (or CYBERGYM_DISPATCH_URL)")
    p_sub.add_argument("--miner", help="your hotkey ss58 (or MINER_HOTKEY)")
    p_sub.set_defaults(func=cmd_submit)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    load_dotenv(getattr(args, "env_file", ".env"))
    try:
        return int(args.func(args))
    except MinerCliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
