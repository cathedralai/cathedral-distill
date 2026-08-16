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


def agent_bundle_message(network: str, netuid: int, round_id: int, miner_hotkey: str,
                         harness_digest: str) -> bytes:
    # byte-identical to the backend: the bytes the BACKEND signs (Ed25519) to attest the exact
    # approved bundle it serves. harness_digest content-addresses the bundle; (network, netuid,
    # round) bind it so the attestation cannot be replayed onto another round or subnet. The miner
    # rebuilds these bytes to VERIFY the served bundle before running it.
    return (f"cybergym:agent-bundle:{network}:{netuid}:{round_id}:{miner_hotkey}:"
            f"{harness_digest}").encode()


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


# --------------------------------------------------------------------------- backend-signature verify
def _ed25519_verify(public_key_base64: str, signature_hex: str, message: bytes) -> None:
    """Fail-closed Ed25519 verify — raises MinerCliError on ANY failure (bad signature, malformed
    key/sig, or no crypto lib). NEVER warn-and-continue: a bad backend signature must stop the miner
    from running an unattested agent."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as exc:                                        # pragma: no cover
        raise MinerCliError("cryptography is required to verify the backend signature "
                            "(pip install cryptography)") from exc
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_base64))
        pub.verify(bytes.fromhex(signature_hex), message)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise MinerCliError(f"backend signature did NOT verify: {exc}") from exc


def _verify_signed_agent(resp: dict, trusted_pubkey: str, *, expect_round: int,
                         expect_miner: str) -> bytes:
    """Fail-closed check of a /v1/agent response, ANCHORED to a trusted producer pubkey (pinned or
    TOFU-fetched by the caller), an EXPECTED round, and YOUR OWN hotkey — NOT to values the artifact
    carries about itself. Enforces: the response's pubkey IS the trusted one; it is for YOU and THIS
    round; the served bytes hash to the claimed digest; and the backend's Ed25519 signature verifies
    over the round-bound message USING THE TRUSTED KEY. Returns the raw agent-bundle bytes. Every
    failure — including a missing/malformed/non-numeric field — raises MinerCliError; NEVER
    warn-and-continue, so a substituted, cross-miner, or replayed bundle can never reach the run."""
    try:
        digest, sig = resp["harness_digest"], resp["backend_signature"]
        pubkey, miner = resp["public_key_base64"], resp["miner_hotkey"]
        network, netuid = resp["network"], resp["netuid"]
        round_id = int(resp["round_id"])
        blob = base64.b64decode(resp["harness_bundle"], validate=True)
    except (KeyError, TypeError, ValueError, __import__("binascii").Error) as exc:
        raise MinerCliError(f"malformed signed-agent response ({exc})") from exc
    if pubkey != trusted_pubkey:
        raise MinerCliError("agent bundle signed by a key that is NOT the trusted backend producer "
                            "key — refusing (possible substitution)")
    if miner != expect_miner:
        raise MinerCliError(f"agent bundle is for miner {miner}, not you ({expect_miner}) — refusing")
    if round_id != int(expect_round):
        raise MinerCliError(f"agent bundle is for round {round_id}, not the expected {expect_round} "
                            "(stale or replayed) — refusing")
    got = "sha256:" + hashlib.sha256(blob).hexdigest()
    if got != digest:
        raise MinerCliError(f"served bundle digest {got} != claimed {digest}")
    # verify against the TRUSTED key (not the pubkey embedded in the artifact) over the round-bound msg
    _ed25519_verify(trusted_pubkey, sig, agent_bundle_message(network, netuid, round_id, miner, digest))
    return blob


def _trusted_pubkey(base: str) -> str:
    """The backend producer pubkey (base64) to ANCHOR trust: PINNED via CYBERGYM_PRODUCER_PUBKEY if
    set (recommended for production — a MITM cannot substitute a key), else fetched from /v1/pubkey
    (trust-on-first-use, with a warning)."""
    pinned = os.environ.get("CYBERGYM_PRODUCER_PUBKEY", "").strip()
    if pinned:
        return pinned
    doc = _http(f"{base}/v1/pubkey", None)
    print("note: trusting the backend pubkey fetched from /v1/pubkey (trust-on-first-use); set "
          "CYBERGYM_PRODUCER_PUBKEY to pin it.", file=sys.stderr)
    return doc["public_key_base64"]


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
    """Draw this round's sealed task set and download your own backend-SIGNED agent bundle, verifying
    the backend's signature over it before saving."""
    import json
    from urllib.parse import urlencode
    base = _require("CYBERGYM_DISPATCH_URL", args.dispatch_url).rstrip("/")
    hotkey, seed = _require("MINER_HOTKEY", args.miner), _require("MINER_HOTKEY_SEED")
    round_id = _current_round(base)
    tasks = _http(f"{base}/v1/task", {
        "miner_hotkey": hotkey, "round_id": round_id,
        "signature": sign(seed, task_message(hotkey, round_id))})
    out = Path(args.out or "dispatch.json")
    out.write_text(json.dumps(tasks, indent=2))

    # download OUR OWN backend-signed agent (owner-only GET, authenticated by the hotkey sig), then
    # ANCHOR trust in the backend pubkey (pinned or TOFU) and VERIFY the signature + digest.
    query = urlencode({"miner_hotkey": hotkey,
                       "signature": sign(seed, agent_message(hotkey, round_id))})
    agent = _http(f"{base}/v1/agent?{query}", None)
    # fail-closed: anchored to the trusted producer key, YOU, and THIS round (not the artifact's claims)
    _verify_signed_agent(agent, _trusted_pubkey(base), expect_round=round_id, expect_miner=hotkey)
    agent_out = Path(args.agent_out or "signed_agent.json")
    agent_out.write_text(json.dumps(agent, indent=2))
    print(f"dispatched round {round_id}: {len(tasks.get('tasks', []))} tasks -> {out}. "
          f"downloaded + VERIFIED your backend-signed agent {agent['harness_digest'][:19]}… "
          f"-> {agent_out}.")
    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    """VERIFY the backend-signed agent, then run it and stream its PoCs hash-chained. This phase wires
    the fail-closed verification; running the agent + the hash-chain + the 1 h limit is phase 5."""
    import json
    art = Path(args.signed_agent)
    if not art.is_file():
        raise MinerCliError(f"signed agent artifact not found: {art} (run `dispatch` first)")
    try:
        resp = json.loads(art.read_text())
    except ValueError as exc:
        raise MinerCliError(f"{art} is not the signed-agent JSON from dispatch: {exc}") from exc
    # fail-closed BEFORE any run, RE-ANCHORED here (not trusting the artifact's own key/round): the
    # bundle must be signed by the trusted producer key, be for THIS round, and hash to its digest —
    # never run an agent the backend did not sign for you this round (catches a tampered/substituted
    # signed_agent.json between dispatch and submit).
    base = _require("CYBERGYM_DISPATCH_URL", args.dispatch_url).rstrip("/")
    hotkey = _require("MINER_HOTKEY", args.miner)
    _verify_signed_agent(resp, _trusted_pubkey(base), expect_round=_current_round(base),
                         expect_miner=hotkey)
    print(f"verified backend-signed agent {resp['harness_digest'][:19]}… "
          "Running it and streaming one hash-chained PoC at a time (with the 1 h limit) lands in "
          "phase 5.")
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
    p_dis.add_argument("--agent-out", help="where to write the verified signed agent "
                       "(default: signed_agent.json)")
    p_dis.set_defaults(func=cmd_dispatch)

    p_sub = sub.add_parser("submit", help="verify + run your signed agent and stream hash-chained PoCs")
    p_sub.add_argument("signed_agent", help="the signed_agent.json artifact from dispatch")
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
