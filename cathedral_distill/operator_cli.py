"""Operator tooling to mint and sign the anchored trust artifacts.

The verification path resolves receipts and configs through a signed key registry
and trusted roots (`receipt_keys`, `signed_config`), but the signing primitives
(`sign_key_registry`, `sign_config`) were library-only — there was no way for an
operator to actually produce them. This is that CLI:

    cathedral-cybergym keygen       --seed-out root.key --public-out root.pub
    cathedral-cybergym sign-registry --in registry.json --root-seed root.key --out registry.signed.json
    cathedral-cybergym sign-config   --in burn.json      --seed issuer.key   --out burn.signed.json

Private material discipline: a generated seed is written to a 0600 file and never
printed; seeds are read from files, never passed on the command line (where they
would leak into shell history and process listings). Every signed artifact is
self-checked before it is written, so a malformed input fails closed here rather
than at a validator.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill import receipt_keys as rk
from cathedral_distill import signed_config as sc


class OperatorError(RuntimeError):
    """A signing operation could not be completed. Fails closed."""


def _read_seed(path: str) -> bytes:
    try:
        seed = Path(path).read_bytes()
    except OSError as exc:
        raise OperatorError(f"cannot read key seed {path!r}: {exc}") from exc
    if len(seed) != 32:
        raise OperatorError(f"key seed {path!r} must be exactly 32 bytes, got {len(seed)}")
    return seed


def _read_json(path: str) -> dict:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise OperatorError(f"cannot read {path!r}: {exc}") from exc
    except ValueError as exc:
        raise OperatorError(f"{path!r} is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise OperatorError(f"{path!r} must be a JSON object")
    return doc


def _write_json(doc: dict, out: str | None) -> None:
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if out is None or out == "-":
        sys.stdout.write(text)
    else:
        Path(out).write_text(text, encoding="utf-8")


def _write_secret(data: bytes, path: str) -> None:
    """Write private key material to a fresh 0600 file (never world-readable)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def cmd_keygen(args: argparse.Namespace) -> int:
    """Generate an Ed25519 keypair. Seed -> 0600 file; public key -> stdout/file."""
    private = Ed25519PrivateKey.generate()
    _write_secret(private.private_bytes_raw(), args.seed_out)
    public_b64 = base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
    if args.public_out and args.public_out != "-":
        Path(args.public_out).write_text(public_b64 + "\n", encoding="utf-8")
    else:
        sys.stdout.write(public_b64 + "\n")
    sys.stderr.write(f"wrote private seed to {args.seed_out} (mode 0600) — keep it offline\n")
    return 0


def cmd_sign_registry(args: argparse.Namespace) -> int:
    """Sign an unsigned key-registry document with a trusted-root seed."""
    unsigned = _read_json(args.in_path)
    if unsigned.get("schema") != rk.REGISTRY_SCHEMA:
        raise OperatorError(f"registry schema must be {rk.REGISTRY_SCHEMA}")
    root_seed = _read_seed(args.root_seed)
    signed = rk.sign_key_registry(unsigned, root_seed)
    # Self-check: the signed registry must verify against this root before we emit it.
    root_id = str(signed["registry_key_id"])
    root_pub = Ed25519PrivateKey.from_private_bytes(root_seed).public_key().public_bytes_raw()
    try:
        rk.verify_key_registry(json.dumps(signed).encode(), {root_id: root_pub},
                               max_age_seconds=10 ** 12)
    except rk.ReceiptKeyError as exc:
        raise OperatorError(f"signed registry failed self-verification: {exc}") from exc
    _write_json(signed, args.out)
    return 0


def cmd_sign_config(args: argparse.Namespace) -> int:
    """Sign an unsigned burn or lane-allocation config with an issuer seed."""
    unsigned = _read_json(args.in_path)
    schema = unsigned.get("schema")
    if schema not in (sc.BURN_CONFIG_SCHEMA, sc.ALLOCATION_CONFIG_SCHEMA):
        raise OperatorError(
            f"config schema must be {sc.BURN_CONFIG_SCHEMA} or {sc.ALLOCATION_CONFIG_SCHEMA}"
        )
    seed = _read_seed(args.seed)
    try:
        signed = sc.sign_config(unsigned, seed)
    except sc.SignedConfigError as exc:
        raise OperatorError(str(exc)) from exc
    _write_json(signed, args.out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cathedral-cybergym",
        description="Mint and sign the anchored trust artifacts for the SN39 lanes.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen", help="generate an Ed25519 keypair")
    p_keygen.add_argument("--seed-out", required=True, help="path for the 32-byte private seed (0600)")
    p_keygen.add_argument("--public-out", help="path for the base64 public key (default: stdout)")
    p_keygen.set_defaults(func=cmd_keygen)

    p_reg = sub.add_parser("sign-registry", help="sign a key-registry document")
    p_reg.add_argument("--in", dest="in_path", required=True, help="unsigned registry JSON")
    p_reg.add_argument("--root-seed", required=True, help="trusted-root private seed file")
    p_reg.add_argument("--out", help="output path (default: stdout)")
    p_reg.set_defaults(func=cmd_sign_registry)

    p_cfg = sub.add_parser("sign-config", help="sign a burn or allocation config")
    p_cfg.add_argument("--in", dest="in_path", required=True, help="unsigned config JSON")
    p_cfg.add_argument("--seed", required=True, help="issuer signing private seed file")
    p_cfg.add_argument("--out", help="output path (default: stdout)")
    p_cfg.set_defaults(func=cmd_sign_config)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except OperatorError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
