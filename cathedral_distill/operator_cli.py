"""Operator tooling to mint and sign the anchored trust artifacts.

The verification path resolves receipts and configs through a signed key registry
and trusted roots (`receipt_keys`, `signed_config`), but the signing primitives
(`sign_key_registry`, `sign_config`) were library-only — there was no way for an
operator to actually produce them. This is that CLI:

    cathedral-cybergym keygen       --seed-out root.key --public-out root.pub
    cathedral-cybergym sign-registry --in registry.json --root-seed root.key --out registry.signed.json
    cathedral-cybergym sign-config   --in burn.json      --seed issuer.key   --out burn.signed.json
    cathedral-cybergym export-scores --score-db scores.sqlite --epoch 42 \
        --network finney --netuid 39 --producer-hotkey 5Producer --out epoch-42.json
    cathedral-cybergym publish-scores --report epoch-42.json \
        --url https://publisher.example/v1/cybergym/scores \
        --token-file intake.token --hmac-secret-file intake.hmac \
        --proof-out epoch-42.proof.json

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
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill import receipt_keys as rk
from cathedral_distill import signed_config as sc
from cathedral_distill.cybergym_score_report import (
    MAX_BODY_BYTES,
    CyberGymScoreReportError,
    body_hmac,
    build_score_report,
    canonical_report_bytes,
    publish_score_report,
    report_digest,
)
from cathedral_distill.cybergym_scores import CyberGymScoreError, CyberGymScoreStore


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


def _write_frozen(data: bytes, path: str) -> bool:
    """Create an immutable-by-convention artifact; never replace different bytes."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        try:
            current = Path(path).read_bytes()
        except OSError as exc:
            raise OperatorError(f"cannot read existing artifact {path!r}: {exc}") from exc
        if current != data:
            raise OperatorError(
                f"refusing to replace {path!r}: it contains a different frozen report"
            )
        return False
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
    except OSError as exc:
        raise OperatorError(f"cannot write frozen artifact {path!r}: {exc}") from exc
    finally:
        os.close(fd)
    return True


def _read_private_text(path: str, *, label: str) -> str:
    """Read an owner-only regular file without following a final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise OperatorError(f"cannot read {label} file {path!r}: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OperatorError(f"{label} file {path!r} is not a regular file")
        if info.st_uid != os.geteuid():
            raise OperatorError(f"{label} file {path!r} is not owned by this user")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise OperatorError(
                f"{label} file {path!r} must not be readable or writable by group/other"
            )
        chunks = []
        remaining = 16_385
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if len(raw) > 16_384:
        raise OperatorError(f"{label} file {path!r} exceeds 16384 bytes")
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise OperatorError(f"{label} file {path!r} is not UTF-8") from exc
    if not value:
        raise OperatorError(f"{label} file {path!r} is empty")
    return value


def _read_frozen_report(path: str) -> bytes:
    try:
        body = Path(path).read_bytes()
    except OSError as exc:
        raise OperatorError(f"cannot read score report {path!r}: {exc}") from exc
    if not body or len(body) > MAX_BODY_BYTES:
        raise OperatorError(
            f"score report must contain 1..{MAX_BODY_BYTES} bytes"
        )
    try:
        document = json.loads(body)
        canonical = canonical_report_bytes(document)
    except (ValueError, UnicodeDecodeError, CyberGymScoreReportError) as exc:
        raise OperatorError(f"score report {path!r} is invalid: {exc}") from exc
    if body != canonical:
        raise OperatorError(
            f"score report {path!r} is not the canonical frozen byte representation"
        )
    return body


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


def cmd_export_scores(args: argparse.Namespace) -> int:
    """Freeze one durably closed score epoch into Cathedral's wire contract."""
    score_db = Path(args.score_db)
    if not score_db.is_file():
        raise OperatorError(
            f"score database {args.score_db!r} does not exist; refusing to create it"
        )
    store = CyberGymScoreStore(str(score_db))
    try:
        report = build_score_report(
            store,
            network=args.network,
            netuid=args.netuid,
            source_epoch=args.epoch,
            producer_hotkey=args.producer_hotkey,
        )
        body = canonical_report_bytes(report)
    except (CyberGymScoreError, CyberGymScoreReportError) as exc:
        raise OperatorError(str(exc)) from exc
    finally:
        store.close()
    created = _write_frozen(body, args.out)
    action = "wrote" if created else "reused byte-identical"
    sys.stderr.write(
        f"{action} closed CyberGym epoch {args.epoch} report at {args.out}; "
        f"scores={len(report['scores'])} report_sha256={report_digest(report)}\n"
    )
    return 0


def cmd_publish_scores(args: argparse.Namespace) -> int:
    """Authenticate and send one exact frozen report to Cathedral's intake."""
    body = _read_frozen_report(args.report)
    token = _read_private_text(args.token_file, label="bearer token")
    secret = _read_private_text(args.hmac_secret_file, label="HMAC secret")
    signature = body_hmac(body, secret)
    try:
        result = publish_score_report(
            body,
            url=args.url,
            bearer_token=token,
            hmac_secret=secret,
            timeout_seconds=args.timeout,
        )
    except CyberGymScoreReportError as exc:
        raise OperatorError(str(exc)) from exc
    proof = json.dumps(
        {"body": body.decode("utf-8"), "signature": signature},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    created = _write_frozen(proof, args.proof_out)
    action = "wrote" if created else "reused byte-identical"
    sys.stderr.write(
        f"{action} accepted CyberGym epoch proof at {args.proof_out}\n"
    )
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cathedral-cybergym",
        description="Create anchored trust artifacts and durable SN39 score handoffs.",
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

    p_export = sub.add_parser(
        "export-scores",
        help="freeze one durably closed CyberGym epoch as a canonical score report",
    )
    p_export.add_argument("--score-db", required=True, help="CyberGym score SQLite file")
    p_export.add_argument("--epoch", required=True, type=int, help="closed source epoch")
    p_export.add_argument("--network", required=True, help="target Bittensor network")
    p_export.add_argument("--netuid", required=True, type=int, help="target subnet uid")
    p_export.add_argument(
        "--producer-hotkey", required=True, help="configured producer validator hotkey"
    )
    p_export.add_argument(
        "--out", required=True, help="fresh or byte-identical frozen report path"
    )
    p_export.set_defaults(func=cmd_export_scores)

    p_publish = sub.add_parser(
        "publish-scores",
        help="POST one frozen score report to Cathedral's authenticated intake",
    )
    p_publish.add_argument("--report", required=True, help="canonical frozen report")
    p_publish.add_argument(
        "--url", required=True, help="full /v1/cybergym/scores HTTPS endpoint"
    )
    p_publish.add_argument(
        "--token-file", required=True, help="owner-only bearer-token file"
    )
    p_publish.add_argument(
        "--hmac-secret-file", required=True, help="owner-only HMAC-secret file"
    )
    p_publish.add_argument(
        "--proof-out",
        required=True,
        help="fresh or byte-identical accepted {body,signature} proof path",
    )
    p_publish.add_argument(
        "--timeout", type=float, default=15.0, help="request timeout in seconds"
    )
    p_publish.set_defaults(func=cmd_publish_scores)

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
