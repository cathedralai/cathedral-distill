"""Operator signing CLI — mint a trusted root, sign a key registry, sign configs.

Proves the artifacts the CLI produces verify through the exact anchored-trust path
a validator uses (`verify_key_registry`, `verify_burn_config`,
`verify_allocation_config`), so an operator can actually stand up the trust the
whole scheme rests on.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import operator_cli as cli  # noqa: E402
from cathedral_distill import receipt_keys as rk  # noqa: E402
from cathedral_distill import signed_config as sc  # noqa: E402
from cathedral_distill.cybergym_scores import EPOCH_CLOSED, CyberGymScoreStore  # noqa: E402

NOW = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)


def _read_pub(path) -> bytes:
    return base64.b64decode(Path(path).read_text().strip())


def test_keygen_writes_a_0600_seed_and_a_public_key(tmp_path):
    seed = tmp_path / "root.key"
    pub = tmp_path / "root.pub"
    assert cli.main(["keygen", "--seed-out", str(seed), "--public-out", str(pub)]) == 0
    assert len(seed.read_bytes()) == 32
    assert len(_read_pub(pub)) == 32
    # the seed file must not be world/group readable
    mode = stat.S_IMODE(os.stat(seed).st_mode)
    assert mode & 0o077 == 0


def _keygen(tmp_path, name) -> tuple[Path, bytes]:
    seed = tmp_path / f"{name}.key"
    pub = tmp_path / f"{name}.pub"
    cli.main(["keygen", "--seed-out", str(seed), "--public-out", str(pub)])
    return seed, _read_pub(pub)


def test_signed_registry_verifies_against_the_root(tmp_path):
    root_seed, root_pub = _keygen(tmp_path, "root")
    _issuer_seed, issuer_pub = _keygen(tmp_path, "issuer")

    unsigned = {
        "schema": rk.REGISTRY_SCHEMA,
        "release": "sn39-2026-07-28",
        "generated_at": "2026-07-28T11:00:00Z",
        "valid_from": "2026-07-28T00:00:00Z",
        "valid_until": "2026-08-28T00:00:00Z",
        "registry_key_id": "cathedral-root-1",
        "keys": [{
            "key_id": "cathedral-config-1",
            "public_key_base64": base64.b64encode(issuer_pub).decode(),
            "valid_from": "2026-07-28T00:00:00Z",
            "valid_until": "2026-08-28T00:00:00Z",
            "status": "active",
        }],
    }
    unsigned_path = tmp_path / "registry.json"
    unsigned_path.write_text(json.dumps(unsigned))
    out = tmp_path / "registry.signed.json"
    assert cli.main(["sign-registry", "--in", str(unsigned_path),
                     "--root-seed", str(root_seed), "--out", str(out)]) == 0

    # verifies through the real anchored path, and resolves the issuer key
    registry = rk.verify_key_registry(out.read_bytes(), {"cathedral-root-1": root_pub},
                                      now=NOW, max_age_seconds=10 ** 9)
    resolved = registry.resolve("cathedral-config-1", at=NOW)
    assert resolved.public_bytes_raw() == issuer_pub


def test_signed_burn_and_allocation_configs_verify(tmp_path):
    issuer_seed, issuer_pub = _keygen(tmp_path, "issuer")
    registry = rk.ReceiptKeyRegistry.from_keys({"cathedral-config-1": issuer_pub})

    def _sign(name, body):
        doc = {
            "schema": body["schema"], "config_version": 3, "network": "finney", "netuid": 39,
            "generated_at": "2026-07-28T11:00:00Z", "valid_from": "2026-07-28T00:00:00Z",
            "valid_until": "2026-08-28T00:00:00Z", "signing_key_id": "cathedral-config-1",
            **{k: v for k, v in body.items() if k != "schema"},
        }
        p = tmp_path / f"{name}.json"
        p.write_text(json.dumps(doc))
        out = tmp_path / f"{name}.signed.json"
        assert cli.main(["sign-config", "--in", str(p), "--seed", str(issuer_seed),
                         "--out", str(out)]) == 0
        return out.read_bytes()

    burn = _sign("burn", {"schema": sc.BURN_CONFIG_SCHEMA,
                          "burn": {"fraction": "0.10", "burn_hotkey": "5Burn"}})
    alloc = _sign("alloc", {"schema": sc.ALLOCATION_CONFIG_SCHEMA, "allocations": [
        {"lane": "cathedral_confidential_tdx", "allocation": "0.50", "enabled": True},
        {"lane": "cathedral_cybergym", "allocation": "0.40", "enabled": True}]})

    burn_cfg = sc.verify_burn_config(burn, registry, network="finney", netuid=39, now=NOW)
    alloc_cfg = sc.verify_allocation_config(alloc, registry, network="finney", netuid=39, now=NOW)
    resolved = sc.resolve_allocation(burn_cfg, alloc_cfg)
    assert resolved.burn_fraction == Decimal("0.10")
    assert set(resolved.lane_allocations) == {"cathedral_confidential_tdx", "cathedral_cybergym"}


def test_wrong_schema_and_short_seed_fail_closed(tmp_path):
    seed, _ = _keygen(tmp_path, "k")
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema": "nope"}))
    assert cli.main(["sign-config", "--in", str(bad), "--seed", str(seed)]) == 2  # bad schema

    short = tmp_path / "short.key"
    short.write_bytes(b"tooshort")
    ok = tmp_path / "cfg.json"
    ok.write_text(json.dumps({"schema": sc.BURN_CONFIG_SCHEMA}))
    assert cli.main(["sign-config", "--in", str(ok), "--seed", str(short)]) == 2  # bad seed len


def test_export_scores_freezes_and_reuses_one_closed_epoch(tmp_path):
    db = tmp_path / "scores.sqlite"
    store = CyberGymScoreStore(str(db))
    store.record_attestation_posture(42, enforced=True, detail="policy configured")
    store.mark_epoch(
        42, state=EPOCH_CLOSED, scored_miners=0,
        at="2026-08-03T10:11:12.123456+00:00",
    )
    store.close()
    out = tmp_path / "epoch-42.json"
    command = [
        "export-scores", "--score-db", str(db), "--epoch", "42",
        "--network", "finney", "--netuid", "39",
        "--producer-hotkey", "5Producer", "--out", str(out),
    ]

    assert cli.main(command) == 0
    first = out.read_bytes()
    assert cli.main(command) == 0
    assert out.read_bytes() == first
    assert stat.S_IMODE(out.stat().st_mode) & 0o077 == 0

    out.write_bytes(b"different")
    assert cli.main(command) == 2


def test_publish_scores_requires_owner_only_secret_files(tmp_path, monkeypatch):
    report_path = tmp_path / "report.json"
    report_path.write_bytes(
        b'{"complete":true,"evidence_sha256":"' + b"0" * 64
        + b'","generated_at":"2026-08-03T10:11:12.123Z","netuid":39,'
        b'"network":"finney","producer_hotkey":"5Producer","score_units":'
        b'"level_weighted_verified_solves","scores":{},"source_epoch":42}'
    )
    token = tmp_path / "token"
    secret = tmp_path / "secret"
    token.write_text("token\n")
    secret.write_text("secret\n")
    token.chmod(0o600)
    secret.chmod(0o644)
    called = []
    monkeypatch.setattr(cli, "publish_score_report", lambda *_a, **_kw: called.append(True))
    command = [
        "publish-scores", "--report", str(report_path),
        "--url", "https://publisher.example/v1/cybergym/scores",
        "--token-file", str(token), "--hmac-secret-file", str(secret),
        "--proof-out", str(tmp_path / "proof.json"),
    ]

    assert cli.main(command) == 2
    assert called == []


def test_publish_scores_freezes_the_exact_accepted_epoch_proof(tmp_path, monkeypatch):
    report_path = tmp_path / "report.json"
    body = (
        b'{"complete":true,"evidence_sha256":"' + b"0" * 64
        + b'","generated_at":"2026-08-03T10:11:12.123Z","netuid":39,'
        b'"network":"finney","producer_hotkey":"5Producer","score_units":'
        b'"level_weighted_verified_solves","scores":{},"source_epoch":42}'
    )
    report_path.write_bytes(body)
    token = tmp_path / "token"
    secret = tmp_path / "secret"
    token.write_text("token\n")
    secret.write_text("secret\n")
    token.chmod(0o600)
    secret.chmod(0o600)
    monkeypatch.setattr(
        cli,
        "publish_score_report",
        lambda *_a, **_kw: {
            "accepted": True,
            "report_sha256": hashlib.sha256(body).hexdigest(),
            "body_sha256": hashlib.sha256(body).hexdigest(),
        },
    )
    proof_path = tmp_path / "proof.json"

    assert cli.main([
        "publish-scores", "--report", str(report_path),
        "--url", "https://publisher.example/v1/cybergym/scores",
        "--token-file", str(token), "--hmac-secret-file", str(secret),
        "--proof-out", str(proof_path),
    ]) == 0

    proof = json.loads(proof_path.read_bytes())
    assert proof == {
        "body": body.decode("utf-8"),
        "signature": cli.body_hmac(body, "secret"),
    }
    assert stat.S_IMODE(proof_path.stat().st_mode) & 0o077 == 0
