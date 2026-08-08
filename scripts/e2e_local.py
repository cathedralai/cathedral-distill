#!/usr/bin/env python3
"""Local end-to-end proof of the CyberGym reward path: miner -> verifier -> validator.

Runs the whole chain on the safe, self-contained synthetic dev path — no chain, no
wallet, no Docker, no external hosts:

  1. miner genuinely solves synthetic challenges (reads the delivered program,
     extracts the magic + buffer size, crafts a one-byte overflow),
  2. the verifier scores the batch and closes the epoch,
  3. `build_score_report` freezes a signed report,
  4. the cathedral-validator publisher ingests + verifies that report and credits
     the miner, and
  5. `mechanism_router.compose` builds the v3 weight vector (70% TDX / 30% CyberGym).

Stages 1-3 use cathedral-distill (this repo). Stages 4-5 use a sibling
cathedral-validator checkout, imported if present; without it the script still
proves stages 1-3 and prints how to enable the rest.

This is DEV/TEST tooling. It runs the service with `attestation_required=False` and
`credit_synthetic_tasks=True` (both loud dev-only overrides) so a synthetic solve is
rewardable in isolation. It is NOT a reward-bearing path. The real reward path adds
the private sealed corpus, the real differential, and Intel-TDX attestation.

Usage:
    python scripts/e2e_local.py
    python scripts/e2e_local.py --require-attestation      # also demo the DCAP gate
    python scripts/e2e_local.py --validator-path ../cathedral-validator

Run it in a venv where both repos are importable, e.g.:
    pip install -e cathedral-distill
    pip install -e 'cathedral-validator[provenance]'
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import sys
import tempfile
import warnings
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MINER = "5MinerE2E"
MINER_UID = 42
TDX_UID = 7
SOURCE_EPOCH = 21
ISSUED = "2026-07-29T12:00:00.000000Z"
PRODUCER = "cathedral-cybergym-producer-sn39"
HMAC_SECRET = "e2e-local-shared-hmac-secret"
RECEIPT_KEY_ID = "cathedral-customer-receipt-2026-07-31-01"
_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    raise SystemExit(1)


# --------------------------------------------------------------------------- #
# Stages 1-3: cathedral-distill (miner -> verifier -> signed report)
# --------------------------------------------------------------------------- #
def _craft_overflow(program: str) -> bytes:
    """A genuine solve: parse the delivered pseudo-C, overflow buf by one byte."""
    magic = bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-f]{2})", program))
    m = re.search(r"char buf\[(\d+)\]", program)
    if m is None:
        raise ValueError("delivered program has no `char buf[N]` to overflow")
    buf = int(m.group(1))
    n = buf + 1
    return magic + n.to_bytes(2, "big") + b"A" * n


def _trace(task_id: str, poc_sha256: str) -> dict:
    # Five DISTINCT steps (no repeated sentence -> clears #126's padded_reasoning check)
    # totalling >=200 reasoning words with >=2 file:line refs, so the submission is
    # trainable, not merely solved. Earlier this was one sentence x5 = 165 words, below
    # the min_reasoning_tokens=200 floor, so the trace/trainable half never passed.
    steps = [
        {"step": 1, "action": "read_file",
         "thought": f"open the delivered target for {task_id} and read its entry at synth.c:1, "
                    "confirming the magic-byte gate that any reaching input must satisfy before "
                    "the parse path is entered, so the reachable surface is understood first"},
        {"step": 2, "action": "read_file",
         "thought": "read the fixed-size stack buffer and the memcpy at synth.c:5, noting the copy "
                    "length is taken from an attacker-controlled field and is never compared against "
                    "the destination capacity before the copy executes on the vulnerable build"},
        {"step": 3, "action": "reason",
         "thought": "reason that the patched build survives the same bytes only because it adds the "
                    "missing bound check the vulnerable revision omits, so only an input whose declared "
                    "length exceeds the destination buffer capacity separates the two builds under the "
                    "differential, which is exactly the property the reward path is set up to pay for"},
        {"step": 4, "action": "write_poc",
         "thought": "write the reproducer as the magic prefix followed by a length field larger than the "
                    "buffer and a payload of that size, so the unchecked copy overruns the stack buffer on "
                    "the vulnerable target and is rejected by the bound check on the patched one"},
        {"step": 5, "action": "verify",
         "thought": "verify the differential locally before submitting the result: the crafted input trips "
                    "the sanitizer abort on the vulnerable build and exits cleanly on the patched build, "
                    "the crash-on-vul and spare-on-fix outcome the validator independently re-runs before "
                    "it will credit the submission as a genuine solve on the sealed task"},
    ]
    return {"task_id": task_id, "poc_sha256": poc_sha256, "model_id": "cathedral/agent-v1",
            "steps": steps, "licence": "cathedral-corpus-v1",
            "model_seal": "sha256:" + hashlib.sha256(b"seal").hexdigest()}


def distill_stages(work: Path) -> dict:
    from cathedral_distill.cybergym_protocol import CyberGymCorpusStore, SubmissionEnvelope
    from cathedral_distill.cybergym_scores import CyberGymScoreStore, CyberGymSolveStore
    from cathedral_distill.cybergym_service import CyberGymService
    from cathedral_distill.cybergym_synthetic import synthetic_holdout
    from cathedral_distill.cybergym_validator import ChainContext
    from cathedral_distill.cybergym_verifier import poc_digest
    from cathedral_distill.cybergym_score_report import build_score_report

    now = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
    chain = ChainContext(block=100, block_hash="0x" + "ab" * 32, network="finney", netuid=39,
                         source_epoch=SOURCE_EPOCH, valid_from_block=100, valid_until_block=460)
    holdout, backend = synthetic_holdout()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # dev-mode attestation/gates warnings; see module docstring
        svc = CyberGymService(
            holdout, chain, backend=backend,
            corpus_store=CyberGymCorpusStore(str(work / "corpus.sqlite")),
            score_store=CyberGymScoreStore(str(work / "scores.sqlite")),
            solve_store=CyberGymSolveStore(str(work / "solves.sqlite")),
            validator_hotkey="5Val", private_key=_KEY, signing_key_id="cybergym-1",
            batch_size=2, cutoff=datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc), as_of=now,
            attestation_required=False, gates_required=False, credit_synthetic_tasks=True)

    print("[1/5] miner: dispatch -> solve -> submit")
    d = svc.dispatch_for(MINER, "sha256:" + hashlib.sha256(b"ckpt").hexdigest(),
                         authenticated_caller=MINER)
    total = Decimal(0)
    for task in d.tasks:
        art = svc.handle_artifact({"task_id": task.task_id, "batch_id": d.batch_id},
                                  authenticated_caller=MINER)
        if "program" not in art:  # handle_artifact returns {"error": ...} or a bytes artifact
            _fail(f"artifact for {task.task_id} has no program: {art.get('error') or list(art)}")
        poc = _craft_overflow(art["program"])
        outcome = svc.submit(
            SubmissionEnvelope(batch_id=d.batch_id, task_id=task.task_id, miner_hotkey=MINER,
                               poc_base64=base64.b64encode(poc).decode(),
                               trace=_trace(task.task_id, poc_digest(poc))),
            authenticated_caller=MINER)
        if not (outcome.solved and outcome.work_units > 0):
            _fail(f"miner did not solve {task.task_id}: {outcome.reason}")
        total += outcome.work_units
        print(f"      solved {task.task_id} (L{task.level}) work_units={outcome.work_units}")

    print("[2/5] verifier: score + close epoch")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        svc.score_epoch(issued_at=ISSUED)
    scored = svc._scores.epoch_scores(SOURCE_EPOCH)
    if scored.get(MINER) != total:
        _fail(f"score mismatch: epoch_scores={scored} expected {{{MINER}: {total}}}")
    print(f"      epoch {SOURCE_EPOCH} scored: {{{MINER}: {scored[MINER]}}}")

    print("[3/5] producer: export signed score report")
    report = build_score_report(svc._scores, network="finney", netuid=39,
                                source_epoch=SOURCE_EPOCH, producer_hotkey=PRODUCER,
                                allow_unattested=True)
    (work / "report.json").write_text(json.dumps(report, indent=2))
    print(f"      report scores={report['scores']} nonce={report.get('nonce', '')[:24]}..")
    return report


# --------------------------------------------------------------------------- #
# Stages 4-5: cathedral-validator publisher (ingest -> verify -> compose v3)
# --------------------------------------------------------------------------- #
def _valid_receipt(miner_hk: str, nonce_val: str) -> dict:
    envelope = {"schema": "cathedral_cybergym_tdx_enclave_commitment_v1",
                "commitment": {"miner_hotkey": miner_hk, "nonce": nonce_val,
                               "task_id": "synth:1", "poc_sha256": "sha256:" + "a" * 64},
                "enclave_pubkey_b64": "", "signature_b64": ""}
    rb = json.dumps(envelope).encode()
    receipt = {"schema": "cathedral_customer_receipt_v1", "cpu_tee": "intel_tdx",
               "intel_verified": True, "execution_binding_verified": True,
               "signing_key_id": RECEIPT_KEY_ID, "issued_at": "2026-08-05T12:00:00.000000Z",
               "result_sha256": hashlib.sha256(rb).hexdigest(), "workload_sha256": "w" * 8}
    unsigned = {k: v for k, v in receipt.items() if k != "signature"}
    signed = json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True, allow_nan=False).encode("ascii")
    receipt["signature"] = {"algorithm": "ed25519",
                            "value_base64": base64.b64encode(_KEY_ATT.sign(signed)).decode()}
    return {"receipt": receipt, "result_b64": base64.b64encode(rb).decode()}


_KEY_ATT = Ed25519PrivateKey.generate()


def _locate_validator(explicit: str | None) -> Path | None:
    repo_root = Path(__file__).resolve().parents[1]
    candidates = [explicit] if explicit else []
    candidates.append(str(repo_root.parent / "cathedral-validator"))
    for c in candidates:
        p = Path(c).expanduser().resolve()
        if (p / "scaffold" / "publisher" / "mechanism_cybergym_adapter.py").exists():
            return p
    return None


def validator_stages(work: Path, report: dict, *, require_attestation: bool,
                     validator_path: str | None) -> None:
    vpath = _locate_validator(validator_path)
    if vpath is None:
        print("[4/5] validator: SKIPPED — no cathedral-validator checkout found.")
        print("      pass --validator-path <dir> (or place it beside this repo) to run "
              "stages 4-5.")
        return
    sys.path.insert(0, str(vpath))
    import os
    os.environ["CATHEDRAL_ALLOCATION_CONTRACT"] = "v3"
    from scaffold.publisher import cybergym_attestation as att  # noqa: E402
    from scaffold.publisher import cybergym_contract as contract  # noqa: E402
    from scaffold.publisher import cybergym_ingest as ingest_mod  # noqa: E402
    from scaffold.publisher import mechanism_cybergym_adapter as adapter  # noqa: E402
    from scaffold.publisher import weights  # noqa: E402
    from scaffold.publisher.mechanism_router import compose, MechanismSpec, ScoreVectorMeta  # noqa: E402
    from scaffold.publisher.store import Store  # noqa: E402

    os.environ[contract.HMAC_SECRET_ENV] = HMAC_SECRET
    os.environ[weights.NETWORK_ENV] = "finney"
    os.environ[weights.NETUID_ENV] = "39"
    epoch = int(report["source_epoch"])
    miner = list(report["scores"])[0]
    generated = datetime.strptime(report["generated_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=timezone.utc)
    now = generated + timedelta(seconds=60)

    def ingest(store: Store, document_raw: dict) -> None:
        # Go through the REAL intake path — validate -> bind the authenticated body ->
        # store behind the epoch fence + attestation-posture ratchet — NOT hand-rolled
        # INSERTs. The whole point of this stage is to guard scaffold.publisher.
        # cybergym_ingest.store_report; re-implementing a legacy row shape here would let
        # the e2e stay green while the real intake (authenticated_body, posture, fence)
        # drifts, which is exactly the seam this script exists to protect.
        body = contract.canonical_report_bytes(contract.normalize_semantic_document(document_raw))
        sig = "sha256=" + contract.body_hmac_hex(body, HMAC_SECRET)
        validated = ingest_mod.validate_report(
            document_raw, audience=("finney", 39),
            producer=document_raw["producer_hotkey"], now=now)
        validated = ingest_mod.bind_authenticated_body(validated, body)
        ingest_mod.store_report(store, validated, signature=sig)
        # Fixture rows store_report does not own: epoch close + the registration snapshot.
        store.write(lambda c: c.execute("CREATE TABLE IF NOT EXISTS cybergym_epoch_status"
                                        "(epoch INTEGER PRIMARY KEY, state TEXT NOT NULL)"))
        store.write(lambda c: c.execute(
            "INSERT OR REPLACE INTO cybergym_epoch_status(epoch,state) VALUES (?,?)",
            (epoch, adapter.EPOCH_CLOSED)))
        store.write(lambda c: c.execute(
            "INSERT OR REPLACE INTO metagraph_hotkeys(network,netuid,hotkey,uid,coldkey,block,"
            "updated_at_iso) VALUES (?,?,?,?,?,?,?)",
            ("finney", 39, miner, MINER_UID, "", 123, "2026-07-01T00:00:00.000Z")))

    def compose_v3(vec, meta):
        specs = [MechanismSpec(mechanism_id="cybergym_v0", owner_pubkey=PRODUCER,
                               weight_fraction=0.30, tier="artifact", owner_uid=None, enabled=True),
                 MechanismSpec(mechanism_id="confidential_tdx", owner_pubkey="5TdxOwner",
                               weight_fraction=0.70, tier="artifact", owner_uid=None, enabled=True)]
        scores = {"cybergym_v0": (vec, meta),
                  "confidential_tdx": ({TDX_UID: 1.0}, ScoreVectorMeta(
                      mechanism_id="confidential_tdx", signed_at_ms=int(now.timestamp() * 1000),
                      sig_ok=True, source="tdx_stub"))}
        return compose(specs, scores, registered_uids={MINER_UID, TDX_UID},
                       now_ms=int(now.timestamp() * 1000), preserve_forfeited=True)

    print("[4/5] validator: ingest report -> verify -> credit the miner")
    store = Store(str(work / "publisher.sqlite"), prefer_env_database_url=False)
    ingest(store, dict(report))
    vec, meta, info = adapter.cybergym_score_snapshot(store, epoch=epoch, now=now)
    if not (meta.sig_ok and vec):
        _fail(f"validator did not credit the miner: {info}")
    print(f"      verified={info.get('verified')} reason={info.get('reason')} "
          f"cybergym_vec={vec}")

    print("[5/5] validator: compose v3 weight vector (70% TDX / 30% CyberGym)")
    final, dbg = compose_v3(vec, meta)
    if round(final.get(MINER_UID, 0.0), 6) != 0.30:
        _fail(f"miner not credited 0.30 in the v3 vector: {final}")
    print(f"      v3 vector={final} sum={round(sum(final.values()), 6)} "
          f"burn={round(dbg.get('forfeited_fraction'), 3)}")
    print(f"\nPASS: miner uid{MINER_UID} earns {final[MINER_UID]} of emission via the "
          f"CyberGym lane, end to end.")

    if require_attestation:
        print("\n--- DCAP attestation gate (require flag ON): pay-vs-burn ---")
        att_root = Path(tempfile.mkdtemp(prefix="cybergym-attest-"))  # cleaned after the loop
        for label, receipt, drop_nonce in [
            ("valid receipt   ", _valid_receipt(miner, report.get("nonce", "")), False),
            ("no receipt      ", None, False),
            ("receipt, no nonce", _valid_receipt(miner, report.get("nonce", "")), True),
        ]:
            fresh = Path(tempfile.mkdtemp(dir=att_root))
            att_trust = fresh / "trusted.json"
            pub = _KEY_ATT.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            att_trust.write_text(json.dumps({"keys": {RECEIPT_KEY_ID: {
                "algorithm": "ed25519", "status": "active",
                "public_key_base64": base64.b64encode(pub).decode(),
                "valid_from": "2026-07-31T00:00:00.000000Z",
                "valid_until": "2027-08-01T00:00:00.000000Z"}}}))
            os.environ[att.REQUIRE_ATTESTATION_ENV] = "1"
            os.environ[att.TRUSTED_KEYS_ENV] = str(att_trust)
            doc = dict(report)
            if drop_nonce:
                doc.pop("nonce", None)
            if receipt is not None:
                doc["attestation_receipt"] = receipt
            s = Store(str(fresh / "pub.sqlite"), prefer_env_database_url=False)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                ingest(s, doc)
                v, m, i = adapter.cybergym_score_snapshot(s, epoch=epoch, now=now)
            fin, _ = compose_v3(v, m)
            paid = fin.get(MINER_UID, 0.0)
            print(f"      {label} attestation={(i.get('attestation') or 'n/a'):>13} "
                  f"miner weight={paid:<4} {'PAYS' if paid else 'BURNS'}")
        os.environ.pop(att.REQUIRE_ATTESTATION_ENV, None)
        shutil.rmtree(att_root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--require-attestation", action="store_true",
                    help="also demonstrate the DCAP gate deciding pay-vs-burn")
    ap.add_argument("--validator-path", help="path to a cathedral-validator checkout "
                    "(default: sibling directory)")
    ap.add_argument("--keep", action="store_true", help="keep the temp working directory")
    args = ap.parse_args(argv)

    work = Path(tempfile.mkdtemp(prefix="cybergym-e2e-"))
    print(f"CyberGym local E2E — miner -> verifier -> validator  (workdir {work})\n")
    try:
        report = distill_stages(work)
        validator_stages(work, report, require_attestation=args.require_attestation,
                         validator_path=args.validator_path)
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
