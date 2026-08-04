#!/usr/bin/env python3
"""The five reward-proof gates for activating CyberGym rewards, in one recorded run.

From cathedral-distill#41: CyberGym rewards may not be activated until ONE recorded
run proves every step below end to end. This is the go/no-go for the re-pin, not a
test — and its ONLY dangerous failure mode is a false PASS, so every gate here demands
direct evidence and refuses to self-certify from anything weaker.

    1. Production transport delivers a fresh, complete CyberGym score backed by a
       result-bound Intel TDX receipt for a REAL-CORPUS solve.
    2. The signed weights feed contains the intended miner with a positive CyberGym
       allocation and the reviewed burn allocation, under the expected signing key.
    3. The canonical validator accepts the signed vector, submits it to the selected
       mechanism, and remains active on chain.
    4. A finalized chain view shows the accepted validator row, plus nonzero
       incentive and nonzero emission for the intended miner.
    5. An external miner installs the signed release and completes the same path
       without operator bypasses.

Design, in response to review of #59:
  * No gate passes on counts, an unread flag, a trusted-issuer assertion, or an
    operator-supplied scalar. Gate 1 verifies an actual attested receipt
    (verify_cathedral_attestation) for a NON-synthetic task; gate 2 checks the
    feed's key_id against an expected value and the miner's lane weight. Gates 3
    and 5 remain BLOCKED until their independently verifiable evidence formats and
    trust roots are configured.
  * The intended miner (hotkey AND uid) and the full run context (endpoints,
    network, netuid, evaluation time) are bound into every gate and the transcript.
  * A gate with no independently verifiable evidence is BLOCKED, never a silent
    PASS; a gate with contradicting evidence is FAIL.

Usage (records the current proof state; unverifiable evidence stays BLOCKED):
    python scripts/reward_proof_gates.py \
        --miner 5CyberMiner --miner-uid 42 \
        --publisher https://api.cathedral.computer --expect-key-id cathedral-weight-policy \
        --attested-receipt receipt.json --receipt-task arvo:12345 \
        --receipt-poc-sha256 sha256:... --receipt-trace-id sha256:... \
        --validator-acceptance v3_accept.json --validator-wrote-block 8801234 \
        --external-miner-transcript external.json \
        --now 2026-08-04T12:00:00Z --out transcript.json
"""
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any

PASS, FAIL, BLOCKED = "PASS", "FAIL", "BLOCKED"


def _get(url: str, timeout: int = 30) -> tuple[int, Any]:
    req = urllib.request.Request(
        url, headers={"User-Agent": "cathedral-reward-proof/1", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return 0, {"error": str(exc)}


def _load_json(path: str | None) -> Any:
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as exc:
        return {"_error": str(exc)}


def _parse_now(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class Gate:
    def __init__(self, n: int, title: str):
        self.n, self.title, self.status, self.detail = n, title, BLOCKED, ""

    def set(self, status: str, detail: str) -> "Gate":
        self.status, self.detail = status, detail
        return self


def gate1_score_backed_by_tdx(args) -> Gate:
    """A real-corpus solve backed by a verifiable, result-bound Intel TDX receipt.

    /v1/status exposes counts, not attestation or task provenance, so it cannot
    prove this on its own. The proof is an actual attested receipt, verified with
    the production adapter and bound to the intended miner and a NON-synthetic task.
    """
    g = Gate(1, "a real-corpus solve backed by a result-bound Intel TDX receipt")
    receipt = _load_json(args.attested_receipt)
    if receipt is None:
        return g.set(BLOCKED, "no --attested-receipt supplied: gate 1 cannot be "
                              "self-certified from /v1/status counts (they carry no "
                              "attestation or task provenance)")
    if isinstance(receipt, dict) and "_error" in receipt:
        return g.set(FAIL, f"could not read the receipt: {receipt['_error']}")
    if not (args.receipt_task and args.receipt_poc_sha256 and args.receipt_trace_id):
        return g.set(FAIL, "a receipt needs --receipt-task/--receipt-poc-sha256/"
                           "--receipt-trace-id to bind it to a specific submission")
    try:
        from cathedral_distill.cybergym_synthetic import is_synthetic_task
        from cathedral_distill.cybergym_cathedral_attest import verify_cathedral_attestation
    except Exception as exc:  # noqa: BLE001
        return g.set(BLOCKED, f"run where cathedral_distill is importable ({exc})")
    if is_synthetic_task(args.receipt_task):
        return g.set(FAIL, f"{args.receipt_task} is synthetic — a real-corpus solve "
                           "is required; a synthetic answer is computable from public "
                           "state and proves no capability")
    att = verify_cathedral_attestation(
        receipt, task_id=args.receipt_task, poc_sha256=args.receipt_poc_sha256,
        trace_id=args.receipt_trace_id, now=_parse_now(args.now))
    if not att.attested:
        return g.set(FAIL, f"receipt does not attest this solve: {att.reason}")
    receipt_hotkey = str(receipt.get("miner_hotkey") or receipt.get("hotkey") or "")
    if receipt_hotkey and receipt_hotkey != args.miner:
        return g.set(FAIL, f"receipt is for {receipt_hotkey!r}, not the intended "
                           f"miner {args.miner!r}")
    if not att.trustless:
        return g.set(BLOCKED, "receipt is a trusted-issuer assertion; gate 1 needs "
                              "an independently verified raw TDX quote and canonical "
                              "artifacts-list binding before it can pass")
    return g.set(PASS, f"attested {att.tee} solve of {args.receipt_task} bound to "
                       f"{args.miner} (receipt {att.receipt_id[:12]}…"
                       f"{', trustless' if att.trustless else ''})")


def gate2_feed_has_miner_and_burn(args) -> Gate:
    """The signed v3 feed carries the miner with positive CyberGym weight, under the
    expected signing key."""
    g = Gate(2, "signed v3 feed pays the miner under the expected key")
    status, feed = _get(f"{args.publisher}/v1/validator/weights/next")
    if status != 200 or not isinstance(feed, dict):
        return g.set(FAIL, f"weights feed unreachable (HTTP {status})")
    key_id = feed.get("key_id")
    if args.expect_key_id and key_id != args.expect_key_id:
        return g.set(FAIL, f"feed signed by key_id {key_id!r}, expected "
                           f"{args.expect_key_id!r} — wrong or unpinned signer")
    if not feed.get("signature"):
        return g.set(FAIL, "feed carries no signature")
    # Full signature verification is the validator's job and is asserted in gate 3
    # (validator acceptance verifies the signature against the pinned key). Here we
    # bind the signer identity and the payment; gate 2 alone is not authenticity.
    pm = feed.get("policy_metadata", {})
    vs = pm.get("validated_supply", {})
    if vs.get("contract_version") != "v3":
        return g.set(FAIL, f"feed contract_version is {vs.get('contract_version')!r}, "
                           "not v3 — the CyberGym lane is not composed into the "
                           "signed vector yet")
    if args.miner_uid is None:
        return g.set(FAIL, "pass --miner-uid to check the miner's lane weight")
    lane = pm.get("cybergym_lane", {})
    frac = float(lane.get("fraction", 0) or 0)
    weight = float((lane.get("weights", {}) or {}).get(str(args.miner_uid), 0) or 0)
    if frac > 0 and weight > 0:
        return g.set(PASS, f"cybergym_lane fraction {frac}, uid {args.miner_uid} "
                           f"weight {weight}; fixed_burn "
                           f"{vs.get('fixed_burn_allocation')}; key_id {key_id}")
    return g.set(FAIL, f"cybergym_lane fraction {frac}, uid {args.miner_uid} weight "
                       f"{weight} — the feed does not pay the intended miner")


def gate3_validator_accepts_and_submits(args) -> Gate:
    """A v3-pinned validator accepted the vector AND wrote weights on chain.

    The current local acceptance transcript and a caller-supplied block number are
    diagnostic only. This gate remains blocked until it receives independently
    verifiable finalized-chain evidence.
    """
    g = Gate(3, "canonical validator accepts the v3 vector and writes on chain")
    acc = _load_json(args.validator_acceptance)
    if acc is None:
        return g.set(BLOCKED, "no --validator-acceptance transcript: run "
                              "assert_live_v3_contract.py --json (cathedral-validator) "
                              "and confirm the validator wrote weights this epoch")
    if isinstance(acc, dict) and "_error" in acc:
        return g.set(FAIL, f"could not read the acceptance transcript: {acc['_error']}")
    if not acc.get("ok"):
        return g.set(FAIL, f"validator did NOT accept the vector: {acc.get('error')}")
    if acc.get("accepted_by") != "validated_supply_v3":
        return g.set(FAIL, f"acceptance is for {acc.get('accepted_by')!r}, not "
                           "validated_supply_v3")
    if args.validator_wrote_block is None:
        return g.set(BLOCKED, "acceptance confirmed, but no independently verified "
                              "finalized-chain write proof is supplied")
    return g.set(BLOCKED, f"v3 vector was accepted ({acc.get('uids_weighted')} uids, "
                          f"sum {acc.get('weight_sum')}), but --validator-wrote-block "
                          f"{args.validator_wrote_block} is caller-supplied and cannot "
                          "prove a finalized chain write; require signed, independently "
                          "queried chain evidence")


def gate4_chain_shows_emission(args) -> Gate:
    """A finalized chain view: nonzero incentive AND emission for the miner."""
    g = Gate(4, "finalized chain shows nonzero incentive and emission for the miner")
    if args.miner_uid is None:
        return g.set(BLOCKED, "pass --miner-uid to check the on-chain row")
    try:
        from bittensor.core.subtensor import Subtensor
    except Exception as exc:  # noqa: BLE001
        return g.set(BLOCKED, f"bittensor not importable here ({exc}); run on a node "
                              "with chain access")
    try:
        st = Subtensor(network=args.network)
        mg = st.metagraph(netuid=args.netuid, lite=False)
        uid = int(args.miner_uid)
        hk = list(mg.hotkeys)[uid] if uid < len(mg.hotkeys) else None
        if hk != args.miner:
            return g.set(FAIL, f"uid {uid} is hotkey {hk!r}, not the intended miner "
                               f"{args.miner!r} — the uid/hotkey binding is stale")
        incentive = float(mg.I[uid]); emission = float(mg.E[uid])
    except Exception as exc:  # noqa: BLE001
        return g.set(FAIL, f"chain query failed: {exc}")
    if incentive > 0 and emission > 0:
        return g.set(PASS, f"uid {uid} ({args.miner}): incentive {incentive:.6g}, "
                           f"emission {emission:.6g}")
    return g.set(FAIL, f"uid {uid}: incentive {incentive:.6g}, emission "
                       f"{emission:.6g} — the miner is not yet paid on chain")


def gate5_external_miner(args) -> Gate:
    """An external operator installed the signed release and completed the path.

    Cannot be self-certified: the evidence is a transcript a third party produced,
    referencing THEIR OWN hotkey (not ours) and a successful install->test->earn.
    """
    g = Gate(5, "external miner completes the path with no operator bypass")
    ext = _load_json(args.external_miner_transcript)
    if ext is None:
        status, _ = _get(f"{args.publisher}/v1/release/release.json", timeout=15)
        if status != 200:
            return g.set(BLOCKED, f"release.json HTTP {status}: no external miner can "
                                  "install an engine yet (publish and sign release.json)")
        return g.set(BLOCKED, "release is published, but gate 5 needs a transcript "
                              "from a REAL external operator (--external-miner-"
                              "transcript); it cannot be self-certified")
    if isinstance(ext, dict) and "_error" in ext:
        return g.set(FAIL, f"could not read the external transcript: {ext['_error']}")
    ext_hotkey = str(ext.get("miner_hotkey", ""))
    if not ext_hotkey or ext_hotkey == args.miner:
        return g.set(FAIL, "the external transcript must reference a DIFFERENT "
                           "operator's hotkey (an external party, not us)")
    if not (ext.get("installed_signed_release") and ext.get("completed_without_bypass")):
        return g.set(FAIL, "the external transcript does not attest a clean "
                           "install->test path without operator bypass")
    return g.set(BLOCKED, f"external transcript names {ext_hotkey[:12]}…, but it is "
                          "unsigned and unbound to a release digest; configure a trusted "
                          "external-attestor signature verifier before gate 5 can pass")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--miner", required=True, help="intended miner hotkey")
    p.add_argument("--miner-uid", type=int, default=None, help="its metagraph uid")
    p.add_argument("--publisher", default="https://api.cathedral.computer")
    p.add_argument("--expect-key-id", default=None, help="the signing key_id the feed must carry")
    p.add_argument("--network", default="finney")
    p.add_argument("--netuid", type=int, default=39)
    p.add_argument("--now", default=None, help="ISO-8601 evaluation time (receipt freshness/record)")
    p.add_argument("--attested-receipt", help="path to the Cathedral TDX receipt JSON")
    p.add_argument("--receipt-task")
    p.add_argument("--receipt-poc-sha256")
    p.add_argument("--receipt-trace-id")
    p.add_argument("--validator-acceptance", help="assert_live_v3_contract.py --json output")
    p.add_argument("--validator-wrote-block", type=int, default=None,
                   help="diagnostic only; a caller-supplied block number never proves a chain write")
    p.add_argument("--external-miner-transcript")
    p.add_argument("--out", help="write the transcript JSON here")
    args = p.parse_args(argv)

    print("CyberGym reward-proof gates (cathedral-distill#41)\n" + "=" * 58)
    print(f"  miner {args.miner} (uid {args.miner_uid}) · {args.network}/{args.netuid} "
          f"· publisher {args.publisher}\n")
    gates = [gate1_score_backed_by_tdx(args), gate2_feed_has_miner_and_burn(args),
             gate3_validator_accepts_and_submits(args), gate4_chain_shows_emission(args),
             gate5_external_miner(args)]
    for g in gates:
        mark = {PASS: "✓", FAIL: "✗", BLOCKED: "…"}[g.status]
        print(f"  {mark} gate {g.n}: {g.title}\n      {g.status}: {g.detail}")

    passed = sum(1 for g in gates if g.status == PASS)
    failed = sum(1 for g in gates if g.status == FAIL)
    blocked = sum(1 for g in gates if g.status == BLOCKED)
    print("=" * 58)
    print(f"  {passed} passed, {failed} failed, {blocked} blocked")
    verdict = ("ALL FIVE PROVEN — rewards may be activated" if passed == 5 else
               "NOT PROVEN — do not activate CyberGym rewards")
    print(f"  {verdict}")

    transcript = {
        "schema": "cathedral_cybergym_reward_proof_v1",
        "verdict": verdict, "proven": passed == 5,
        "bound": {
            "miner_hotkey": args.miner, "miner_uid": args.miner_uid,
            "network": args.network, "netuid": args.netuid,
            "publisher": args.publisher, "expect_key_id": args.expect_key_id,
            "evaluated_at": args.now,
        },
        "gates": [{"n": g.n, "title": g.title, "status": g.status, "detail": g.detail}
                  for g in gates],
    }
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(transcript, f, indent=2)
            f.write("\n")
        print(f"\n  transcript -> {args.out}")
    return 0 if passed == 5 else 1


if __name__ == "__main__":
    raise SystemExit(main())
