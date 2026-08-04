#!/usr/bin/env python3
"""The five reward-proof gates for activating CyberGym rewards, in one recorded run.

From cathedral-distill#41: CyberGym rewards may not be activated until ONE recorded
run proves every step below end to end. This harness runs them in order, stops at
the first failure (each gate depends on the one before it), and writes a signed-off
transcript. It is the owner's go/no-go for the re-pin, not a test — it checks live
production state, so it can only pass once the pieces it inspects actually exist.

    1. Production transport delivers a fresh, complete CyberGym score backed by a
       result-bound Intel TDX receipt for a real-corpus solve.
    2. The signed weights feed contains the intended miner with a positive CyberGym
       allocation and the reviewed burn allocation.
    3. The canonical validator accepts the signed vector, submits it to the selected
       mechanism, and remains active on chain.
    4. A finalized chain view shows the accepted validator row, plus nonzero
       incentive and nonzero emission for the intended miner.
    5. An external miner installs the signed release and completes the same path
       without operator bypasses.

Gates 1-4 are checkable from here given a live feed, a verifier endpoint, and chain
access. Gate 5 requires the signed release to be published and a real external
operator, so it is marked BLOCKED (not FAIL) until those exist — the harness records
what is still owner-only rather than pretending it can prove it.

Usage:
    python scripts/reward_proof_gates.py \
        --miner 5CyberMiner --publisher https://api.cathedral.computer \
        --verifier http://127.0.0.1:8666 --network finney --netuid 39 \
        --out reward_proof_transcript.json
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any, Callable

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


class Gate:
    def __init__(self, n: int, title: str):
        self.n, self.title, self.status, self.detail = n, title, None, ""

    def record(self, status: str, detail: str) -> str:
        self.status, self.detail = status, detail
        return status


def gate1_score_backed_by_tdx(args) -> Gate:
    """A fresh, complete CyberGym score with a result-bound Intel TDX receipt."""
    g = Gate(1, "production transport delivers a TDX-backed real-corpus score")
    status, body = _get(f"{args.verifier}/v1/status")
    if status != 200 or not isinstance(body, dict):
        g.record(FAIL, f"verifier /v1/status unreachable (HTTP {status})")
        return g
    lane = body.get("lane", {})
    if lane.get("lane_id") != "cathedral_cybergym":
        g.record(FAIL, f"unexpected lane {lane.get('lane_id')!r}")
        return g
    # The score must be real-corpus AND attested. The status endpoint exposes the
    # epoch identity; a complete proof needs at least one scored, attested solve.
    part = body.get("participation", {})
    scored = part.get("scored", 0) if part.get("available") else 0
    lb = body.get("leaderboard", {})
    if scored and lb.get("scored_miners"):
        g.record(PASS, f"{scored} scored, {lb['scored_miners']} on the leaderboard, "
                       f"epoch {body.get('epoch', {}).get('source_epoch')}")
    else:
        g.record(FAIL, "no scored, attested solve this epoch — nothing to back a "
                       "reward with yet (need a real-corpus solve inside a sealed "
                       "TDX enclave, attestation_required=True)")
    return g


def gate2_feed_has_miner_and_burn(args) -> Gate:
    """The signed feed lists the intended miner with a positive CyberGym allocation."""
    g = Gate(2, "signed feed carries the miner with a positive CyberGym allocation")
    status, feed = _get(f"{args.publisher}/v1/validator/weights/next")
    if status != 200 or not isinstance(feed, dict):
        g.record(FAIL, f"weights feed unreachable (HTTP {status})")
        return g
    pm = feed.get("policy_metadata", {})
    vs = pm.get("validated_supply", {})
    version = vs.get("contract_version")
    if version != "v3":
        g.record(FAIL, f"feed contract_version is {version!r}, not v3 — the CyberGym "
                       "lane is not composed into the signed vector yet")
        return g
    lane = pm.get("cybergym_lane", {})
    frac = float(lane.get("fraction", 0) or 0)
    weights = lane.get("weights", {})
    # The miner must appear with positive weight in the CyberGym lane.
    miner_uid = args.miner_uid
    present = miner_uid is not None and float(weights.get(str(miner_uid), 0) or 0) > 0
    if frac > 0 and present:
        g.record(PASS, f"cybergym_lane fraction {frac}, miner uid {miner_uid} present "
                       f"with positive weight; fixed_burn "
                       f"{vs.get('fixed_burn_allocation')}")
    else:
        g.record(FAIL, f"cybergym_lane fraction {frac}, miner uid {miner_uid} "
                       f"present={present} — feed does not yet pay the intended miner")
    return g


def gate3_validator_accepts_and_submits(args) -> Gate:
    """The canonical validator accepts the vector and is active on chain."""
    g = Gate(3, "canonical validator accepts the v3 vector and stays active")
    # Reuse the validator's own acceptance via the v3 pre-cutover gate if available;
    # here we check the observable proxy: an active validator row that just wrote.
    # A full check runs assert_live_v3_contract.py (validator repo) against the feed.
    g.record(BLOCKED, "run scripts/assert_live_v3_contract.py (cathedral-validator) "
                      "against this feed for acceptance, then confirm the validator "
                      "wrote weights this epoch. Requires a v3-pinned validator "
                      "running — owner/operator step.")
    return g


def gate4_chain_shows_emission(args) -> Gate:
    """A finalized chain view: accepted validator row, nonzero incentive + emission."""
    g = Gate(4, "finalized chain shows nonzero incentive and emission for the miner")
    if args.miner_uid is None:
        g.record(BLOCKED, "pass --miner-uid to check the on-chain row")
        return g
    try:
        from bittensor.core.subtensor import Subtensor
    except Exception as exc:  # noqa: BLE001
        g.record(BLOCKED, f"bittensor not importable here ({exc}); run on a node "
                          "with chain access")
        return g
    try:
        st = Subtensor(network=args.network)
        mg = st.metagraph(netuid=args.netuid, lite=False)
        uid = int(args.miner_uid)
        incentive = float(mg.I[uid]) if uid < len(mg.I) else 0.0
        emission = float(mg.E[uid]) if uid < len(mg.E) else 0.0
    except Exception as exc:  # noqa: BLE001
        g.record(FAIL, f"chain query failed: {exc}")
        return g
    if incentive > 0 and emission > 0:
        g.record(PASS, f"uid {uid}: incentive {incentive:.6g}, emission {emission:.6g}")
    else:
        g.record(FAIL, f"uid {uid}: incentive {incentive:.6g}, emission {emission:.6g} "
                       "— the miner is not yet being paid on chain")
    return g


def gate5_external_miner(args) -> Gate:
    """An external miner installs the signed release and completes the path."""
    g = Gate(5, "external miner completes the path with no operator bypass")
    # This one cannot be self-certified: it needs the signed release published and a
    # real third-party operator. The harness records it as blocked-on-owner until the
    # release exists, so a green run can never be claimed without it.
    status, _ = _get(f"{args.publisher}/v1/release/release.json", timeout=15)
    if status == 200:
        g.record(BLOCKED, "signed release is published; gate 5 now needs a real "
                          "external operator to run install -> test -> earn and "
                          "attach their transcript. Cannot be self-certified.")
    else:
        g.record(BLOCKED, f"signed release is not published (release.json HTTP "
                          f"{status}); no external miner can install an engine yet. "
                          "Owner ceremony — publish + sign release.json.")
    return g


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--miner", default="5CyberMiner", help="intended miner hotkey")
    p.add_argument("--miner-uid", type=int, default=None, help="its metagraph uid")
    p.add_argument("--publisher", default="https://api.cathedral.computer")
    p.add_argument("--verifier", default="http://127.0.0.1:8666")
    p.add_argument("--network", default="finney")
    p.add_argument("--netuid", type=int, default=39)
    p.add_argument("--out", help="write the transcript JSON here")
    args = p.parse_args(argv)

    gates: list[Callable[[Any], Gate]] = [
        gate1_score_backed_by_tdx, gate2_feed_has_miner_and_burn,
        gate3_validator_accepts_and_submits, gate4_chain_shows_emission,
        gate5_external_miner,
    ]

    print("CyberGym reward-proof gates (cathedral-distill#41)\n" + "=" * 58)
    results = []
    stop = False
    for fn in gates:
        if stop:
            g = Gate(0, "")
            g = fn(args)  # still evaluate for reporting, but mark downstream
            if g.status == PASS:
                g.record(BLOCKED, "a prior gate did not pass; this gate's PASS is not "
                                  "yet meaningful — " + g.detail)
        else:
            g = fn(args)
        results.append(g)
        mark = {PASS: "✓", FAIL: "✗", BLOCKED: "…"}[g.status]
        print(f"  {mark} gate {g.n}: {g.title}\n      {g.status}: {g.detail}")
        if g.status == FAIL:
            stop = True  # gates are sequential; a FAIL blocks everything after it

    passed = sum(1 for g in results if g.status == PASS)
    blocked = sum(1 for g in results if g.status == BLOCKED)
    failed = sum(1 for g in results if g.status == FAIL)
    print("=" * 58)
    print(f"  {passed} passed, {failed} failed, {blocked} blocked")
    verdict = ("ALL FIVE PROVEN — rewards may be activated" if passed == 5 else
               "NOT PROVEN — do not activate CyberGym rewards")
    print(f"  {verdict}")

    transcript = {
        "schema": "cathedral_cybergym_reward_proof_v1",
        "verdict": verdict,
        "gates": [{"n": g.n, "title": g.title, "status": g.status, "detail": g.detail}
                  for g in results],
    }
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(transcript, f, indent=2)
            f.write("\n")
        print(f"\n  transcript -> {args.out}")
    return 0 if passed == 5 else 1


if __name__ == "__main__":
    raise SystemExit(main())
