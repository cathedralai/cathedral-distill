"""Close one fresh CyberGym E2E epoch from its durable state.

This is intentionally a separate, one-shot operator command.  It rebuilds the
fresh loopback verifier from the same protected environment as the server,
restores accepted PoCs from the solve store, and calls ``score_epoch``.  The
existing ``cathedral-cybergym export-scores`` command then freezes the already
closed score DB into the normal score-report wire contract.

It remains restricted to the explicit unattested E2E configuration and is never
a weight-publishing command.
"""
from __future__ import annotations

import argparse
import json
import sys

from cathedral_distill.cybergym_fresh_server import build_service_from_environment


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cathedral-cybergym-fresh-e2e-close",
        description="Restore and close one durable loopback fresh-CyberGym E2E epoch.",
    )
    parser.add_argument(
        "--issued-at",
        required=True,
        help="stable ISO-8601 receipt timestamp (pinned on first close attempt)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    service = build_service_from_environment()
    results = service.score_epoch(issued_at=args.issued_at)
    state, detail = service._scores.epoch_state(service.chain.source_epoch)
    payload = {
        "schema": "cathedral_cybergym_fresh_e2e_close_v1",
        "source_epoch": service.chain.source_epoch,
        "state": state,
        "detail": detail,
        "scored_miners": [result.miner_hotkey for result in results],
        "scores": {
            hotkey: str(score)
            for hotkey, score in service._scores.epoch_scores(service.chain.source_epoch).items()
        },
    }
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
