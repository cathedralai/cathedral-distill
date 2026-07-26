#!/usr/bin/env python3
"""Generate a distillation corpus for the hermes-extract track.

One command once a teacher endpoint exists:

    TEACHER_BASE_URL=https://... TEACHER_API_KEY=... \\
        python3 scripts/make_corpus.py --rows 500 --out corpus.jsonl \\
        --teachers teachers.json

Three rules this script enforces rather than trusts:

**Training and evaluation must be disjoint.** Prompts come from the same
generator as the eval set but a different seed, and the script *verifies*
disjointness — any training item whose reference or title collides with the
sealed eval set (seed 39) is dropped, and canaries are never generated for
training. A corpus that overlaps the eval set would turn every score into a
contamination artefact.

**No registry entry, no corpus.** The licence gate (`teacher_registry`) runs
before the first request. `--transport-test` exists for proving an endpoint
works — it sends up to 3 rows, marks everything it writes `transport_test`,
and its output must never be used as training data.

**Only verified rows survive.** The filter is deterministic: completion parses
as a JSON object, `content_hash` is copied verbatim from the prompt, and
duplicate completions collapse. A teacher that hallucinates hashes or repeats
itself cannot inflate the corpus.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import evalset  # noqa: E402
from cathedral_distill import teacher as tc  # noqa: E402
from cathedral_distill import teacher_registry as tr  # noqa: E402
from cathedral_distill.grader import parse_model_json  # noqa: E402

EVAL_SEED = 39  # the sealed set's seed — training must never reuse it
_HASH_LINE = re.compile(r"^content_hash: ([0-9a-f]{64})$", re.MULTILINE)


def load_teachers(path: Path) -> tr.TeacherRegistry:
    """Load a reviewed-teacher policy file (the `as_policy()` shape)."""
    payload = json.loads(path.read_text())
    if payload.get("schema") != tr.REGISTRY_SCHEMA:
        raise SystemExit(f"{path}: not a {tr.REGISTRY_SCHEMA} document")
    registry = tr.TeacherRegistry()
    for row in payload["teachers"]:
        registry.add(
            tr.TeacherRecord(
                teacher_id=row["teacher_id"],
                licence_digest=row["licence_digest"],
                licence_uri=row["licence_uri"],
                reviewed_at=datetime.fromisoformat(row["reviewed_at"]),
                review_expires_at=datetime.fromisoformat(row["review_expires_at"]),
                reviewer=row["reviewer"],
                permitted_purposes=frozenset(row["permitted_purposes"]),
                commercial_use=bool(row.get("commercial_use")),
                competing_model_training=bool(row.get("competing_model_training")),
                attribution_required=bool(row.get("attribution_required")),
                attribution_threshold=row.get("attribution_threshold", ""),
                attribution_text=row.get("attribution_text", ""),
                notes=row.get("notes", ""),
            )
        )
    return registry


def training_items(rows: int, seed: int):
    """Training prompts, verified disjoint from the sealed eval set."""
    if seed == EVAL_SEED:
        raise SystemExit("training seed must differ from the eval seed")
    eval_items = evalset.build(seed=EVAL_SEED)
    forbidden = {
        (i.checks["expected"]["reference"], i.checks["expected"]["title"])
        for i in eval_items
    }
    # Over-generate, then drop collisions. No canaries in training, ever.
    candidates = evalset.build(seed=seed, items=rows + 16, canaries=0)
    kept = [
        item for item in candidates
        if (item.checks["expected"]["reference"],
            item.checks["expected"]["title"]) not in forbidden
    ][:rows]
    if len(kept) < rows:
        raise SystemExit(f"only {len(kept)} disjoint items available; lower --rows")
    return kept


def keep_extraction(record: tc.DistillRecord) -> bool:
    """A row survives only if the completion is verified against its prompt."""
    parsed, _reason = parse_model_json(record.completion)
    if parsed is None:
        return False
    match = _HASH_LINE.search(record.prompt)
    if match is None:
        return False
    # The raw→verified rule: the hash must be copied verbatim, or the row
    # teaches the exact mistake that sinks Cards in production.
    return parsed.get("content_hash") == match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=200)
    parser.add_argument("--seed", type=int, default=1039)
    parser.add_argument("--out", type=Path, default=Path("corpus.jsonl"))
    parser.add_argument("--teachers", type=Path,
                        help="reviewed-teacher policy JSON (required unless --transport-test)")
    parser.add_argument("--transport-test", action="store_true",
                        help="3 rows max, bypasses the licence gate, output "
                             "marked unusable as training data")
    args = parser.parse_args()

    config = tc.TeacherConfig.from_env()
    client = tc.TeacherClient(config)
    print(f"teacher: {config.teacher_id} via {config.base_url}", file=sys.stderr)

    if args.transport_test:
        items = training_items(3, args.seed)
        records = [client.generate(i.prompt, seed=n) for n, i in enumerate(items)]
        for record in records:
            row = record.as_dict()
            row["transport_test"] = True  # never training data
            print(json.dumps({"ok": True, "record_hash": row["record_hash"],
                              "logprobs": row["top_k_logprobs"] is not None,
                              "chars": len(row["completion"])}))
        print("transport OK — output not written; this mode never produces a corpus",
              file=sys.stderr)
        return 0

    if not args.teachers:
        raise SystemExit("--teachers is required: no registry entry, no corpus")
    registry = load_teachers(args.teachers)

    items = training_items(args.rows, args.seed)
    records = tc.build_corpus(
        client, [i.prompt for i in items],
        registry=registry, at=datetime.now(UTC),
    )
    kept = tc.filter_corpus(records, keep=keep_extraction)
    with args.out.open("w") as handle:
        for record in kept:
            handle.write(json.dumps(record.as_dict(), sort_keys=True) + "\n")

    manifest = tc.corpus_manifest(kept)
    manifest["generated_rows"] = len(records)
    manifest["kept_rows"] = len(kept)
    manifest["training_seed"] = args.seed
    manifest["disjoint_from_eval_seed"] = EVAL_SEED
    manifest_path = args.out.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"kept {len(kept)}/{len(records)} rows -> {args.out}", file=sys.stderr)
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
