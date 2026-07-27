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
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill import evalset  # noqa: E402
from cathedral_distill import evalset_v1  # noqa: E402
from cathedral_distill import teacher as tc  # noqa: E402
from cathedral_distill import teacher_registry as tr  # noqa: E402
from cathedral_distill.grader import grade_item, parse_model_json  # noqa: E402

TRACKS = {
    # track -> (generator module, sealed eval seed, default training seed)
    "v0": (evalset, 39, 1039),
    "v1": (evalset_v1, 41, 2041),
}
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


def training_items(rows: int, seed: int, track: str = "v0"):
    """Training prompts, verified disjoint from the sealed eval set."""
    builder, eval_seed, _default = TRACKS[track]
    if seed == eval_seed:
        raise SystemExit("training seed must differ from the eval seed")
    eval_items = builder.build(seed=eval_seed)
    forbidden = {
        (i.checks["expected"]["reference"], i.checks["expected"]["title"])
        for i in eval_items
    }
    # v1 bundles contain several documents; also refuse any training prompt
    # that mentions a sealed-set reference anywhere in its text.
    eval_refs = tuple(r for r, _t in forbidden if not r.startswith("CANARY/"))
    # Over-generate, then drop collisions. No canaries in training, ever.
    candidates = builder.build(seed=seed, items=rows + 24, canaries=0)
    kept = [
        item for item in candidates
        if (item.checks["expected"]["reference"],
            item.checks["expected"]["title"]) not in forbidden
        and not any(ref in item.prompt for ref in eval_refs)
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
    parser.add_argument("--track", choices=sorted(TRACKS), default="v0")
    parser.add_argument("--rows", type=int, default=200)
    parser.add_argument("--seed", type=int, default=0,
                        help="training seed; 0 means the track default")
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

    if not args.seed:
        args.seed = TRACKS[args.track][2]

    if args.transport_test:
        items = training_items(3, args.seed, args.track)
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

    items = training_items(args.rows, args.seed, args.track)

    # The licence gate runs once, before any token, exactly as build_corpus
    # would — generation below is streamed rather than batched so a crash at
    # row 150 costs one row, not the whole run.
    registry.assert_permitted(
        client.teacher_id, purpose=tr.PURPOSE_DISTILLATION, at=datetime.now(UTC))

    by_prompt = {i.prompt: i for i in items}

    def verified(record) -> bool:
        if args.track != "v1":
            return keep_extraction(record)
        item = by_prompt.get(record.prompt)
        return item is not None and grade_item(
            item.item_id, record.completion, item.checks).passed

    # Resume: rows already on disk are not regenerated. Seeds are stable per
    # prompt index, so a completed seed identifies a completed row.
    done_seeds: set[int] = set()
    seen_completions: set[str] = set()
    if args.out.exists():
        for line in args.out.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            done_seeds.add(int(row["seed"]))
            seen_completions.add(hashlib.sha256(
                row["completion"].encode()).hexdigest())
        print(f"resuming: {len(done_seeds)} rows already on disk", file=sys.stderr)

    generated = kept_rows = 0
    with args.out.open("a") as handle:
        for index, item in enumerate(items):
            if index in done_seeds:
                continue
            try:
                record = client.generate(item.prompt, seed=index)
            except tc.TeacherError as exc:
                print(f"[{index}] permanent failure, skipping: {exc}", file=sys.stderr)
                continue
            generated += 1
            content_key = hashlib.sha256(record.completion.encode()).hexdigest()
            if content_key in seen_completions or not verified(record):
                continue
            seen_completions.add(content_key)
            handle.write(json.dumps(record.as_dict(), sort_keys=True) + "\n")
            handle.flush()  # a killed process must not lose the last rows
            kept_rows += 1
            if kept_rows % 10 == 0:
                print(f"[{index + 1}/{len(items)}] kept {kept_rows}", file=sys.stderr)

    kept = [
        tc.DistillRecord(
            prompt=r["prompt"], completion=r["completion"],
            teacher_id=r["teacher_id"], sampling=r["sampling"], seed=r["seed"],
            top_k_logprobs=r["top_k_logprobs"], reasoning=r.get("reasoning"),
            record_hash=r["record_hash"])
        for r in (json.loads(l) for l in args.out.read_text().splitlines() if l.strip())
    ]
    manifest = tc.corpus_manifest(kept)
    manifest["generated_rows"] = generated
    manifest["kept_rows"] = len(kept)
    manifest["track"] = args.track
    manifest["training_seed"] = args.seed
    manifest["disjoint_from_eval_seed"] = TRACKS[args.track][1]
    manifest["with_reasoning"] = sum(r.reasoning is not None for r in kept)
    manifest_path = args.out.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"kept {len(kept)} rows ({generated} generated this run) -> {args.out}",
          file=sys.stderr)
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
