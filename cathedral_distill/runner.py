"""The evaluation runner — the program the attested eval image executes.

Contract, inherited from `sat-king` because the quote binds
`sha256(image_digest ‖ sha256hex(stdout))`:

- **stdout carries exactly one artifact**: the canonical pre-attestation receipt
  bytes from `polaris_attest.polaris_stdout`. No banner, no progress, no
  trailing newline. Anything else on stdout silently breaks the hardware
  binding, which is why `main()` swaps `sys.stdout` for stderr around the whole
  run and only touches the real fd once, at the end, in binary mode.
- Every diagnostic goes to stderr.
- Inputs are read from fixed mount paths; per-item results are written to an
  artifact file so a validator can later demand Merkle openings
  (`challenge.py`) without the receipt having to carry every output.

The runner takes a *backend* — any `(prompt) -> text` callable. `command_backend`
wraps a subprocess per item (the shape VerifyML's `run-local` uses, so a
llama.cpp / ollama invocation drops straight in); tests inject a plain function.
The runner does not know or care whether the model is real: its receipt is about
binding whatever ran, not vouching for it.

Latency is measured around the backend call per item. Token counts are
whitespace token counts of prompt and output — an approximation, but one the
enclave computes identically for every submission, which is what comparability
requires. The receipt schema treats them as workload facts, not billing.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Callable, Sequence

from cathedral_distill import eval_receipt as er
from cathedral_distill import polaris_attest as pa
from cathedral_distill.grader import grade_item, grader_digest
from cathedral_distill.sealed_set import EvalItem

_QUANT = Decimal("0.000000000001")

# The decode contract the backend is expected to honour. Digested into
# `runtime.decode_digest`, so a score is only comparable to another score
# produced under the same sampling identity.
DEFAULT_DECODE = {"temperature": 0, "seed": 39, "max_tokens": 1024, "top_p": 1.0}


def decode_digest(params: dict) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(
        json.dumps(params, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class RunnerError(RuntimeError):
    """Raised when the run cannot produce a valid receipt."""


@dataclass(frozen=True)
class ItemOutcome:
    """One graded item, retained for Merkle openings."""

    item_id: str
    output_commitment: str
    passed: bool
    latency_ms: Decimal


@dataclass(frozen=True)
class RunResult:
    receipt: dict
    outcomes: tuple[ItemOutcome, ...]
    leaves: tuple[bytes, ...]


def command_backend(template: str, *, timeout_s: float = 120.0) -> Callable[[str], str]:
    """Wrap a shell-free subprocess as a backend.

    `template` is split with shlex once, at construction. The prompt travels on
    stdin — never in argv, where it would hit length limits and process listings.
    """
    argv = shlex.split(template)
    if not argv:
        raise RunnerError("empty backend command")

    def infer(prompt: str) -> str:
        proc = subprocess.run(
            argv,
            input=prompt.encode("utf-8"),
            capture_output=True,
            timeout=timeout_s,
        )
        if proc.returncode != 0:
            # A crashed inference is an empty output: it grades as a fail on
            # every field rather than aborting the whole run, because one bad
            # item must not void an otherwise honest receipt.
            print(
                f"[runner] backend exit {proc.returncode}: "
                f"{proc.stderr.decode(errors='replace')[:200]}",
                file=sys.stderr,
            )
            return ""
        return proc.stdout.decode("utf-8", errors="replace")

    return infer


def _tokens(text: str) -> int:
    return len(text.split())


def _percentile(sorted_values: Sequence[Decimal], q: float) -> Decimal:
    """Nearest-rank percentile on a pre-sorted list. Deterministic, no interpolation."""
    if not sorted_values:
        return Decimal(0)
    rank = max(1, -(-int(q * len(sorted_values) * 100) // 100))  # ceil
    return sorted_values[min(rank, len(sorted_values)) - 1]


def run_eval(
    items: Sequence[EvalItem],
    infer: Callable[[str], str],
    *,
    identity: dict,
    model: dict,
    runtime: dict,
    evalset: dict,
    decode: dict | None = None,
) -> RunResult:
    """Run every item, grade deterministically, build the pre-attestation receipt.

    `identity` carries the fields the validator authorised (network, netuid,
    epoch, eval_id, hotkeys, nonce, times, block window) — the runner binds them
    verbatim and invents none of them.
    """
    if not items:
        raise RunnerError("no items to evaluate")

    runtime = dict(runtime)
    runtime.setdefault("decode_digest", decode_digest(decode or DEFAULT_DECODE))

    outcomes: list[ItemOutcome] = []
    leaves: list[bytes] = []
    latencies: list[Decimal] = []
    input_tokens = 0
    output_tokens = 0

    for item in items:
        started = time.monotonic()
        output = infer(item.prompt)
        elapsed_ms = Decimal(str(round((time.monotonic() - started) * 1000.0, 3)))

        verdict = grade_item(item.item_id, output, item.checks)
        commitment = er.digest_bytes((output or "").encode("utf-8"))

        outcomes.append(
            ItemOutcome(
                item_id=item.item_id,
                output_commitment=commitment,
                passed=verdict.passed,
                latency_ms=elapsed_ms,
            )
        )
        leaves.append(er.item_leaf(item.item_id, commitment, verdict.passed))
        latencies.append(elapsed_ms)
        input_tokens += _tokens(item.prompt)
        output_tokens += _tokens(output or "")
        print(
            f"[runner] {item.item_id} passed={verdict.passed} "
            f"reason={verdict.reason or '-'} ms={elapsed_ms}",
            file=sys.stderr,
        )

    graded = len(outcomes)
    passed = sum(1 for outcome in outcomes if outcome.passed)
    score = er.canonical_decimal(
        (Decimal(passed) / Decimal(graded)).quantize(_QUANT)
    )
    ordered = sorted(latencies)
    p50 = _percentile(ordered, 0.50)
    p95 = _percentile(ordered, 0.95)

    receipt = {
        "schema": er.SCHEMA,
        **identity,
        "model": dict(model),
        "runtime": dict(runtime),
        "evalset": dict(evalset),
        "grader": {
            "grader_id": "extraction_exact_v0",
            "grader_digest": grader_digest(),
            "harness_digest": harness_digest(),
        },
        "score": {
            "graded_items": graded,
            "passed_items": passed,
            "score": score,
            "items_root": er.items_root(leaves),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "latency_p50_ms": er.canonical_decimal(p50),
            "latency_p95_ms": er.canonical_decimal(p95 if p95 >= p50 else p50),
            "work_units": str(graded),
        },
        "eval_authorization": None,
        "attestation": dict(pa._BLANK_ATTESTATION),
    }
    return RunResult(receipt=receipt, outcomes=tuple(outcomes), leaves=tuple(leaves))


def harness_digest() -> str:
    """Content digest of this runner, pinned in the receipt as `harness_digest`."""
    import hashlib

    return "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def write_outcomes(outcomes: Sequence[ItemOutcome], path: Path) -> None:
    """Persist per-item results for later Merkle openings, one JSON line each."""
    with path.open("w", encoding="utf-8") as handle:
        for outcome in outcomes:
            handle.write(
                json.dumps(
                    {
                        "item_id": outcome.item_id,
                        "output_commitment": outcome.output_commitment,
                        "passed": outcome.passed,
                        "latency_ms": str(outcome.latency_ms),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cathedral-eval-runner")
    parser.add_argument("--identity", required=True,
                        help="JSON file with the validator-authorised identity fields")
    parser.add_argument("--model", required=True,
                        help="JSON file with model_id/weights_digest/tokenizer_digest")
    parser.add_argument("--runtime", required=True,
                        help="JSON file with image_digest/runner_digest")
    parser.add_argument("--evalset-meta", required=True,
                        help="JSON file with the receipt's evalset block")
    parser.add_argument("--items", required=True,
                        help="JSON file of eval items (opened inside the enclave)")
    parser.add_argument("--backend-command", required=True,
                        help="command template; prompt arrives on stdin")
    parser.add_argument("--decode-params",
                        help="JSON file of sampling params; defaults to the "
                             "canonical DEFAULT_DECODE contract")
    parser.add_argument("--outcomes", default="/cathedral/artifacts/outcomes.jsonl")
    args = parser.parse_args(argv)

    def load(path: str) -> dict:
        return json.loads(Path(path).read_text())

    raw_items = json.loads(Path(args.items).read_text())
    items = [
        EvalItem(item_id=entry["item_id"], prompt=entry["prompt"],
                 checks=entry["checks"])
        for entry in raw_items["items"]
    ]

    # stdout is the binding surface. Anything the run prints must go to stderr,
    # including prints from libraries we do not control — so the whole run
    # executes with stdout redirected, and the receipt bytes are written to the
    # real descriptor exactly once, in binary, with no trailing newline.
    real_stdout = sys.stdout
    with contextlib.redirect_stdout(sys.stderr):
        result = run_eval(
            items,
            command_backend(args.backend_command),
            identity=load(args.identity),
            model=load(args.model),
            runtime=load(args.runtime),
            evalset=load(args.evalset_meta),
            decode=load(args.decode_params) if args.decode_params else None,
        )
        write_outcomes(result.outcomes, Path(args.outcomes))

    real_stdout.buffer.write(pa.polaris_stdout(result.receipt))
    real_stdout.buffer.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
