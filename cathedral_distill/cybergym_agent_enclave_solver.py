"""Agent-in-enclave CyberGym workload — the agent MANUFACTURES the PoC and the SAME
enclave runs the differential and signs the result.

Where :func:`cathedral_distill.cybergym_enclave_solver.main` *ingests* a pre-made PoC
(``CYBERGYM_POC_B64``) and only runs+signs the differential, this entrypoint runs the
reasoning agent (:func:`cathedral_distill.cybergym_agent.run_agent`) to *produce* the
PoC inside the enclave, then hands that PoC to
:func:`cathedral_distill.cybergym_enclave_solver.solve` over the **same** differential
backend. The attested result therefore binds a solve this enclave both reasoned out and
verified — the workload behind a firewalled-egress ``PROFILE_AGENT_ENCLAVE`` receipt.

TRUST INVARIANT (the reason this is not "trust the agent"): the envelope verdict is
DERIVED by ``solve()`` from an INDEPENDENT vul/fix differential run, never from the
agent's own ``run_poc``. An agent that lies about a crash still yields a signed
``VERDICT_FAIL`` — ``solve()`` is the authority, exactly as the validator's
``verify_persistent_enclave_attestation`` re-derives it.

ONE differential backend is shared by BOTH halves (the agent's ``run_poc`` and
``solve()``), built via the solver's ``_backend_from_environment`` so it is the
ASan-safe ``sandboxed_subprocess_backend`` (``memory_bytes=None`` — virtual AS is never
capped). This deliberately avoids the 1 GiB ``RLIMIT_AS`` cap on the agent-screening
driver path (``agent_contract._limits``), which would silently turn every real
sanitizer crash into a "no crash".

WHAT THIS MODULE DOES NOT DO (enforced elsewhere / tracked):
  * Egress is not enforced here. The agent's model call rides ``complete``; in the
    enclave that must be pinned to the allowlisted model host by the container/enclave
    network layer (see ``AGENT_ENCLAVE_EGRESS`` / cathedral-compute#142). This module is
    transport- and network-agnostic.
  * The reasoning trace is produced here (``AgentResult.trace``) but its BYTES are not
    yet folded into ``enclave_commitment_bytes`` — only ``trace_id`` is bound. Binding
    ``sha256(trace)`` into the signed commitment is a commitment-schema change tracked
    for adversarial review, not done in this slice.
  * No live restricted-egress Cathedral profile exists yet to obtain a real receipt, so
    today this runs under the local simulation harness / a synthetic corpus, not attested
    TDX.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable, Mapping, Sequence

from cathedral_distill.cybergym_agent import AgentResult, run_agent
from cathedral_distill.cybergym_enclave_solver import (
    _backend_from_environment,
    _required,
    solve,
)
from cathedral_distill.cybergym_verifier import VerifierBackend

# The agent produced no PoC (budget exhausted / no crash found): there is nothing to
# attest, so emit no envelope and exit non-zero rather than sign an empty solve.
NO_POC_EXIT = 2


def solve_with_agent(
    *,
    task_id: str,
    trace_id: str,
    miner_hotkey: str,
    nonce: str,
    complete: Callable[[list[dict[str, Any]]], str],
    workspace: Mapping[str, str],
    backend: VerifierBackend,
    model_id: str,
    signing_key=None,
    max_turns: int = 10,
    on_step: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[AgentResult, bytes | None]:
    """Run the agent to manufacture a PoC, then run+sign the differential over it.

    ``complete`` is the (enclave-pinned) chat model; ``workspace`` maps file paths to
    contents (at minimum the vulnerable build); ``backend`` is the shared ASan-safe
    differential runner used by BOTH the agent and ``solve()``.

    Returns ``(agent_result, envelope)``. ``envelope`` is ``None`` iff the agent
    produced no PoC — the caller then attests nothing. When a PoC is produced, the
    envelope's verdict is re-derived by ``solve()`` from an independent vul/fix run, so
    it is authoritative regardless of what the agent claimed.
    """
    result = run_agent(
        complete,
        task_id=task_id,
        workspace=workspace,
        backend=backend,
        miner_hotkey=miner_hotkey,
        model_id=model_id,
        max_turns=max_turns,
        on_step=on_step,
    )
    if result.poc is None:
        return result, None
    envelope = solve(
        task_id=task_id,
        poc_bytes=result.poc,
        trace_id=trace_id,
        miner_hotkey=miner_hotkey,
        nonce=nonce,
        backend=backend,
        signing_key=signing_key,
    )
    return result, envelope


def _completer_from_environment() -> Callable[[list[dict[str, Any]]], str]:
    """Build the chat completer from the enclave-pinned inference route.

    ``CYBERGYM_INFERENCE_BASE`` must point at the allowlisted model host (in a real
    enclave, the localhost gateway the egress firewall permits). The provider key rides
    ``CYBERGYM_INFERENCE_KEY``; ``CYBERGYM_MODEL`` selects the model bound into the trace.
    Imported lazily so tests can inject ``complete`` without the CLI's HTTP client.
    """
    from cathedral_distill.cybergym_agent_cli import make_completer

    base = _required("CYBERGYM_INFERENCE_BASE")
    key = os.environ.get("CYBERGYM_INFERENCE_KEY", "").strip()
    model = _required("CYBERGYM_MODEL")
    return make_completer(base, key, model)


def _workspace_from_environment() -> dict[str, str]:
    """The files the agent may read (the vulnerable build + level hints).

    ``CYBERGYM_WORKSPACE_DIR`` is a directory whose text files become the
    ``{relative_path: contents}`` mapping. In the real enclave this is where the sealed
    corpus is unwrapped AFTER attestation (attest.v1 has no mount, so a public image
    cannot carry the vulnerable build — it is the answer); here it is a plain directory.
    """
    root = _required("CYBERGYM_WORKSPACE_DIR")
    workspace: dict[str, str] = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            try:
                with open(full, encoding="utf-8") as handle:
                    workspace[rel] = handle.read()
            except (OSError, UnicodeDecodeError):
                continue  # skip binaries / unreadable files — the agent reads source text
    if not workspace:
        raise SystemExit(f"CYBERGYM_WORKSPACE_DIR is empty or unreadable: {root}")
    return workspace


def main(argv: Sequence[str] | None = None) -> int:
    """Enclave entrypoint: run the agent, run+sign the differential, emit the envelope.

    Inputs come from the protected, bound environment:

        CYBERGYM_TASK_ID          the dispatched task id
        CYBERGYM_TRACE_ID         the reasoning-trace id bound into the commitment
        CYBERGYM_MINER_HOTKEY     the dispatched miner, bound into the commitment
        CYBERGYM_NONCE            the batch nonce, bound into the commitment
        CYBERGYM_MODEL            the model id (bound into the trace)
        CYBERGYM_INFERENCE_BASE   the enclave-pinned, allowlisted model endpoint
        CYBERGYM_INFERENCE_KEY    the provider key (optional; localhost gateway may inject)
        CYBERGYM_WORKSPACE_DIR    the unwrapped vulnerable build the agent reads
        CYBERGYM_REPRODUCE_CMD    the baked-binary differential (attest.v1), or
        CYBERGYM_CORPUS_MANIFEST  the digest-pinned image manifest (Docker path)

    The signed envelope is written to stdout — its sha256 is what the Cathedral receipt
    binds as ``result_sha256``. The reasoning trace is written to ``CYBERGYM_TRACE_OUT``
    when set. Exit ``NO_POC_EXIT`` (no envelope) when the agent found no crash.
    """
    result, envelope = solve_with_agent(
        task_id=_required("CYBERGYM_TASK_ID"),
        trace_id=_required("CYBERGYM_TRACE_ID"),
        miner_hotkey=_required("CYBERGYM_MINER_HOTKEY"),
        nonce=_required("CYBERGYM_NONCE"),
        complete=_completer_from_environment(),
        workspace=_workspace_from_environment(),
        backend=_backend_from_environment(),
        model_id=_required("CYBERGYM_MODEL"),
    )
    if envelope is None:
        sys.stderr.write(f"no PoC produced ({result.reason}); nothing to attest\n")
        return NO_POC_EXIT
    # Emit the authoritative signed result FIRST: the envelope is the receipt-bound
    # output, so a later error on the OPTIONAL diagnostic trace write must never be
    # able to drop a genuine solve.
    sys.stdout.buffer.write(envelope)
    sys.stdout.buffer.flush()
    trace_out = os.environ.get("CYBERGYM_TRACE_OUT", "").strip()
    if trace_out and result.trace is not None:
        try:
            with open(trace_out, "w", encoding="utf-8") as handle:
                json.dump(result.trace, handle, sort_keys=True, separators=(",", ":"))
        except OSError as exc:
            sys.stderr.write(f"warning: could not write CYBERGYM_TRACE_OUT ({exc})\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
