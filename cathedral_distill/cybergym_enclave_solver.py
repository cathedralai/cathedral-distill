"""The approved CyberGym solver workload — runs INSIDE the attested TDX enclave (#94/#95).

This is the persistent real-corpus path's *worker* half. Its `workload_sha256` is
exactly what `verify_persistent_enclave_attestation` pins as
`expected_workload_sha256`, so only this program can produce a creditable solve.

Inside the enclave it:

1. generates an Ed25519 keypair whose private half never leaves the enclave;
2. runs the vul/fix differential on the dispatched task (the real, corpus-baked
   builds), producing the same `DifferentialResult.solved` the validator would;
3. writes an `enclave_result_bytes` envelope — the public key, the
   `(task, poc, trace, verdict)` commitment, and a signature over it — as its
   result.

A live Cathedral `attest.v1` receipt then binds that result as `result_sha256`
and the program as `workload_sha256`, both under Cathedral's Ed25519 signature
(verified against Intel's DCAP chain). The validator's
`verify_persistent_enclave_attestation` re-checks the workload allowlist, the
result binding, and the signature — so a looked-up PoC signed outside this
workload can never be credited.

Nothing here trusts the caller: the verdict is computed from the differential,
not asserted, and the private key exists only for this process's lifetime.
"""
from __future__ import annotations

import base64
import os
import sys
from typing import Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_distill.cybergym_cathedral_attest import (
    enclave_commitment_bytes,
    enclave_result_bytes,
)
from cathedral_distill.cybergym_verifier import (
    VerifierBackend,
    observe_differential,
    poc_digest,
)

VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"


def solve(
    *,
    task_id: str,
    poc_bytes: bytes,
    trace_id: str,
    miner_hotkey: str,
    nonce: str,
    backend: VerifierBackend,
    signing_key: Ed25519PrivateKey | None = None,
) -> bytes:
    """Run the differential and return the signed enclave result envelope bytes.

    `backend(task_id, poc, mode)` returns the exit code for the vulnerable
    (`mode != "fix"`) or patched build; `DifferentialResult.solved` is the exact
    crash-vuln-and-clean-patch test the validator applies. The verdict is derived,
    never taken from the caller. The commitment binds the dispatched `miner_hotkey`
    and batch `nonce`, so the receipt is valid only for this miner and dispatch and
    cannot be resubmitted by another miner. A fresh key is generated when
    `signing_key` is omitted (the private half never leaves the enclave).
    """
    key = signing_key or Ed25519PrivateKey.generate()
    # Confirmed, never a single observation: this path SIGNS the verdict, so a
    # flaky crash credited here is the hardest kind to unwind (#153).
    result = observe_differential(task_id, poc_bytes, backend)
    verdict = VERDICT_PASS if result.solved else VERDICT_FAIL
    pd = poc_digest(poc_bytes)
    signature = key.sign(
        enclave_commitment_bytes(
            task_id=task_id, poc_sha256=pd, trace_id=trace_id,
            miner_hotkey=miner_hotkey, nonce=nonce, verdict=verdict,
        )
    )
    return enclave_result_bytes(
        enclave_pubkey_b64=base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        task_id=task_id,
        poc_sha256=pd,
        trace_id=trace_id,
        miner_hotkey=miner_hotkey,
        nonce=nonce,
        verdict=verdict,
        signature_b64=base64.b64encode(signature).decode(),
    )


def _backend_from_environment() -> VerifierBackend:
    """The differential backend over the corpus baked into this worker.

    Two shapes, so the same solver runs on either Cathedral profile:

      * a **result-bound `attest.v1`** job — no Docker, no egress, no uploaded
        files, a 60s ceiling: set `CYBERGYM_REPRODUCE_CMD` and the sealed vul/fix
        BINARIES are baked in and driven as sandboxed subprocesses (the
        `cybergym-verify` contract). This is the profile whose receipt binds
        `result_sha256`, so it is the one the persistent-enclave verifier accepts;
      * a **persistent `custom.v1`** worker — set `CYBERGYM_CORPUS_MANIFEST` and the
        sealed vul/fix IMAGES run via Docker.

    Imported lazily so the hardware-free path (and this module's tests) never need
    Docker or the binaries.
    """
    reproduce_cmd = os.environ.get("CYBERGYM_REPRODUCE_CMD", "").strip()
    if reproduce_cmd:
        from cathedral_distill.cybergym_verifier import sandboxed_subprocess_backend

        return sandboxed_subprocess_backend(reproduce_cmd)

    from cathedral_distill.cybergym_repro import docker_reproduce_backend
    from cathedral_distill.cybergym_repro_manifest import load_private_repro_manifest_file

    manifest = load_private_repro_manifest_file(_required("CYBERGYM_CORPUS_MANIFEST"))

    def backend(task_id: str, poc: bytes, mode: str) -> int:
        return docker_reproduce_backend(task_id, poc, mode, manifest=manifest)

    return backend


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def _poc_from_environment() -> bytes:
    """The miner's PoC. An `attest.v1` job cannot take an uploaded file, so the PoC
    arrives base64 in `CYBERGYM_POC_B64` (part of the bound workload); the Docker
    path may instead mount it at `CYBERGYM_POC_PATH`."""
    b64 = os.environ.get("CYBERGYM_POC_B64", "").strip()
    if b64:
        import base64 as _b64

        return _b64.b64decode(b64, validate=True)
    with open(_required("CYBERGYM_POC_PATH"), "rb") as handle:
        return handle.read()


def main(argv: Sequence[str] | None = None) -> int:
    """Enclave entrypoint: read the dispatched task/poc/trace, solve, emit the result.

    Inputs come from the protected, bound environment (never stdin the caller
    controls after dispatch):

        CYBERGYM_TASK_ID          the dispatched task id
        CYBERGYM_POC_B64          the miner's PoC, base64 (attest.v1: no uploads)
        CYBERGYM_POC_PATH         or a mounted PoC file (Docker/custom.v1 path)
        CYBERGYM_TRACE_ID         the reasoning-trace id bound into the commitment
        CYBERGYM_MINER_HOTKEY     the dispatched miner, bound into the commitment
        CYBERGYM_NONCE            the batch nonce, bound into the commitment
        CYBERGYM_REPRODUCE_CMD    the baked-binary differential (attest.v1), or
        CYBERGYM_CORPUS_MANIFEST  the digest-pinned image manifest (Docker path)

    The signed envelope is written to stdout — its sha256 is what the Cathedral
    receipt binds as `result_sha256`.
    """
    envelope = solve(
        task_id=_required("CYBERGYM_TASK_ID"),
        poc_bytes=_poc_from_environment(),
        trace_id=_required("CYBERGYM_TRACE_ID"),
        miner_hotkey=_required("CYBERGYM_MINER_HOTKEY"),
        nonce=_required("CYBERGYM_NONCE"),
        backend=_backend_from_environment(),
    )
    sys.stdout.buffer.write(envelope)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
