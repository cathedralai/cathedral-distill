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

from cathedral_distill.cybergym import DifferentialResult
from cathedral_distill.cybergym_cathedral_attest import (
    enclave_commitment_bytes,
    enclave_result_bytes,
)
from cathedral_distill.cybergym_verifier import VerifierBackend, poc_digest

VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"


def solve(
    *,
    task_id: str,
    poc_bytes: bytes,
    trace_id: str,
    backend: VerifierBackend,
    signing_key: Ed25519PrivateKey | None = None,
) -> bytes:
    """Run the differential and return the signed enclave result envelope bytes.

    `backend(task_id, poc, mode)` returns the exit code for the vulnerable
    (`mode != "fix"`) or patched build; `DifferentialResult.solved` is the exact
    crash-vuln-and-clean-patch test the validator applies. The verdict is derived,
    never taken from the caller. A fresh key is generated when `signing_key` is
    omitted (the production path — the private half never leaves the enclave).
    """
    key = signing_key or Ed25519PrivateKey.generate()
    vul = int(backend(task_id, bytes(poc_bytes), "vul"))
    fix = int(backend(task_id, bytes(poc_bytes), "fix"))
    result = DifferentialResult(task_id=task_id, vul_exit_code=vul, fix_exit_code=fix)
    verdict = VERDICT_PASS if result.solved else VERDICT_FAIL
    pd = poc_digest(poc_bytes)
    signature = key.sign(
        enclave_commitment_bytes(
            task_id=task_id, poc_sha256=pd, trace_id=trace_id, verdict=verdict
        )
    )
    return enclave_result_bytes(
        enclave_pubkey_b64=base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        task_id=task_id,
        poc_sha256=pd,
        trace_id=trace_id,
        verdict=verdict,
        signature_b64=base64.b64encode(signature).decode(),
    )


def _docker_backend_from_environment() -> VerifierBackend:
    """The production differential backend over the corpus baked into this worker.

    Reads the digest-pinned private manifest the image ships with and runs the
    sealed vul/fix images via Docker, network-isolated. Imported lazily so the
    hardware-free path (and this module's tests) never require Docker.
    """
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


def main(argv: Sequence[str] | None = None) -> int:
    """Enclave entrypoint: read the dispatched task/poc/trace, solve, emit the result.

    Inputs come from the protected environment and a mounted PoC file, never from
    stdin the caller controls after dispatch:

        CYBERGYM_TASK_ID          the dispatched task id
        CYBERGYM_POC_PATH         path to the miner's PoC bytes
        CYBERGYM_TRACE_ID         the reasoning-trace id bound into the commitment
        CYBERGYM_CORPUS_MANIFEST  the digest-pinned manifest baked into this worker

    The signed envelope is written to stdout — its sha256 is what the Cathedral
    receipt binds as `result_sha256`.
    """
    task_id = _required("CYBERGYM_TASK_ID")
    trace_id = _required("CYBERGYM_TRACE_ID")
    with open(_required("CYBERGYM_POC_PATH"), "rb") as handle:
        poc_bytes = handle.read()
    envelope = solve(
        task_id=task_id,
        poc_bytes=poc_bytes,
        trace_id=trace_id,
        backend=_docker_backend_from_environment(),
    )
    sys.stdout.buffer.write(envelope)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
