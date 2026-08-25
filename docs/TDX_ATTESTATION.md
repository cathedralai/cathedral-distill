# CyberGym on Intel TDX — the attestation model

A CyberGym solve earns only when it ran inside a genuine Intel TDX enclave and the
validator can verify it. `verify_submission_receipt`
([`cybergym_attest.py`](../cathedral_distill/cybergym_attest.py)) routes **three** profiles,
fail-closed — each attesting a strictly stronger property than the last:

| | `attest.v1` — result quote | `persistent_enclave` — baked-corpus worker | `agent_enclave` — in-enclave agent |
|---|---|---|---|
| **What runs** | one bounded command, stock image + uploaded workspace | a persistent worker with the corpus baked in and an enclave-held key runs the vul/fix differential on a **supplied** PoC | the reasoning agent **manufactures** the PoC inside a firewalled enclave, and the same enclave runs the differential |
| **Binds** | the exact `(task, poc, trace)` via `report_data[32:64]` | `workload_sha256` + `result_sha256` — the approved solver's envelope signs `(task, poc, trace, verdict)` | the above **plus** a pinned workload and a **verified egress allowlist** |
| **What it proves** | a bounded command ran attested — synthetic tasks only (a bounded enclave can't hold the ~4 GB arvo image) | an approved solver **verified** this PoC in a real enclave. The PoC is an **input**, so this does *not* prove the PoC was found there | the PoC was **discovered** inside the firewalled enclave — the anti-lookup control |
| **Real corpus image?** | no | **yes** | **yes** |
| **Adapter** | `verify_cathedral_attestation(...)` | `verify_persistent_enclave_attestation(...)` | routed in `verify_submission_receipt`; worker `cybergym_agent_enclave_solver.py` |

`attest.v1` is proven live on real hardware (real Intel DCAP quotes). The persistent-enclave
verifier **and** its worker (`cybergym_enclave_solver.py`) are implemented and tested — but
because the PoC is supplied to that worker, it attests **verification, not discovery**: a
miner can look up a PoC and feed it in. The `agent_enclave` profile is the control that
closes that gap by attesting discovery, and it is **not yet live** — no restricted-egress
Cathedral profile exists to obtain a real receipt (`cybergym_agent_enclave_solver` runs under
a simulation harness today; egress is not enforced). That is the remaining anti-lookup
build, tracked as `cathedral-compute#142`.

> **`custom.v1` boot quote** (`verify_boot_attestation`) binds only the machine boot and the
> customer SSH key — `workload_result_binding` is always false — so it is **not** a submission
> credit path: `verify_submission_receipt` does not route it.

## `attest.v1` — result-bound solve

The miner's solve runs as a one-shot TDX job and writes `result.txt` = a canonical
commitment to `(task_id, poc_sha256, trace_id)`. Cathedral binds it into the quote:

```
report_data[0:32]  = sha256(nonce_hex || e2e_pubkey_b64)
report_data[32:64] = sha256(bound_digest || result_sha256 || egress_log_sha
                            || files_sha || policy_sha || artifacts_sha)
```

`verify_cathedral_attestation` checks the receipt is genuine Intel-TDX and **sealed**
(`reuse=forbidden`, `egress=none`, `tdx_cpu`), then recomputes the commitment from the
submitted `(task, poc, trace)` and matches it to the attested artifact digest. An
attestation cannot be replayed for another task, lifted from another miner, or paired
with an out-of-enclave trace. Because the enclave is bounded, this path runs **synthetic**
tasks (the un-cheatable holdout), which solve fully in-enclave.

## `custom.v1` — real corpus image, in TDX

> **Background / design note.** This section walks through the `custom.v1` boot-quote
> mechanics and their evolution into the persistent enclave. Per the routing table above,
> the boot quote is **not** a submission credit path (`verify_submission_receipt` does not
> route it); the live credit paths are `attest.v1` / `persistent_enclave` / `agent_enclave`;
> and the persistent enclave attests *verification*, not *discovery* — the `agent_enclave`
> profile (`cathedral-compute#142`), not yet live, is the anti-lookup control.

A sealed TDX worker keeps the **real** `n132/arvo:{id}-vul` build running with SSH access
after a *verified boot*. The miner SSHes in and runs the genuine reproduction
(`/bin/arvo`) — the real crash happens inside Intel TDX — then submits the PoC; the
validator runs the real vul/fix differential and scores it.

The boot quote binds the machine + the customer key, not the PoC output:

```
report_data[0:32] = sha256(nonce_hex || base64(customer_ssh_public_key))
verified = intel_verified (quote chains to the Intel TDX PCK cert)
           AND binding_verified (the report_data above matches)
```

`verify_boot_attestation(receipt, expected_ssh_pubkey=...)` confirms the worker is a
genuine Intel-TDX boot **and** that the miner's registered SSH key is the key bound into
the quote.

**Safety — this attests the environment, not the solve.** Two limits:

1. The miner's registered `expected_ssh_pubkey` is required. Without it, a pass could
   only prove "*some* TDX worker booted", which any party with any `custom.v1` worker
   satisfies, so the verifier refuses outright (`attested=False`) instead of returning
   a key-unbound pass. A stale, future-dated, or timestamp-less receipt is refused on
   the same freshness bounds as `verify_cathedral_attestation`.
2. Even key-bound, the quote does **not** bind the PoC (`result_bound` is always false):
   the customer holds the SSH private key, so a miner could present a valid key-bound boot
   quote alongside a PoC obtained anywhere (looked up). It is defense-in-depth /
   environment attestation, **not** proof-of-solve.

## Trustless mode

Both verifiers accept a `quote_verifier(quote_b64, expected_report_data_hex)` to check
the raw quote against Intel DCAP collateral instead of trusting Cathedral's own
`intel_verified` flag. The raw-quote/DCAP parse is the standing infrastructure seam; the
binding logic is independent of it and always runs.

## The production real-corpus path

`attest.v1` gives the strongest per-result binding but can't hold the corpus image;
`custom.v1` runs the real corpus image but its boot quote binds only the environment. The
production real-ARVO-in-TDX validator combines them: a **persistent `custom.v1` worker**
with the corpus baked in, where the **enclave generates its own signing keypair** (private
key never leaves the enclave) and the boot quote binds that enclave key. The enclave runs
the reproduction and **signs a commitment over `(task, poc, trace)`** — so the output is
bound to the attested enclave, and a miner cannot sign a looked-up PoC's commitment outside
it. (Binding the *customer's* SSH key, as the plain SSH flow does, does not achieve this —
the customer holds that private key.)

The **verifier** for this is `verify_persistent_enclave_attestation`. Its binding matches
what a live Cathedral `attest.v1` receipt actually exposes (`cathedral_customer_receipt_v1`,
confirmed on real hardware 2026-08-05): the receipt binds `workload_sha256` and
`result_sha256` under Cathedral's Ed25519 signature, verified against Intel's DCAP chain — it
does **not** expose a `report_data[0:32] = nonce||pubkey` field. So the enclave key rides in
the result, exactly the way `attest.v1` already binds its `result.txt` commitment. The
approved solver writes an `enclave_result_bytes` envelope — its generated public key, the
`(task, poc, trace[, verdict])` commitment, and a signature over it — as its result. The
verifier then requires three bindings:

1. `workload_sha256 == expected_workload_sha256` — only the approved solver ran, so a miner
   cannot substitute a workload that echoes a looked-up answer;
2. `sha256(result_bytes) == result_sha256` — the attested result IS that envelope, so its
   committed solve cannot be swapped;
3. the enclave signature over the commitment — the trustless-external layer (#95): an outside
   party confirms the verdict from the signature alone, no corpus and no re-execution.

Receipt trust is the same seam as `verify_cathedral_attestation`: trusted-issuer by default
(`intel_verified` + `report_data_match` + `execution_binding_verified`), or independent via
`receipt_verifier` (cathedral-compute's `verify_customer_receipt`). `result_bound=True` only
when all three hold, on the same freshness bounds as `attest.v1`.

The enclave **worker** is
[`cybergym_enclave_solver`](../cathedral_distill/cybergym_enclave_solver.py), packaged by
[`Dockerfile.cybergym-enclave`](../Dockerfile.cybergym-enclave). It generates the keypair,
runs the same `DifferentialResult.solved` differential the validator would, and writes the
signed `enclave_result_bytes` envelope as its result — so `solve()`'s output is exactly what
`verify_persistent_enclave_attestation` accepts (proven by `test_cybergym_enclave_solver`).
What remains is purely operational: baking the vul/fix corpus into the image and running it as
a Cathedral persistent worker.
