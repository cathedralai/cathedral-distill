# CyberGym on Intel TDX — the attestation model

A CyberGym solve earns only when it ran inside a genuine Intel TDX enclave and the
validator can verify it. Two Cathedral profiles provide that, with complementary
strengths; [`cybergym_cathedral_attest.py`](../cathedral_distill/cybergym_cathedral_attest.py)
verifies both, fail-closed.

| | `attest.v1` — result quote | `custom.v1` — boot quote |
|---|---|---|
| **What runs** | one bounded command, stock image + uploaded workspace | a customer image on a sealed worker, SSH access |
| **Binds** | the exact `(task, poc, trace)` via `report_data[32:64]` | the machine boot + the customer SSH key |
| **`workload_result_binding`** | yes | no |
| **Real corpus image?** | no (bounded; can't hold the ~4 GB arvo image) | **yes** — runs `n132/arvo:{id}` in TDX |
| **Pricing** | $0.20 / completed receipt | ~$0.40 / worker-hour (Sealed CPU Small), from workload-ready |
| **Adapter** | `verify_cathedral_attestation(...)` | `verify_boot_attestation(...)` |

Both are proven live on real hardware (real Intel DCAP quotes).

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
genuine Intel-TDX boot **and** that the operator's own SSH key — the one used to run the
reproduction — is the key bound into the quote. Result-binding of the PoC then rests on
the sealed worker plus the key-bound SSH session, not a per-result quote.

## Trustless mode

Both verifiers accept a `quote_verifier(quote_b64, expected_report_data_hex)` to check
the raw quote against Intel DCAP collateral instead of trusting Cathedral's own
`intel_verified` flag. The raw-quote/DCAP parse is the standing infrastructure seam; the
binding logic is independent of it and always runs.

## The production real-corpus path

`attest.v1` gives the strongest per-result binding but can't hold the corpus image;
`custom.v1` runs the real corpus image but its boot quote doesn't bind the result. The
production real-ARVO-in-TDX validator combines them: a **persistent `custom.v1` worker**
with the corpus baked in runs the reproduction and emits a signed commitment over
`(task, poc, trace)` — the corpus image of `attest.v1`'s result binding. That is an
infrastructure/build step (a long-lived sealed worker), not a code gap; the verification
adapters for both quote shapes are in place and tested.
