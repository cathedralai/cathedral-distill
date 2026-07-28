# Shared receipt / lane / config contract

*Issue [cathedral-validator#1](https://github.com/cathedralai/cathedral-validator/issues/1) — "Integrate Compute CPU/GPU and Distill into one configurable validator".*

One validator independently verifies Compute and Distill work and produces **one
auditable SN39 weight vector**. Every lane is verified through the same discipline,
composed under a Cathedral-signed burn + allocation config, and audited end to end.
This document is the shared contract the Validator and Distill repos agree on.

> **Scope / safety.** This is the reviewable integration. It does **not** change the
> currently active live allocation and does **not** enable a new reward lane —
> activation is a separate owner decision. The composer here is not the live signed
> vector; it is the input the publisher/validator would use once activated.

## 1. Lanes and the one tuple they all emit

A *lane* is one verified workload. Every lane, whatever its receipt format, reduces
a verified result to the same contribution tuple:

```json
{ "miner_hotkey": "5…", "receipt_id": "receipt-sha256:…", "work_units": "42" }
```

`work_units` is a canonical decimal string (no floats) that the **validator derives**
from the receipt — never a number the miner or signer asserts.

| Lane id (example)            | Receipt schema                       | Module                        |
|------------------------------|--------------------------------------|-------------------------------|
| `cathedral_confidential_tdx` | `cathedral_assurance_receipt_v2` CPU | `compute_receipt.py`          |
| `cathedral_confidential_gpu` | `cathedral_assurance_receipt_v2` GPU | `compute_receipt.py`          |
| `cathedral_distill`          | `cathedral_distill_receipt_v1`       | `distill_receipt.py`          |
| `cathedral_cybergym`         | `cathedral_cybergym_receipt_v1`      | `cybergym_receipt.py`         |

Lane ids are **not** hard-coded in the composer; they come from the signed
allocation config (§4). Adding a lane is a config entry, not a code change.

## 2. The shared assurance body

`cathedral_assurance_receipt_v2` is the base receipt. `cathedral_distill_receipt_v1`
is a versioned extension of it (`+ evaluation`); the Compute GPU receipt is the same
base `+ platform.gpu`. The shared body — verified by **one** set of functions in
both lanes (`distill_receipt.validate_tcb`, `.canonical_bytes`, `.compute_receipt_id`,
…) — is:

```
schema · receipt_id · signing_key_id · signature · subject_hotkey · epoch_id ·
source_epoch · issued_at · platform_pseudonym · measurement · tcb ·
policy_registry_release · policy_registry_digest · policy_profile_ids ·
channel · work · assurance · lifecycle
```

> **Cross-repo status — not yet reconciled.** "The same base receipt" above is true
> *within this repo*: `compute_receipt.py` and `distill_receipt.py` share one set of
> validation functions over this exact field list. It is **not yet true against
> `cathedralai/cathedralconfidential`**, the authoritative issuer of
> `cathedral_assurance_receipt_v2`. That repo's parser requires an **exact** top-level
> key match with no extension point; `compute_receipt.py` adds a required `platform`
> key that the real issuer never emits and always rejects, and `distill_receipt.py`
> adds `evaluation` the same way. Concretely: a receipt this repo builds is refused by
> `cathedralconfidential`'s own parser, and a receipt `cathedralconfidential` actually
> issues is refused here (`platform` is required). `tests/test_receipt_v2_cross_repo_contract.py`
> pins the real upstream key set and asserts this divergence explicitly, so it stays a
> tracked fact rather than a silent one. Resolving it — extending the upstream schema
> to accept these extensions, or giving the extended receipts their own schema name —
> is an owner decision, not something this repo can close unilaterally.

Shared disciplines (identical across all receipt families):

- **Canonical bytes** — JSON, sorted keys, ASCII, `,`/`:` separators, no whitespace,
  **no floats**; decimal strings for scored values; six-fraction-digit UTC.
- **`receipt_id`** = `receipt-sha256:` + SHA-256 of the canonical body before
  `receipt_id`/`signature` are added; recomputed and compared on verify.
- **Anchored key** — `signing_key_id` is resolved through a signed
  `ReceiptKeyRegistry` (`receipt_keys.py`); the verifier **never** trusts a
  caller-supplied key.
- **Strict TDX/TCB** — 64-hex `measurement`; TCB status known and not `Revoked`;
  32-hex SVN; advisories listed unless `UpToDate`; `debug_enabled` false;
  `collateral_current` true.
- **Replay / epoch binding** — `source_epoch` must equal the authorized epoch.
- **Lifecycle + freshness** — `issued`, no revocation, evidence not expired.

## 3. Compute: CPU TEE + optional confidential GPU

The Compute receipt's `platform` block names the confidential CPU TEE and,
optionally, a confidential GPU bound to it:

- **`cpu_tee`** — which TEE the `measurement` + `tcb` describe:
  - `intel_tdx` — `measurement` is `tdx-measurement-sha256:<64 hex>`; `tcb` is the
    Intel TDX TCB (non-Revoked status, 32-hex SVN, advisories listed unless
    UpToDate, debug OFF, current collateral).
  - `amd_sev_snp` — `measurement` is `sev-snp-measurement-sha384:<96 hex>` (the
    48-byte launch measurement); `tcb` is the SEV-SNP TCB (guest-policy DEBUG
    disabled, versioned bootloader/tee/snp/microcode SVNs, current collateral).
- **`class`** — `confidential_cpu` (the CPU TEE alone is the proof) or
  `confidential_gpu` (a *composite*). The `platform.gpu` block (`cc_mode`,
  `vbios_measurement`, `attestation_report_digest`, `bound_measurement`) admits
  **only** when all hold:
  1. `cc_mode == "on"`;
  2. `bound_measurement == receipt.measurement` — the GPU is bound to *this*
     receipt's confidential guest (its CPU-TEE measurement — the guest binding);
  3. an injected **GPU attestation verifier** confirms the report.

  Because the GPU receipt structurally carries and verifies the full CPU-TEE body and
  must bind to it, **a GPU attestation on its own never admits**. With no verifier
  configured, the GPU lane is `NOT_PROVEN`, never a silent pass.

> **This does NOT yet match Cathedral's live confidential-GPU G4 profile —
> corrected 2026-07-28 after re-verification.** An earlier version of this
> paragraph claimed the live `gcp-g4-rtx-pro-6000-sev-v1` receipt fit this
> contract; re-fetching that receipt live (read-only) shows it does not.
> Its `cpu_tee` is the string `amd_sev` (not `amd_sev_snp` — `_CPU_TEES` does
> not accept it), and, more importantly, the receipt carries **no raw
> `measurement` or `tcb` at all**, for any `cpu_tee` value: no
> `sev-snp-measurement-sha384:` string, no SVN/status/advisory data — only
> `provider`/`profile_id`/`machine_type` and a `verification` block of plain
> booleans (`gpu_attestation_verified`, `guest_binding_verified`,
> `runtime_execution_verified`) that Cathedral itself asserts. The `run_url`
> the receipt references (`/v1/attest/runs/{id}`) 404s, so there is no richer
> endpoint exposing the raw quote material this section's structural checks
> require. Populating `measurement`/`tcb` from this API would mean fabricating
> values to satisfy the regex — exactly the "genuine TEE is not the right
> proof" failure mode `attestation.py` exists to prevent — so this profile is
> **not currently creditable** through `compute_receipt.py`. Closing this gap
> needs either Cathedral exposing real attestation material for this profile,
> or an explicit decision to add a distinct, honestly-weaker "Cathedral
> trusted-issuer" receipt path that doesn't claim independently-checkable
> measurement/TCB evidence — not a silent reuse of the `amd_sev_snp` path.

Two injection seams carry the raw-quote checks, both threaded through
`integrated_feed.verify_lane_receipt`:

- **`gpu_attestation_verifier`** — *required* for a `confidential_gpu` receipt (a
  confidential GPU is separate hardware the CPU-TEE signature can't vouch for);
  absent, the GPU lane is `NOT_PROVEN`.
- **`cpu_quote_verifier`** — *optional* for the CPU TEE. Absent, the receipt is
  admitted on the anchored signature (the trusted-issuer model — the authorized
  signer attested the TEE before signing, which is how the live platform issues
  receipts); present, the raw TDX/SEV-SNP quote is re-verified independently (the
  trustless model). It also re-checks the CPU TEE underneath a GPU composite.

## 4. Remote-controlled signed config (`signed_config.py`)

Two small signed, versioned documents let the validator change economics without a
redeploy. Both are verified with the receipt discipline and fail closed:

- **`cathedral_burn_config_v1`** — `burn.fraction` (decimal) + `burn.burn_hotkey`.
- **`cathedral_lane_allocation_v1`** — `allocations: [{lane, allocation, enabled}]`.

Every apply verifies: **signer authority** (id resolved via the anchored registry),
**network/subnet target** (`network`/`netuid`), **freshness** (validity window +
publication-age ceiling), **rollback protection** (monotonic `config_version`; a
config older than the applied fence is refused), and — for burn — the **burn
destination** against an operator pin.

`resolve_allocation(burn, allocation)` combines them into composer inputs and
enforces the **completeness invariant**: `Σ(enabled allocations) + burn == 1`. A
disabled lane's share is folded into burn.

## 5. Safe composition (`lane_feed.compose_vector`)

One deterministic pre-burn vector. Each lane's `allocation` is its share of the total
emission; `Σ allocation + burn == 1` (fail-closed otherwise). A lane is *contributing*
only if it has positive verified work. **The share of any missing or invalid lane goes
to burn — never to another lane:**

```
effective_burn = 1 − Σ(allocation of contributing lanes)
               = burn_fraction + Σ(allocation of missing/invalid lanes)
```

Per-miner rows normalize to sum 1.0 (the pre-burn grammar `base_component == 0`,
`weight == external_component`); the *variable* effective burn rides in
`burn_snapshot.forced_burn_percentage`. So dropping the Distill lane raises burn — it
does not inflate Compute's earners. After the burn is applied, each contributing
miner's share of the **total** emission equals its configured allocation.

## 6. One pipeline + audit trail (`integrated_feed.py`)

`verify_lane_receipt(kind, receipt, …)` is the single verification entry for all four
receipt kinds and returns a `PASS` / `FAIL` / `NOT_PROVEN` decision. `compose_integrated`
takes a resolved config + the decisions and returns `{feed, audit}`, where the audit
ties each step:

```
receipt_id → verdict → lane contribution → configured allocation → final weight
```

plus per-lane `contributing`/`burned_allocation`, the burn `base`/`effective` fraction,
and the applied `config_version`s. This is the operator's "why did this miner get this
weight" record.

## 7. PASS / FAIL / NOT_PROVEN matrix

Verdicts are **proven**, not asserted. `PASS` = independently verified. `FAIL` = a check
proved the receipt/config wrong. `NOT_PROVEN` = evidence could not be checked (never a
fail-open). Every row below is exercised by the test suite.

| Subject          | PASS (verified)                                             | FAIL (proven wrong)                                            | NOT_PROVEN (uncheckable)                          |
|------------------|-------------------------------------------------------------|---------------------------------------------------------------|---------------------------------------------------|
| **Compute CPU**  | valid TDX body, sig, epoch, freshness → contribution         | bad sig / `debug_enabled` / `Revoked` / wrong epoch / expired  | — (CPU evidence is self-contained)                |
| **Compute GPU**  | composite bound to TDX + verifier admits                     | `cc_mode≠on` / unbound to TDX / verifier rejects               | no GPU attestation verifier configured            |
| **Distill**      | counts cross-check, sig, epoch, freshness → contribution     | `work_units≠passed_items` / bad sig / stale / wrong epoch      | — (evaluation evidence is in the receipt)         |
| **Remote burn**  | signer + target + fresh + version ≥ fence + destination pin  | bad signer / wrong subnet / stale / rollback / wrong dest.     | registry unreachable (operator keeps last-applied) |
| **Remote alloc** | signer + target + fresh + `Σ+burn==1`                        | bad signer / wrong subnet / stale / rollback / incoherent sum  | registry unreachable (operator keeps last-applied) |

A `FAIL` or `NOT_PROVEN` lane forfeits its allocation to **burn** (§5); it never
inflates another lane. Tests: `tests/test_compute_receipt.py`,
`tests/test_signed_config.py`, `tests/test_receipt_contract.py`,
`tests/test_integrated_e2e.py`.

## 8. How the validator consumes this

`cathedral-validator` depends on this package (the `cathedral_distill` modules above)
and, in a default-OFF shadow lane, pulls the signed configs, verifies each lane's
receipts through `verify_lane_receipt`, composes with `compose_integrated`, and logs
the audit trail — without touching the live `validated_supply_v2` thin path. Turning
the composed feed into the signed, broadcast vector is the separate owner activation.
