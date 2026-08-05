# CyberGym score intake — producer identity and transport runbook

The CyberGym verifier scores miners on its own host and publishes one frozen
report per closed epoch. The canonical validator ingests that report at
`POST /v1/cybergym/scores`, re-verifies it, and composes the CyberGym lane into
the signed weight vector. Nothing crosses that boundary except the exact bytes
of one canonical document plus two credentials.

This is the operator path for wiring that boundary in production: which strings
must match on both hosts, what the HMAC actually covers, in what order the
switches may be thrown, and what each failure looks like from the producer side.

> **Scope.** This document configures a transport. It does not register anything
> on chain, spend TAO, or set weights. It does show how to mint the two shared
> credentials, on the host that will hold them, writing straight to 0600 files —
> no command here prints private material to a terminal, and the runbook never
> asks you to paste a secret into a shell where it would land in history or a
> process listing.

---

## The two sides

| | Producer (this repository) | Validator (`cathedral-validator`) |
|---|---|---|
| Builds | `cathedral-cybergym export-scores` freezes one closed epoch | — |
| Sends | `cathedral-cybergym publish-scores` POSTs the exact frozen bytes | — |
| Accepts | — | `POST /v1/cybergym/scores` (`cybergym_ingest`) |
| Re-verifies | — | `cybergym_contract.verify_stored_report` on every read |
| Composes | — | `cybergym_bridge.cybergym_allocation` → the signed vector |

The producer holds no wallet and calls no chain. The validator is the only
weight writer. The report is the whole interface.

---

## The seven strings that must match

Everything the intake checks is one of these. A mismatch is refused, never
tolerated, and the refusal is always visible in the `publish-scores` exit
message as `score intake refused the report with HTTP <code>: <detail>`.

| What | Producer side | Validator side | Mismatch |
|---|---|---|---|
| Route | `--url .../v1/cybergym/scores` | route mounted on a full-role process | `404 cybergym_ingest_not_enabled`, or a `404` carrying `x-cathedral-rejection-reason: route_not_served_by_<role>_role` |
| Bearer | `--token-file` | `CATHEDRAL_CYBERGYM_SCORES_TOKEN` | `401 invalid_cybergym_token` |
| HMAC secret | `--hmac-secret-file` | `CATHEDRAL_CYBERGYM_SCORES_HMAC_SECRET` | `401 invalid_cybergym_signature` |
| Producer identity | `--producer-hotkey` (frozen into the document) | `CATHEDRAL_CYBERGYM_PRODUCER_HOTKEY` — a plain string compared for equality, not a key | `403 producer_hotkey_mismatch` |
| Network | `--network` | `CATHEDRAL_WEIGHT_POLICY_NETWORK` | `400 cybergym_audience_mismatch` |
| Netuid | `--netuid` | `CATHEDRAL_WEIGHT_POLICY_NETUID` | `400 cybergym_audience_mismatch` |
| Epoch | `--epoch` (the score store's own counter) | strictly increasing per audience | `409 epoch_too_old` / `409 epoch_conflict` |

The audience pair is deliberately read from the SAME two variables the signed
weight vector uses, so an ingested report can only ever belong to the audience
this validator already publishes for. Both are **required**: unset or malformed
is `503 cybergym_audience_not_configured`, never a default. A validator that has
never set them cannot accept a report at all, which is the intended posture —
the alternative is silently ingesting for the wrong subnet.

---

## What the HMAC covers, exactly

`publish-scores` sends two headers:

```text
Authorization: Bearer <contents of --token-file>
X-Cathedral-Cybergym-Signature: sha256=<hex>
```

The signature is `HMAC-SHA256(key = secret UTF-8 bytes, message = the request
body bytes)`, hex-encoded, with the literal prefix `sha256=`. The message is the
**exact bytes of the frozen report file** — not a re-serialization, not the
parsed document, not a canonicalization performed at send time:

* `export-scores` writes the canonical form once (`sort_keys`, `(",", ":")`
  separators, ASCII-escaped, UTF-8) and refuses to overwrite that file with
  different bytes;
* `publish-scores` reads those bytes, re-derives the canonical form, and refuses
  to send if the file is not byte-identical to it;
* those same bytes are HMAC'd and are the request body.

The validator streams the body under a size cap, verifies the HMAC **before**
parsing any JSON, and persists the exact authenticated bytes alongside the
normalized document. Every later read re-verifies that stored HMAC rather than
trusting a column, so a row written into the database by anything without the
secret fails verification and contributes nothing.

Two consequences worth stating plainly:

* **The transport proves possession of a shared secret, not producer identity.**
  Anyone holding the secret can mint a document the validator will accept for the
  configured producer. The `producer_hotkey` field is a declared string compared
  for equality against configuration
  (`scaffold/publisher/cybergym_ingest.py:353-358`) — it is not a signature, not a
  key, and not checked against the chain. The HMAC secret is therefore the entire
  authentication story; treat it with the care that implies.
* **Rotating the HMAC secret makes previously stored reports unverifiable.** That
  fails closed — the lane contributes nothing until a new report arrives under
  the new secret, and its share forfeits to burn — but it is not free. Rotate at
  an epoch boundary and publish immediately afterwards.

Minting the two credentials (run on the host that will hold them, and never
paste the output anywhere):

```bash
umask 077
python3 -c 'import secrets; print(secrets.token_hex(32))' > intake.hmac
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > intake.token
chmod 600 intake.hmac intake.token
```

Both files must be owner-readable only; `publish-scores` refuses group- or
world-accessible credential files. The same two values go into the validator
process environment — by service-manager environment file, not by an
`export` typed at a shell.

---

## Exactly one producer per audience, and the epoch counter is one-way

`CATHEDRAL_CYBERGYM_PRODUCER_HOTKEY` is required, and the epoch fence is scoped
to the **audience**, not to the producer. Those two facts belong together: the
composing adapter reads the single newest complete report for an audience, so a
second admitted producer could outbid the real one simply by posting a higher
epoch. One configured producer plus one audience fence removes that entirely.

The cost is deliberate:

* **Changing the producer identity does NOT reset the epoch counter.** A
  replacement label must continue *above* the highest `source_epoch` already
  stored for that audience. Its first post at a lower epoch is refused
  `409 epoch_too_old`. Because the identity is only a string (step 2), changing it
  is cheap in every respect except this one — which is the expensive one.
* **A test or placeholder identity is not free.** Any epoch accepted under a
  placeholder producer permanently raises the audience's epoch floor. Decide the
  final producer identity *before* the first accepted post.
* **A rebuilt score database is a rollback.** The producer's `source_epoch` comes
  from its own durable score store. Recreating that store restarts the counter at
  a low value and every post is then refused `409 epoch_too_old` until the
  counter passes the stored high-water mark. The durable score database is part
  of the identity; back it up accordingly.

Retries are safe: a byte-identical repost of the newest epoch is idempotent and
answers `200` with `"idempotent": true`. A *different* document at a stored epoch
is `409 epoch_conflict` — the fence never silently replaces a stored epoch.

---

## Order of operations

Each step states what to check and what failure looks like. Do not skip ahead:
the last step is the only one that can change a live weight vector.

### 1. Schema

The validator database must carry the two CyberGym tables
(`cybergym_score_reports`, `cybergym_scores`). They arrive with the publisher's
own migrations and are applied at process start.

*Check:* both tables exist in the database the validator process is configured
against.
*Failure:* the route answers `500 cybergym_store_failed` on POST, and the reader
side logs a missing-table warning and contributes nothing.

### 2. Producer identity

Choose the final producer identity. Set `CATHEDRAL_CYBERGYM_PRODUCER_HOTKEY` on
the validator to exactly that value, and pass the identical string to
`export-scores --producer-hotkey`.

**It is a label, not a key.** Despite the name, this value is never used as a
keypair. The intake reads the document's `producer_hotkey` field, strips
surrounding whitespace, and compares it for **string equality** against the
configured value (`scaffold/publisher/cybergym_ingest.py:353-358`); the producer
side applies the same bounded-string normalization
(`cathedral_distill/cybergym_score_report.py:76-81`). Neither side decodes ss58,
derives an address, checks a signature, or consults the chain. Concretely:

* it does **not** have to be a real keypair — no private key exists for it, and
  none is needed on the producer host;
* it does **not** have to be registered on the target subnet, or on any subnet;
* it is **not** the source of any authentication. Authentication is the bearer
  token and the HMAC, and nothing else. A correct `producer_hotkey` on a document
  with a bad HMAC is refused; a placeholder `producer_hotkey` on a document with a
  good HMAC is accepted if it matches the configured string.

The only constraints the code imposes are that it be a non-empty string of at
most 128 characters and that the two sides agree byte-for-byte. An ss58 address
is a reasonable convention because it is unambiguous and greppable, but it is a
convention — the guarantee is agreement between two configured strings, not
identity.

(The *miner* hotkeys inside `scores` are a different matter: those must resolve
in the metagraph snapshot or the lane reads `no_uid_mapping`. That requirement
does not extend to the producer.)

*Check:* the two strings are byte-identical, including case and any leading or
trailing characters that are not whitespace.
*Failure:* `403 producer_hotkey_mismatch`, and — because the fence is audience
scoped — a wrong value that was ever accepted has already consumed epochs. That
is the real reason to decide this once: not key custody, but the one-way epoch
counter in the next section.

### 3. Audience

Set `CATHEDRAL_WEIGHT_POLICY_NETWORK` and `CATHEDRAL_WEIGHT_POLICY_NETUID` on the
validator process explicitly. Confirm they are the values that process actually
sees: a service manager that exports them *after* sourcing an environment file
wins over the file, and the file is what an operator reads.

*Check:* the running process's audience equals the `--network` / `--netuid` you
will export with.
*Failure:* `503 cybergym_audience_not_configured` when unset,
`400 cybergym_audience_mismatch` when the report disagrees.

### 4. Credentials

Install the bearer and the HMAC secret in the validator process environment
(`CATHEDRAL_CYBERGYM_SCORES_TOKEN`, `CATHEDRAL_CYBERGYM_SCORES_HMAC_SECRET`) and
place the matching 0600 files on the producer host.

*Check:* both are non-empty in the running process.
*Failure:* `503 cybergym_token_required` or `503 cybergym_hmac_secret_required`.
Neither is an "accept unsigned" state — an unconfigured secret refuses, it never
downgrades.

### 5. Open the intake

Set `CATHEDRAL_CYBERGYM_INGEST_ENABLED=1` and restart the process. The route is
served only by a full-role process; narrower service roles answer `404` with an
`x-cathedral-rejection-reason` header naming the role.

*Check:* an unauthenticated POST returns `401`, not `404`. `404` here means the
route is off or the process role does not serve it; `401` means the route is
live and refusing you, which is the correct state before you authenticate.

### 6. Freeze and publish one epoch

```bash
cathedral-cybergym export-scores \
  --score-db "$CYBERGYM_SCORE_DB" --epoch 42 \
  --network finney --netuid 39 \
  --producer-hotkey "$CYBERGYM_PRODUCER_HOTKEY" \
  --out epoch-42.json

cathedral-cybergym publish-scores \
  --report epoch-42.json \
  --url https://<validator-intake-host>/v1/cybergym/scores \
  --token-file intake.token \
  --hmac-secret-file intake.hmac \
  --proof-out epoch-42.proof.json
```

`export-scores` refuses an epoch that is not durably `closed`, so a mid-scoring
epoch cannot be published as if nobody solved it. `generated_at` is the first
persisted close time, never the current clock, which is what makes a repeated
export byte-identical and a delayed retry unable to look fresh.

*Check:* the acceptance JSON on stdout carries `"accepted": true`, the
`report_sha256` you expected, and a `score_count` matching the epoch.
`publish-scores` already verifies both digests and fails if either differs.
*Failure:* the transport is HTTPS-only except on loopback. A self-signed or
private-CA endpoint fails with a certificate error and no flag overrides it; the
supported route is OpenSSL's default verify paths, i.e. point `SSL_CERT_FILE` at
the trusted CA bundle (or `SSL_CERT_DIR` at a hashed directory) in the
environment that runs `publish-scores`.

### 7. Confirm it reads back verified

The composing side re-derives everything: the stored body digest, the stored
HMAC, the normalized semantics, the semantic report digest, every derived column,
and every score row. A stored report that fails any of those contributes nothing
and its share burns.

*Check:* the lane reports `reason: "ok"` and a non-zero `n_uids`.
*Failure reasons to expect, and what each means:* `no_report` (nothing stored for
this audience), `stale` (see the clocks below), `empty_report` (a legal, funded
epoch in which nobody scored — its share burns), `no_uid_mapping` (every scored
hotkey is absent from the metagraph snapshot), `signature_invalid` /
`report_digest_mismatch` / `rows_tampered` (the stored row is not what was
authenticated).

### 8. Turn on the mechanism — last

`CATHEDRAL_CYBERGYM_MECHANISM_ENABLED` and `CATHEDRAL_CYBERGYM_WEIGHT_FRACTION`
are both default-off (`unset` and `0.0`). The fraction is a number in `[0, 1]`;
anything unparseable, negative, or above 1 is refused **down** to `0.0` and
logged, never clamped up — a value of `25` meaning "25 percent" disables the lane
rather than handing it the entire vector.

Ordering constraint: under the v3 allocation contract the CyberGym lane is
mandatory, and the validator refuses to sign the ENTIRE vector if the lane cannot
be composed — including when the mechanism is disabled or the fraction is not
exactly the contract's CyberGym allocation. Set the mechanism switch and the
fraction **first**, confirm step 7, and only then move the allocation contract to
v3. Doing it in the other order stops vector signing outright.

---

## Three clocks, and what each one breaks

| Clock | Bound | Exceeded → |
|---|---|---|
| `generated_at` vs now | `CATHEDRAL_CYBERGYM_MAX_SCORE_AGE_SECS`, default `3600` | lane reads `stale`, contributes nothing, its share forfeits to burn |
| `generated_at` ahead of now | `CATHEDRAL_CYBERGYM_MAX_FUTURE_SKEW_SECS`, default `120` | intake refuses `400 report_in_future`; a stored future-dated row reads as `future_dated` |
| metagraph snapshot age | `CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS_MAX_AGE_SECS`, default `600` | burn destination unresolvable → empty allocation → under v3, the whole vector refuses to sign |

The first clock is the one operators underestimate. `generated_at` is the epoch's
close time and never advances, so the composable lifetime of a report is
`max_score_age` from the moment the epoch closed — not from the moment it was
posted. **The epoch cadence must be shorter than that bound**, or the lane is
stale for part of every cycle and burns its share. If CyberGym epochs close less
often than hourly, raise `CATHEDRAL_CYBERGYM_MAX_SCORE_AGE_SECS` to exceed the
real cadence with margin, deliberately and in writing.

---

## The `metagraph_hotkeys` dependency

The composing bridge resolves two different things through one fresh snapshot of
the `metagraph_hotkeys` table:

* **every recipient's UID→hotkey binding.** A signed UID weight is not a durable
  identity: a deregistered UID can be reassigned before the validator applies the
  vector. The lane carries the hotkey observed for each recipient and refuses to
  compose when a current one-to-one mapping cannot be proven.
* **the burn destination.** It is resolved from the configured burn *hotkey*,
  verified in both directions (the hotkey's UID, and that UID bound to no other
  hotkey). A bare numeric burn UID is never trusted, because UIDs are recycled
  when miners deregister and a guessed UID is how a forfeited share ends up in a
  miner's wallet.

Freshness is a single bound, `CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS_MAX_AGE_SECS`
(default 600 seconds): rows stamped older than that are invisible, and if nothing
survives the filter the snapshot is treated as absent. Absent means refuse.

So the CyberGym lane inherits an availability dependency on whatever keeps that
table fresh. **This runbook deliberately does not name that unit.** Identify it
on the deployment you are configuring rather than copying a name from a document:

```bash
systemctl list-timers --all --no-pager
systemctl --user list-timers --all --no-pager
```

Then confirm the candidate actually writes `metagraph_hotkeys` in the database
the publisher process reads — check the unit's `ExecStart` and the database path
it is pointed at. Do not infer it from a plausible name: a registration-snapshot
job that writes a hotkey *file* for an enrollment registry is a different thing
from whatever upserts this *table*, and only the latter is the dependency.

Once you know the cadence, the arithmetic is the point. The margin is
`floor(max_age / interval) - 1` consecutive missed runs before the newest row
falls outside the window — a refresher on the same period as the bound has **no**
margin at all, and one at half the bound tolerates exactly one miss. When it does
fall outside, the burn destination cannot be resolved, the lane returns an empty
allocation, and under the v3 contract the validator signs no vector at all. Pick
the pairing deliberately, write down which of the two numbers you chose, and
monitor the refresher as a production dependency of weight-setting. If it runs as
a *user* unit, lingering must be enabled for its account or the dependency stops
with the last logout — one more reason to confirm which unit it is.

---

## Failure reference

Producer-visible HTTP status → cause → fix.

| Status | Detail | Cause | Fix |
|---|---|---|---|
| 404 | `cybergym_ingest_not_enabled` | intake off | set `CATHEDRAL_CYBERGYM_INGEST_ENABLED=1`, restart |
| 404 | `route_not_served_by_<role>_role` | narrow service role | post to a full-role process |
| 401 | `invalid_cybergym_token` | bearer differs | re-sync `CATHEDRAL_CYBERGYM_SCORES_TOKEN` |
| 401 | `invalid_cybergym_signature` | secret differs, or the body was altered in transit | re-sync the HMAC secret; check no proxy rewrites the body |
| 403 | `producer_hotkey_mismatch` | declared signer is not the configured one | fix `--producer-hotkey`, or the validator's configured value |
| 400 | `cybergym_audience_mismatch` | wrong network/netuid | re-export for the configured audience |
| 400 | `complete_required` | non-complete document | only closed epochs may be exported; re-export |
| 400 | `report_in_future` | `generated_at` beyond the skew allowance | fix clock skew on the producer host |
| 409 | `epoch_too_old` | epoch below the audience high-water mark | publish a higher epoch; a rebuilt score store cannot be replayed |
| 409 | `epoch_conflict` | different document at a stored epoch | do not re-cut a published epoch; publish the next one |
| 413 | `cybergym_report_too_large` | body over the 65 536-byte cap | fewer scored miners per epoch, or split epochs |
| 503 | `cybergym_*_not_configured` / `*_required` | missing credential, producer, audience, or store | complete steps 2–4 before enabling ingest |
| 500 | `cybergym_store_failed` | schema missing or database error | apply the publisher's migrations, then retry |

---

## What this runbook does not cover

Choosing the CyberGym allocation fraction as economic policy, moving the
allocation contract to v3, and setting weights are separate decisions with
separate authorities; the sequenced cutover is in
[`CYBERGYM_V3_CUTOVER_RUNBOOK.md`](CYBERGYM_V3_CUTOVER_RUNBOOK.md).

On-chain registration is out of scope here for a reason worth restating: the
validator's own weight-setting hotkey must of course be registered and funded,
but that is a different key from `CATHEDRAL_CYBERGYM_PRODUCER_HOTKEY`, which is a
configured label and needs neither (see step 2). Nothing on this transport path
requires registering or funding anything.

The evidence digest a report commits to
(`cathedral_cybergym_evidence_manifest_v1`) and the receipt contract behind it
are documented in [`RECEIPT_CONTRACT.md`](RECEIPT_CONTRACT.md) and
[`INTEGRATION_CONTRACT.md`](INTEGRATION_CONTRACT.md); the disposable pre-launch
rehearsal of this same path is in
[`PRIVATE_V2_CYBERGYM_E2E.md`](PRIVATE_V2_CYBERGYM_E2E.md).
