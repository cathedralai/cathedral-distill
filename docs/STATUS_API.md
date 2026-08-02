# Live status API — a miner's progress, in one GET

Two anonymous, read-only routes, served by every validator alongside the wire
protocol. No auth, no rate limit beyond a 5-second server-side cache, CORS-open
(a dashboard is expected to run on a different origin than the validator).

```
GET /v1/status   — this epoch's identity, state, participation, leaderboard, corpus
GET /v1/keys     — the signed key registry a receipt's signing_key_id resolves against
```

Source of truth: [`cathedral_distill/status.py`](../cathedral_distill/status.py)
(`build_status`) and [`cathedral_distill/cybergym_http.py`](../cathedral_distill/cybergym_http.py)
(the two routes). Reference client: [`site/index.html`](../site/index.html)'s "Live"
section — vanilla JS, no dependency, polls this exact shape.

---

## GET /v1/status

### Quick example

```bash
curl -s https://<validator-host>/v1/status | python3 -m json.tool
```

A real response, captured live off a running validator mid-epoch:

```json
{
  "schema": "cathedral.distill.status.v1",
  "generated_at": "2026-07-30T16:08:52.140592Z",
  "lane": {
    "lane_id": "cathedral_cybergym",
    "receipt_schema": "cathedral_cybergym_receipt_v1"
  },
  "epoch": {
    "source_epoch": 21,
    "network": "finney",
    "netuid": 39,
    "valid_from_block": 100,
    "valid_until_block": 460,
    "validator_hotkey": "5Validator",
    "signing_key_id": "cybergym-1",
    "signing_public_key_digest": "sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c",
    "available": true,
    "manifest_schema": "cathedral_cybergym_epoch_manifest_v1",
    "manifest_digest": "sha256:e89fda11845c7ce76558d21bcaa8bad1df64599cd8039628cbab460702cfe9f3"
  },
  "state": {
    "available": true,
    "state": "open",
    "detail": "no scoring pass has been recorded for this epoch"
  },
  "participation": {
    "available": true,
    "scored": 0,
    "pending": 1,
    "committed": 1,
    "unscorable": 0,
    "durable_solves": 1
  },
  "leaderboard": {
    "available": true,
    "scored_miners": 0,
    "total_earned_units": "0",
    "truncated": false,
    "top": []
  },
  "corpus": {
    "available": true,
    "total_rows": 5,
    "this_epoch_rows": 5
  },
  "cache": {
    "ttl_secs": 5.0,
    "age_secs": 0.0
  }
}
```

### Field reference

**Top level**

| Field | Meaning |
|---|---|
| `schema` | `cathedral.distill.status.v1` — check this before trusting the shape. |
| `generated_at` | When this snapshot was built (UTC, ISO 8601). |
| `lane.lane_id` / `lane.receipt_schema` | Which lane this is and the receipt schema its signed receipts carry — pin these before comparing across validators. |
| `cache.ttl_secs` / `cache.age_secs` | Server-side cache window and how stale *this* response is. A dashboard polling faster than `ttl_secs` gets the same snapshot back — that's the point, not a bug. |

**`epoch`** — this epoch's public identity

| Field | Meaning |
|---|---|
| `source_epoch` | The epoch number every receipt this window is signed under. |
| `network`, `netuid` | Which chain/subnet this validator is running for. |
| `valid_from_block`, `valid_until_block` | The authorized block window. A receipt outside this range fails verification. |
| `validator_hotkey`, `signing_key_id`, `signing_public_key_digest` | Who signs, under which key, and that key's public digest — resolve `signing_key_id` against `GET /v1/keys` to actually verify a receipt. |
| `manifest_digest` | A digest over the full draw manifest. Anyone holding the manifest can confirm this validator is running the one they think it is — **without** the manifest itself being published (see below). |

> **Deliberately withheld:** `batch_size`, `cutoff`, `as_of`, the level weights, and
> the gate policy are part of the full manifest but never appear here. They tell a
> miner how to time or shape a submission for maximum credit while the epoch is
> still open — publishing them would hand out exactly the information the sealed-batch
> design exists to deny. Only the manifest's `digest` is public.

**`state`** — is this epoch open or closed

| Field | Meaning |
|---|---|
| `state` | `"open"` (still accepting submissions) or `"closed"` (scored and composed). |
| `detail` | Human-readable reason, e.g. `"no scoring pass has been recorded for this epoch"`. |

**`participation`** — where things stand while the epoch is open; this is the
field that answers *"is my submission stuck, or just not scored yet"*

| Field | Meaning |
|---|---|
| `committed` | Miners with at least one solve on record this epoch. |
| `pending` | Solved and durably recorded, **awaiting** a scoring pass. |
| `scored` | Counted in the last scoring pass — these are the numbers behind `leaderboard`. |
| `unscorable` | A miner who re-committed to a **different** model mid-epoch, abandoning their prior solves (a deliberate, self-inflicted state — see [MINING.md](MINING.md) — never triggered by anyone else's action; dispatch is caller-bound). |
| `durable_solves` | Total solve rows on record for this epoch, independent of scoring. |

**`leaderboard`** — earned units once a scoring pass has run; **empty is a
normal answer**, not an error, while `state.state == "open"`

| Field | Meaning |
|---|---|
| `scored_miners` | How many miners have a score this epoch. |
| `total_earned_units` | Sum of earned units across all scored miners (a `Decimal`, always a string — never round-trip it through a float). |
| `top` | Up to `leaderboard_limit` (default 25) rows: `{rank, miner_hotkey, earned_units}`, highest first. |
| `truncated` | `true` if more miners scored than `top` shows. |

**`corpus`** — the aggregated training corpus this validator has produced;
this **is** the subnet's product, not a proxy for it — `CyberGymCorpusStore`
only accepts a row once it has already passed verification, trainability, and
licensing

| Field | Meaning |
|---|---|
| `total_rows` | Every corpus-eligible solve across all epochs this validator has run. Accumulates; never resets. |
| `this_epoch_rows` | The subset from the current epoch — the rate the corpus is growing at right now. |

**`key_registry`** — present only if this validator serves one (see below);
same shape as `GET /v1/keys`'s `status()`, so a dashboard can show key freshness
without a second request when it's already embedded here.

### Failing soft

Every section above can independently report `{"available": false, "detail":
"<ExceptionType>: <message>"}` instead of its normal shape — a locked SQLite
connection mid-verify degrades *that* section, never the whole response. Check
`available` before reading a section's other fields.

---

## GET /v1/keys

The root-signed key registry, served verbatim (not re-serialised — the
published digest is over these exact bytes) so a receipt's `signing_key_id` is
resolvable by anyone holding only the root public key.

```bash
curl -s https://<validator-host>/v1/keys
```

- **200** — the signed registry body, with an `ETag` header. Send
  `If-None-Match` on repeat requests; a match returns **304** with no body.
- **503** — `{"error": "no key registry is configured on this host"}` if the
  operator hasn't pointed this validator at a signed registry yet, or
  `{"error": "<reason>"}` if the configured registry fails its own freshness or
  signature check. Either way this **fails closed**: a registry nobody can
  verify is refused rather than served, since serving unverifiable bytes only
  relocates the failure to every consumer at once.

A signed registry has its own freshness bound (`generated_at` + a max-age,
default 24h) **independent of** its stated `valid_until` — a technically
still-valid year-long registry is still refused the next day if it hasn't been
re-served. This is intentional: freshness proves the operator is still
operating, not just that a signature was once made.

---

## Understanding a win or a loss

The honest, minimal story `/v1/status` tells a miner, end to end:

1. **Dispatch** (`POST /cybergym/dispatch`) puts you in `committed` the moment
   your first solve for this commitment lands.
2. A solved, submitted PoC moves you to `pending` — accepted and durable, not
   yet scored. `corpus.this_epoch_rows` ticks up here too, if your trace
   cleared the quality floor.
3. A scoring pass moves scored miners from `pending` to `scored`, and
   populates `leaderboard.top` with your rank and earned units.
4. **`unscorable`** means you re-committed to a different model mid-epoch — the
   validator abandoned your prior solves for the OLD commitment (never the
   epoch, never another miner's). This is dispatch being caller-bound: only you
   can do this to your own solves, and it only costs your unscored work, never
   the lane. See [MINING.md § What will get you a zero](MINING.md#what-will-get-you-a-zero).
5. **A zero on the leaderboard despite `durable_solves > 0`** means every solve
   this epoch failed a gate the validator won't relax — wrong task, off-batch,
   an unregistered commitment, or a trace that didn't clear the structural
   quality floor. `/v1/status` doesn't publish per-submission gate reasons (that
   detail is in your own verdict from `POST /cybergym/submit`, not a public
   surface); the aggregate view only tells you *whether* you scored, not *why
   not* — check the verdict you got back at submit time for that.

---

## Building a dashboard

A dashboard is a consumer of the routes above, not a route of its own. Everything
here is served by `GET /v1/status` and `GET /v1/keys`; nothing below needs a new
public surface, and two things must never become one.

### Two things a public dashboard must never publish

**Sealed holdout task ids.** The whole anti-gaming design rests on the scored
batch being unknowable before the model hash is committed. A per-task solve-rate
panel for the private holdout hands miners exactly what the seal exists to
withhold — and it does so continuously, to everyone, forever. Aggregate across
tasks; never enumerate them. Public ARVO/OSS-Fuzz development tasks are safe to
name because they are already public; holdout tasks are not.

**PoC bytes, and `poc_sha256` for a task the reader has not solved.** A verified
PoC is a working exploit for a real vulnerability. Distribution of this corpus is
access-gated on purpose; a public dashboard is the opposite of gated. Publish
counts and outcomes, never payloads.

Both are properties of what you *render*, not of what the API returns — `/v1/status`
already declines to publish per-submission detail (see [Understanding a win or a
loss](#understanding-a-win-or-a-loss)), and a dashboard should not reintroduce it
by joining against its own submit-time records.

### From `GET /v1/status`

| Panel | Fields | Why it earns its space |
|---|---|---|
| **Verification funnel** | `participation.durable_solves`, `leaderboard.scored_miners`, `corpus.this_epoch_rows` | The drop-off *is* the product. Every subnet can show work completed; this one can show what it refused. Render it as a funnel, not a total. |
| **Corpus growth** | `corpus.total_rows`, `corpus.this_epoch_rows` | The flywheel, and the one line that should only ever go up. `total_rows` never resets, so it is the honest all-time number. |
| **Participation** | `committed`, `pending`, `scored`, `unscorable` | `unscorable` is the interesting one: it is always self-inflicted (a mid-epoch re-commit to a different model) and never caused by anyone else, so a spike means miners are confused, not attacked. |
| **Emission concentration** | `leaderboard.top[].earned_units`, `total_earned_units` | King-of-the-hill centralises *by design*. Publish top-1 share and a concentration index so that is a visible property rather than something an observer discovers and mistakes for capture. |
| **Epoch liveness** | `epoch.state`, `epoch.detail`, `source_epoch`, `valid_from_block`, `valid_until_block` | A stalled epoch fails silently — it looks exactly like a quiet one. Show the block window and how far into it the epoch is. |
| **Snapshot freshness** | `cache.age_secs`, `cache.ttl_secs` | Polling faster than `ttl_secs` returns the same snapshot. Render the age so a cached number is never mistaken for a stuck one. |
| **Section health** | each section's `available` / `detail` | Sections fail independently (see [Failing soft](#failing-soft)). A panel whose section reports `available: false` must say so, not render a stale or zero value. |

### From `GET /v1/keys`

| Panel | Why |
|---|---|
| **Verifiability** — `signing_key_id` and `signing_public_key_digest` from `/v1/status`, resolved against this registry | Lets a reader confirm which key signed the receipts behind every number on the page. A dashboard that cannot be checked is marketing. |
| **Registry state** | A **503** here is meaningful, not an outage: the registry is unconfigured or failed its own freshness or signature check, and is refused rather than served. Show "unverifiable" rather than hiding the panel — that distinction is the point of failing closed. |

Also worth surfacing `manifest_digest`: anyone holding the draw manifest can
confirm this validator is running the one they think it is, without the manifest
being published.

### Not yet served

These need new aggregate fields before a dashboard can show them honestly. Listed
because the gap is easy to paper over with a plausible-looking chart built from
something else.

| Metric | Why it matters | Status |
|---|---|---|
| **Task-pool exhaustion** — distinct tasks solved ÷ available | The first symptom is scores flatlining with no visible cause, which reads as a broken mechanism. Deployments running a small slice hit this early. | needs a count of available tasks, published as a total only — never as a list |
| **Level mix** — solved counts per `level0`…`level3` | `level0` is the scarce capability and carries the highest weight, so it is the real quality signal; a rising total made entirely of `level3` is a fall in quality that a single number hides. | needs per-level aggregation |
| **Attestation coverage** — share of creditable solves that were attested | Separates "verified" from "verified inside a TEE". `attested` exists per submission but is not aggregated anywhere public. | needs aggregation |
| **Verify latency** p50/p99 | A differential that slows down silently starves the epoch rather than failing it. | not instrumented |
| **Frontier turnover** — epochs held, challenger attempts, win margin | Whether king-of-the-hill is contested or parked. | not aggregated |

### Do not show

**Total submissions** as a headline: it rewards volume, and volume is the one
thing a miner can manufacture. **Any self-reported number** — the validator
re-derives every figure it scores, and a dashboard that renders a reported one
quietly gives up the property the subnet is built on. **The burn share** as a
time series: it is a fixed floor, so a flat line only invites the question of
whether it is broken.

---

## Serving this from your own validator

```python
from cathedral_distill.cybergym_http import make_threaded_server

httpd = make_threaded_server(
    service, host="127.0.0.1", port=8666,
    healthz={"status": "ok", "lane": "cathedral_cybergym"},
    key_registry=None,   # or a ServedKeyRegistry once you've run the key ceremony
)
httpd.serve_forever()
```

Loopback is the default because the same server also exposes three mutating POST
routes. A non-loopback bind is refused unless the caller supplies a transport
`authenticator` and sets `require_authentication=True`. The identity mechanism is
deployment-specific; see [VALIDATING.md](VALIDATING.md#authenticating-the-mutating-routes).

`/v1/status` and `/v1/keys` come for free with `make_threaded_server` /
`make_server` — nothing to wire up beyond the service itself. See
[`cathedral_distill/cybergym_repro_server.py`](../cathedral_distill/cybergym_repro_server.py)
for a complete reference server.

To point a dashboard at your validator, either serve `site/index.html` with
`<meta name="cathedral-status-endpoint" content="https://your-host/v1/status">`
set, or append `?status=https://your-host/v1/status` to the page URL — the page
makes no request at all until one of those is set.
