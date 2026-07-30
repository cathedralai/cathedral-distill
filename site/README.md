# Cathedral SN39 — launch site

Three self-contained static pages. No build step, and no external requests
unless you opt in to live status (below).

| Page | Audience | Purpose |
|---|---|---|
| `index.html` | operators / validators / general | What the subnet is: differential verification, epoch loop, scoring, honest status. |
| `research.html` | security researchers / ML | The technical case: anti-contamination sealing, the dataset thesis, prior art + citations. |
| `arena.html` | miners | Cathedral Arena — the CTF-style workspace (a **proposed** product; the verification mechanism behind it is built). |

## Serve locally

```bash
cd site && python -m http.server 8000
# open http://localhost:8000
```

## Live status (opt-in)

`index.html` has a **Live** section that fills itself from a running validator's
`GET /v1/status` (see [`../cathedral_distill/status.py`](../cathedral_distill/status.py)).
It is **off by default**: the endpoint `<meta>` in `<head>` is empty, so the page
makes no external request and the section stays hidden. That keeps these pages
self-contained, and means a down or misconfigured validator cannot degrade one.

To turn it on, set the endpoint for the deployment:

```html
<meta name="cathedral-status-endpoint" content="https://validator.example/v1/status">
```

Or point a local page at a local validator without editing anything:

```
http://localhost:8000/index.html?status=http://127.0.0.1:8080/v1/status
```

Behaviour worth knowing before you wire it up:

- The section is revealed **only** on a well-formed payload carrying the expected
  schema. A 503, a network error, bad JSON, a wrong schema, or an unreadable
  epoch all leave it hidden and the rest of the page untouched.
- It polls every 15s, and stops entirely while the tab is hidden — a background
  tab is pure load on a validator nobody is looking at.
- Every value is inserted as text, never as HTML. Miner hotkeys are remote input.
- It shows **one validator**, not a network-wide view, and says so on the page.
- The validator caches the payload for 5s, so the poll rate does not translate
  into store reads.

## Design notes

- One accent colour (`--accent`), spent only on CTAs, verdicts, and the ~3 things
  that matter per page. Semantic red/green appear only inside the differential
  diagram.
- One reader per page; each has a real hero and a single primary CTA.
- Every capability claim traces to the repo; anything unbuilt is labelled with a
  status banner. Market/competitor claims are cited on `research.html` and in
  [`../docs/COMPETITIVE_LANDSCAPE.md`](../docs/COMPETITIVE_LANDSCAPE.md).

> **Before external launch:** confirm the on-chain netuid (public trackers list
> netuid 39 under another project) and replace placeholder GitHub links if the
> canonical repo/handles change.
