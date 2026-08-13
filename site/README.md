# Cathedral launch site

Self-contained static pages. No build step, and no external requests unless you opt in to live status (below).

| Page | Audience | Purpose |
|---|---|---|
| `index.html` | operators / validators / general | What the subnet is: differential verification, epoch loop, scoring, honest status. |
| `compute.html` | developers / agent builders | **Cathedral Compute** product: attested sandboxes vs E2B/Daytona, API profiles, pricing, honest comparison. |
| `arena.html` | miners | SN39 Arena — CTF loop on Compute workers (proposed UI; verification mechanism built). |
| `research.html` | security researchers / ML | The technical case: anti-contamination sealing, dataset thesis, prior art. |

## Serve locally

```bash
cd site && python3 -m http.server 8000
# open http://localhost:8000/compute.html
```

## Live status (opt-in)

`index.html` has a **Live** section that fills itself from a running validator's
`GET /v1/status` (see [`../cathedral_distill/status.py`](../cathedral_distill/status.py)).
It is **off by default**: the endpoint `<meta>` in `<head>` is empty, so the page
makes no external request and the section stays hidden.

## Design notes

- **Subnet pages** (`index`, `research`, `arena`): green accent (`--accent`), verification / go.
- **Compute page** (`compute.html`): orange accent (`--compute`), infra landing (dot grid, terminal hero, E2B-adjacent warmth). Honest comparison table vs E2B/Daytona.
- Shared: terminal chrome, split hero, bento grid, mobile nav drawer.
- Every capability claim traces to the repo or [cathedral.computer/docs](https://cathedral.computer/docs/); unbuilt items use status banners.

> **Before external launch:** confirm the on-chain netuid and replace placeholder GitHub links if canonical repos change.
