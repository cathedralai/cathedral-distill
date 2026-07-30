# Cathedral SN39 — launch site

Three self-contained static pages. No build step, no external requests.

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
