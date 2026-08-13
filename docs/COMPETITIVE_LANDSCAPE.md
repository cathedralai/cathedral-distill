# Competitive landscape

Where Cathedral sits relative to the incumbents in code security and to the other
security work on Bittensor. The through-line: **everyone else scores an
*opinion* about whether code is vulnerable; Cathedral scores an *execution* that
proves it.**

> Market and competitor figures below are cited to public sources. Product
> capabilities of Cathedral itself are grounded in the repo.

---

## The one axis that matters: alert vs. proof

| | What it produces | How it's judged | Failure mode |
|---|---|---|---|
| **Snyk / Semgrep / GitHub Advanced Security** | An *alert*: "this code pattern may be vulnerable" | Pattern / semantic match against rules or a CVE DB | **False positives** — noise the team can't triage |
| **Bitsec (Bittensor SN60)** | A *prediction*: boolean + a list of vuln categories | Jaccard similarity of predicted vs. expected categories | Rewards overlap-with-a-label, not exploitability |
| **Cathedral SN39** | A *PoC*: a byte-string input | Differential crash test — the binary either crashes the vulnerable build and spares the patched one, or it doesn't | (By design, almost none — a wrong PoC simply scores zero) |

## Traditional SAST/SCA: drowning in false positives

The category's defining problem is noise. A 2025 Ghost Security study ran
traditional SAST across public Go/Python/PHP repos: of 2,116 flagged
vulnerabilities, **180 were real — a 91% false-positive rate**
([Pixee analysis](https://www.pixee.ai/blog/sast-false-positives-reduction)). The
industry's answer is *reachability/exploitability* analysis to prioritise —
Snyk's reachability layer, for instance, reportedly cuts hundreds of thousands of
annual alerts down to a fraction of a percent that are actually critical
([Pixee](https://www.pixee.ai/blog/sast-false-positives-reduction);
[Snyk reachability docs](https://docs.snyk.io/scan-fix-and-prevent/fix/prioritize-issues-for-fixing/reachability-analysis)).

- **Snyk** — developer-first SCA + SAST (Snyk Code), reachability via static
  analysis + AI, validated by human researchers
  ([Snyk](https://snyk.io/articles/sast-dast-iast-rasp/)).
- **Semgrep** — lightweight semantic pattern-matching SAST; free for OSS, Team
  tier ~$40/dev/mo ([Semgrep](https://semgrep.dev/resources/semgrep-vs-github/)).
- **GitHub Advanced Security / CodeQL** — semantic SAST + Dependabot + secret
  scanning; ~$30/committer/mo, ~$58,800/yr for a 100-dev org
  ([Semgrep vs GitHub](https://semgrep.dev/resources/semgrep-vs-github/);
  [DEV: Semgrep vs CodeQL](https://dev.to/rahulxsingh/semgrep-vs-codeql-lightweight-patterns-vs-semantic-analysis-for-sast-2026-412k)).

**Where Cathedral differs:** these tools tell you a door *might* be unlocked.
Cathedral trains a model that *walks through it and proves it did*. A verified PoC
is the one signal SAST/SCA structurally cannot emit — proof of exploitability,
not a ranked guess. That "proof" layer is the commercial wedge: it's what turns a
865k-alert firehose into the handful that are actually poppable.

> **One-liner:** *Snyk tells you a door might be unlocked; Cathedral trains an AI
> that walks through it — and hands you the receipt.*

## Bitsec (Bittensor SN60): the closest neighbour

Bitsec is the existing security subnet on Bittensor — AI-powered vulnerability
*detection* for smart contracts and code. Miners return a `PredictionResponse`
(a boolean plus a list of `Vulnerability` objects); validators score by **Jaccard
similarity of vulnerability categories** against an expected response
([subnet-060 report](https://github.com/igorsyl/bittensor-report/blob/main/subnets/subnet-060.md);
[Subnet Alpha: Bitsec](https://subnetalpha.ai/subnet/bitsec/)).

**Where Cathedral differs:**

- **Execution vs. similarity.** Bitsec's reward is set-overlap with a label — an
  opinion metric that a miner can approximate by predicting common categories.
  Cathedral's reward is a crash the validator re-runs. There is no partial credit
  for "sounds right."
- **Anti-contamination by construction.** Cathedral's scored batch is sealed
  *after* the model is committed; a similarity-to-label task has no equivalent
  guarantee that the labels weren't in training.
- **The corpus is the product.** Bitsec ships detections; Cathedral ships a
  verified PoC + trace dataset explicitly designed as re-trainable, licensed
  training data.

## Autonomous exploitation is the tailwind, not a competitor

XBOW — a fully autonomous AI pentester — became the first AI to top HackerOne's
US leaderboard in Q2 2025 with 1,000+ reports, including a real Palo Alto
GlobalProtect flaw ([TechRepublic](https://www.techrepublic.com/article/news-ai-xbow-tops-hackerone-us-leaderboad/);
[GIGAZINE](https://gigazine.net/gsc_news/en/20250625-hackerone-xbow/)). XBOW is a
*product* that finds live bugs; Cathedral is the *incentive layer and data engine*
underneath the capability. XBOW proves the market believes autonomous exploit
discovery works — Cathedral is where the verified training data for it gets
produced, in the open, without contamination.

## Academic grounding (not competitors — foundations)

- **CyberGym** (UC Berkeley, Dawn Song lab; arXiv 2506.02548): 1,507 historical
  vulns across 188 projects; the task *is* "produce a PoC that crashes the
  pre-patch build." Cathedral's workload is this, turned into an incentive
  mechanism ([CyberGym](https://www.cybergym.io/cybergym/)).
- **ARVO** (arXiv 2408.02153): 5,000+ (later 6,100+) reproducible memory vulns
  from OSS-Fuzz, each with a triggering input, the developer patch, and automatic
  rebuild at vulnerable/patched revisions — the raw material for the holdout, and
  auto-updating as OSS-Fuzz finds more
  ([ARVO](https://arxiv.org/abs/2408.02153)).

## What we could add (not built)

- **Repair track.** Produce a patch that blocks the PoC and passes regression
  tests. This is a *different challenge contract* the repo does not implement —
  the exploit track is what exists today. A repair track would let Cathedral
  compete directly with the "fix" half of Snyk/GHAS, using the same verified-by-
  execution discipline (does the patched build spare the PoC *and* pass tests?).

## Summary positioning

**Cathedral is not another scanner.** Scanners rank guesses; Cathedral mints
proofs. On Bittensor it replaces similarity-to-a-label with a crash the validator
re-runs, and its by-product — a sealed, execution-verified PoC/trace corpus — is
the asset the whole AI-security category is racing to accumulate.
