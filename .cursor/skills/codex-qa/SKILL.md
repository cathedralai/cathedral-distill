---
name: codex-qa
description: Run a Codex-family QA pass after implementation and before declaring a work pass complete, marking a PR ready, or claiming production. Use when shipping code, receipts, trust copy, egress, attestation, catalogs, or any behavior change.
---

# Codex QA work pass

This is a required step of the work pass. Do not wait for the user to ask.

## Trigger

Run this skill whenever you:

- Implement or fix code
- Change trust copy, receipts, attestation, egress, catalogs, or signed fields
- Are about to mark a PR ready for review
- Are about to say the work is done, live, or shippable

Skip only when the user explicitly says to skip QA. Missing Codex CLI login is not a skip.

## Place in the work pass

1. Implement the change.
2. Add or run focused tests.
3. Commit and push a pre-testing revision when cloud-agent git rules require it.
4. Run this Codex QA pass.
5. Fix every Critical/High finding that is a fail-closed, honesty, or signed-policy mismatch in the same pass.
6. Re-run focused tests.
7. Update the PR with the QA verdict and residuals.
8. Only then declare the work pass complete.

## Runner

Try in order. Do not stall on login.

1. If `npx @openai/codex` is installed and `codex doctor` reports credentials, or `OPENAI_API_KEY` is set, run Codex against the diff and the changed trust surfaces.
2. Otherwise launch a Cursor `Task` subagent with model `gpt-5.6-sol-xhigh`. That is the Codex-family fallback when the CLI has no credentials.
3. If both fail, write an INCONCLUSIVE artifact naming the blocker and still produce a structured self-audit in the same finding format. Do not claim Codex QA passed.

## What to hand the reviewer

- Exact commits and PR heads
- The contract that must be true after this change
- Files and functions that mint, map, verify, or advertise the change
- Residuals the change is not allowed to paper over

Ask it to:

- Hunt fail-open parsers and signed-versus-enforced mismatches
- Re-fetch live catalogs or endpoints before calling anything production
- Ignore unrelated CI when judging the jobs that actually exercise the change
- Refuse unpublished measurements, invented APIs, or fake solver digests

## Finding format

Use C / H / M / L. Each finding needs:

- ID and title
- File:function, or live URL
- Expected versus actual
- Suggested fix
- Disposition: `fix-now`, `document-residual`, or `out-of-scope`

PolarIS PR review comments may use P0–P3. For this work pass, treat P0/P1 as C/H.

## Disposition

Fix in this pass:

- Fail-open guest, attestor, or consumer parsers
- Signed receipt fields that do not match enforcement
- Contradictory encodings that silently pick a winner
- Docs or errors that claim a stronger guarantee than the code

Do not:

- Invent unpublished measurements or solver digests
- Close tracker issues because a draft PR exists
- Treat an unmerged mint as live
- Flip security booleans to satisfy a consumer without the corresponding enforcement
- Use GitHub Actions `GITHUB_TOKEN` commits as the only PolarIS push (pull-request CI will not retrigger)

Document and leave open:

- Product residuals the user already accepted
- Features not in the live catalog
- Intentional cap or compatibility mismatches named in the PR

## Artifacts

Write a markdown report:

- Cloud agent runs: `/opt/cursor/artifacts/codex-qa-<topic>.md`
- PolarIS: also `docs/qa-audits/YYYY-MM-DD-<topic>/` with the report plus evidence files

The report must include:

- Verdict: live or not; ship-blocking or not
- Findings
- What was fixed in this pass versus residual
- Commands and URLs used as evidence

## Stop conditions

The work pass is not complete if:

- Unfixed C/H fail-closed or honesty findings remain
- QA was skipped because credentials were missing
- Production or live was claimed without a fresh catalog or receipt fetch

A PR may be marked ready after QA when residuals are named in the PR body and are outside the claimed scope.
