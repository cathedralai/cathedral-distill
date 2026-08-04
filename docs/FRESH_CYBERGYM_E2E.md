# Fresh CyberGym verifier E2E

`cathedral-cybergym-fresh-e2e-server` exercises a fresh-task verifier without
touching the legacy ARVO reference service.  Each finalized epoch nonce and the
validator-held `CYBERGYM_FRESH_SEED` derive a new, admitted task set.  The seed
is never dispatched; its commitment is pinned in the durable epoch manifest.

This process is deliberately **loopback-only and non-reward-bearing**.  It
requires an explicit development acknowledgement because it does not configure
the production transport identity adapter, Intel-TDX policy, or emission gate
policy.  Do not expose it publicly and do not use it to submit weights.

## Start a clean E2E verifier

Create owner-only state and seed files outside the repository.  Reuse the same
seeds across a restart of one E2E epoch; replacing either seed changes the
receipt/task identity and is intentionally refused by the durable manifest.

```bash
install -d -m 700 /srv/cathedral-fresh-e2e
openssl rand -hex 32 > /srv/cathedral-fresh-e2e/fresh.seed
openssl rand -hex 32 > /srv/cathedral-fresh-e2e/signing.seed
chmod 600 /srv/cathedral-fresh-e2e/*.seed

CYBERGYM_E2E_ALLOW_UNATTESTED=1 \
CYBERGYM_FRESH_SEED="$(< /srv/cathedral-fresh-e2e/fresh.seed)" \
CYBERGYM_SIGNING_SEED="$(< /srv/cathedral-fresh-e2e/signing.seed)" \
CYBERGYM_CORPUS_DB=/srv/cathedral-fresh-e2e/corpus.sqlite \
CYBERGYM_SCORE_DB=/srv/cathedral-fresh-e2e/scores.sqlite \
CYBERGYM_SOLVE_DB=/srv/cathedral-fresh-e2e/solves.sqlite \
CYBERGYM_E2E_AS_OF=2026-08-04T12:00:00+00:00 \
CYBERGYM_HOST=127.0.0.1 PORT=8667 \
  cathedral-cybergym-fresh-e2e-server
```

Reach the loopback service through an SSH tunnel:

```bash
ssh -N -L 8667:127.0.0.1:8667 jared@5.78.154.20
curl http://127.0.0.1:8667/healthz
```

`GET /healthz` reports `task_source: fresh-sealed`.  It intentionally does not
advertise a reusable static task list: tasks are created from the current
finalized epoch nonce at dispatch time.  Repeating a dispatch for a pinned model
commitment returns the same batch; a new epoch returns a different task set.

## Close and export the E2E epoch

Keep `CYBERGYM_E2E_AS_OF` unchanged for the lifetime of the source epoch.  It is
part of the durable epoch manifest; a different value, seed, chain anchor, or
signing key is a deliberate restart refusal.  After the submission window, run
the close command with the same protected environment used by the server:

```bash
CYBERGYM_E2E_ALLOW_UNATTESTED=1 \
CYBERGYM_FRESH_SEED="$(< /srv/cathedral-fresh-e2e/fresh.seed)" \
CYBERGYM_SIGNING_SEED="$(< /srv/cathedral-fresh-e2e/signing.seed)" \
CYBERGYM_CORPUS_DB=/srv/cathedral-fresh-e2e/corpus.sqlite \
CYBERGYM_SCORE_DB=/srv/cathedral-fresh-e2e/scores.sqlite \
CYBERGYM_SOLVE_DB=/srv/cathedral-fresh-e2e/solves.sqlite \
CYBERGYM_E2E_AS_OF=2026-08-04T12:00:00+00:00 \
  cathedral-cybergym-fresh-e2e-close --issued-at 2026-08-04T13:00:00.000000Z

cathedral-cybergym export-scores \
  --score-db /srv/cathedral-fresh-e2e/scores.sqlite \
  --epoch 21 --network finney --netuid 39 \
  --producer-hotkey cathedral-fresh-e2e \
  --out /srv/cathedral-fresh-e2e/epoch-21.json
```

The close command restores accepted PoCs from `CYBERGYM_SOLVE_DB`, re-derives
the sealed task batch, and writes only a durably closed score epoch.  The
existing exporter then freezes a canonical report.  Neither command publishes
weights or turns this non-reward E2E verifier into a production authority.

`--issued-at` must be a real UTC timestamp with exactly six fractional digits.
The close command validates it before the durable first-write-wins pin.  If a
pre-validation E2E build already pinned a malformed timestamp, it refuses a
silent replacement.  After confirming the epoch is still open and has no score
rows, recover it explicitly with an auditable repair:

```bash
cathedral-cybergym-fresh-e2e-close \
  --issued-at 2026-08-04T13:00:00.000000Z \
  --repair-invalid-issued-at \
  --repair-reason 'pre-validation E2E timestamp pin'
```

## Required E2E evidence

Record the source commit, health response, dispatch, artifact digest, accepted
submission, durable solve rows, closed score report, and downstream validator
preview.  A restart with the same three SQLite files and seed must preserve the
same epoch manifest.  A changed fresh seed must fail closed rather than silently
score substituted task bytes.

For a reward-bearing deployment, replace this entrypoint with a configured
production service: authenticated batch-scoped artifact transport, persistent
TDX attestation validation, emission gates, and a real fresh challenge builder
must all be present before any weight path is enabled.
