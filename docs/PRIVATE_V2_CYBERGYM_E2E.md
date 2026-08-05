# Private-v2 CyberGym verifier E2E

`cathedral-cybergym-private-v2-e2e-server` is the loopback-only deployment
entrypoint for a live infrastructure E2E. It replaces neither the production
miner transport nor the production reward authority.

It requires one reward-ready private-v2 manifest, digest-addressed artifact and
reference-PoC directories, both exact Docker images, and durable SQLite stores.
The manifest must pass corpus admission before the server opens its socket.

## Required configuration

```text
CYBERGYM_HOST=127.0.0.1
PORT=8668
CYBERGYM_E2E_ALLOW_UNATTESTED=1
CYBERGYM_E2E_MINER_HOTKEY=<registered test hotkey>
CYBERGYM_E2E_BEARER_TOKEN_FILE=<mode-0600 bearer token file>
CYBERGYM_SIGNING_SEED=<64 hex characters; protect the service-manager environment>
CYBERGYM_CORPUS_MANIFEST=<private-v2 manifest>
CYBERGYM_CHALLENGE_ARTIFACT_DIR=<digest-addressed miner artifact directory>
CYBERGYM_REFERENCE_POC_DIR=<digest-addressed validator-only reference directory>
CYBERGYM_CORPUS_DB=<durable corpus sqlite>
CYBERGYM_SOLVE_DB=<durable solve sqlite>
CYBERGYM_SCORE_DB=<durable score sqlite>
CYBERGYM_VALIDATOR_HOTKEY=<verifier hotkey>
```

The bearer file must be owner-readable only. The server maps a valid bearer to
the configured hotkey; it never trusts the request body's miner field. Every
dispatch, artifact read, and submission is then bound to that caller's sealed
batch.

For a private task outside the legacy ARVO subset, its manifest entry must also
commit `crash_evidence`: the expected sanitizer name plus permitted non-zero
exit codes and terminating signals. This makes the classifier part of the
immutable task evidence rather than relying on a task-id-specific server table.

Run the server behind an SSH tunnel:

```bash
cathedral-cybergym-private-v2-e2e-server
```

## Close and export

After a solved submission, stop or leave the server idle and close the epoch
with a stable timestamp:

```bash
cathedral-cybergym-private-v2-e2e-close --issued-at 2026-08-05T00:00:00.000000Z
cathedral-cybergym export-scores --score-db "$CYBERGYM_SCORE_DB" --epoch 21 \
  --network finney --netuid 39 --producer-hotkey "$CYBERGYM_VALIDATOR_HOTKEY" \
  --out private-v2-epoch.json
```

The resulting canonical report and signed receipts are the inputs to the
validator's configured CyberGym intake. This entrypoint never opens a chain
client or calls `set_weights`.
