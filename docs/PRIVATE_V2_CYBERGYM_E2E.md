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
CYBERGYM_E2E_AS_OF=<restart-stable timezone-aware ISO-8601, e.g. 2026-08-05T00:00:00Z>
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

`CYBERGYM_E2E_AS_OF` must be the SAME value for the server and the later close
command. It is the epoch's draw timestamp, pinned into the durable epoch manifest
on the first run; the close process rebuilds the service and must reproduce that
manifest exactly, so a wall-clock default would make the epoch unclosable across
processes (and its exported report impossible to reproduce byte-for-byte). Set it
once in the shared service-manager environment.

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
  --allow-unattested-e2e --out private-v2-epoch.json
```

Both commands need the same protected environment as the server; the close
process rebuilds the service and must reproduce the pinned epoch manifest.

`--allow-unattested-e2e` is required, not optional. This entrypoint runs with
`CYBERGYM_E2E_ALLOW_UNATTESTED=1` and therefore no Intel-TDX policy, so the
posture stamped beside the scores says the epoch's solves were credited
unattested and the exporter refuses it (exit 2) without the flag.

The resulting canonical report and signed receipts are shaped exactly like a
production hand-off — the wire contract has no enforcement field — so they are
inputs to a **disposable loopback preview** intake only, never to the validator's
production CyberGym intake. This entrypoint never opens a chain client or calls
`set_weights`.
