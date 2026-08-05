# CyberGym v3 cutover runbook (SN39, finney)

The executable form of Part 2 of ai-hpc's E2E report (2026-08-05). That report
proved the reward path numerically: a real miner solved a sealed task, the
verifier scored `work_units=2`, and the validator composed a v3 lane crediting
UID 250 with the full 0.30. Nothing in that proof touched the chain. This
document is the part that does.

**Audience.** One operator, alone, at an hour when nobody is awake to check
their reasoning. Every step is a command you can paste and a sentence telling
you what GREEN looks like. Where a check is *not* runnable today, it says so
rather than inventing one.

**Scope.** Rolling SN39's live allocation from `validated_supply_v1`
(90% Intel TDX / 10% fixed burn) to `validated_supply_v3` (70% Intel TDX /
30% CyberGym / 0% fixed burn). It spans two repositories and two hosts, which
is why it lives here rather than in either one's deploy notes:

| Side | Repository | Host (as of 2026-08-05) |
|---|---|---|
| Verifier / producer | `cathedral-distill` (this repo) | `cathedralhq` (5.78.154.20) |
| Publisher (composes the signed vector) | `cathedral-validator` | `polaris-tdx-7e93d5de`, `cathedral-scorer-sn39.service` |
| Validator (writes weights) | `cathedral-validator` | `polaris-tdx-7e93d5de`, `cathedral-validator-passive.service` |

**This document authorizes nothing.** It describes the order operations must
happen in if someone decides to do them. Section 5 is the argument for *not*
doing them yet, and it should be read before section 1.

---

## 0. Three names that are easy to confuse

Getting these wrong is the most likely way to take the subnet dark, so they are
stated before anything else.

| Name | Where it lives | Values |
|---|---|---|
| **Policy pin** | The validator's `require_policy` (`[weight_policy]` in its TOML, or `--require-policy`, or `CATHEDRAL_VALIDATOR_REQUIRE_POLICY`) | `validated_supply_v1`, `validated_supply_v3` |
| **Allocation contract** | The publisher's `CATHEDRAL_ALLOCATION_CONTRACT` | `v2` (default), `v3` |
| **`contract_version`** | Stamped *inside* the signed vector by the publisher, and onto the validator's result event | `"v2"`, `"v3"` |

The trap: **policy pin `validated_supply_v1` admits `contract_version` `"v2"`,
not `"v1"`.** There is no `"v1"` contract version. `scaffold/validator_thin.py`
`vector_to_uid_weights` reads:

```python
if require_policy == REQUIRE_POLICY_VALIDATED_SUPPLY_V1:
    ...
    if supply_version != "v2":
        raise wire.VectorError(
            "validator pinned to validated_supply_v1 rejects "
            f"contract_version {supply_version!r}"
        )
```

`SN39_PINNED_REQUIRE_POLICIES` in the same file is the closed two-member tuple
`(validated_supply_v1, validated_supply_v3)` — the SN39 mainnet trust profile's
one field with two admissible values, so that the roll from the launch contract
to v3 is a reviewed re-pin rather than a config edit anything could make.
`confidential_primary_v1` is a valid CLI pin for other subnets and is **not** an
SN39 posture.

---

## THE SEQUENCING FACT

**There is no overlap window. A dark gap is designed in.**

- A validator pinned to `validated_supply_v1` that fetches a **v3** vector
  raises `VectorError` out of `vector_to_uid_weights`, emits `VECTOR_REJECTED`,
  and submits nothing. It does not fall back to the 90/10 split. It does not
  degrade. It goes dark and stays dark until it is re-pinned.
- A validator pinned to `validated_supply_v3` that fetches a **v2** vector
  raises on `validated_supply is None or supply_version != "v3"`. Same outcome,
  in the other direction.

This is deliberate. The alternative — a pin that accepts either — is a pin that
does not pin anything, and a tampered publisher could then move mainnet weights
without anyone re-pinning a validator. The cost of that guarantee is that the
publisher flip and the validator re-pin cannot both be correct at the same
instant. One of them is wrong for however long you take.

**The mitigation is timing, not cleverness.** SN39's weight-update rate limit is
100 blocks. At ~12s/block that is ~20 minutes during which the chain would
refuse a second write from this validator anyway — the validator spends it
emitting `WEIGHT_COOLDOWN_SKIPPED`, not writing. Land the whole flip inside that
window and the dark gap costs nothing, because no write was possible in it.

So:

1. Wait for a confirmed `WEIGHTS_SUBMITTED`.
2. Immediately do publisher flip **and** validator re-pin, back to back, one
   operator, no pauses between them, nothing else interleaved.
3. Confirm the next tick accepts a v3 vector, well before the cooldown expires.

Read the rate limit from the validator's own log rather than assuming 100:

```bash
sudo grep '"event":"WEIGHT_COOLDOWN_SKIPPED"' \
  /var/log/cathedral-validator/validator-events.jsonl | tail -1
```

The `detail` carries `weights_rate_limit=<blocks>`,
`blocks_since_last_update=<n>` and the block at which the next write becomes
possible. That difference, times the block time, is your real budget.

---

## 1. Preconditions — every one GREEN before anything starts

Run these in order. A RED at any point ends the session; nothing below it is
meaningful. All of them are reads.

Throughout, on the validator host:

```bash
VAL=/opt/cathedral-validator-staging-9475f4f      # confirm with P1.a, do not assume
EVENTS=/var/log/cathedral-validator/validator-events.jsonl
```

### P1 — The validator is up and actually writing

A validator that is not cleanly completing v1 ticks must not have v3 layered on
top. "Running" is not the bar; "wrote to the chain recently" is.

**P1.a — identify the process by observation, not by unit name.** Several units
exist and most are masked; the drop-in that actually runs is not the one the
unit file names.

```bash
ps -eo pid,user,cmd | grep '[s]caffold.cli serve'
systemctl list-units --type=service --state=running --no-pager | grep -i cathedral
sudo systemctl cat cathedral-validator-passive.service
```

Read the *last* `ExecStart=` in that output. Drop-ins override, and the
overriding one is at the bottom.

GREEN: exactly one `scaffold.cli serve … --broadcast` process. Note its
`--config` path and its interpreter prefix; those are `$VAL` and the config you
will edit in step 3. As of 2026-08-05 that is
`cathedral-validator-passive.service`, overridden by
`/etc/systemd/system/cathedral-validator-passive.service.d/20-quickstart.conf`,
running `$VAL/.venv/bin/python -m scaffold.cli serve --config
/etc/cathedral-validator/validator-thin-sn39-relay.toml --broadcast`.

**P1.b — a chain write landed inside the last hour.**

```bash
sudo grep '"event":"WEIGHTS_SUBMITTED"' "$EVENTS" | tail -1 | cut -c1-200
date -u
```

GREEN: a `"status":"PASS"` line whose `ts` is within the last ~40 minutes (about
two tick intervals; `interval_secs = 1500`). `PENDING_RECEIPT_RECOVERED` also
proves a write landed — it is the restart path re-proving an existing receipt —
but it is not a substitute for a fresh `WEIGHTS_SUBMITTED`.

RED: the newest of those is hours old, or the tail is a repeating
STARTUP → `TICK_FAILED` → restart cycle. Fix that first. It is its own incident,
not a step in this one.

**P1.c — the shadow audit is not flagging.**

```bash
/usr/local/bin/cathedral-mismatch-check
```

GREEN: `no recent mismatch; shadow audit not persistently failing`, exit 0.
This script alerts on `PROVENANCE_VECTOR_MISMATCH` inside 30 minutes, and on 90
minutes of `PROVENANCE_AUDIT_FAIL` with no `PROVENANCE_AUDIT_PASS`. It
deliberately ignores `PROVENANCE_VECTOR_STALE_EPOCH`, which is the publisher's
~60s serving race against the 311s epoch and self-resolves.

**P1.d — no pending unproven receipt.**

```bash
sudo tail -n 20 "$EVENTS" | grep -E 'PENDING_RECEIPT_NOT_PROVEN|PRE_SIGN_HEAD_DRIFT_RETRY' | tail -3
```

GREEN: nothing recent, or a `PENDING_RECEIPT_NOT_PROVEN` that a later
`PENDING_RECEIPT_RECOVERED` resolved. Flipping while an attempt is unresolved
mixes two fence transitions in one window and makes the rollback in section 4
ambiguous.

### P2 — The composing publisher runs code that *has* the v3 lane

**This is the precondition most likely to be assumed rather than checked, and it
is RED as of 2026-08-05.** `CATHEDRAL_ALLOCATION_CONTRACT=v3` set on a build
that predates the v3 code is not an error — it is silently inert. The publisher
would keep composing v2, the re-pinned validator would reject every vector, and
the subnet would be dark with no failing check anywhere to say why.

**P2.a — find the process that actually serves the live vector.** The public
feed and the local composer must be the same vector, or you are about to
configure the wrong process.

```bash
curl -fsS -m 30 https://api.cathedral.computer/v1/validator/weights/next \
  | python3 -c 'import json,sys; p=json.load(sys.stdin); print("api ", p["vector_id"], p["policy_version"])'
curl -fsS -k -m 30 https://127.0.0.1:8012/v1/validator/weights/next \
  | python3 -c 'import json,sys; p=json.load(sys.stdin); print("8012", p["vector_id"], p["policy_version"])'
```

GREEN: identical `vector_id`. As of 2026-08-05 both return the vector composed
by `cathedral-scorer-sn39.service` on `127.0.0.1:8012`.

**P2.b — resolve the code tree that process imports, not its WorkingDirectory.**
These differ on this host: the unit drop-in pins `WorkingDirectory` to an
`/opt/cathedral-sn39/releases/…` tree, but the venv's `scaffold` package
resolves elsewhere. The importable tree is the one that runs.

```bash
sudo /home/polaris/cathedral-scorer/.venv/bin/python \
  -c 'import scaffold, os; print(os.path.dirname(scaffold.__file__))'
```

**P2.c — assert the v3 lane exists in that tree.**

```bash
TREE=$(sudo /home/polaris/cathedral-scorer/.venv/bin/python \
  -c 'import scaffold, os; print(os.path.dirname(scaffold.__file__))')
sudo ls "$TREE/publisher/" | grep -i cybergym
sudo grep -n 'ALLOCATION_CONTRACT_ENV\|_compose_cybergym_lane_v3\|V3_CYBERGYM_ALLOCATION' \
  "$TREE/publisher/weights.py"
sudo grep -n cybergym_ingest "$TREE/publisher/app.py"
```

GREEN: `cybergym_bridge.py`, `cybergym_ingest.py`, `cybergym_contract.py`,
`mechanism_cybergym_adapter.py` present; `weights.py` defines
`ALLOCATION_CONTRACT_ENV` and `_compose_cybergym_lane_v3`; `app.py` mounts
`cybergym_ingest`.

RED as of 2026-08-05: the tree is `/home/polaris/cathedral-scorer/scaffold` at
`990c7a49`, and **all three greps return nothing**. Until a publisher build
carrying the v3 code is deployed to the composing process, there is no flip to
sequence. Note the corollary: `CATHEDRAL_CYBERGYM_INGEST_ENABLED=1` and
`CATHEDRAL_CYBERGYM_PRODUCER_HOTKEY` are already present in
`/etc/cathedral/scorer-canary.env.sh` and are currently doing nothing, which is
why `POST /v1/cybergym/scores` answers 404 on both `:8012` and
`api.cathedral.computer`. Do not read that 404 as "ingest is safely off by
policy"; it is "the endpoint does not exist in this build".

**P2.d — end-to-end confirmation once a v3-capable build is deployed.**

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -X POST https://api.cathedral.computer/v1/cybergym/scores -d '{}'
```

GREEN after deployment: `401` (bad bearer) or `503` (not fully configured) —
either proves the route exists. `404` means it still does not.

### P3 — The Distill pin includes #96, everywhere it is claimed

Three places claim the Distill contract commit and all three must agree:
`cathedral-validator`'s `pyproject.toml` `integration` extra, its
`cathedral_thin/integration.py` `DISTILL_CONTRACT_COMMIT` (a regression test in
`tests/thin/test_integration_admission_gates.py` asserts their exact equality),
and the tree actually installed on the box.

`cathedral-distill#96` merged as `b2ad1eddf9235921f8f680342605d5c8a84a8d87` at
2026-08-05T05:48Z.

```bash
sudo -u cathedral-validator "$VAL/.venv/bin/cathedral-validator-integration-preview" --lanes \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["distill_contract_commit"]); [print(" ", l["lane_id"]) for l in d["lanes"]]'
```

GREEN: prints `b2ad1eddf9235921f8f680342605d5c8a84a8d87` (or a later commit that
is an ancestor of `cathedral-distill/main` and contains #96), and lists
`cathedral_cybergym` among the lanes. Verified GREEN on 2026-08-05.

**P3.b — the integration extra is installed, not merely pinned.** `--lanes` is
a static description and prints happily without the dependency; a real preview
raises `IntegrationUnavailable` without it.

```bash
sudo "$VAL/.venv/bin/python" -m pip show cathedral-cybergym
```

GREEN: a version and a location. RED as of 2026-08-05: `Package(s) not found`.
Remediation is `python -m pip install -e '.[integration]'` in that venv, which
installs the pinned commit — a change to the validator host, so it belongs in a
deliberate deploy, not in the flip window.

### P4 — A real producer hotkey, registered, with its transport proven

The E2E used a **label** producer (`cathedral-private-v2-e2e`) and a loopback
server. Production needs a registered ss58 identity and a real POST.

```bash
sudo grep -E '^export CATHEDRAL_CYBERGYM_PRODUCER_HOTKEY=' /etc/cathedral/scorer-canary.env.sh
```

GREEN: an ss58 you deliberately generated, that you can prove is registered on
finney/39, and whose signing material is held by the verifier rig.

RED as of 2026-08-05: it is
`5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY` — the canonical Substrate
`//Alice` development key. That is a placeholder, not an identity.

Two properties of `scaffold/publisher/cybergym_ingest.py` make this a decision
you make once:

- The intake admits **exactly one producer per audience**, and epochs are fenced
  **monotonically**. Rotating the producer key does **not** reset the epoch
  counter: a replacement key must post above the highest `source_epoch` already
  stored for that audience or it is refused `epoch_too_old` (409).
- The report body is bound to the declared signer: a document naming a producer
  other than the configured one is 403.

**P4.b — prove the transport, not just the key.** From the verifier rig, with a
real closed epoch:

```bash
cathedral-cybergym publish-scores \
  --report /path/to/frozen-report.json \
  --url https://api.cathedral.computer/v1/cybergym/scores \
  --token-file /path/to/bearer.token \
  --hmac-secret-file /path/to/hmac.secret \
  --proof-out /path/to/accepted-proof.json
```

GREEN: exit 0 and a written `{body, signature}` proof. The secrets are
`CATHEDRAL_CYBERGYM_SCORES_TOKEN` and `CATHEDRAL_CYBERGYM_SCORES_HMAC_SECRET`
(bearer plus HMAC-SHA256 over the exact request body bytes) and must match on
both ends. Provision them out of band; they appear nowhere in this document.

Also note the verifier-rig dependency from the report: once #96 is deployed
there, `run-server.sh` must export a timezone-aware ISO-8601 `CYBERGYM_E2E_AS_OF`,
and the server and the close process must share the same value — that is the
bug #96 fixed. Epoch 21 on the current rig is already closed with the test
score; reset the rig's state before a production run.

### P5 — Attestation is real

`cathedral-validator#61` is the gate: admit a genuine Intel-TDX–attested
CyberGym miner receipt through the validator's own attestation policy, not
through a developer or `allow-unattested` path. The E2E deliberately ran
`attestation_required=False` and `gates_required=False` — correct for an infra
proof, explicitly never in production.

```bash
gh issue view 61 -R cathedralai/cathedral-validator --json state,title
```

GREEN: `CLOSED`. RED as of 2026-08-05: `OPEN`.

There is no host-side command that substitutes for this. The check is that the
issue's acceptance criteria are met — the receipt independently
attestation-verified, the preview binding the exact report, evidence digest,
receipt, producer and source epoch, and duplicate stateful consumption
rejected.

### P6 — The sealed private corpus is the live corpus

The public ARVO set is 0/6 scoreable: its answers are publicly pullable, so a
lookup miner farms it. Only the private, sealed holdout — the one this E2E used
— is reward-legitimate. This is item 1 of `cathedral-distill#80` and the last
day-sized piece.

```bash
gh issue view 80 -R cathedralai/cathedral-distill --json state,title
cathedral-cybergym-admit /path/to/holdout-manifest.json --out /tmp/stamped.json
```

GREEN: every task admitted (exit 0), the stamped manifest digest-bound to the
image digests it was decided against, and the deployed verifier drawing from
that holdout rather than the public pool. Registry access control for the
private vul/fix images is part of this, not a follow-up: a holdout whose images
anyone can pull is a public corpus with extra steps.

RED as of 2026-08-05: `#80` OPEN, deployed corpus still 6/6 public.

Related and easy to miss: `#80` item 6 — `admit_pool` returns stamped in-memory
objects that nothing serializes, so `admitted: true` is an operator-typed claim
with no binding to the image digest. That becomes load-bearing the moment a real
holdout manifest exists, which is now.

---

## 2. Non-writing preview against the real producer feed

Everything here is read-only with respect to the chain. It is still not
read-only with respect to the validator's durable state, which is why the first
thing it does is move that state out of the way.

### 2.a — Enable the mechanism and intake (still no allocation change)

On the publisher, in `/etc/cathedral/scorer-canary.env.sh` (the file
`cathedral-scorer-sn39.service` sources):

```
CATHEDRAL_CYBERGYM_INGEST_ENABLED=1
CATHEDRAL_CYBERGYM_PRODUCER_HOTKEY=<the real producer ss58 from P4>
CATHEDRAL_CYBERGYM_SCORES_TOKEN=<bearer>
CATHEDRAL_CYBERGYM_SCORES_HMAC_SECRET=<shared secret>
CATHEDRAL_CYBERGYM_MECHANISM_ENABLED=1
CATHEDRAL_CYBERGYM_WEIGHT_FRACTION=0.30
```

Leave `CATHEDRAL_ALLOCATION_CONTRACT` **unset** (defaults to `v2`). With the
contract still v2, `weights.build_signed_vector` never calls
`_compose_cybergym_lane_v3`, so none of the above can move a live weight. That
is the whole point of doing it as a separate step: the intake starts collecting
real reports while the allocation is unchanged, and you get to watch the lane
compose before it counts.

Restart the composer and verify:

```bash
sudo systemctl restart cathedral-scorer-sn39.service
sleep 20
curl -sS -o /dev/null -w '%{http_code}\n' \
  -X POST https://api.cathedral.computer/v1/cybergym/scores -d '{}'
curl -fsS -k -m 30 https://127.0.0.1:8012/v1/validator/weights/next \
  | python3 -c 'import json,sys; p=json.load(sys.stdin); m=p.get("policy_metadata") or {}; print("contract", (m.get("validated_supply") or {}).get("contract_version"), "| cybergym_lane", "cybergym_lane" in m)'
```

GREEN: the intake answers `401`/`503` rather than `404`, and the served vector
still reports `contract v2 | cybergym_lane False`. If `contract_version` moved
to `v3` here, stop: the allocation contract is set somewhere you did not look,
and the live validator is about to reject every vector.

### 2.b — Keep the metagraph snapshot fresh

The bridge resolves both recipient UIDs and the burn destination by hotkey
through the publisher's `metagraph_hotkeys` snapshot, and fails closed if it is
stale — an unresolved burn destination yields an empty allocation and the caller
keeps V1 (in the v2 posture) or refuses to sign at all (in v3, see 3.b). The
freshness ceiling is `CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS_MAX_AGE_SECS`, currently
600.

```bash
sudo grep -E 'PAYABLE_HOTKEYS_MAX_AGE_SECS' /etc/cathedral/scorer-canary.env.sh
systemctl list-timers --all --no-pager | grep -i registration-snapshot
```

GREEN: the snapshot refresher fires comfortably inside that ceiling. A 600s
ceiling refreshed every 10 minutes has no margin; either widen the interval's
headroom or raise the ceiling deliberately, but know which you did.

### 2.c — Run the preview, against disposable state

`--consume-receipts` is the authoritative pass: it records each credited receipt
in the replay ledger so it can never be credited again. Run it at most once per
epoch, and never against the live ledger on a rehearsal.

The preview CLI takes only `--bundle`, `--lanes`, `--out`,
`--allow-unpoliced-preview` and `--consume-receipts` — it has no `--state-file`
and no `--runtime-root`. Its durable state is the **replay ledger and
epoch-state SQLite files named inside the bundle**, so that is where disposal
happens: point them at fresh paths under a scratch directory, exactly as
`cathedral-validator#61` step 5 specifies.

```bash
PREVIEW=/var/tmp/cybergym-preview-$(date -u +%Y%m%dT%H%M%SZ)
sudo -u cathedral-validator mkdir -p "$PREVIEW"
# The bundle's ledger/epoch-state paths must point inside $PREVIEW before this runs.
sudo -u cathedral-validator "$VAL/.venv/bin/cathedral-validator-integration-preview" \
  --bundle /path/to/preview-bundle.json \
  --out "$PREVIEW/preview.json"
```

Read that output first. Only then, once per epoch, the authoritative pass with
`--consume-receipts` appended. Do **not** pass `--allow-unpoliced-preview`: it
deliberately previews a funded lane without the measurement/TCB/advisory policy,
block window, or replay ledger, and its result is explicitly not evidence that a
receipt would be admitted under a launch policy.

**Verification — the composed vector matches the independent reproduction.**
The strongest signal in the E2E was that the two repositories agreed without
coordination: the verifier's `export-scores` printed
`report_sha256 = b459d713…`, and the validator recomputed the identical semantic
canonical digest over its own nine `SEMANTIC_KEYS`. Reproduce that property, do
not assume it:

```bash
python3 -c '
import json,sys
p=json.load(open(sys.argv[1]))
print(json.dumps(p["feed"], indent=2, sort_keys=True))' "$PREVIEW/preview.json"
```

GREEN: the credited UIDs and shares equal what the verifier's own frozen report
says they should be, and the lane total equals 0.30.

**Verification — no chain client is instantiated.** This is mechanical and worth
running exactly as written; "the CLI is documented as non-writing" is not a
check.

```bash
sudo -u cathedral-validator "$VAL/.venv/bin/python" - <<'PY'
import io, contextlib, sys
from cathedral_thin import integration_cli
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rc = integration_cli.main(["--bundle", "/path/to/preview-bundle.json",
                               "--out", "/var/tmp/preview-check.json"])
roots = {"bittensor", "substrateinterface", "async_substrate_interface"}
loaded = sorted(m for m in sys.modules if m.split(".")[0] in roots)
print("rc", rc, "| chain modules loaded:", loaded or "none")
assert not loaded, loaded
PY
```

GREEN: `rc 0 | chain modules loaded: none`. Confirmed working against
`--lanes` on 2026-08-05.

**Verification — the live validator did not move.**

```bash
sudo tail -n 5 "$EVENTS"
sudo stat -c '%n %y' /var/lib/cathedral-validator/thin-state.json \
  /var/lib/cathedral-validator/journal-*.json | grep -v '\.bak'
```

GREEN: no new `WEIGHTS_*` event attributable to the preview, and the state and
journal mtimes unchanged by it. (The state fence only advances on
`ok and broadcast` in `validator_thin.py`, so a preview should not touch it —
this confirms rather than assumes.)

---

## 3. The flip

Do not start this without all of section 1 GREEN and section 2 clean. Have both
shells open and both commands typed before you begin.

### 3.a — Wait for the starting gun

```bash
sudo tail -f "$EVENTS" | grep --line-buffered -E 'WEIGHTS_SUBMITTED|WEIGHT_COOLDOWN_SKIPPED'
```

Wait for a `"event":"WEIGHTS_SUBMITTED"` with `"status":"PASS"`. Note the
wall-clock time. From that moment you have the cooldown — read it from the next
`WEIGHT_COOLDOWN_SKIPPED` line, `weights_rate_limit=<blocks>`, ~20 minutes at
100 blocks — during which no write was possible anyway. Everything below happens
inside it.

Do not start the flip on a `PENDING_RECEIPT_RECOVERED`. That is a restart
re-proving an old receipt, not a fresh write, and it does not reset the
cooldown clock you are budgeting against.

### 3.b — Publisher flip

```bash
# In /etc/cathedral/scorer-canary.env.sh
CATHEDRAL_ALLOCATION_CONTRACT=v3
CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2=0
```

Both, together. `validated_supply_metadata()` refuses to compose v3 unless the
fixed burn is exactly 0:

```python
if contract == "v3":
    if not math.isclose(burn_percentage(), 0.0, rel_tol=0.0, abs_tol=1e-12):
        raise VectorError("validated_supply v3 requires exactly 0% fixed burn")
```

`CATHEDRAL_WEIGHT_POLICY_BURN_HOTKEY` stays set and unchanged. v3 burns no
*fixed* share, but the burn hotkey remains the sink for forfeited and ineligible
lane mass, so an explicit destination is still demanded — and
`CATHEDRAL_WEIGHT_POLICY_BURN_UID` must stay empty, because
`_validated_supply_common` refuses a vector whose burn destination pins a UID
(UIDs are recycled; a guessed UID is how a burn ends up in a miner's wallet).

```bash
sudo systemctl restart cathedral-scorer-sn39.service
sleep 20
curl -fsS -k -m 30 https://127.0.0.1:8012/v1/validator/weights/next \
  | python3 -c 'import json,sys; p=json.load(sys.stdin); m=p["policy_metadata"]; v=m["validated_supply"]; l=m.get("cybergym_lane") or {}; print("contract", v["contract_version"], "tdx", v["intel_tdx_allocation"], "cybergym", v.get("cybergym_allocation"), "fixed_burn", v["fixed_burn_allocation"]); print("lane fraction", l.get("fraction"), "contributing", l.get("contributing_fraction"), "forfeited", l.get("forfeited_fraction"), "burn_uid", l.get("burn_uid"))'
```

GREEN: `contract v3 tdx 0.7 cybergym 0.3 fixed_burn 0.0`, and a `cybergym_lane`
whose `fraction` is 0.30.

If the publisher refuses to sign at all, read the error before touching
anything: `_compose_cybergym_lane_v3` raises rather than emitting a partial
vector when the lane cannot be proven — mechanism disabled, a configured
fraction that is not exactly 0.30, an unresolved burn destination, or a lane
mass that does not equal the fraction. A publisher that cannot compose is
recoverable; a publisher that composed something ambiguous is not.

### 3.c — Validator re-pin, immediately

No pause. Edit the config the running process actually uses (from P1.a):

```bash
sudo cp /etc/cathedral-validator/validator-thin-sn39-relay.toml \
        /etc/cathedral-validator/validator-thin-sn39-relay.toml.bak-prev3-$(date -u +%s)
sudo sed -i 's/^require_policy = "validated_supply_v1"$/require_policy = "validated_supply_v3"/' \
        /etc/cathedral-validator/validator-thin-sn39-relay.toml
sudo grep -n 'require_policy\|^mechanism' /etc/cathedral-validator/validator-thin-sn39-relay.toml
sudo systemctl restart cathedral-validator-passive.service
```

**Change `[weight_policy] require_policy` and nothing else.** In particular
leave `[provenance] mechanism = "validated_supply_v1"` exactly as it is. That
field selects which *evidence* a run admits and which burn contract applies, not
the allocation — `sn39_public_reproduction.py` pins it to `validated_supply_v1`
in both postures on purpose, and widening it would move the burn rather than the
split. Changing it will fail the public reproduction.

### 3.d — Verify the flip landed

```bash
sudo tail -n 40 "$EVENTS" | grep -E 'STARTUP|VECTOR_ACCEPTED|VECTOR_REJECTED|WEIGHTS_'
```

GREEN, in this order:

- `STARTUP` with `"policy_pin":"validated_supply_v3"` in its detail;
- `VECTOR_ACCEPTED`;
- `WEIGHT_COOLDOWN_SKIPPED` (expected — you are inside the cooldown), then at
  its expiry a `WEIGHTS_SUBMITTED` whose `contract_version` is `"v3"` and whose
  `uid_count` is greater than 2.

RED: `VECTOR_REJECTED` with `reason=VectorError`. The two vectors disagree. Go
to section 4's rollback now, do not debug in place — every minute past the
cooldown expiry is a minute of real dark.

**In-window cross-check.** Confirm the served vector and the accepted result
agree on the contract, from the validator's own event stream and the publisher's
metadata — both already shown above. That is the check that fits inside the
cooldown.

The **public reproduction** is the stronger independent check, and it is
deliberately *not* in the flip window. It selects its expected lane by the
*pin* and then requires the result's own stamp to agree
(`_PIN_TO_DRY_RUN_CONTRACT_VERSION`), so neither direction of a disagreement can
reproduce; under a v3 pin `_assert_current_dry_run_v3` additionally requires
burn share exactly 0, `intel_tdx_share` 0.70, `cybergym_share` 0.30, and a full
UID vector summing to 1.0.

It cannot be run from any working install on this host, by design — it is a
third-party reproduction and it enforces that posture:

- Run from the deployed release tree
  (`$VAL/scripts/assert_sn39_public_reproduction.py`) it exits 3 with
  `SN39 public reproduction: NOT_PROVEN: cannot resolve the reproducer Git
  revision` — a release tree is not a Git checkout.
- Run from an existing checkout such as `/opt/cathedral-validator-selfserve` it
  exits 1 with `SN39 public reproduction: FAIL: reproducer checkout is not
  pristine (modified, untracked, or ignored files are forbidden)` — an in-place
  checkout has a `.venv/`, a `__pycache__/` and an operator's TOML in it.

Do it properly, out of band, after the watch window: a fresh clone of
`cathedral-validator` at the reproducer revision, with its virtualenv created
**outside** the tree, and `git status --porcelain=v1 --untracked-files=all
--ignored=matching` empty before you run it. GREEN is
`SN39 public reproduction: PASS {…}`, exit 0. Budget it as its own task; do not
spend cooldown on it.

---

## 4. One epoch of watching, and the exact rollback

### 4.a — What to watch

For one full epoch (≥ 25 minutes, ideally two ticks):

```bash
sudo tail -f "$EVENTS" | grep --line-buffered -E \
  'WEIGHTS_SUBMITTED|VECTOR_REJECTED|TICK_FAILED|PROVENANCE_(AUDIT|VECTOR)_'
```

- **`WEIGHTS_SUBMITTED`** — `contract_version` is `"v3"`, `burn_share` is
  `0.000000`, and the UID vector sums to 1.0. A `burn_share` of `0.100000` means
  a v2 vector got through; that is impossible under a v3 pin, so it means the
  pin did not take.
- **`VECTOR_REJECTED`** — any occurrence is a rollback trigger.
- **`PROVENANCE_AUDIT_PASS` with `vector_agrees=true`** — the shadow audit
  independently recomputed and agreed. `PROVENANCE_VECTOR_MISMATCH` is a
  rollback trigger; `PROVENANCE_VECTOR_STALE_EPOCH` is not (it is the
  publisher's serving race, self-resolving).
- **On-chain acceptance and finalization** — confirm the extrinsic in the
  `WEIGHTS_SUBMITTED` event's `extrinsic_hash` / `block_hash` / `block_number`
  reached a finalized block. Do not call it done on submission alone.
- **The lane's own numbers** — from `policy_metadata.cybergym_lane` on the
  served vector: `contributing_fraction` above 0 means real miners are being
  paid. `forfeited_fraction` of 0.30 with `contributing_fraction` 0 means the
  entire CyberGym allocation is burning. See section 5.
- **`cathedral-mismatch-check`** — should stay quiet across the whole window.

Once the window closes and the posture is stable, run the public reproduction
from a pristine clone as described at the end of 3.d. It is the check that
proves the pin and the vector agree to someone who does not trust either host.

### 4.b — Rollback

Revert in the reverse order of the flip: **validator pin first, publisher
second.** The validator is the thing writing to the chain; getting it back to a
pin that matches the *current* published vector is what stops the dark gap. If
you revert the publisher first you have simply moved the mismatch, and the
validator stays dark for the whole gap.

```bash
# 1. Validator: back to the launch pin.
sudo sed -i 's/^require_policy = "validated_supply_v3"$/require_policy = "validated_supply_v1"/' \
        /etc/cathedral-validator/validator-thin-sn39-relay.toml

# 2. Publisher: back to the launch contract.
#    In /etc/cathedral/scorer-canary.env.sh:
#      unset (or set to v2) CATHEDRAL_ALLOCATION_CONTRACT
#      CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2=10
#      CATHEDRAL_CYBERGYM_MECHANISM_ENABLED=0
sudo systemctl restart cathedral-scorer-sn39.service

# 3. Then restart the validator so it fetches a v2 vector under a v1 pin.
sudo systemctl restart cathedral-validator-passive.service
```

Confirm the v2 posture is back before walking away:

```bash
curl -fsS -k -m 30 https://127.0.0.1:8012/v1/validator/weights/next \
  | python3 -c 'import json,sys; v=json.load(sys.stdin)["policy_metadata"]["validated_supply"]; print(v["contract_version"], v["fixed_burn_allocation"])'
sudo tail -n 20 "$EVENTS" | grep -E 'STARTUP|VECTOR_ACCEPTED|WEIGHTS_SUBMITTED'
```

GREEN: `v2 0.1`, a `STARTUP` carrying `policy_pin=validated_supply_v1`, a
`VECTOR_ACCEPTED`, and at the next cooldown expiry a `WEIGHTS_SUBMITTED` with
`burn_share=0.100000`.

### 4.c — DO NOT restore the state file or the journal

**Never** roll back `/var/lib/cathedral-validator/thin-state.json` or
`/var/lib/cathedral-validator/journal-*.json` as part of this. Not from the
`.bak-*` files sitting next to them, not from any snapshot. There is no
situation in this runbook where restoring them is the right move.

Both hold a **monotonic** fence, `highest_attempted_policy_version`, and the
code refuses to move it backwards:

```python
stored_policy_fence = _state_policy_fence(current)
if new_policy_fence <= stored_policy_fence:
    raise ValueError(
        f"stale attempted policy version {new_policy_fence} <= "
        f"durable fence {stored_policy_fence}"
    )
```

and `accept_vector` rejects any vector at or below the fence:

```python
if pv <= fence_version:
    raise wire.VectorError(
        f"rollback/replay: vector policy_version {pv} <= last accepted {fence_version}"
    )
```

An older journal carries a *lower* fence. Restoring one re-opens the window on
every policy version between it and now — which is exactly a policy version that
has **already been attempted** becoming attemptable again. That is a double
write against the same signed vector, and it is a worse outcome than any dark
gap this runbook can produce. The fences are the mechanism that makes "the exact
signed attempt remains fenced" true across restarts; restoring an older copy
removes it.

The correct handling of a wedged fence is to leave both files alone, let the
validator re-prove its pending receipt on restart (the
`PENDING_RECEIPT_NOT_PROVEN` → `PENDING_RECEIPT_RECOVERED` path), and if that
does not resolve, escalate rather than edit. The historical `.bak-*` files in
`/var/lib/cathedral-validator/` are forensic records of past incidents, not a
restore set.

Rolling back the config, the env, and the deployed publisher build is all safe
and all reversible. Durable fence state is not part of the config.

---

## 5. What this does not do

Read this before section 1, not after.

### With no corpus scores flowing, v3 pays *more* to burn than v2 does

The CyberGym lane composes through `mechanism_eligibility.compose_eligible` with
`preserve_forfeited=True` (`scaffold/publisher/cybergym_bridge.py`, verified at
line 388). That flag means an unproven share is never reallocated to anyone: it
does not get renormalized across the other lanes, and it does not get spread
over the miners who *did* score. It goes to the burn identity, and only there.
The spec carries `requires_forfeit_preservation=True`, so
`mechanism_router.compose` raises `ForfeitPreservationRequired` if anyone ever
composes this lane through the legacy renormalizing path. There is no silent
fallback.

The intake makes the empty case explicit rather than exceptional. From
`cybergym_ingest.py`: an empty `scores` object is *legal and meaningful* — "nobody
scored this epoch" — "which makes the mechanism non-contributing so its share
burns."

Put together, with an empty or unscoreable corpus:

| | Intel TDX miners | Burn |
|---|---|---|
| **v2** (today) | 0.90 | 0.10 |
| **v3**, corpus producing nothing | 0.70 | **0.30** |

Flipping to v3 before the sealed corpus is live and producing scores **triples
the burn** and cuts the TDX miners' share by more than a fifth. It is not
neutral, it is not "getting the plumbing in place", and it is not free. It is a
strictly worse economy than the one running today, for exactly as long as
nothing is scoring.

That is the reason not to flip early. Preconditions P5 (real attestation) and P6
(sealed corpus) are not paperwork — they are what makes 0.30 flow to miners
instead of to the burn hotkey.

### It does not make the lane self-healing

`_compose_cybergym_lane_v3` raises rather than emitting a partial vector when
the lane cannot be proven. That is correct — an ambiguous split is worse than no
split — but the consequence is that a v3 publisher whose burn destination stops
resolving stops signing entirely, and a v3-pinned validator with nothing to
fetch writes nothing. In the v2 posture the same failure is soft: the bridge
returns an empty allocation and the caller keeps its V1 vector. v3 removes that
cushion. The metagraph snapshot freshness in 2.b is therefore a *liveness*
dependency after the flip, not just a correctness one.

### It does not prove any miner earned anything

The E2E's solve returned `trainable:false —
solved_trace_below_floor:too_few_steps,thin_reasoning,no_file_references`:
reward-creditable, but below the corpus-training quality floor. That was fine
for an infra proof. It is not evidence that the reward curve is calibrated, that
the private holdout is large enough to survive a real epoch, or that an
exhausted holdout degrades gracefully (`TaskPool` refuses rather than recycles).

### It does not resolve the v3 code ownership question

The report flags that a v3 `weights.py` exists on `cathedral-validator/main`
*and* divergently on `cathedral`'s unmerged `feat/allocation-v3-70-30-0` branch.
Make `cathedral-validator` the sole owner before enabling v3, or a composed
vector and its public reproduction can disagree while both look correct locally.

### It does not authorize anything

No step here is an approval. The chain writes described are the ones the live
validator already performs; the change is which contract they carry. The
decision to make that change is not this document's to make.

---

## Appendix — observed state, 2026-08-05 ~06:30–07:00 UTC

Everything below was read from the live host; none of it was changed.

| Fact | Value |
|---|---|
| Validator writer | `cathedral-validator-passive.service` + `20-quickstart.conf` drop-in |
| Validator command | `/opt/cathedral-validator-staging-9475f4f/.venv/bin/python -m scaffold.cli serve --config /etc/cathedral-validator/validator-thin-sn39-relay.toml --broadcast` |
| Policy pin | `validated_supply_v1` |
| Last write | `WEIGHTS_SUBMITTED` 06:58:42Z, `uids=2 burn_uid=204 burn_share=0.100000`, `contract_version: null` |
| Weight rate limit | `weights_rate_limit=100` blocks (~20 min) |
| State / journal | `/var/lib/cathedral-validator/thin-state.json`, `journal-193d0fdd….json` |
| Composing publisher | `cathedral-scorer-sn39.service`, `127.0.0.1:8012`, serving the same `vector_id` as `api.cathedral.computer` |
| Publisher code tree | `/home/polaris/cathedral-scorer/scaffold` @ `990c7a49` — **no CyberGym modules, no `ALLOCATION_CONTRACT_ENV`, no `_compose_cybergym_lane_v3`** |
| Burn hotkey | `5G3qVaXzKMPDm5AJ3dpzbpUC27kpccBvDwzSWXrq8M6qMmbC`, fixed burn 10%, burn UID resolved to 204 |
| Configured producer | `5Grwva…HGKutQY` (Substrate `//Alice` dev key) |
| Distill pin | `b2ad1eddf9235921f8f680342605d5c8a84a8d87` (= #96) in the repo, the deployed tree, and `--lanes` |
| `cathedral-cybergym` in validator venv | **not installed** |
| `POST /v1/cybergym/scores` | 404 on both `:8012` and `api.cathedral.computer` |
| `cathedral-validator#61` | OPEN |
| `cathedral-distill#80` | OPEN |

Precondition roll-up: **P1 GREEN, P3(a) GREEN. P2, P3(b), P4, P5, P6 RED.**
The cutover is not runnable today, and section 5 explains why running it anyway
would be worse than waiting.
