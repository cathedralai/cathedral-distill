# cathedral-distill

**The CyberGym track: verified vulnerability discovery for Bittensor SN39.**

<div align="center">
  <video controls width="800" src="https://github.com/user-attachments/assets/930814df-e648-40f2-8d1a-6adcaae3f3f4"></video>
  <p><a href="https://www.youtube.com/watch?v=KQRz6r9HJAs">Watch on YouTube</a></p>
</div>

Miners compete by producing proof-of-concept exploits for **already-patched,
publicly-disclosed** software vulnerabilities. The mechanism verifies each PoC
by running it, with no judge model and no self-reported score. Its live reward
loop is not open yet. Verified PoCs and licensed reasoning traces are intended
to form a training corpus for the next specialist model.

> **Scope and posture.** This is authorized security research. Every
> reward-eligible real-corpus task is a historical vulnerability with a public
> fix, and verification *requires* the patched build to exist, so such a task
> cannot target an unpatched or arbitrary live system. Synthetic tasks are
> non-rewarding development fixtures. The subnet does not discover or exploit
> vulnerabilities in live systems. See [Responsible use](#responsible-use).

## What is available today

| Question | Today |
|---|---|
| Local development | **Available now, as a dry run.** `cathedral-cybergym-agent --local` generates one synthetic task and checks only that the PoC crashes the vulnerable side. No patched-build differential, no dispatch, submission, attestation, scoring, durability, or anti-gaming enforcement. It drives an OpenAI-compatible LLM endpoint you supply (`AGENT_API_BASE`, `AGENT_API_KEY`, `AGENT_MODEL`), which can be a local model |
| Live validator participation | **Not yet.** The CLI's live-dispatch mode is Phase-2-gated and exits with a message; no public validator endpoint is published |
| Miner transport | **None supported yet.** `--local` is not a transport, and the reference HTTP service is a development aid, not a supported miner endpoint. A Bittensor axon can swap in over the same handlers later |
| Intel TDX requirement | A solve is intended to earn only when attested from inside Intel TDX; solved-but-unattested credits zero. See the attestation boundary below |
| Registration | SN39 hotkey registration and an on-chain model commit are part of the live loop. **The live loop is not open: do not register or spend for this track before a launch notice** |
| On-chain reward activation | **Pending.** The CyberGym bridge exists in [`cathedral`](https://github.com/cathedralai/cathedral), but it is disabled and the live signed-vector builder does not call it. The team must choose one of the two reward architectures below. An owner action alone does not activate rewards |

The mechanism is implemented and tested hardware-free, the CyberGym lane runs end
to end in those tests, and the real binary backend (ARVO plus OSS-Fuzz
differential) is built and proven on real vulnerabilities. What remains is the
attested production worker described below, the full corpus at scale, a
Bittensor axon, a selected reward architecture, and proof of effective miner
emission.

### Reward activation has two architectures

Choose one architecture before any chain-owner ceremony:

1. **One composed vector on mechanism 0.** First replace the current 90% Intel
   TDX plus 10% fixed-burn contract with a versioned signed allocation policy
   that assigns the full emission across Intel TDX, CyberGym, and fixed burn,
   including where forfeited CyberGym share goes. Then wire the CyberGym bridge
   into `weights.build_signed_vector` before signing and keep the existing
   mechanism-0 chain writer. The Cathedral-signed allocation document must be
   authoritative. Publisher and validator releases must follow one coordinated
   compatibility rollout because the current validator rejects allocation drift.
2. **A separate on-chain mechanism 1.** Build and deploy a signed mechanism-1
   allocation policy, vector, and chain writer, including the treatment of
   forfeited share. Only then should the current subnet owner create the second
   mechanism and set its emission split. Creating the mechanism does not provide
   its validator weights.

For either architecture, a lane with missing, stale, incomplete, unauthenticated,
unmapped, or ineligible evidence sends its configured share to burn. No surviving
lane inherits forfeited mass.

Either choice remains blocked from launch until one recorded run proves every
step below:

1. Production transport delivers a fresh, complete CyberGym score backed by a
   result-bound Intel TDX receipt for a real-corpus solve.
2. The signed weights feed contains the intended miner with a positive CyberGym
   allocation and the reviewed burn allocation.
3. The canonical validator accepts the signed vector, submits it to the selected
   mechanism, and remains active on chain.
4. A finalized chain view shows the accepted validator row, plus nonzero
   incentive and nonzero emission for the intended miner.
5. An external miner installs the signed release and completes the same path
   without operator bypasses.

### The attestation boundary, exactly

Both TDX adapters are built and tested against real Intel DCAP quotes, but they
prove different things, and the difference is the whole boundary:

- **`attest.v1` binds a solve to a quote**, and that per-solve binding is proven.
  Because the enclave is bounded and cannot hold the multi-GB corpus image, this
  path runs **synthetic** tasks only.
- **`custom.v1` runs the real corpus image inside TDX**, and a genuine ARVO
  reproduction did run in a TDX VM whose boot quote verified. But a boot quote
  binds the machine and the customer's SSH key, not the PoC. `result_bound` is
  always false on this path, and the customer holds that private key, so a miner
  could pair a valid boot quote with a PoC obtained elsewhere. It is environment
  attestation, **not** proof of solve.

So an **attested real-corpus solve is NOT PROVEN.** Closing it needs the
persistent enclave-key worker described in
[docs/TDX_ATTESTATION.md](docs/TDX_ATTESTATION.md), where the enclave generates
its own signing keypair and signs a commitment over `(task, poc, trace)`. That
is an infrastructure and build step, not a gap in the verification code.

## Choose your path

| Role | Start here |
|---|---|
| Compete in the CyberGym or Distill track | **[The mining guide](docs/MINING.md)** in this repository |
| Run or audit a validator | [`cathedral/VALIDATOR.md`](https://github.com/cathedralai/cathedral/blob/main/VALIDATOR.md); this track's validator side: [docs/VALIDATING.md](docs/VALIDATING.md) |
| Provide Intel TDX CPU compute | [`cathedral-compute/MINING.md`](https://github.com/cathedralai/cathedral-compute/blob/main/MINING.md) |
| Use Cathedral Computer as a customer | [Product and API documentation](https://cathedral.computer/docs/) |
| Contribute to protocol code | [`cathedral` issues](https://github.com/cathedralai/cathedral/issues), [this repo's issues](https://github.com/cathedralai/cathedral-distill/issues) |

## Challenge, solve, replay, score, handoff

[CyberGym](https://github.com/sunblaze-ucb/cybergym) (UC Berkeley, Dawn Song's
lab) supplies the task shape: a codebase with a known, patched vulnerability. The
miner's model must produce a **PoC**, a byte-string input that triggers the bug.
The result is a physical fact, not an opinion:

```
PASS  <=>  the PoC CRASHES the vulnerable build   (exit code not in {0, 300})
           AND does NOT crash the patched build
```

That differential is the anti-gaming core. A generic segfault that also crashes
the patched build fails, so the input must trigger *the specific vulnerability
the patch fixed*. A passing PoC is a witness in the sense SAT uses: expensive to
produce, trivial and deterministic to check. The validator re-runs it rather than
trusting it, and re-derives every number, so a reported score is never an input.

The epoch loop:

```
1. Miner commits its model hash on-chain
2. Validator draws a sealed batch from the private holdout, using a nonce
   issued AFTER the commit, so the miner cannot have trained on it
3. The miner's model produces PoCs under a fixed budget
4. Each PoC is independently replayed: crashes vul, spares fix?
5. score = sum over the batch of weight[level] x solved
6. The highest score holds the frontier; a challenger must beat the incumbent
   RE-SCORED on the same batch, by a margin
7. The winner's approved artifacts enter the gated registry and training corpus
```

Scoring is difficulty-weighted by how much the model was told: `level0` gives
only the vulnerable code (find *and* exploit, blind), `level3` hands over the
patch diff. Blind discovery is the scarce capability, so it is weighted highest
(`level0` >> `level1` > `level2` > `level3`), and it is nearly un-memorisable,
because you cannot pre-store a PoC for a bug you were never told exists.

**Handoff to the validator.** This repository scores; it does not set weights.
Scored output crosses into `cathedral` through the scored-to-weights bridge,
where the SN39 validator applies its own identity, policy, freshness, receipt,
allocation, and burn checks before any chain decision. That bridge is off by
default today.

### What a verified solve does and does not prove

Worth stating exactly, because "the program crashed" invites more than it earns.
The claim a passing PoC supports is narrow:

```
Under this pinned environment, this input produces this observable
difference between these two builds.
```

That is a real fact, reproducible by anyone with the same digest-pinned image,
which is the entire point. It is **not** a claim that the bug is exploitable in
production, that it yields code execution rather than a denial of service, that
the model grasped the root cause, or that the model discovered the bug rather
than recalling one it had seen. That last one is a supply problem, handled
structurally below rather than checked after the fact.

The crash differential is also one predicate, not the only possible one.
Memory-safety bugs announce themselves through a sanitizer, which is why they
are the lane that exists today. Authorization bypass, secret disclosure, path
traversal, and injection are checkable in principle, but each needs its own
deterministic predicate rather than an exit code.

## Anti-gaming

Execution settles whether a PoC works. It cannot settle whether the model solved
the task or retrieved an answer it already had, because a memorised PoC and a
discovered one are the same bytes. Novelty has to be designed out by controlling
what the miner could have seen before it answered. Every property below is
tested:

- **The differential test** kills a whole class of cheating: a crash that is not
  the specific vulnerability fails, and skipping hard tasks cannot top the score.
- **Sealed, recency-rotated tasks.** The scored batch is drawn from
  vulnerabilities disclosed *after* the model was committed. Public ARVO and
  OSS-Fuzz tasks are development data only.
- **Commit-then-challenge.** The model hash is committed before the batch nonce
  exists, so the batch is unknowable in advance.
- **The validator re-derives the score.** Work units are a pure function of the
  committed task.
- **Paired evaluation.** A challenger is compared only to the incumbent re-scored
  on the *same* batch, so the crown never turns on which vulnerabilities each
  drew.
- **The trace bonus has a quality floor.** A padded or unlicensed reasoning trace
  earns nothing, and the gate is model-free, so it cannot be gamed with compute.

## What is built

| Capability | Status |
|---|---|
| **Score a solution**, differential crash test, level-weighted, re-derivable | **built** ([`cybergym.py`](cathedral_distill/cybergym.py)) |
| **Distribute problems**, sealed batch draw, private holdout, commit-then-challenge | **built** ([`cybergym_batch.py`](cathedral_distill/cybergym_batch.py)) |
| **Verify a solution**, run PoC to differential result (backend injected) | **built, logic** ([`cybergym_verifier.py`](cathedral_distill/cybergym_verifier.py)) |
| **Aggregate the dataset**, trace contract, structural quality gate, reuse licence | **built** ([`trace_submission.py`](cathedral_distill/trace_submission.py)) |
| **Share emission to valuable miners**, king-of-the-hill, independent reward books | **built** ([`frontier.py`](cathedral_distill/frontier.py), [`roles.py`](cathedral_distill/roles.py)) |
| **Spot-check without re-running everything**, Merkle openings, chain-derived challenges | **built** ([`challenge.py`](cathedral_distill/challenge.py)) |
| **Real binary backend**, real ARVO and OSS-Fuzz vul/fix differential, network-isolated, digest-pinned | **built and proven** ([`cybergym_repro.py`](cathedral_distill/cybergym_repro.py), [`corpus_images.py`](cathedral_distill/corpus_images.py)) |
| **Attested verification (L1)**, binding a solve to an Intel TDX quote | **adapters built and tested on real DCAP quotes.** Per-solve binding proven on the synthetic profile only; the attested real-corpus solve is **not proven** pending the enclave-key worker ([`cybergym_cathedral_attest.py`](cathedral_distill/cybergym_cathedral_attest.py), [TDX_ATTESTATION.md](docs/TDX_ATTESTATION.md)) |
| Network transport, reference HTTP service (a Bittensor axon can swap in over the same handlers) | **built (HTTP)**, development aid only ([`cybergym_http.py`](cathedral_distill/cybergym_http.py), [`cybergym_repro_server.py`](cathedral_distill/cybergym_repro_server.py)) |
| Durable validator handoff | **built, not reward-active.** A durably closed score epoch can be frozen into the canonical report, HMAC-authenticated, and posted to `cathedral-validator`'s score intake. The validator independently binds it to admitted receipts; this does not alter the live allocation or call `set_weights` ([`cybergym_score_report.py`](cathedral_distill/cybergym_score_report.py), [`docs/CYBERGYM_TRACK.md`](docs/CYBERGYM_TRACK.md)) |
| Reward wiring | **not live.** `cathedral-validator` is the sole canonical authority. The older bridge in `cathedral` remains disabled. Choose and sign the full allocation contract, integrate only through the canonical writer, then pass the reward proof gates above |
| Full corpus at scale, the ~130 GB+ ARVO/OSS-Fuzz image set | infra; the shipped reference slice is 5 static ARVO tasks for development, not a reward holdout |

## Modules

| Module | What it does |
|---|---|
| [`cybergym.py`](cathedral_distill/cybergym.py) | differential crash verification, level-weighted scoring, `cybergym_work_units_v1` |
| [`cybergym_batch.py`](cathedral_distill/cybergym_batch.py) | sealed batch draw, private/public holdout split, commit-then-challenge |
| [`cybergym_verifier.py`](cathedral_distill/cybergym_verifier.py) | PoC to differential result; injected backend, timeout-safe |
| [`trace_submission.py`](cathedral_distill/trace_submission.py) | the training-corpus contract and its structural quality gate |
| [`frontier.py`](cathedral_distill/frontier.py) | king-of-the-hill, paired evaluation, eligibility gates, emission split |
| [`roles.py`](cathedral_distill/roles.py) | miner-role separation and independent reward accounting |
| [`bundle_registry.py`](cathedral_distill/bundle_registry.py) | model/bundle identity, first-wins registration, version chains |
| [`registry_line.py`](cathedral_distill/registry_line.py) | the submission record: digests and a receipt URI, never the recipe |
| [`challenge.py`](cathedral_distill/challenge.py) | validator spot-checks: Merkle openings, chain-derived challenges |
| [`teacher_registry.py`](cathedral_distill/teacher_registry.py) | reviewed-teacher allowlist with pinned licence digests |
| [`eval_receipt.py`](cathedral_distill/eval_receipt.py), [`sealed_set.py`](cathedral_distill/sealed_set.py), [`polaris_attest.py`](cathedral_distill/polaris_attest.py) | the receipt, sealing, and TDX-attestation substrate the attested lane builds on |

## Guides

- **[Mining](docs/MINING.md)**: how to compete. The scoring, the epoch loop, what
  you submit, the trace bonus, a reference setup, and what earns a zero.
- **[Validating](docs/VALIDATING.md)**: how to run a validator. Drawing sealed
  batches, fail-closed verification, managing the private holdout, spot-checks,
  the confidential-compute ladder, and corpus aggregation.
- **[Live status API](docs/STATUS_API.md)**: `GET /v1/status` and `GET /v1/keys`.
  Every field, a real example, and how a miner reads a win, a loss, or a
  re-commit.
- **[Fresh CyberGym verifier E2E](docs/FRESH_CYBERGYM_E2E.md)**: a loopback-only,
  durable fresh-task path for miner/verifier testing. It is explicitly
  non-reward-bearing until the production identity, TDX, and emission controls
  plus a non-mechanically-recoverable challenge delivery path are configured.
- **[TDX attestation](docs/TDX_ATTESTATION.md)**: the two profiles, what each
  binds, and the production path.

## Launch and positioning

- **[Positioning](docs/POSITIONING.md)**: what SN39 is, why verified discovery,
  the miner contract, built versus to-build.
- **[Competitive landscape](docs/COMPETITIVE_LANDSCAPE.md)**: versus Snyk,
  Semgrep, GitHub Advanced Security, Bitsec. Alert versus proof, with sources.
- **[Launch copy](docs/LAUNCH_COPY.md)**: X thread, Discord announcement, FAQ.
- **Site**: `site/index.html` (the subnet), `site/research.html` (the technical
  case), `site/arena.html` (the proposed Cathedral Arena). Open locally or serve
  the `site/` directory.

## Run the tests

Requires Python 3.11 or newer. The installed package is `cathedral-cybergym`.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

The suite collects 1099 tests, all hardware-free: the verifier backend is
injected, so the full mechanism is exercised without the CyberGym binary corpus.
How many of them *run* depends on the machine, which is why no passing total is
claimed here. `tests/test_cybergym_hw.py` skips without `CYBERGYM_RUN_HW=1` and
the real vul/fix dataset, and one synthetic test skips without a C compiler on
`PATH`. A green suite proves software behavior, not live attestation,
deployment, or any on-chain reward.

## Verifier image contract

The verifier runs as a digest-pinned OCI workload
([`Dockerfile.cybergym-verify`](Dockerfile.cybergym-verify)): a fixed input
mount, the canonical result to stdout and nothing else (it is the attestation
binding surface), logs to stderr, pulled by digest so the bytes cannot change
after admission. In production it is intended to run inside a
confidential-compute enclave, both because it executes adversarial crashing
binaries and because the crash result is bound to the attestation quote.

## Responsible use

- **Targets are patched and disclosed.** A task only exists because a fix
  already exists, and verification depends on the patched build. The subnet does
  not discover or exploit unpatched vulnerabilities in live systems.
- **Aligned teachers only.** The teacher a model distills from is reviewed and
  licence-gated
  ([`teacher_registry.py`](cathedral_distill/teacher_registry.py)).
  Safety-ablated ("abliterated") models are not used: a worse teacher and a
  liability.
- **Distribution is gated.** A model trained on this corpus is distributed to
  verified security researchers under access controls, not published as ungated
  open weights.
- **Everything is evidence.** Every result is a reproducible receipt. The point
  of the subnet is verifiable defensive work, not opaque capability.

## Licence

MIT. See [LICENSE](LICENSE).
