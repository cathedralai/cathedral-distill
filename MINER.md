# Run a CyberGym miner (SN39)

A CyberGym miner earns by **solving sealed vulnerability challenges**: an agent reads a
vulnerable build, writes a proof-of-crash (PoC), runs it, and refines until it crashes the
target. That real trajectory is your submission. Three steps to running from a clean box.

> This is the minimal CLI path. For the VS-Code / Dev-Container flow and the agent internals,
> see [docs/AGENT_QUICKSTART.md](docs/AGENT_QUICKSTART.md).

## 1. Install (no root)

```bash
git clone https://github.com/cathedralai/cathedral-distill.git
cd cathedral-distill
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```
This gives you the `cathedral-cybergym-agent` command.

## 2. Point it at a model

The agent drives any OpenAI-compatible `/chat/completions` endpoint. Local is recommended
(private, no per-call cost):
```bash
ollama pull hermes3
export AGENT_API_BASE=http://localhost:11434/v1
export AGENT_API_KEY=            # local server needs none
export AGENT_MODEL=hermes3
```
Or a hosted provider: set `AGENT_API_BASE` / `AGENT_API_KEY` / `AGENT_MODEL` to it.

## 3. Solve

**Test locally first** — a synthetic challenge, no server, no chain:
```bash
cathedral-cybergym-agent --local --level 0
```
You'll see the agent stream each step (`list_files` → `read_file` → `run_poc`) and a
crash/clean result. Bump `--level` (0–3) as it works.

**Then mine for real** — register a hotkey and solve a live validator's batch:
```bash
btcli subnet register --netuid 39 --wallet.name <coldkey> --wallet.hotkey <hotkey>

cathedral-cybergym-agent \
  --dispatch-url <validator-url> \
  --miner <your-hotkey-ss58> \
  --submit
```
It dispatches the batch, solves each task, and POSTs the submission (PoC + trace) the
validator verifies. **You earn proportional to verified solves** — solving *real*
ARVO/OSS-Fuzz bugs is the competitive edge (the agent's `run_poc` runs the image
differential against `n132/arvo:{id}-vul`/`-fix`).

## Going production: attestation

For production emission the agent runs **inside an Intel-TDX enclave** and binds its
trajectory into the receipt, so only genuine in-enclave solves earn (the validator
DCAP-verifies a representative receipt each epoch). See [docs/CYBERGYM_TRACK.md](docs/CYBERGYM_TRACK.md).

---
Prereqs: Python 3.11/3.12, a container runtime (Docker, or `udocker` for no-sudo) for the
real image differential, and a registered SN39 hotkey to submit.
</content>
