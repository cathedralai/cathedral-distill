# CyberGym agent — quickstart (VS Code)

A real tool-using agent that solves CyberGym challenges: it **reads the vulnerable
build, reasons, writes a PoC, runs it, observes crash/no-crash, and refines** until
it crashes the target — and records that *real* trajectory as the submission (which
is also the training-corpus row). This replaces the old one-shot "prompt → PoC"
call. Code: `cathedral_distill/cybergym_agent.py` (the loop) +
`cathedral_distill/cybergym_agent_cli.py` (the runner).

## Run it in VS Code

1. **Open the folder** — with the Dev Container (`.devcontainer/`) VS Code builds a
   Python 3.11 env and `pip install -e .` for you. (Or use your own venv:
   `pip install -e .`.)
2. **Pick your model** (any OpenAI-compatible `/chat/completions` endpoint):
   - **Local Hermes** (recommended for miners — private, no per-call cost):
     ```
     ollama pull hermes3            # or run Hermes on vLLM / llama.cpp
     export AGENT_API_BASE=http://localhost:11434/v1
     export AGENT_API_KEY=          # local server needs none
     export AGENT_MODEL=hermes3
     ```
   - **Hosted model**: set `AGENT_API_BASE` / `AGENT_API_KEY` / `AGENT_MODEL` to your
     provider (e.g. `https://yunwu.ai/v1`, a key, `deepseek-v4-pro`).
3. **Run** — Command Palette → *Run Task* → **“CyberGym: solve locally (live
   trajectory)”**, pick a level. The agent streams each step live in the terminal
   and writes `.cybergym/trajectory.jsonl`. Or press **F5** (*CyberGym agent (local,
   debug)*) to step through it in the debugger.

## What you get

- **Live trajectory** in the terminal — one line per step (`read_file`, `write_poc`,
  `verify`) with the agent's reasoning and the crash/clean result.
- `.cybergym/trajectory.jsonl` — the full run (`@META` / `@STEP …` / `@RESULT`),
  the artifact the trajectory viewer renders and replays.
- On a solve: `…trajectory.jsonl.submission.json` — the exact
  `cathedral_cybergym_submission_envelope_v1` (PoC + trace) the validator verifies.

## The Hermes function-calling loop

The agent is model-agnostic. It uses the **Hermes / Nous function-calling format**:
tools are declared in a `<tools>` block and the model answers with
`<tool_call>{"name": …, "arguments": …}</tool_call>`, parsed from the text — so it
works with a real Hermes model *and* any other chat model. Tools: `list_files`,
`read_file`, `run_poc` (runs a candidate against the vulnerable build and reports
crash/clean). One tool per turn, so every step carries its own reasoning (a padded
or repetitive trajectory fails the trace floor and is not corpus-eligible).

## Real data (real ARVO/OSS-Fuzz bugs)

The synthetic tasks are for fast dev. Against **real** CyberGym tasks the verify is
a Docker-image differential (`n132/arvo:{id}-vul`/`-fix`). On a box with a container
runtime (Docker, or **udocker** for no-sudo userspace) the reference verifier
`verify_real.sh <arvo_id> [poc]` pulls the images and runs the differential
(crash-vulnerable / clean-patched). Point the agent's `run_poc` at that build and it
tests candidates against the genuine vulnerable target. Solving real bugs is the
miners' competitive edge — this loop is the starting point.

## Roadmap (later)

- **Attestation** — production runs the agent + tools *inside an Intel TDX enclave*
  and binds the trajectory into the TDX `report_data` (`cybergym_attest`), so only
  genuine in-enclave solves earn. See `docs/CYBERGYM_TRACK.md`.
- **SafeClaw** — a runtime security harness that vetoes each tool call by policy and
  runs the agent inside a sandbox (the containment), so a capable
  vulnerability-finding agent can't become a liability.
- **OpenClaw runtime** — wrap this loop in OpenClaw (multi-agent workspaces +
  Docker/allowlist sandbox) as the hardened runtime.
- **Trajectory viewer** — a VS Code webview that renders `.cybergym/trajectory.jsonl`
  with replay (today the terminal stream + the JSONL are the monitor).
