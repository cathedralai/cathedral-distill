# AGENTS.md — cathedral-distill

CyberGym track for SN39. Miners produce verified PoCs for already-patched
public vulnerabilities. The live reward loop is not open unless the code and
docs both say it is.

## Work-pass Codex QA

After implementation and tests, before declaring work done or marking a PR
ready, follow `.cursor/skills/codex-qa/SKILL.md`. Do not wait to be asked.
Missing Codex CLI login is not a skip: default is GPT-5.6 extra high
(`gpt-5.6-sol` + `xhigh`, or Cursor Task `gpt-5.6-sol-xhigh`). Drop to
GPT-5.6 high only when extra-high usage is exhausted. Do not use GPT-5.5.

Write the report to `/opt/cursor/artifacts/codex-qa-<topic>.md`. Fix
fail-closed and honesty findings in the same pass.

## Hard rules for this repo

- Documented collected-test counts in `README.md` must match the suite.
  `tests/test_documented_counts.py` fails if they drift.
- Trust copy must not claim a stronger guarantee than enforcement.
  `tls_pinning: true` on Cathedral-hosted TDX means guest DNS plus CONNECT
  to public IPv4 :443, not SPKI or CA pinning. Do not enable `agent_enclave`
  rewards on that bit alone.
- PolarIS `allow:` mapping is not on `main` until the consumer PR merges.
  When that work is in scope, contradictory `allow:` versus
  `egress_allowlist` must reject. Do not describe the mapping as already
  shipped.
