# AGENTS.md — cathedral-distill

CyberGym track for SN39. Miners produce verified PoCs for already-patched
public vulnerabilities. The live reward loop is not open unless the code and
docs both say it is.

## Work-pass Codex QA

After implementation and tests, before declaring work done or marking a PR
ready, follow `.cursor/skills/codex-qa/SKILL.md`. Do not wait to be asked.
Missing Codex CLI login is not a skip: fall back to a Cursor Task with model
`gpt-5.6-sol-xhigh`.

Write the report to `/opt/cursor/artifacts/codex-qa-<topic>.md`. Fix
fail-closed and honesty findings in the same pass.

## Hard rules for this repo

- Documented collected-test counts in `README.md` must match the suite.
  `tests/test_documented_counts.py` fails if they drift.
- PolarIS `allow:` egress may map to `restricted` only when the allowlist
  matches. Contradictory `allow:` versus `egress_allowlist` must reject.
- `tls_pinning: true` is the SN39 boolean. On Cathedral-hosted TDX it means
  guest DNS plus CONNECT to public IPv4 :443, not SPKI or CA pinning. Error
  text must stay honest. Do not enable `agent_enclave` rewards on that bit
  alone.
