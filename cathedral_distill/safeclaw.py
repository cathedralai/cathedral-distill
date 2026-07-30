"""SafeClaw — a DEMO of a runtime security harness for autonomous AI agents.

⚠️  DEMONSTRATION ONLY — NOT A SECURITY GUARANTEE. This module illustrates an
*architecture*; it is not a hardened control, is unproven, gates nothing in the
SN39 reward path, and has dozens of documented bypasses. See ``docs/SAFECLAW.md``
and the ``DEMO_ONLY`` flag below, and read "Honest scope" before drawing any
security conclusion from it.

**The idea being demonstrated: do not make the LLM the security layer.** Every
action an agent proposes — a shell command, a file read/write, a network call —
is routed through a *deterministic* policy engine that scores its risk and decides
**ALLOW / ASK / SANDBOX / DENY** *before* it executes. A denied action never runs;
the agent receives a blocked observation it cannot argue its way past, because the
decision is code, not a prompt. (That only means the LLM cannot *talk* its way out
of a decision already made — an adversary evades the block by crafting bytes the
detectors never classify as DENY; see below.) Every decision is emitted as a
structured :class:`ActionEvent` — the audit trail.

**Honest scope — read this.** The policy layer here is **pattern-based risk scoring
and monitoring plus a naive-attack blocker**. It is *defense-in-depth*, NOT a
containment guarantee. Detectors match literal sensitive substrings in a lightly
normalised surface. Obfuscation the normaliser does not undo — globs the shell
expands *after* the check (``cat ~/.ssh/id*``), variable-assembled paths
(``a=/etc/;b=shadow;cat $a$b``), command substitution (``$(...)``), reading a whole
directory instead of a named secret (``tar czf - ~/.ssh``), alternate encodings,
and exfil/escape channels the regexes don't enumerate (DNS, a ``python`` upload
one-liner, ``git push``) — produces **NO signal and is therefore ALLOWed, silently.**
The harness does not detect "uncertainty"; it only matches known patterns. An
adversarial review of this module confirmed dozens of such bypasses (catalogued in
``docs/SAFECLAW.md``). This silent-ALLOW failure mode is exactly why the **real
containment is the sandbox**: the agent must run where host secrets are not mounted,
the network is denied, and it is unprivileged — so that even a command that evades
the policy has nothing to steal and nowhere to send it. SafeClaw's job is to *raise
the cost of naive attacks, score and flag risk, force whole untrusted categories
(e.g. PoC execution) into the sandbox, and log everything* — not to be an
impenetrable filter over a shell.

Detectors match on the sensitive **path/target** (not the leading tool), so some
alternate readers (``dd``, ``head``, ``xxd``, ``python -c open(...)``) are caught by
the file they name — but only when the secret path appears *literally*. Context-
aware: under the ``cybergym`` profile authoring and running PoCs is the job (→
sandboxed), while host credentials / exfiltration / sandbox escape are denied in
every profile *when spelled recognisably*.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Iterable, Mapping, Sequence

#: This module is a DEMONSTRATION of an architecture, not a production control.
#: It is unproven, gates nothing in the SN39 reward path, and has documented
#: bypasses (see docs/SAFECLAW.md). Exposed as an explicit, importable flag so a
#: caller can assert it is never mistaken for a real containment boundary.
DEMO_ONLY = True


class Decision(IntEnum):
    """Ordered by severity so ``max`` picks the strictest outcome."""

    ALLOW = 0      # run directly
    ASK = 1        # pause for human approval
    SANDBOX = 2    # run, but only inside an isolated sandbox
    DENY = 3       # never runs

    @property
    def label(self) -> str:
        return self.name


# Risk categories and their base weights (contribution to a 0..100 score).
CREDENTIAL_ACCESS = "credential_access"
EXFILTRATION = "exfiltration"
DANGEROUS_EXEC = "dangerous_exec"
PRIVILEGE = "privilege_escalation"
HOST_ESCAPE = "host_escape"
NETWORK_RAW = "network_raw"
EXPLOIT_AUTHORING = "exploit_authoring"

_WEIGHTS = {
    CREDENTIAL_ACCESS: 60,
    EXFILTRATION: 55,
    HOST_ESCAPE: 55,
    DANGEROUS_EXEC: 45,
    PRIVILEGE: 40,
    NETWORK_RAW: 30,
    EXPLOIT_AUTHORING: 20,
}


@dataclass(frozen=True)
class Signal:
    category: str
    weight: int
    detail: str
    match: str


@dataclass(frozen=True)
class Action:
    """A proposed agent action, normalised so detectors see one text surface.

    `tool` is the agent tool (e.g. 'shell', 'read_file', 'write_file', 'http').
    `command` is the shell command (for shell), `path` the file path, `url` the
    network target, `content` any written content. `surface` concatenates them
    for pattern matching (lightly normalised: matched case-folded, with common
    quotes/backslashes and a bare $HOME stripped and whitespace collapsed — this
    defeats only trivial obfuscation; it is NOT obfuscation-resistant, as the shell
    re-expands globs, variables and command substitution after the check)."""

    tool: str
    command: str = ""
    path: str = ""
    url: str = ""
    content: str = ""
    args: Mapping[str, object] = field(default_factory=dict)

    @property
    def surface(self) -> str:
        return " ".join(x for x in (self.command, self.path, self.url, self.content) if x)


# --------------------------------------------------------------------------- #
# Normalisation — collapse obvious obfuscation before matching so a detector
# sees `cat ~/.ssh/id_rsa` whether the agent wrote `cat  ~/.ssh/id_rsa`,
# `c""at ~/.ssh/id_rsa`, or `cat $HOME/.ssh/id_rsa`. This is defence-in-depth,
# not a claim of completeness — the sandbox is the backstop for what slips past.
# --------------------------------------------------------------------------- #
_STRIP = re.compile(r"""['"\\]""")          # quotes and backslash-escapes
_WS = re.compile(r"\s+")
_HOME = re.compile(r"\$\{?HOME\}?|\$\{?home\}?")


def normalise(text: str) -> str:
    t = _STRIP.sub("", text or "")
    t = _HOME.sub("~", t)
    t = _WS.sub(" ", t)
    return t.strip().lower()


# --------------------------------------------------------------------------- #
# Detectors — each returns Signals for a normalised action surface.
# --------------------------------------------------------------------------- #
_CREDENTIAL_PATHS = re.compile(
    r"(~|/root|/home/[^/\s]+)?/?\.?(ssh/id_[a-z0-9]+|ssh/[^ ]*_rsa|aws/credentials|"
    r"config/gcloud|kube/config|netrc|git-credentials|npmrc|pypirc|docker/config)"
    r"|/etc/(shadow|gshadow|sudoers)|id_rsa|id_ed25519|\.env(\.[a-z]+)?\b|"
    r"credentials\.json|service[-_]account.*\.json|secrets?\.(ya?ml|json|env)"
)
_CRED_KEYWORDS = re.compile(
    r"\b(aws_secret_access_key|aws_access_key_id|private[_-]?key|bearer [a-z0-9._-]{12,}|"
    r"password\s*=|passwd\b|api[_-]?key|access[_-]?token)\b"
)

_EXFIL = re.compile(
    r"curl[^|]*(-T|--upload-file|-d @|--data(-binary)? @|-F [^ ]*=@|-X (post|put)[^|]*@)"
    r"|wget[^|]*--post-file"
    r"|\bscp\b[^ ]* [^ ]+@|(^|\s)(nc|ncat|netcat)\b[^|]*\b\d{2,5}\b"
    r"|(mysqldump|pg_dump|mongodump)[^|]*\|[^|]*(curl|wget|nc|ncat)"
    r"|(base64|xxd|cat)[^|]*\|[^|]*(curl|wget|nc)"
    r"|(aws s3 cp|gsutil cp|rclone copy)[^ ]* [^ ]+ (s3|gs|remote):"
)

_REVERSE_SHELL = re.compile(
    r"bash -i[^\n]*/dev/tcp/|/dev/tcp/\d|nc[^\n]* -e |ncat[^\n]* -e |"
    r"python[0-9]?[^\n]*socket[^\n]*(exec|/bin/sh|/bin/bash)|"
    r"mkfifo[^\n]*(nc|ncat)|socat[^\n]*exec"
)

_DANGEROUS_EXEC = re.compile(
    r"(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh\b"           # curl | sh
    r"|rm\s+-[rf]{1,2}[a-z]*\s+(/|~|\*|\$home|/\*)"        # rm -rf / etc
    r"|:\(\)\s*\{\s*:\|:&\s*\};:"                          # fork bomb
    r"|dd\s+[^\n]*of=/dev/(sd|nvme|xvd)"                   # disk wipe
    r"|mkfs\.[a-z0-9]+\s+/dev/"                            # reformat
    r"|>\s*/dev/(sd|nvme)"                                 # overwrite disk
    r"|chmod\s+(-r\s+)?(0?777|a\+rwx)"                     # world-writable
    r"|eval\s+.*(curl|wget|base64)"                        # eval remote
    r"|base64\s+-d[^|]*\|\s*(ba)?sh"                       # base64 | sh
    r"|echo\s+[a-z0-9+/=]{40,}\s*\|\s*base64\s+-d\s*\|\s*(ba)?sh"
)

_PRIVILEGE = re.compile(
    r"(^|\s)(sudo|su\s|doas)\b|chmod\s+[ug]?\+s|setcap\b|"
    r">\s*/etc/(passwd|hosts|sudoers|cron)|tee\s+/etc/|"
    r"\b(insmod|modprobe|rmmod)\b|mount\s+-o|/etc/ld\.so\.preload"
)

_HOST_ESCAPE = re.compile(
    r"/var/run/docker\.sock|/proc/1/|/proc/self/(exe|root|cwd)|nsenter\b|"
    r"--privileged|cap_add|/sys/fs/cgroup[^\n]*release_agent|chroot\s+/host|/host/"
)

_NETWORK_RAW = re.compile(
    r"\b\d{1,3}(\.\d{1,3}){3}\b(:\d+)?"                    # raw IPv4 literal
    r"|https?://\d{1,3}(\.\d{1,3}){3}"                     # http to raw IP
)

# In a security/CyberGym context the agent is *supposed* to author memory-safety
# PoCs. These are not "bad" — they are the job — so they raise the score toward
# SANDBOX, never DENY.
_EXPLOIT_AUTHORING = re.compile(
    r"\b(memcpy|strcpy|strcat|gets|sprintf|alloca|system|popen)\s*\("
    r"|\b(malloc|free)\s*\(|use[- ]after[- ]free|heap[- ]overflow|"
    r"buffer overflow|shellcode|/bin/sh\\x|\\x[0-9a-f]{2}\\x[0-9a-f]{2}"
)


def _scan(pattern: re.Pattern, category: str, detail: str, text: str) -> list[Signal]:
    m = pattern.search(text)
    if not m:
        return []
    return [Signal(category=category, weight=_WEIGHTS[category], detail=detail,
                   match=(m.group(0) or "")[:80])]


def detect(action: Action) -> list[Signal]:
    """Run every detector over the normalised action surface. Pure + deterministic."""
    s = normalise(action.surface)
    signals: list[Signal] = []
    signals += _scan(_CREDENTIAL_PATHS, CREDENTIAL_ACCESS, "reads/copies a secret file", s)
    signals += _scan(_CRED_KEYWORDS, CREDENTIAL_ACCESS, "references a secret value", s)
    signals += _scan(_EXFIL, EXFILTRATION, "sends data off-box", s)
    signals += _scan(_REVERSE_SHELL, EXFILTRATION, "opens a reverse shell", s)
    signals += _scan(_DANGEROUS_EXEC, DANGEROUS_EXEC, "destructive or remote-piped exec", s)
    signals += _scan(_PRIVILEGE, PRIVILEGE, "privilege escalation / host config", s)
    signals += _scan(_HOST_ESCAPE, HOST_ESCAPE, "sandbox/container escape", s)
    signals += _scan(_NETWORK_RAW, NETWORK_RAW, "connects to a raw IP", s)
    signals += _scan(_EXPLOIT_AUTHORING, EXPLOIT_AUTHORING, "authors memory-safety exploit code", s)
    return signals


# --------------------------------------------------------------------------- #
# Policy — a small, auditable decision function over the signals.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class PolicyProfile:
    """A named policy. `hard_deny` categories are denied on sight regardless of
    score; `sandbox_categories` force at least SANDBOX; thresholds map the summed
    score to a decision. `allow_paths` whitelists benign reads."""

    name: str
    hard_deny: frozenset[str]
    sandbox_categories: frozenset[str]
    sandbox_tools: frozenset[str] = frozenset()   # tools whose mere execution is untrusted → SANDBOX
    deny_score: int = 70
    sandbox_score: int = 40
    ask_score: int = 25
    allow_paths: tuple[str, ...] = ()

    @staticmethod
    def default() -> "PolicyProfile":
        # A general coding agent: no credentials, no exfil, no escape, no
        # destructive exec, no writing exploit code. Shell risk is content-based
        # (normal dev shouldn't be sandboxed wholesale).
        return PolicyProfile(
            name="default",
            hard_deny=frozenset({CREDENTIAL_ACCESS, EXFILTRATION, HOST_ESCAPE}),
            sandbox_categories=frozenset({DANGEROUS_EXEC, PRIVILEGE, EXPLOIT_AUTHORING}),
        )

    @staticmethod
    def cybergym() -> "PolicyProfile":
        # A bug-finding agent: authoring + RUNNING PoCs is the JOB, so ALL
        # execution is untrusted and sandboxed (not denied) — but touching host
        # creds, exfiltrating, or escaping the sandbox is still denied.
        return PolicyProfile(
            name="cybergym",
            hard_deny=frozenset({CREDENTIAL_ACCESS, EXFILTRATION, HOST_ESCAPE}),
            sandbox_categories=frozenset({EXPLOIT_AUTHORING, DANGEROUS_EXEC, NETWORK_RAW}),
            sandbox_tools=frozenset({"shell", "exec", "run", "run_poc", "bash", "terminal"}),
        )


@dataclass(frozen=True)
class Assessment:
    action: Action
    signals: tuple[Signal, ...]
    score: int
    decision: Decision
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"tool": self.action.tool, "score": self.score,
                "decision": self.decision.label, "reasons": list(self.reasons),
                "signals": [{"category": s.category, "match": s.match} for s in self.signals]}


class PolicyEngine:
    """Assess an action and decide — deterministically. No model in the loop."""

    def __init__(self, profile: PolicyProfile | None = None) -> None:
        self.profile = profile or PolicyProfile.default()

    def assess(self, action: Action) -> Assessment:
        p = self.profile
        surface_l = normalise(action.surface)
        if any(surface_l.startswith(normalise(a)) or normalise(a) in surface_l for a in p.allow_paths):
            return Assessment(action, (), 0, Decision.ALLOW, ("allow-listed",))
        signals = tuple(detect(action))
        score = min(100, sum(s.weight for s in signals))
        cats = {s.category for s in signals}
        reasons: list[str] = []
        decision = Decision.ALLOW

        hard = cats & p.hard_deny
        if hard:
            decision = Decision.DENY
            reasons.append("hard-deny category: " + ", ".join(sorted(hard)))
        else:
            if score >= p.deny_score:
                decision = Decision.DENY
                reasons.append(f"risk score {score} ≥ deny threshold {p.deny_score}")
            elif (cats & p.sandbox_categories) or score >= p.sandbox_score:
                decision = Decision.SANDBOX
                sc = cats & p.sandbox_categories
                reasons.append("sandbox category: " + ", ".join(sorted(sc)) if sc
                               else f"risk score {score} ≥ sandbox threshold {p.sandbox_score}")
            elif score >= p.ask_score:
                decision = Decision.ASK
                reasons.append(f"risk score {score} ≥ ask threshold {p.ask_score}")
            # Untrusted-execution tools are sandboxed regardless of content signals
            # (running a built binary looks benign but must still be isolated).
            if action.tool in p.sandbox_tools and decision < Decision.SANDBOX:
                decision = Decision.SANDBOX
                reasons.append(f"execution tool '{action.tool}' → sandbox")
        if not reasons:
            reasons.append("no risk signals")
        return Assessment(action, signals, score, decision, tuple(reasons))


# --------------------------------------------------------------------------- #
# Guard — intercepts an action, decides, executes (or refuses), and logs.
# --------------------------------------------------------------------------- #
@dataclass
class ActionEvent:
    seq: int
    agent: str
    tool: str
    surface: str
    score: int
    decision: str
    reasons: list[str]
    outcome: str                     # executed | sandboxed | blocked | ask-pending | error
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


class EventLog:
    """The append-only audit trail of every action and decision."""

    def __init__(self) -> None:
        self._events: list[ActionEvent] = []

    def append(self, ev: ActionEvent) -> None:
        self._events.append(ev)

    def events(self) -> list[ActionEvent]:
        return list(self._events)

    def blocked(self) -> list[ActionEvent]:
        return [e for e in self._events if e.decision == Decision.DENY.label]

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(e.to_dict()) for e in self._events)


@dataclass(frozen=True)
class GuardResult:
    decision: Decision
    allowed: bool                    # did the action actually run?
    output: str                      # tool output, or the block message the agent sees
    assessment: Assessment


class SafeClawGuard:
    """The policy enforcement point (defense-in-depth, NOT the containment
    boundary). `execute(action, run, sandbox_run)` decides first, then runs `run`
    (ALLOW), `sandbox_run` (SANDBOX), or refuses (DENY/ASK). Once an action is
    decided DENY/ASK the agent cannot argue the block away — the decision is code,
    not a prompt — but detection can be evaded upstream, so a bypassing action is
    simply never classified DENY. The sandbox is the real containment. Every call
    is logged.
    """

    def __init__(self, engine: PolicyEngine, log: EventLog | None = None,
                 agent: str = "agent", approve: Callable[[Assessment], bool] | None = None) -> None:
        self.engine = engine
        self.log = log or EventLog()
        self.agent = agent
        self.approve = approve       # optional human-approval callback for ASK
        self._seq = 0

    def execute(self, action: Action,
                run: Callable[[], str],
                sandbox_run: Callable[[], str] | None = None) -> GuardResult:
        a = self.engine.assess(action)
        self._seq += 1
        blocked_msg = ("BLOCKED BY POLICY [{}]: {}. This action did not run."
                       .format(a.decision.label, "; ".join(a.reasons)))

        def emit(outcome: str, detail: str = "") -> None:
            self.log.append(ActionEvent(self._seq, self.agent, action.tool, action.surface[:200],
                                        a.score, a.decision.label, list(a.reasons), outcome, detail[:200]))

        if a.decision == Decision.DENY:
            emit("blocked")
            return GuardResult(a.decision, False, blocked_msg, a)
        if a.decision == Decision.ASK:
            if self.approve is None or not self.approve(a):
                emit("ask-pending")
                return GuardResult(a.decision, False,
                                   "HELD FOR APPROVAL: " + "; ".join(a.reasons) + ". Not run.", a)
            # approved -> fall through to run
        if a.decision == Decision.SANDBOX:
            runner = sandbox_run or run
            if sandbox_run is None:
                # No sandbox available for a must-sandbox action -> refuse, fail closed.
                emit("blocked", "no sandbox available")
                return GuardResult(Decision.DENY, False,
                                   blocked_msg + " (requires a sandbox; none configured)", a)
            try:
                out = runner()
            except Exception as exc:  # a failing sandbox run is an observation, not a crash
                emit("error", str(exc)); return GuardResult(a.decision, True, f"error: {exc}", a)
            emit("sandboxed")
            return GuardResult(a.decision, True, out, a)
        # ALLOW (or approved ASK)
        try:
            out = run()
        except Exception as exc:
            emit("error", str(exc)); return GuardResult(a.decision, True, f"error: {exc}", a)
        emit("executed")
        return GuardResult(a.decision, True, out, a)


def action_from_tool_call(name: str, arguments: Mapping[str, object]) -> Action:
    """Map a generic agent tool call to an Action for the guard."""
    a = {k: str(v) for k, v in (arguments or {}).items()}
    if name in ("shell", "exec", "run", "terminal", "bash"):
        return Action(tool="shell", command=a.get("command", a.get("cmd", "")))
    if name in ("read_file", "cat", "open"):
        return Action(tool="read_file", path=a.get("path", a.get("file", "")))
    if name in ("write_file", "write", "edit"):
        return Action(tool="write_file", path=a.get("path", ""), content=a.get("content", ""))
    if name in ("http", "fetch", "download", "curl"):
        return Action(tool="http", url=a.get("url", a.get("target", "")), command=a.get("command", ""))
    # unknown tool: put everything on the surface so detectors still see it
    return Action(tool=name, command=" ".join(a.values()))


__all__ = [
    "DEMO_ONLY",
    "Decision", "Signal", "Action", "detect", "normalise",
    "PolicyProfile", "Assessment", "PolicyEngine",
    "ActionEvent", "EventLog", "GuardResult", "SafeClawGuard", "action_from_tool_call",
    "CREDENTIAL_ACCESS", "EXFILTRATION", "DANGEROUS_EXEC", "PRIVILEGE",
    "HOST_ESCAPE", "NETWORK_RAW", "EXPLOIT_AUTHORING",
]
