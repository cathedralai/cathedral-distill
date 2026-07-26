"""Teacher client and corpus builder for the distillation track.

Provider-agnostic on purpose: the teacher is one config value, not an
architecture. `TeacherConfig` reads an OpenAI-compatible chat-completions
endpoint from the environment (`TEACHER_BASE_URL`, `TEACHER_API_KEY`,
`TEACHER_MODEL`), so swapping K2 → K3 → anything else is an env change and a
registry review, never a code change.

Three rules this module enforces rather than documents:

**No corpus without a licence gate.** `build_corpus` refuses to generate a
single row unless the teacher passes `TeacherRegistry.assert_permitted` for the
distillation purpose. Cathedral publishes signed receipts; a receipt proving a
licence-violating distillation occurred is evidence against Cathedral, so the
gate sits in front of the very first token.

**Logprobs from row one.** Every record carries `top_k_logprobs` (None when the
provider withholds them). Sequence-level SFT is where the pipeline starts, but
logit-KL distillation is where the quality jump lives, and retrofitting a corpus
format is a rewrite. The field exists from the first row so it never has to be
retrofitted.

**The key never appears in a record, a log line, or an error.** Records are
content-addressed (`record_hash`) so the corpus can be deduplicated, audited,
and referenced from receipts without re-reading row bodies.

The HTTP transport is injectable. Tests pass a function; production uses the
stdlib `urllib` transport below, HTTPS-only, no third-party dependency.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable, Mapping, Sequence

from cathedral_distill.teacher_registry import (
    PURPOSE_DISTILLATION,
    TeacherRegistry,
)

RECORD_SCHEMA = "cathedral_distill_record_v1"
RECORD_DOMAIN = b"cathedral-distill-record-v1\x00"

Transport = Callable[[Mapping[str, Any]], Mapping[str, Any]]


class TeacherError(RuntimeError):
    """Raised on teacher configuration or transport failure. Never carries the key."""


@dataclass(frozen=True)
class TeacherConfig:
    """One teacher endpoint. `teacher_id` is what the registry reviews."""

    provider: str
    model: str
    version: str
    base_url: str
    api_key: str = field(repr=False)  # never in repr, never in errors
    temperature: float = 0.2
    max_tokens: int = 2048
    top_logprobs: int = 5
    timeout_s: float = 120.0

    @property
    def teacher_id(self) -> str:
        return f"{self.provider}/{self.model}/{self.version}"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "TeacherConfig":
        env = env or os.environ
        base_url = env.get("TEACHER_BASE_URL", "").rstrip("/")
        api_key = env.get("TEACHER_API_KEY") or env.get("KIMI_API_KEY") or ""
        if not base_url:
            raise TeacherError(
                "TEACHER_BASE_URL is not set — the teacher endpoint is config, "
                "and this module will not guess a hostname to send a key to"
            )
        if not base_url.startswith("https://"):
            raise TeacherError("TEACHER_BASE_URL must be https://")
        if not api_key:
            raise TeacherError("TEACHER_API_KEY (or KIMI_API_KEY) is not set")
        return cls(
            provider=env.get("TEACHER_PROVIDER", "yunwei"),
            model=env.get("TEACHER_MODEL", "kimi-k3"),
            version=env.get("TEACHER_VERSION", "2026-07-27"),
            base_url=base_url,
            api_key=api_key,
            temperature=float(env.get("TEACHER_TEMPERATURE", "0.2")),
            max_tokens=int(env.get("TEACHER_MAX_TOKENS", "2048")),
            top_logprobs=int(env.get("TEACHER_TOP_LOGPROBS", "5")),
        )


def urllib_transport(config: TeacherConfig) -> Transport:
    """Stdlib HTTPS transport for an OpenAI-compatible /chat/completions."""

    def send(body: Mapping[str, Any]) -> Mapping[str, Any]:
        request = urllib.request.Request(
            config.base_url + "/chat/completions",
            method="POST",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {config.api_key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=config.timeout_s) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:200]
            # The Authorization header must never ride along on an exception.
            raise TeacherError(f"teacher endpoint returned {exc.code}: {detail}") from None
        except urllib.error.URLError as exc:
            raise TeacherError(f"teacher endpoint unreachable: {exc.reason}") from None

    return send


def _trim_logprobs(payload: Any, k: int) -> list[dict[str, Any]] | None:
    """Normalise provider logprobs to [{token, top: [{token, logprob}]}]."""
    if not isinstance(payload, Mapping):
        return None
    content = payload.get("content")
    if not isinstance(content, list) or not content:
        return None
    out: list[dict[str, Any]] = []
    for position in content:
        if not isinstance(position, Mapping):
            return None
        top = [
            {"token": str(alt.get("token")), "logprob": float(alt.get("logprob"))}
            for alt in (position.get("top_logprobs") or [])[:k]
            if isinstance(alt, Mapping)
        ]
        out.append({"token": str(position.get("token")), "top": top})
    return out


@dataclass(frozen=True)
class DistillRecord:
    """One teacher completion, content-addressed and receipt-ready."""

    prompt: str
    completion: str
    teacher_id: str
    sampling: Mapping[str, Any]
    seed: int
    top_k_logprobs: Sequence[Mapping[str, Any]] | None
    record_hash: str
    # The teacher's chain-of-thought, when the provider exposes it
    # (reasoning models return it separately from the answer). Often the most
    # valuable training signal in the row: it shows *how* sources were ranked,
    # not just which one won.
    reasoning: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": RECORD_SCHEMA,
            "prompt": self.prompt,
            "completion": self.completion,
            "teacher_id": self.teacher_id,
            "sampling": dict(self.sampling),
            "seed": self.seed,
            "top_k_logprobs": (
                [dict(p) for p in self.top_k_logprobs]
                if self.top_k_logprobs is not None
                else None
            ),
            "reasoning": self.reasoning,
            "record_hash": self.record_hash,
        }


def _record_hash(body: Mapping[str, Any]) -> str:
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(RECORD_DOMAIN + encoded).hexdigest()


class TeacherClient:
    def __init__(self, config: TeacherConfig, transport: Transport | None = None):
        self._config = config
        self._transport = transport or urllib_transport(config)

    @property
    def teacher_id(self) -> str:
        return self._config.teacher_id

    def generate(self, prompt: str, *, seed: int) -> DistillRecord:
        """One completion, recorded with everything needed to reproduce it."""
        config = self._config
        sampling = {
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            "top_logprobs": config.top_logprobs,
        }
        response = self._transport(
            {
                "model": config.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": config.temperature,
                "max_tokens": config.max_tokens,
                "seed": seed,
                "logprobs": True,
                "top_logprobs": config.top_logprobs,
            }
        )
        try:
            choice = response["choices"][0]
            completion = str(choice["message"]["content"] or "")
        except (KeyError, IndexError, TypeError) as exc:
            raise TeacherError("teacher response missing choices[0].message.content") from exc

        logprobs = _trim_logprobs(choice.get("logprobs"), config.top_logprobs)
        reasoning = choice["message"].get("reasoning_content") or None
        body = {
            "prompt": prompt,
            "completion": completion,
            "teacher_id": config.teacher_id,
            "sampling": sampling,
            "seed": seed,
            "top_k_logprobs": logprobs,
            "reasoning": reasoning,
        }
        return DistillRecord(
            prompt=prompt,
            completion=completion,
            teacher_id=config.teacher_id,
            sampling=sampling,
            seed=seed,
            top_k_logprobs=logprobs,
            reasoning=reasoning,
            record_hash=_record_hash(body),
        )


def build_corpus(
    client: TeacherClient,
    prompts: Sequence[str],
    *,
    registry: TeacherRegistry,
    at: datetime,
    published_licence: bytes | None = None,
    base_seed: int = 0,
) -> list[DistillRecord]:
    """Generate a corpus, licence-gated before the first token.

    Seeds are `base_seed + index`, so the corpus is reproducible per prompt and
    two runs with the same inputs are comparable row by row.
    """
    registry.assert_permitted(
        client.teacher_id,
        purpose=PURPOSE_DISTILLATION,
        at=at,
        published_licence=published_licence,
    )
    return [
        client.generate(prompt, seed=base_seed + index)
        for index, prompt in enumerate(prompts)
    ]


def filter_corpus(
    records: Iterable[DistillRecord],
    *,
    keep: Callable[[DistillRecord], bool],
) -> list[DistillRecord]:
    """Deterministic filter + dedupe. No model in the loop.

    `keep` is the task's own acceptance check (schema parses, hashes verify —
    SparkProof's raw→verified consistency, reused). Deduplication is by
    completion content, so a teacher that repeats itself cannot inflate the
    corpus.
    """
    seen: set[str] = set()
    out: list[DistillRecord] = []
    for record in records:
        content_key = hashlib.sha256(record.completion.encode()).hexdigest()
        if content_key in seen:
            continue
        if not keep(record):
            continue
        seen.add(content_key)
        out.append(record)
    return out


def corpus_manifest(records: Sequence[DistillRecord]) -> dict[str, Any]:
    """Digest-only description of a corpus, safe to cite in a receipt."""
    hashes = sorted(record.record_hash for record in records)
    encoded = json.dumps(hashes, separators=(",", ":")).encode()
    return {
        "rows": len(records),
        "teachers": sorted({record.teacher_id for record in records}),
        "with_logprobs": sum(r.top_k_logprobs is not None for r in records),
        "corpus_digest": "sha256:" + hashlib.sha256(encoded).hexdigest(),
    }
