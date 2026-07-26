"""The `hermes-extract-v0` evaluation set.

The first track's student replaces the extraction step of the baseline Hermes
agent: read a fetched regulatory page, emit the facts a Card needs — title,
issuer, date, reference — plus a citation whose `content_hash` is copied
**verbatim** from the fetch result. That last field is the discipline the whole
Card pipeline depends on: validators re-fetch sources and compare hashes
byte-for-byte, so a model that paraphrases, truncates, or invents a hash sinks
the card no matter how good its prose is.

Grading is therefore exact-match throughout — `grader.py`'s extraction kind, no
model judging a model.

### Why the documents are synthetic but the URLs are real

Item documents are generated deterministically from a seed, styled as the
notices the real source pool publishes, and each cites a URL from the *actual*
`cathedral-eval-spec` EU AI Act pool. Live page bodies would break determinism —
the same eval must grade identically forever, and eur-lex.europa.eu does not
freeze its HTML for our benefit. Synthetic bodies with pinned hashes keep every
receipt reproducible while the task distribution stays honest to the workload.

This also makes the canary construction clean: a canary document contains a
reference code and obligation that exist nowhere on the public internet, because
they were minted here. A model that answers a canary correctly *without having
been shown the document* has read the sealed set — there is no other source.

### Determinism contract

`build()` with the same `seed` yields byte-identical items, so
`sealed_set.canonical_set` yields the same `plaintext_digest`, so a receipt's
evalset binding is stable across authoring machines. `random.Random(seed)` is
used exclusively; nothing reads the clock, the locale, or the filesystem.
"""
from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass

from cathedral_distill.sealed_set import EvalItem

EVALSET_ID = "hermes-extract-v0"
DEFAULT_SEED = 39  # the netuid; any fixed value works, this one is memorable
DEFAULT_ITEMS = 32
DEFAULT_CANARIES = 4

# The real EU AI Act source pool from cathedral-eval-spec. URLs only — bodies
# are generated. (url, source_class, publisher)
SOURCE_POOL: tuple[tuple[str, str, str], ...] = (
    ("https://eur-lex.europa.eu/eli/reg/2024/1689/oj", "official_journal",
     "Official Journal of the European Union"),
    ("https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
     "law_text", "EUR-Lex"),
    ("https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai",
     "regulator", "European Commission DG Connect"),
    ("https://digital-strategy.ec.europa.eu/en/policies/ai-office",
     "regulator", "European Commission AI Office"),
    ("https://digital-strategy.ec.europa.eu/en/library",
     "regulator", "European Commission DG Connect"),
    ("https://www.edpb.europa.eu/news/news_en",
     "regulator", "European Data Protection Board"),
    ("https://www.europarl.europa.eu/topics/en/article/20230601STO93804/"
     "eu-ai-act-first-regulation-on-artificial-intelligence",
     "parliament", "European Parliament"),
    ("https://commission.europa.eu/news_en",
     "government", "European Commission"),
)

_TOPICS = (
    "general-purpose AI model obligations",
    "high-risk system conformity assessment",
    "prohibited practices enforcement",
    "transparency obligations for deployers",
    "AI regulatory sandbox participation",
    "serious incident reporting",
    "codes of practice for GPAI providers",
    "market surveillance coordination",
)

_ACTIONS = (
    "publishes guidance on", "opens consultation regarding",
    "adopts implementing decision on", "issues clarification concerning",
    "announces enforcement priorities for", "updates the timeline for",
)

INSTRUCTION = (
    "You are the extraction step of a regulatory intelligence agent. Read the "
    "fetched document below and return ONLY a JSON object with exactly these "
    "fields: title (string), issuer (string), published (YYYY-MM-DD), "
    "reference (string), source_url (string), content_hash (string — copy the "
    "value from the fetch result verbatim, never shorten or recompute it), "
    "obligation_count (integer)."
)


@dataclass(frozen=True)
class _Doc:
    title: str
    issuer: str
    published: str
    reference: str
    source_url: str
    body: str
    obligation_count: int
    canary: bool


def _make_doc(rng: random.Random, index: int, *, canary: bool) -> _Doc:
    url, _cls, publisher = SOURCE_POOL[rng.randrange(len(SOURCE_POOL))]
    topic = _TOPICS[rng.randrange(len(_TOPICS))]
    action = _ACTIONS[rng.randrange(len(_ACTIONS))]
    year = rng.choice((2024, 2025, 2026))
    month, day = rng.randint(1, 12), rng.randint(1, 28)
    published = f"{year:04d}-{month:02d}-{day:02d}"

    if canary:
        # Minted here; exists nowhere else. Correctly extracting this reference
        # without seeing the document is proof of having read the sealed set.
        reference = f"CANARY/{rng.getrandbits(48):012x}"
        title = f"Delegated notice {reference} on {topic}"
    else:
        reference = f"C({year}) {rng.randint(1000, 9999)} final"
        title = f"{publisher} {action} {topic}"

    obligations = rng.randint(2, 7)
    lines = [
        f"# {title}",
        f"Issuer: {publisher}",
        f"Published: {published}",
        f"Reference: {reference}",
        f"Source: {url}",
        "",
        f"The {publisher} {action} {topic}. This notice concerns the "
        f"application of Regulation (EU) 2024/1689.",
        "",
        "Obligations introduced by this notice:",
    ]
    for n in range(obligations):
        clause = _TOPICS[rng.randrange(len(_TOPICS))]
        lines.append(f"  {n + 1}. Operators shall document {clause} "
                     f"within {rng.choice((30, 60, 90))} days.")
    lines.append("")
    lines.append(f"Contact reference desk quoting {reference}.")
    return _Doc(
        title=title, issuer=publisher, published=published, reference=reference,
        source_url=url, body="\n".join(lines), obligation_count=obligations,
        canary=canary,
    )


def _content_hash(body: str) -> str:
    """64-hex content hash of the fetched body, as the fetch tool reports it.

    BLAKE3 when the wheel is installed (matching the Card schema's citation
    format), SHA-256 hex otherwise — both are 64 lowercase hex chars, and the
    grading contract is *verbatim copy*, so the algorithm choice never affects a
    verdict. The algorithm actually used is recorded in each item's checks.
    """
    try:  # pragma: no cover - environment-dependent
        import blake3  # type: ignore

        return blake3.blake3(body.encode()).hexdigest()
    except ImportError:
        return hashlib.sha256(body.encode()).hexdigest()


def _hash_algorithm() -> str:
    try:  # pragma: no cover - environment-dependent
        import blake3  # type: ignore  # noqa: F401

        return "blake3"
    except ImportError:
        return "sha256"


def build(
    *,
    seed: int = DEFAULT_SEED,
    items: int = DEFAULT_ITEMS,
    canaries: int = DEFAULT_CANARIES,
) -> list[EvalItem]:
    """Build the set. Same seed → byte-identical items, forever."""
    if items <= 0 or canaries < 0 or canaries >= items:
        raise ValueError("need items > 0 and 0 <= canaries < items")
    rng = random.Random(seed)
    # Canary positions drawn from the same stream so they are stable per seed
    # but not clustered at the tail.
    canary_at = set(rng.sample(range(items), canaries))

    out: list[EvalItem] = []
    algorithm = _hash_algorithm()
    for index in range(items):
        doc = _make_doc(rng, index, canary=index in canary_at)
        digest = _content_hash(doc.body)
        prompt = (
            f"{INSTRUCTION}\n\n"
            f"--- fetch result ---\n"
            f"url: {doc.source_url}\n"
            f"content_hash: {digest}\n"
            f"--- document ---\n"
            f"{doc.body}\n"
        )
        expected = {
            "title": doc.title,
            "issuer": doc.issuer,
            "published": doc.published,
            "reference": doc.reference,
            "source_url": doc.source_url,
            "content_hash": digest,
            "obligation_count": doc.obligation_count,
        }
        out.append(
            EvalItem(
                item_id=f"hx0-{index:03d}",
                prompt=prompt,
                checks={
                    "kind": "extraction",
                    "expected": expected,
                    "required_fields": sorted(expected),
                    # Copy-exactly fields get no normalisation slack at all.
                    "normalize_default": {"casefold": True,
                                          "collapse_whitespace": True},
                    "normalize": {
                        "content_hash": {"casefold": False,
                                         "collapse_whitespace": False},
                        "reference": {"casefold": False},
                        "source_url": {"casefold": False},
                    },
                    "hash_algorithm": algorithm,
                    "canary": doc.canary,
                },
            )
        )
    return out


def manifest(items: list[EvalItem]) -> dict[str, object]:
    """Publishable description of the set: counts and digests, no content."""
    body = json.dumps(
        [item.as_dict() for item in items], sort_keys=True, separators=(",", ":")
    ).encode()
    return {
        "evalset_id": EVALSET_ID,
        "item_count": len(items),
        "canary_count": sum(bool(i.checks.get("canary")) for i in items),
        "hash_algorithm": _hash_algorithm(),
        "content_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
        "source_pool": sorted({u for u, _c, _p in SOURCE_POOL}),
    }
