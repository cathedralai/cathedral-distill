"""`hermes-extract-v1` — the hardened evaluation set.

v0 taught us (for under a dollar) that clean single-document extraction is
solved at 3B: llama-3.2-3b scored 31/32 and the frontier would be decided by
noise at the ceiling. v1 exists to reopen the gap between "can follow a format"
and "can reason about which source to trust" — while keeping every verdict
exact-match, because the grader must stay deterministic.

Each item is now a **bundle of fetch results**, not one document:

- **Distractors.** Several notices on the *same topic* from different issuers,
  dates, and references, each internally consistent. Extracting fields from the
  wrong one produces well-formed, plausible, wrong answers.
- **Conflicts + an authority rule.** The instruction states the rule the Card
  pipeline actually uses: higher source class outranks newer date; among equal
  classes the latest `published` wins. Some items are decided by class (a newer
  regulator notice loses to an older official-journal entry — punishing recency
  bias), others by date. The model must *apply* the rule, not pattern-match.
- **Noise.** Off-topic notices padding the bundle, so evidence selection is
  part of the task.
- **Hash selection.** Every fetch result carries its own `content_hash`; the
  expected answer requires the hash of the *authoritative* document, copied
  verbatim. Citing the wrong document's hash — or a mixture of fields from
  different documents — fails. Evidence selection is thereby graded with the
  same byte-exact check as everything else.

The generator stays fully deterministic per seed, canaries still mint
nonexistent references, and the grading contract is unchanged — `grader.py`
needs no modification, because "harder" lives entirely in the task, not in the
judge.
"""
from __future__ import annotations

import random

from cathedral_distill.evalset import (
    SOURCE_POOL,
    _content_hash,
    _hash_algorithm,
)
from cathedral_distill.sealed_set import EvalItem

EVALSET_ID = "hermes-extract-v1"
DEFAULT_SEED = 41
DEFAULT_ITEMS = 32
DEFAULT_CANARIES = 4

# The authority ranking the instruction states and the ground truth applies.
# Mirrors cathedral-eval-spec's curation order. Lower index = more authoritative.
CLASS_RANK: tuple[str, ...] = (
    "official_journal",
    "law_text",
    "regulator",
    "parliament",
    "government",
    "secondary_analysis",
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

INSTRUCTION = (
    "You are the extraction step of a regulatory intelligence agent. Below are "
    "several fetch results. They may disagree.\n"
    "Authority rule: a document from a higher-ranked source class is "
    "authoritative over any lower-ranked document regardless of date; among "
    "documents of the same class, the most recent `Published` date is "
    "authoritative. Class ranking, highest first: "
    + " > ".join(CLASS_RANK) + ".\n"
    "Identify the single authoritative document for the topic in the QUESTION "
    "and return ONLY a JSON object with exactly these fields, taken from that "
    "document alone (never mix documents): title (string), issuer (string), "
    "published (YYYY-MM-DD), reference (string), source_url (string), "
    "content_hash (string — copy the authoritative document's hash from its "
    "fetch result verbatim), obligation_count (integer)."
)


def _pick_date(rng: random.Random) -> str:
    return (f"{rng.choice((2024, 2025, 2026)):04d}-"
            f"{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}")


def _notice(rng: random.Random, topic: str, source, *, canary: bool = False):
    url, source_class, publisher = source
    published = _pick_date(rng)
    if canary:
        reference = f"CANARY/{rng.getrandbits(48):012x}"
        title = f"Delegated notice {reference} on {topic}"
    else:
        reference = f"C({published[:4]}) {rng.randint(1000, 9999)} final"
        title = f"{publisher} notice on {topic}"
    obligations = rng.randint(2, 7)
    lines = [
        f"# {title}",
        f"Issuer: {publisher}",
        f"Source class: {source_class}",
        f"Published: {published}",
        f"Reference: {reference}",
        f"Source: {url}",
        "",
        f"The {publisher} addresses {topic} under Regulation (EU) 2024/1689.",
        "Obligations introduced:",
    ]
    for n in range(obligations):
        lines.append(
            f"  {n + 1}. Operators shall document "
            f"{_TOPICS[rng.randrange(len(_TOPICS))]} within "
            f"{rng.choice((30, 60, 90))} days."
        )
    body = "\n".join(lines)
    return {
        "title": title, "issuer": publisher, "published": published,
        "reference": reference, "source_url": url, "source_class": source_class,
        "obligation_count": obligations, "body": body,
        "content_hash": _content_hash(body),
    }


def _authoritative(docs) -> dict:
    """Apply the stated rule: class rank first, then latest date."""
    return max(
        docs,
        key=lambda d: (-CLASS_RANK.index(d["source_class"]), d["published"]),
    )


def _decided_by(docs) -> str:
    """Whether the winner was decided by class alone or needed the date rule.

    Derived from the actual contenders rather than asserted, so the diagnostic
    can never disagree with the ground truth.
    """
    best_rank = min(CLASS_RANK.index(d["source_class"]) for d in docs)
    top_class = [d for d in docs if CLASS_RANK.index(d["source_class"]) == best_rank]
    return "date" if len(top_class) > 1 else "class"


def build(
    *,
    seed: int = DEFAULT_SEED,
    items: int = DEFAULT_ITEMS,
    canaries: int = DEFAULT_CANARIES,
) -> list[EvalItem]:
    """Build the hardened set. Same seed → byte-identical items."""
    if items <= 0 or canaries < 0 or canaries >= items:
        raise ValueError("need items > 0 and 0 <= canaries < items")
    rng = random.Random(seed)
    canary_at = set(rng.sample(range(items), canaries))
    out: list[EvalItem] = []
    algorithm = _hash_algorithm()

    for index in range(items):
        topic = _TOPICS[rng.randrange(len(_TOPICS))]
        is_canary = index in canary_at

        # On-topic contenders from distinct source classes. 3 or 4 of them —
        # each a plausible answer, only one authoritative under the rule.
        pool = list(SOURCE_POOL)
        rng.shuffle(pool)
        contenders = [
            _notice(rng, topic, source, canary=is_canary and n == 0)
            for n, source in enumerate(pool[: rng.choice((3, 4))])
        ]
        # Half the items are decided by class, half by date-within-class. For
        # the date-decided ones, force a same-class pair so recency matters;
        # the class-decided ones naturally punish recency bias instead.
        if index % 2 and len(contenders) >= 2:
            contenders[1] = dict(
                contenders[1],
                **{"source_class": contenders[0]["source_class"]},
            )
            # rebuild body/hash for the altered distractor so its fetch result
            # stays internally consistent
            rebuilt = _notice(
                rng, topic,
                (contenders[1]["source_url"], contenders[0]["source_class"],
                 contenders[1]["issuer"]),
            )
            contenders[1] = rebuilt

        # Off-topic noise: 1-2 notices about different topics entirely.
        noise_topics = [t for t in _TOPICS if t != topic]
        noise = [
            _notice(rng, noise_topics[rng.randrange(len(noise_topics))],
                    pool[-(n + 1)])
            for n in range(rng.choice((1, 2)))
        ]

        answer = _authoritative(contenders)
        bundle = contenders + noise
        rng.shuffle(bundle)  # authoritative doc position is not a signal

        sections = []
        for n, doc in enumerate(bundle):
            sections.append(
                f"--- fetch result {n + 1} ---\n"
                f"url: {doc['source_url']}\n"
                f"content_hash: {doc['content_hash']}\n"
                f"--- document {n + 1} ---\n"
                f"{doc['body']}\n"
            )
        prompt = (
            f"{INSTRUCTION}\n\n"
            + "\n".join(sections)
            + f"\nQUESTION: Extract the authoritative record for: {topic}\n"
        )

        expected = {
            "title": answer["title"],
            "issuer": answer["issuer"],
            "published": answer["published"],
            "reference": answer["reference"],
            "source_url": answer["source_url"],
            "content_hash": answer["content_hash"],
            "obligation_count": answer["obligation_count"],
        }
        out.append(
            EvalItem(
                item_id=f"hx1-{index:03d}",
                prompt=prompt,
                checks={
                    "kind": "extraction",
                    "expected": expected,
                    "required_fields": sorted(expected),
                    "normalize_default": {"casefold": True,
                                          "collapse_whitespace": True},
                    "normalize": {
                        "content_hash": {"casefold": False,
                                         "collapse_whitespace": False},
                        "reference": {"casefold": False},
                        "source_url": {"casefold": False},
                    },
                    "hash_algorithm": algorithm,
                    "canary": is_canary,
                    # Diagnostic only — lets an operator see whether failures
                    # cluster on class-decided or date-decided items.
                    "decided_by": _decided_by(contenders),
                },
            )
        )
    return out
