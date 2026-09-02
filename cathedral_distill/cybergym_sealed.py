"""Seal-time task identity: mint a re-sealed bug an id that does not name its origin.

Re-sealing (``scripts/reseal_task.py``) strips the answer out of a real upstream
bug -- private answer-stripped images, the reference PoC bind-mounted at run time
rather than baked -- and genericises the disclosed metadata. Until now it kept the
UPSTREAM id, and that alone is disqualifying: ``arvo:<n>`` names a publicly
pullable ``n132/arvo:<n>-vul`` whose ``/tmp/poc`` is the answer, so
:func:`corpus_admission.public_catalog_task_id` refuses the task however private
our own image is (issues #157/#165). Every other gate passed; the id killed it.
That refusal is correct and stays -- the fix belongs here, at seal time, which is
what #165's refusal message and #131 both point at.

**Why the id must be keyed, not just opaque.** A hash of the origin alone is
reversible by anyone: the upstream corpus is public and small enough to enumerate,
so ``sha256("arvo:12345")`` is a lookup table, not a seal. The nonce is therefore
an HMAC under a validator-held seal key. That buys three properties at once:

* **unlinkable** -- without the key, a sealed id says nothing about which bug it is;
* **deterministic** -- one bug under one key always mints the same id, so a re-seal
  is reproducible and a duplicate admission is detectable rather than silently
  paying twice for the same bug;
* **non-malleable by the operator** -- an operator cannot re-roll the id to dodge a
  refusal, because the id is a function of the origin, not of the attempt.

Determinism is a deliberate trade, and the cost is worth stating: a stable id is also
a stable HANDLE, so a miner who solves a task once can recognise it in a later round
and replay the answer without re-deriving it. That is not a leak of the origin (the id
still says nothing about which bug it is), and it is the same exposure any stable task
identity carries; the alternative -- a fresh id per dispatch -- would destroy duplicate
detection and let one bug be admitted and paid under many identities, which is the
worse failure. Cross-round replay is the scoring layer's problem (a task already solved
by a miner should not pay them again), not something a random id would fix.

**Nonce width is a security parameter, not cosmetic.** Issue #118 is exactly this
mistake made once already: a task id truncated to the last 8 characters of a nonce,
so two different challenges could collide onto one id. At 32 bits a few thousand
tasks carry a birthday-collision probability in the fractions of a percent -- small,
but a collision here merges two distinct bugs into one identity on the reward path.
:data:`SEALED_NONCE_HEX` is 16 hex characters (64 bits), which puts the same corpus
at a negligible bound, and the grammar in ``cybergym.py`` accepts a nonce of any
length so widening cost nothing.

The origin string never travels with the task. It is returned separately by
:func:`sealed_origin_terms` so the caller can record it in the manifest's PRIVATE
``origin_terms``, where admission enforces by construction that it never reappears
in a disclosed field (#131/#132).
"""
from __future__ import annotations

import hmac
import re
from hashlib import sha256

SEALED_TASK_PREFIX = "sealedvuln:"

#: Hex characters of HMAC output kept for the nonce. 16 => 64 bits; see the module
#: docstring on why this is deliberately not 8 (issue #118).
SEALED_NONCE_HEX = 16

_SEAL_DOMAIN = b"cathedral-cybergym-sealed-id-v1\x00"

#: An upstream reference we know how to seal: ``arvo:<n>`` / ``oss-fuzz:<n>``, the
#: two public-catalog forms ``corpus_admission`` refuses. Case-insensitive, because
#: the refusal it exists to satisfy is too.
_ORIGIN_RE = re.compile(r"\A(arvo|oss-fuzz):([0-9]+)\Z", re.IGNORECASE)


class SealedTaskError(ValueError):
    """A sealed task id could not be minted from the inputs given."""


def is_sealed_task(task_id: object) -> bool:
    """Whether ``task_id`` was minted by this module.

    Unlike ``is_synthetic_task`` / ``is_fresh_task``, a true answer here does NOT
    imply non-rewardable: a re-sealed task is a real upstream vulnerability whose
    artifact renders no part of the trigger, so it earns on the ordinary admission
    gates. The predicate exists to identify provenance, not to withhold reward.
    """
    return isinstance(task_id, str) and task_id.startswith(SEALED_TASK_PREFIX)


def parse_origin(origin_id: str) -> tuple[str, str]:
    """Split a public-catalog origin into ``(catalog, number)``, normalised.

    Normalisation is load-bearing, not tidiness. The id is deterministic so that one
    bug has one identity and a duplicate is detectable; any spelling of the same bug
    that survives to the HMAC mints a SECOND identity, and two identities for one bug
    is the corpus paying twice for it. So the catalog is lower-cased and the number is
    canonicalised through ``int`` — ``arvo:012345`` and ``arvo:12345`` are the same
    bug and must not seal apart.

    Raises rather than passing an unrecognised string through: minting a sealed id
    from something we cannot parse would produce an id whose origin terms we also
    cannot derive, and the disclosure check would then police nothing.
    """
    match = _ORIGIN_RE.match((origin_id or "").strip())
    if not match:
        raise SealedTaskError(
            f"origin must be arvo:<n> or oss-fuzz:<n>, got {origin_id!r}"
        )
    return match.group(1).lower(), str(int(match.group(2)))


def sealed_nonce(origin_id: str, *, seal_key: bytes) -> str:
    """The keyed nonce for one upstream bug.

    Domain-separated so this key cannot be made to produce a value that collides
    with another HMAC use of the same secret elsewhere in the stack.
    """
    if not isinstance(seal_key, (bytes, bytearray)) or not seal_key:
        raise SealedTaskError("a non-empty seal key is required to mint a sealed id")
    catalog, number = parse_origin(origin_id)
    material = _SEAL_DOMAIN + f"{catalog}:{number}".encode()
    digest = hmac.new(bytes(seal_key), material, sha256).hexdigest()
    return digest[:SEALED_NONCE_HEX]


def sealed_task_id(origin_id: str, *, seal_key: bytes, index: int = 0) -> str:
    """The sealed task id for one upstream bug: ``sealedvuln:<nonce>:<index>``.

    ``index`` is the within-seal ordinal the task-id grammar requires; it stays 0
    for the ordinary one-task-per-bug case.
    """
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise SealedTaskError("index must be a non-negative integer")
    return f"{SEALED_TASK_PREFIX}{sealed_nonce(origin_id, seal_key=seal_key)}:{index}"


def sealed_origin_terms(origin_id: str) -> tuple[str, ...]:
    """Identifiers of the hidden origin, for the manifest's PRIVATE ``origin_terms``.

    Only the QUALIFIED reference (``arvo:12345``) is returned -- never the bare number.
    That is deliberate and it is measured: real ARVO ids are 3 to 5 digits (21 of the
    4,993 archived cases are 3-digit) and OSS-Fuzz issue ids run 3-5 or 8-9, while
    ``origin_terms`` are matched as case-insensitive SUBSTRINGS against every disclosed
    field. In a corpus whose descriptions and sanitizer traces are made of integers --
    ``256``, ``512``, ``65536``, sizes, offsets, line numbers -- a bare id number is not
    evidence of a leak, and treating it as one costs twice over:

    * ``disclosed_origin_fingerprints`` reports a false leak and admission drops a
      legitimate task, off a fresh supply that is already thin; and
    * ``genericise_disclosure`` scrubs the same terms at seal time, so the digits are
      redacted out of honest prose first -- ``version 2.1`` becomes ``version 2.<redacted>``.

    ``corpus_admission`` makes exactly this argument about its own scan ("NOT the
    free-text description ... would over-refuse", "do not fake wider coverage with a
    heuristic that over-refuses"); a bare integer is that heuristic. The qualified form
    is high-confidence: nothing writes ``arvo:12345`` by accident. A sealer that knows a
    specific task's metadata really does carry the raw number can still pass it through
    ``admit_private_manifest(..., forbidden_terms=...)``, which is unioned with these.

    When the caller wrote a non-canonical number (``arvo:012345``), the AS-WRITTEN
    spelling is included alongside the canonical one: the id normalises so that one bug
    seals to one identity, but a disclosed field could still carry whichever spelling the
    upstream metadata used, and a term that is not listed is a term admission does not
    police.

    These are for the private field ONLY -- returning them alongside the id is not
    an invitation to disclose them.
    """
    catalog, number = parse_origin(origin_id)
    terms = [f"{catalog}:{number}"]
    written = _ORIGIN_RE.match((origin_id or "").strip()).group(2)
    if written != number:
        terms.append(f"{catalog}:{written}")
    return tuple(terms)
