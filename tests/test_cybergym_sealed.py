"""Seal-time task identity (#157/#165 follow-through).

Re-sealing strips the answer out of a real upstream bug, but until now it kept the
UPSTREAM id — and `arvo:<n>` / `oss-fuzz:<n>` name a publicly pullable image whose
baked `/tmp/poc` is the answer, so `corpus_admission` refuses the task on the id
alone however private our own images are. Every other gate passed; the id killed
it. These tests hold the minted id to the three properties that make it a seal
rather than a rename: it clears the catalog refusal, it is unlinkable to the
origin without the key, and it is wide enough not to repeat #118's collision.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from cathedral_distill import cybergym as cg  # noqa: E402
from cathedral_distill.corpus_admission import (  # noqa: E402
    disclosed_origin_fingerprints,
    public_catalog_task_id,
)
from cathedral_distill.cybergym_sealed import (  # noqa: E402
    SEALED_NONCE_HEX,
    SealedTaskError,
    is_sealed_task,
    sealed_nonce,
    sealed_origin_terms,
    sealed_task_id,
)

KEY = b"a-validator-held-seal-key"
OTHER_KEY = b"a-different-validator-held-key"
ORIGIN = "arvo:12345"


class TestTheSealedIdClearsTheRefusalThatBlockedIt:
    def test_a_sealed_id_is_not_a_public_catalog_id(self):
        """The whole point: admission's #165 refusal must not fire on it."""
        assert public_catalog_task_id(sealed_task_id(ORIGIN, seal_key=KEY)) is None

    def test_the_origin_it_replaces_would_have_been_refused(self):
        assert public_catalog_task_id(ORIGIN) == "arvo:12345"

    def test_a_sealed_id_is_a_valid_task_id(self):
        """The grammar must accept it, or the seal mints an unusable task."""
        task_id = sealed_task_id(ORIGIN, seal_key=KEY)
        assert cg.Task(task_id=task_id, level=cg.Level.level1,
                       binary_digest="sha256:" + "ab" * 32).task_id == task_id

    def test_it_is_recognised_as_sealed(self):
        assert is_sealed_task(sealed_task_id(ORIGIN, seal_key=KEY))
        assert not is_sealed_task(ORIGIN)
        assert not is_sealed_task(None)


class TestItIsAFourthProvenanceNotAReuseOfTheUnpaidOnes:
    """`CyberGymService.rewardable_task` withholds units from the two GENERATED
    sources by prefix predicate — `is_fresh_task` unconditionally, `is_synthetic_task`
    unless overridden. A re-sealed task is a real upstream bug that bakes no answer,
    so it must fall through both and earn on the ordinary admission gates. That only
    holds while the prefixes stay disjoint, which is what these assert."""

    def test_a_sealed_id_is_not_seen_as_fresh_or_synthetic(self):
        from cathedral_distill.cybergym_fresh import is_fresh_task
        from cathedral_distill.cybergym_synthetic import is_synthetic_task

        task_id = sealed_task_id(ORIGIN, seal_key=KEY)
        assert not is_fresh_task(task_id), "would be permanently unpaid"
        assert not is_synthetic_task(task_id), "would be unpaid without an override"

    def test_the_generated_prefixes_are_not_seen_as_sealed(self):
        assert not is_sealed_task("freshvuln:abc:0")
        assert not is_sealed_task("synthvuln:abc:0")


class TestUnlinkability:
    def test_the_id_does_not_contain_the_origin_number(self):
        task_id = sealed_task_id("arvo:12345", seal_key=KEY)
        assert "12345" not in task_id
        assert "arvo" not in task_id

    def test_a_different_key_gives_a_different_id_for_the_same_bug(self):
        """Without the key the id is not derivable — that is what makes it a seal
        rather than a hash anyone can precompute over the public catalog."""
        assert (sealed_task_id(ORIGIN, seal_key=KEY)
                != sealed_task_id(ORIGIN, seal_key=OTHER_KEY))

    def test_different_bugs_under_one_key_differ(self):
        assert (sealed_task_id("arvo:1", seal_key=KEY)
                != sealed_task_id("arvo:2", seal_key=KEY))

    def test_the_two_catalogs_do_not_collide_on_one_number(self):
        assert (sealed_task_id("arvo:7", seal_key=KEY)
                != sealed_task_id("oss-fuzz:7", seal_key=KEY))


class TestDeterminism:
    def test_the_same_bug_and_key_always_mint_the_same_id(self):
        """A re-seal must be reproducible, and a duplicate detectable — otherwise the
        same bug can be admitted twice under two identities and paid twice."""
        assert (sealed_task_id(ORIGIN, seal_key=KEY)
                == sealed_task_id(ORIGIN, seal_key=KEY))

    def test_a_non_canonical_number_seals_to_the_same_id(self):
        """`arvo:012345` is the same bug as `arvo:12345`. Sealing them apart would
        give one bug two identities, and the corpus would pay for it twice."""
        assert (sealed_task_id("arvo:012345", seal_key=KEY)
                == sealed_task_id("arvo:12345", seal_key=KEY))

    def test_a_non_canonical_spelling_is_still_policed(self):
        """The id normalises, but a disclosed field may carry whichever spelling the
        upstream metadata used — an unlisted term is one admission does not police."""
        assert sealed_origin_terms("arvo:012345") == ("arvo:12345", "arvo:012345")

    def test_case_and_surrounding_space_do_not_change_the_id(self):
        """`ARVO:12345` is the same bug; minting a second identity for it would
        defeat the duplicate detection determinism exists to provide."""
        assert (sealed_task_id("  ARVO:12345 ", seal_key=KEY)
                == sealed_task_id("arvo:12345", seal_key=KEY))

    def test_an_operator_cannot_re_roll_the_id(self):
        """The id is a function of the origin, not of the attempt, so a refused seal
        cannot be retried into a fresh identity."""
        first = sealed_task_id(ORIGIN, seal_key=KEY)
        assert all(sealed_task_id(ORIGIN, seal_key=KEY) == first for _ in range(5))


class TestNonceWidthDoesNotRepeatIssue118:
    def test_the_nonce_is_64_bits_not_32(self):
        """#118 was a task id truncated to 8 nonce characters, so two challenges
        could collide onto one identity. 16 hex characters is the fix."""
        assert SEALED_NONCE_HEX == 16
        assert len(sealed_nonce(ORIGIN, seal_key=KEY)) == 16

    def test_ten_thousand_bugs_mint_ten_thousand_distinct_ids(self):
        ids = {sealed_task_id(f"arvo:{n}", seal_key=KEY) for n in range(10_000)}
        assert len(ids) == 10_000


class TestOriginTermsAreHandedBackForThePrivateField:
    def test_the_qualified_reference_is_returned(self):
        assert sealed_origin_terms("arvo:12345") == ("arvo:12345",)

    def test_terms_are_normalised(self):
        assert sealed_origin_terms("OSS-Fuzz:99") == ("oss-fuzz:99",)

    def test_the_bare_number_is_deliberately_not_a_term(self):
        """Measured, not stylistic: real ARVO ids are 3-5 digits and terms match as
        case-insensitive SUBSTRINGS, so a bare number in a corpus of crash traces
        (`256`, `512`, `65536`, sizes, offsets) is not evidence of a leak. Including it
        both false-refuses honest tasks off an already-thin fresh supply and lets
        `genericise_disclosure` redact digits out of honest prose."""
        from reseal_task import genericise_disclosure

        terms = sealed_origin_terms("arvo:256")
        assert "256" not in terms
        context = {"description": "heap overflow of 1 byte past a 256-entry table"}
        # The honest description survives sealing intact...
        assert genericise_disclosure(context, terms) == context
        # ...and admission does not read it as fingerprinting the origin.
        assert disclosed_origin_fingerprints(2, context, forbidden_terms=terms) == ()

    def test_the_qualified_form_is_still_caught(self):
        """Dropping the bare number must not drop the real signal: nothing writes
        `arvo:256` by accident."""
        terms = sealed_origin_terms("arvo:256")
        leaky = {"sanitizer_trace": "re-sealed from arvo:256 upstream"}
        assert disclosed_origin_fingerprints(2, leaky, forbidden_terms=terms) == ("arvo:256",)


class TestItRefusesWhatItCannotSeal:
    @pytest.mark.parametrize("bad", ["", "  ", "sealedvuln:abc:0", "arvo:", "arvo:x",
                                     "harvo:12", "arvo12345", None, "12345"])
    def test_an_unparseable_origin_is_refused(self, bad):
        """Minting from an origin we cannot parse would leave origin_terms underived,
        which silently disables the disclosure check for that task."""
        with pytest.raises(SealedTaskError, match="origin must be"):
            sealed_task_id(bad, seal_key=KEY)

    @pytest.mark.parametrize("bad", [b"", None, "a string key", 0])
    def test_a_missing_or_non_bytes_key_is_refused(self, bad):
        with pytest.raises(SealedTaskError, match="seal key"):
            sealed_task_id(ORIGIN, seal_key=bad)

    @pytest.mark.parametrize("bad", [-1, True, 1.5, "0", None])
    def test_a_bad_index_is_refused(self, bad):
        with pytest.raises(SealedTaskError, match="index"):
            sealed_task_id(ORIGIN, seal_key=KEY, index=bad)


class TestTheSealerHelper:
    def test_seal_identity_returns_the_id_and_its_private_terms(self):
        """Kept as one call: an id sealed without its terms recorded looks safe and
        silently disables the disclosure check."""
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from reseal_task import seal_identity

        task_id, terms = seal_identity(ORIGIN, seal_key=KEY)
        assert task_id == sealed_task_id(ORIGIN, seal_key=KEY)
        assert terms == ("arvo:12345",)

    def test_admit_resealed_refuses_a_public_catalog_id_up_front(self):
        """Fail at the top of the seal, not after a build and a registry push."""
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from reseal_task import admit_resealed

        with pytest.raises(ValueError, match="public-catalog id"):
            admit_resealed(
                "arvo:12345", level=0, vul_image="x@sha256:" + "0" * 64,
                fix_image="y@sha256:" + "1" * 64, reference_poc=b"p",
                challenge_artifact=b"c", backend=None, probe_run=None,
            )

    def test_a_sealed_id_without_origin_terms_is_refused(self):
        """A sealed id is proof there IS a hidden origin. Recording none leaves
        forbidden_terms empty, so the task looks sealed and is not."""
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from reseal_task import admit_resealed

        with pytest.raises(ValueError, match="no origin_terms"):
            admit_resealed(
                sealed_task_id(ORIGIN, seal_key=KEY), level=0,
                vul_image="x@sha256:" + "0" * 64, fix_image="y@sha256:" + "1" * 64,
                reference_poc=b"p", challenge_artifact=b"c",
                backend=None, probe_run=None,
            )
