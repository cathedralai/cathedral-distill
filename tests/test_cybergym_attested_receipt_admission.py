"""What still stands between a real CyberGym miner receipt and a paid solve.

The process-level CyberGym E2E proved artifact -> durable score -> canonical report
-> authenticated intake, but it ran with ``attestation_required=False``. That
proves the reward *plumbing*, not the reward *policy*: nothing in it exercises the
Intel-TDX gate, so "the reward path works" and "the reward path works with real
attestation" are still two different claims.

A genuine quote cannot be produced without a genuine TDX enclave, and this suite
does not pretend otherwise. What it CAN establish — and what turns the remaining
hardware step from a leap into a single known move — is the complement:

  * a receipt that is complete and correctly bound in **every** dimension the
    validator checks, carrying a **synthetic** quote (a well-formed, correctly
    bound attestation document signed by a key that is not one of the verifier's
    pinned roots), is refused for **exactly** that reason and no other; and
  * moving that one signer into the verifier's trusted roots — the step real
    hardware and real Intel collateral perform — admits the identical receipt,
    credits it, and composes it into the lane.

Read together those two facts say: every non-quote precondition is already
satisfied by this receipt, so the quote is the only remaining variable. The
per-dimension tests then hold that claim honest — each binding is separately
load-bearing, so "correctly bound in every dimension" is a checked statement
rather than an assertion.

The bindings exercised here are the ones the enclave commits into ``report_data``
(batch, task, PoC attempt, trajectory, miner, model commitment, and the private
challenge artifact the validator dispatched) plus the verifier-held policy the
token is judged against (TEE kind, pinned enclave measurement, GPU measurement
allow-list, freshness) and the transport authorization that binds a caller to one
sealed batch. Every refusal below is the running service's, reached through
``CyberGymService.submit`` on the private-v2 reward-ready source — the closest
shape to production this repository can run without Docker and without a rig.

SCOPE, stated plainly: the token format the acceptance path admits is
``cathedral_cc_attestation_v1`` — a normalized, Ed25519-signed evidence document —
not an Intel DCAP quote. Nothing here parses DCAP collateral, and
``cybergym_cathedral_attest`` (which does understand a real Cathedral TDX worker
receipt) is not wired into this path. ``test_a_cathedral_tdx_worker_receipt_is_not
_admissible_here`` pins that gap so it cannot be mistaken for solved.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.attestation import (  # noqa: E402
    ATTESTATION_SCHEMA,
    AttestationPolicy,
    attestation_policy_digest,
    sign_attestation,
)
from cathedral_distill.cybergym_attest import submission_report_data  # noqa: E402
from cathedral_distill.cybergym_holdout import Holdout  # noqa: E402
from cathedral_distill.cybergym_private_artifacts import (  # noqa: E402
    PrivateChallengeArtifactStore,
    PrivateReferencePoCStore,
)
from cathedral_distill.cybergym_protocol import (  # noqa: E402
    CyberGymCorpusStore,
    ProtocolError,
    SubmissionEnvelope,
)
from cathedral_distill.cybergym_repro import ReproTaskSource  # noqa: E402
from cathedral_distill.cybergym_repro_manifest import (  # noqa: E402
    load_private_repro_manifest,
)
from cathedral_distill.cybergym_scores import (  # noqa: E402
    CyberGymScoreStore,
    CyberGymSolveStore,
)
from cathedral_distill.cybergym_service import CyberGymService  # noqa: E402
from cathedral_distill.cybergym_validator import ChainContext  # noqa: E402
from cathedral_distill.cybergym_verifier import poc_digest  # noqa: E402

TASK_ID = "arvo:368"
EPOCH = 21
MINER = "5RegisteredMiner"
MODEL = "sha256:" + hashlib.sha256(b"registered-checkpoint").hexdigest()
VALIDATOR = "5Validator"
NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
ISSUED = "2026-07-29T12:00:00Z"

CRASHING = b"the-known-crashing-input"
MINER_ARTIFACT = b"int parse(const unsigned char *input, unsigned long length);\n"
ASAN = b"==42==ERROR: AddressSanitizer: heap-use-after-free\n...\nABORTING\n"
CLEAN = b"Executed /tmp/poc without incident\n"

# The verifier's pinned enclave measurement (SEC-TDX-1: a genuine TEE is not the
# right TEE) and the root it resolves a quote's signer through (SEC-1/2/3: never a
# key the token itself supplies). In production these are the Intel DCAP roots and
# the measured CyberGym runner image.
MEASURE = "tdx-mrtd:" + "ab" * 24
DCAP_ROOT_ID = "intel-dcap-root-1"
DCAP_ROOT_SEED = bytes(range(32))
DCAP_ROOT_PUB = (
    Ed25519PrivateKey.from_private_bytes(DCAP_ROOT_SEED).public_key().public_bytes_raw()
)

# The synthetic quote: correctly shaped and correctly bound, signed by a key that
# no hardware vouches for. This is what a receipt looks like when everything
# except the enclave is real, and it is the ONLY defect this suite ever leaves in.
SYNTHETIC_KEY_ID = "synthetic-enclave-key-no-hardware-vouches-for-this"
SYNTHETIC_SEED = bytes(range(1, 33))
SYNTHETIC_PUB = (
    Ed25519PrivateKey.from_private_bytes(SYNTHETIC_SEED).public_key().public_bytes_raw()
)

UNTRUSTED_SIGNER_REFUSAL = (
    "rejected_unattested:tdx_attestation_invalid:attestation verification failed: "
    f"attestation signer {SYNTHETIC_KEY_ID!r} is not a trusted root"
)
UNBOUND_REFUSAL = (
    "rejected_unattested:tdx_attestation_invalid:attestation verification failed: "
    "report_data is not bound to this receipt (nonce mismatch)"
)


# --------------------------------------------------------------------------- #
# A production-shaped verifier: private-v2 reward-ready source, durable stores,
# authenticated transport, and a real Intel-TDX attestation policy.
# --------------------------------------------------------------------------- #

class _FakeDocker:
    """The differential runner seam, standing in for the docker CLI.

    Crashes iff the known crashing input is mounted against the vulnerable build,
    exactly as ``tests/test_cybergym_repro`` does. It records every invocation so a
    test can assert the expensive differential was never reached — an unattested
    submission must not be able to spend verifier capacity.
    """

    def __init__(self) -> None:
        self.runs: list[str] = []

    def __call__(self, argv, capture_output=False, timeout=None):
        mount = next(a for a in argv if a.endswith(":/tmp/poc:ro"))
        path = mount.split(":", 1)[0]
        self.runs.append(path)
        with open(path, "rb") as handle:
            poc = handle.read()
        image = argv[argv.index(mount) + 1]
        crashed = image.split("@", 1)[0].endswith("-vul") and poc == CRASHING
        return subprocess.CompletedProcess(
            argv, 1 if crashed else 0, stdout=ASAN if crashed else CLEAN, stderr=b""
        )


def _manifest():
    """A reward-ready private manifest: digest-pinned images, artifact and reference."""
    return load_private_repro_manifest(
        {
            "schema": "cathedral_cybergym_private_repro_manifest_v2",
            "source_epoch": EPOCH,
            "tasks": [
                {
                    "task_id": TASK_ID,
                    "level": 2,
                    "disclosed_at": "2026-07-27T11:00:00Z",
                    "vulnerable_image": f"registry.test/arvo-368-vul@sha256:{'ab' * 32}",
                    "fixed_image": f"registry.test/arvo-368-fix@sha256:{'cd' * 32}",
                    "context": {
                        "description": "memory-safety task",
                        "sanitizer_trace": "AddressSanitizer: expected finding",
                    },
                    "challenge_artifact_digest": (
                        "sha256:" + hashlib.sha256(MINER_ARTIFACT).hexdigest()
                    ),
                    "reference_poc_digest": (
                        "sha256:" + hashlib.sha256(CRASHING).hexdigest()
                    ),
                }
            ],
        }
    )


def _policy(*, trusted: dict[str, bytes], gpu: frozenset[str] | None = None):
    return AttestationPolicy(
        trusted_roots=dict(trusted),
        allowed_measurements=frozenset({MEASURE}),
        allowed_gpu_measurements=gpu,
    )


def _service(tmp_path, *, policy: AttestationPolicy | None, name: str = "run",
             receipt_policy=None):
    """The running verifier on durable stores, attestation ENFORCED unless stated.

    ``policy=None`` is the hardware-free E2E posture — the configuration the
    infrastructure E2E ran — and is only used by the tests that are about that
    posture rather than about a receipt.
    """
    manifest = _manifest()
    source = ReproTaskSource(
        manifest,
        challenge_artifacts=PrivateChallengeArtifactStore(
            manifest, {TASK_ID: MINER_ARTIFACT}
        ),
        reference_pocs=PrivateReferencePoCStore(manifest, {TASK_ID: CRASHING}),
        backend=_FakeDocker(),
    )
    chain = ChainContext(
        block=100,
        block_hash="0x" + "cd" * 32,
        network="finney",
        netuid=39,
        source_epoch=EPOCH,
        valid_from_block=100,
        valid_until_block=460,
    )
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    return CyberGymService(
        Holdout(pool=source, _context={}),
        chain,
        backend=source.backend,
        corpus_store=CyberGymCorpusStore(str(root / "corpus.sqlite")),
        score_store=CyberGymScoreStore(str(root / "scores.sqlite")),
        solve_store=CyberGymSolveStore(str(root / "solves.sqlite")),
        validator_hotkey=VALIDATOR,
        private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
        signing_key_id="cybergym-attested-1",
        batch_size=1,
        cutoff=None,
        as_of=NOW,
        attestation_policy=policy,
        cathedral_receipt_policy=receipt_policy,
        attestation_now=NOW,
        attestation_required=policy is not None,
        # The emission gates are a different control with its own coverage; this
        # suite isolates the attestation gate, so the anti-gaming policy is out of
        # scope here and says so rather than being quietly absent.
        gates_required=False,
    )


def _trace(task_id: str, poc_sha: str) -> dict:
    """A trajectory that clears the structural quality floor.

    The floor is not what this suite is about, but it has to be cleared: a thin
    trace makes a solve untrainable, and an untrainable solve would muddy the
    "refused for exactly one reason" claim with a second, unrelated verdict.
    """
    long = (
        "I open the delivered vulnerable build and read the CFF number parser; a freed "
        "dictionary object is dereferenced during number parsing, so a font whose CFF "
        "header frees then re-reads the operand drives the use-after-free on the "
        "vulnerable build while the patched build guards the object lifetime"
    )
    steps = [
        {
            "step": 1,
            "action": "read_file",
            "thought": f"open the delivered artifact for {task_id} at src/cff/cffparse.c:1; {long}",
        },
        {
            "step": 2,
            "action": "read_file",
            "thought": f"locate cff_parse_num at src/cff/cffparse.c:440 and the object lifetime; {long}",
        },
        {
            "step": 3,
            "action": "reason",
            "thought": f"the freed object is read during number parsing at cffparse.c:440; {long}",
        },
        {
            "step": 4,
            "action": "write_poc",
            "thought": f"build the CFF font input that reaches the freed read; {long}",
        },
        {
            "step": 5,
            "action": "verify",
            "thought": f"confirm crash on vul, clean on fix; the validator re-runs it; {long}",
        },
    ]
    return {
        "task_id": task_id,
        "poc_sha256": poc_sha,
        "model_id": "cathedral/agent-v1",
        "steps": steps,
        "licence": "cathedral-corpus-v1",
        "model_seal": "sha256:" + hashlib.sha256(b"seal").hexdigest(),
    }


def _quote(
    *,
    report_data: str,
    seed: bytes = SYNTHETIC_SEED,
    key_id: str = SYNTHETIC_KEY_ID,
    tee: str = "intel_tdx",
    measurement: str = MEASURE,
    issued_at: str = ISSUED,
    gpu_measurement: str | None = None,
) -> str:
    """One base64 attestation token, defaulting to the synthetic-signer case."""
    token = sign_attestation(
        {
            "schema": ATTESTATION_SCHEMA,
            "tee": tee,
            "measurement": measurement,
            "gpu_measurement": gpu_measurement,
            "report_data": report_data,
            "issued_at": issued_at,
            "signing_key_id": key_id,
        },
        seed,
    )
    return base64.b64encode(token).decode("ascii")


def _receipt(dispatch, **binding):
    """A receipt bound in every dimension, with named fields left overridable.

    Each keyword is one binding the enclave commits into ``report_data``. Leaving
    them all at their defaults produces the fully bound receipt; overriding exactly
    one produces a receipt whose ONLY defect is that dimension, which is what makes
    each refusal below attributable.
    """
    task = dispatch.tasks[0]
    digest = poc_digest(CRASHING)
    trace = _trace(task.task_id, digest)
    from cathedral_distill.cybergym_protocol import _trace_from_dict

    bound = {
        "batch_id": dispatch.batch_id,
        "task_id": task.task_id,
        "poc_sha256": digest,
        "trace_id": _trace_from_dict(trace).trace_id(),
        "miner_hotkey": MINER,
        "model_commitment": dispatch.model_commitment,
        "artifact_digest": task.artifact_digest,
    }
    quote_kwargs = {k: binding.pop(k) for k in list(binding) if k not in bound}
    bound.update(binding)
    return SubmissionEnvelope(
        batch_id=dispatch.batch_id,
        task_id=task.task_id,
        miner_hotkey=MINER,
        poc_base64=base64.b64encode(CRASHING).decode("ascii"),
        trace=trace,
        artifact_digest=task.artifact_digest,
        attestation=_quote(
            report_data=submission_report_data(**bound), **quote_kwargs
        ),
    )


def _dispatch(service):
    return service.dispatch_for(MINER, MODEL, authenticated_caller=MINER)


# --------------------------------------------------------------------------- #
# The claim: one defect, one refusal, and the quote is that defect
# --------------------------------------------------------------------------- #

def test_a_fully_bound_receipt_with_a_synthetic_quote_is_refused_for_exactly_that_reason(
    tmp_path,
):
    """Everything real except the enclave — and the refusal names only the enclave.

    The reason string is compared exactly, not by substring. That is the whole
    point: a receipt that also had a stale timestamp, an unpinned measurement, or a
    loose binding would produce a different string, so an exact match is the
    machine-checkable form of "nothing else is wrong with this receipt".
    """
    service = _service(tmp_path, policy=_policy(trusted={DCAP_ROOT_ID: DCAP_ROOT_PUB}))
    runner = service.holdout.pool._run
    dispatch = _dispatch(service)

    outcome = service.submit(_receipt(dispatch), authenticated_caller=MINER)

    assert outcome.reason == UNTRUSTED_SIGNER_REFUSAL
    assert not outcome.attested and not outcome.creditable
    assert not outcome.solved and outcome.work_units == Decimal(0)
    # Refused before the adversarial differential: an unverifiable proof must not
    # be able to spend a validator's Docker capacity.
    assert runner.runs == []
    # And nothing durable was created for it: no corpus row to train on, no score.
    assert service._corpus.rows(source_epoch=EPOCH) == []
    assert service._scores.epoch_scores(EPOCH) == {}


def test_trusting_that_one_signer_is_the_only_change_that_admits_the_receipt(tmp_path):
    """The remaining hardware step, isolated to a single verifier-held anchor.

    The receipt is built once and submitted unchanged to two services that differ
    in exactly one input: whether the quote's signer resolves through the verifier's
    trusted roots. Real hardware plus real Intel collateral is what makes that
    resolution honest; nothing else about the receipt has to change. Byte-identical
    envelope in, opposite verdicts out.

    This is emphatically NOT a genuine quote — the signer is a local Ed25519 key
    and trusting it is exactly what a deployment must never do. It is a control
    that isolates the variable.
    """
    refusing = _service(
        tmp_path, policy=_policy(trusted={DCAP_ROOT_ID: DCAP_ROOT_PUB}), name="refusing"
    )
    admitting = _service(
        tmp_path,
        policy=_policy(
            trusted={DCAP_ROOT_ID: DCAP_ROOT_PUB, SYNTHETIC_KEY_ID: SYNTHETIC_PUB}
        ),
        name="admitting",
    )
    receipt = _receipt(_dispatch(refusing))
    # The batch is drawn from the chain-anchored nonce, so both services dispatch
    # the identical sealed batch and the identical receipt answers both.
    assert _dispatch(admitting).batch_id == receipt.batch_id

    assert refusing.submit(receipt, authenticated_caller=MINER).reason == (
        UNTRUSTED_SIGNER_REFUSAL
    )

    admitted = admitting.submit(receipt, authenticated_caller=MINER)
    assert admitted.attested and admitted.solved and admitted.creditable
    assert admitted.work_units > 0 and admitted.reason == "solved_trainable"

    # ... and it carries all the way through to the lane the validator would read.
    admitting.score_epoch(issued_at="2026-07-29T12:00:00.000000Z")
    assert admitting._scores.epoch_scores(EPOCH)[MINER] > 0
    lane = admitting.compose_lane(allocation=Decimal("0.30"))
    assert {c.miner_hotkey for c in lane.contributions} == {MINER}


# --------------------------------------------------------------------------- #
# Each binding, separately load-bearing
# --------------------------------------------------------------------------- #

def _trusted_service(tmp_path, name: str):
    """A verifier that trusts the enclave key, so only the BINDING can refuse.

    The per-dimension tests below need the signer question already settled: if the
    quote were untrusted as well, every refusal would collapse onto the signer and
    prove nothing about the binding under test.
    """
    return _service(
        tmp_path,
        policy=_policy(
            trusted={DCAP_ROOT_ID: DCAP_ROOT_PUB, SYNTHETIC_KEY_ID: SYNTHETIC_PUB}
        ),
        name=name,
    )


@pytest.mark.parametrize(
    "dimension,value",
    [
        ("batch_id", "some-other-batch"),
        ("task_id", "arvo:999"),
        ("poc_sha256", poc_digest(b"a-different-attempt")),
        ("trace_id", "sha256:" + "11" * 32),
        ("miner_hotkey", "5SomeoneElse"),
        ("model_commitment", "sha256:" + hashlib.sha256(b"other-model").hexdigest()),
        ("artifact_digest", "sha256:" + hashlib.sha256(b"substituted").hexdigest()),
    ],
)
def test_each_bound_digest_is_separately_required(tmp_path, dimension, value):
    """Unbind exactly one dimension and the receipt stops being creditable.

    The submitted envelope is unchanged and still perfectly correct; only what the
    enclave committed differs. So this is the replay question in each of its forms:
    another batch's quote, another task's, another attempt's, another trajectory's,
    another miner's, another committed model's, another challenge artifact's. All
    seven land on the same refusal because ``report_data`` is one digest over all
    of them — which is the design: there is no partial credit for a partially bound
    attestation.
    """
    service = _trusted_service(tmp_path, name=f"unbound-{dimension}")
    runner = service.holdout.pool._run
    dispatch = _dispatch(service)

    outcome = service.submit(
        _receipt(dispatch, **{dimension: value}), authenticated_caller=MINER
    )

    assert outcome.reason == UNBOUND_REFUSAL
    assert not outcome.attested and not outcome.creditable
    assert outcome.work_units == Decimal(0)
    assert runner.runs == []


def test_an_attestation_from_the_artifact_free_domain_cannot_answer_a_private_task(
    tmp_path,
):
    """A private-v2 task needs the v3 (artifact-bound) domain, not merely a match.

    ``submission_report_data`` uses a different domain separator once a challenge
    artifact is in play, so an enclave that committed only (batch, task, PoC, trace,
    miner, model) — the shape a public-corpus task uses — cannot be carried over to
    a task whose bytes the validator delivered privately. Without this, a miner
    could attest under the weaker binding and then be handed any artifact.
    """
    service = _trusted_service(tmp_path, name="artifact-free-domain")
    dispatch = _dispatch(service)
    receipt = _receipt(dispatch, artifact_digest=None)

    outcome = service.submit(receipt, authenticated_caller=MINER)

    assert outcome.reason == UNBOUND_REFUSAL
    assert not outcome.creditable


# --------------------------------------------------------------------------- #
# The verifier-held policy the quote is judged against
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "override,expected",
    [
        (
            {"tee": "amd_sev_snp"},
            "rejected_unattested:tdx_attestation_invalid:CyberGym requires an Intel "
            "TDX enclave, got tee='amd_sev_snp'",
        ),
        (
            {"measurement": "tdx-mrtd:" + "ee" * 24},
            "rejected_unattested:tdx_attestation_invalid:attestation verification "
            "failed: attestation measurement is not in the allow-list",
        ),
        (
            {"issued_at": "2026-07-20T00:00:00Z"},
            "rejected_unattested:tdx_attestation_invalid:attestation verification "
            "failed: attestation is stale or issued in the future",
        ),
        (
            {"gpu_measurement": "vbios:" + "ff" * 16},
            "rejected_unattested:tdx_attestation_invalid:attestation verification "
            "failed: GPU measurement is not in the allow-list",
        ),
    ],
)
def test_the_verifier_policy_refuses_a_perfectly_bound_quote(
    tmp_path, override, expected
):
    """Binding is necessary and not sufficient — the runner and the clock matter too.

    Each of these receipts commits the right submission. What they get wrong is the
    thing the verifier holds rather than the thing the miner supplies: which TEE,
    which measured runner image, how old a proof may be, which accelerator. A quote
    can be perfectly bound to this solve and still describe an enclave this subnet
    never approved.
    """
    service = _trusted_service(tmp_path, name="policy-" + next(iter(override)))
    dispatch = _dispatch(service)

    outcome = service.submit(_receipt(dispatch, **override), authenticated_caller=MINER)

    assert outcome.reason == expected
    assert not outcome.attested and outcome.work_units == Decimal(0)


def test_a_missing_quote_is_a_soft_refusal_not_a_protocol_error(tmp_path):
    """No attestation at all is the same verdict, reached by the shortest path."""
    service = _trusted_service(tmp_path, name="missing-quote")
    dispatch = _dispatch(service)
    task = dispatch.tasks[0]
    digest = poc_digest(CRASHING)

    outcome = service.submit(
        SubmissionEnvelope(
            batch_id=dispatch.batch_id,
            task_id=task.task_id,
            miner_hotkey=MINER,
            poc_base64=base64.b64encode(CRASHING).decode("ascii"),
            trace=_trace(task.task_id, digest),
            artifact_digest=task.artifact_digest,
            attestation=None,
        ),
        authenticated_caller=MINER,
    )

    assert outcome.reason == "rejected_unattested:missing_tdx_attestation"
    assert not outcome.attested and outcome.work_units == Decimal(0)


# --------------------------------------------------------------------------- #
# Validator request authorization: the sealed batch the caller actually holds
# --------------------------------------------------------------------------- #

def test_the_authenticated_caller_is_bound_to_its_own_sealed_batch(tmp_path):
    """A correct quote does not let another identity spend this batch.

    Authorization runs before verification, so these are hard protocol errors
    rather than soft non-credit: an unauthorized caller has no submission to judge.
    They matter to this suite because they are the other half of "correctly bound" —
    a receipt is only admissible from the miner the validator dispatched to.
    """
    service = _trusted_service(tmp_path, name="authorization")
    dispatch = _dispatch(service)
    receipt = _receipt(dispatch)

    with pytest.raises(ProtocolError, match="does not match submission miner_hotkey"):
        service.submit(receipt, authenticated_caller="5Attacker")

    # ... and the private challenge artifact is not readable without the batch.
    assert service.handle_artifact(
        {"task_id": dispatch.tasks[0].task_id, "batch_id": dispatch.batch_id}
    )["error"] == "private challenge artifact requires an authenticated caller"
    assert "active sealed batch" in service.handle_artifact(
        {"task_id": dispatch.tasks[0].task_id, "batch_id": dispatch.batch_id},
        authenticated_caller="5Attacker",
    )["error"]


def test_the_envelope_artifact_digest_must_match_what_was_dispatched(tmp_path):
    """Substituted challenge bytes are refused before the quote is even opened."""
    service = _trusted_service(tmp_path, name="envelope-artifact")
    dispatch = _dispatch(service)
    receipt = _receipt(dispatch)
    substituted = SubmissionEnvelope(
        batch_id=receipt.batch_id,
        task_id=receipt.task_id,
        miner_hotkey=receipt.miner_hotkey,
        poc_base64=receipt.poc_base64,
        trace=receipt.trace,
        artifact_digest="sha256:" + hashlib.sha256(b"substituted").hexdigest(),
        attestation=receipt.attestation,
    )

    with pytest.raises(ProtocolError, match="artifact_digest does not match"):
        service.submit(substituted, authenticated_caller=MINER)


# --------------------------------------------------------------------------- #
# The other direction: an unattested epoch must not become a publishable report
# --------------------------------------------------------------------------- #

def test_the_running_service_records_its_attestation_posture_beside_the_scores(
    tmp_path,
):
    """An attested epoch says so where the exporter can read it, and exports.

    The score database is the only thing that travels from verifier to exporter, so
    it is where enforcement has to be written down. With the stamp present the
    normal production export is unchanged.
    """
    from cathedral_distill.cybergym_score_report import build_score_report

    service = _trusted_service(tmp_path, name="posture-attested")
    service.submit(_receipt(_dispatch(service)), authenticated_caller=MINER)
    service.score_epoch(issued_at="2026-07-29T12:00:00.000000Z")

    posture = service._scores.attestation_posture(EPOCH)
    assert posture["enforced"] is True
    # And it says WHICH policy — see the swapped-root regression below.
    assert posture["policy_digest"] == attestation_policy_digest(
        _policy(trusted={DCAP_ROOT_ID: DCAP_ROOT_PUB, SYNTHETIC_KEY_ID: SYNTHETIC_PUB})
    )
    document = build_score_report(
        service._scores,
        network="finney",
        netuid=39,
        source_epoch=EPOCH,
        producer_hotkey=VALIDATOR,
    )
    assert document["scores"][MINER] > 0


def test_a_swapped_trust_root_cannot_resume_the_epoch_it_did_not_open(tmp_path):
    """The reviewer's bypass, reproduced and refused.

    Pinning "a policy exists" pins nothing an attacker wants. The demonstrated
    sequence was: open epoch N under the Intel DCAP root, watch it refuse a receipt,
    then restart the SAME epoch on the SAME score database with `trusted_roots`
    swapped to the miner's own key. The previously-refused receipt was admitted and
    credited, the posture still read ``enforced=True`` because a policy still
    existed, and ``build_score_report`` exported the result with no flag and no
    warning — unattested-in-substance work, indistinguishable on the wire from work
    an Intel root vouched for.

    The posture now binds the policy's CONTENT, so the swap is refused on exactly
    the terms a dropped policy already was: at the door, before a receipt can be
    submitted at all. What the operator gets is a refusal naming both digests, not a
    silently re-anchored epoch.
    """
    from cathedral_distill.cybergym_score_report import build_score_report

    # 1. The epoch opens under the Intel root, and refuses the synthetic receipt.
    honest = _service(
        tmp_path, policy=_policy(trusted={DCAP_ROOT_ID: DCAP_ROOT_PUB}), name="swap"
    )
    receipt = _receipt(_dispatch(honest))
    assert honest.submit(receipt, authenticated_caller=MINER).reason == (
        UNTRUSTED_SIGNER_REFUSAL
    )
    opened_with = honest._scores.attestation_posture(EPOCH)["policy_digest"]
    assert opened_with

    # 2. The same epoch, the same databases, the miner's own key now trusted.
    with pytest.raises(ProtocolError) as raised:
        _service(
            tmp_path,
            policy=_policy(
                trusted={DCAP_ROOT_ID: DCAP_ROOT_PUB, SYNTHETIC_KEY_ID: SYNTHETIC_PUB}
            ),
            name="swap",
        )
    assert "attestation POLICY changed" in str(raised.value)
    assert opened_with in str(raised.value)

    # 3. The receipt is still refused, and the epoch was never re-anchored.
    assert honest.submit(receipt, authenticated_caller=MINER).reason == (
        UNTRUSTED_SIGNER_REFUSAL
    )
    assert honest._scores.attestation_posture(EPOCH)["policy_digest"] == opened_with
    assert honest._scores.epoch_scores(EPOCH) == {}

    # 4. And the export is empty: the swap produced no credited solve to publish.
    #    Before this, the identical sequence exported ``{MINER: 2.0}`` under a
    #    posture that read "enforced", with no flag and no warning.
    honest.score_epoch(issued_at="2026-07-29T12:00:00.000000Z")
    assert build_score_report(
        honest._scores,
        network="finney",
        netuid=39,
        source_epoch=EPOCH,
        producer_hotkey=VALIDATOR,
    )["scores"] == {}


def test_an_unchanged_policy_resumes_the_same_epoch_cleanly(tmp_path):
    """The other half of a usable control: a correct restart must not be an outage.

    A guard that refused whenever a policy object was rebuilt would make every
    legitimate restart look like the attack above, and the first operator to hit it
    would reach for the opt-out. The digest is taken over a canonical manifest, so a
    policy reconstructed from the same configuration — different dict, different
    frozenset, different order — resumes without complaint, and the receipt that was
    refused before is refused again for the same reason.
    """
    first = _service(
        tmp_path, policy=_policy(trusted={DCAP_ROOT_ID: DCAP_ROOT_PUB}), name="resume"
    )
    receipt = _receipt(_dispatch(first))
    assert first.submit(receipt, authenticated_caller=MINER).reason == (
        UNTRUSTED_SIGNER_REFUSAL
    )
    opened_with = first._scores.attestation_posture(EPOCH)["policy_digest"]

    resumed = _service(
        tmp_path,
        policy=AttestationPolicy(
            trusted_roots=dict({DCAP_ROOT_ID: bytes(DCAP_ROOT_PUB)}),
            allowed_measurements=frozenset(sorted({MEASURE})),
            allowed_gpu_measurements=None,
        ),
        name="resume",
    )
    assert resumed._scores.attestation_posture(EPOCH)["policy_digest"] == opened_with
    # The sealed batch is drawn from the chain-anchored nonce, so the resumed
    # process re-dispatches the identical batch and the same receipt answers it.
    assert _dispatch(resumed).batch_id == receipt.batch_id
    assert resumed.submit(receipt, authenticated_caller=MINER).reason == (
        UNTRUSTED_SIGNER_REFUSAL
    )


def test_an_epoch_opened_without_a_recorded_policy_digest_fails_closed(tmp_path):
    """The pre-existing-epoch case: unnamed policy, no resume, no export.

    A score database written by the build that stamped only the enforcement flag
    claims attestation but cannot say what it enforced, so there is nothing for a
    restart to be checked against. Admitting it would hand the swap back to anyone
    who could arrange one run under the older build, so it is refused exactly as an
    unrecorded posture is.
    """
    from cathedral_distill.cybergym_score_report import (
        CyberGymScoreReportError,
        build_score_report,
    )

    root = tmp_path / "legacy"
    root.mkdir(parents=True, exist_ok=True)
    store = CyberGymScoreStore(str(root / "scores.sqlite"))
    with store._connection:
        store._connection.execute(
            "INSERT INTO cybergym_epoch_attestation"
            "(epoch, enforced, detail, policy_digest, recorded_at) VALUES (?,?,?,?,?)",
            (EPOCH, 1, "Intel-TDX attestation policy configured", "", ISSUED),
        )
    store.close()

    with pytest.raises(ProtocolError, match="without recording WHICH policy"):
        _service(
            tmp_path,
            policy=_policy(trusted={DCAP_ROOT_ID: DCAP_ROOT_PUB}),
            name="legacy",
        )

    reopened = CyberGymScoreStore(str(root / "scores.sqlite"))
    reopened.mark_epoch(
        EPOCH, state="closed", scored_miners=0, at="2026-07-29T12:00:00.000000+00:00"
    )
    with pytest.raises(CyberGymScoreReportError, match="not WHICH policy"):
        build_score_report(
            reopened,
            network="finney",
            netuid=39,
            source_epoch=EPOCH,
            producer_hotkey=VALIDATOR,
        )


def test_an_unattested_e2e_epoch_cannot_be_exported_by_accident(tmp_path):
    """The E2E's own scores refuse to become production-shaped bytes.

    This is the configuration ai-hpc's infrastructure E2E ran, and correctly so.
    What must not follow from it is a report that a canonical validator cannot
    distinguish from an attested epoch: the wire contract has no enforcement field,
    and `publish-scores` sees only frozen bytes and a URL. So the refusal lands on
    the command that turns the database into those bytes, and an operator who
    genuinely wants the preview says so in as many words.
    """
    import warnings

    from cathedral_distill.cybergym_score_report import (
        CyberGymScoreReportError,
        build_score_report,
    )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # the service's own unattested-mode warning
        service = _service(tmp_path, policy=None, name="unattested-e2e")
    service.submit(
        SubmissionEnvelope(
            batch_id=_dispatch(service).batch_id,
            task_id=TASK_ID,
            miner_hotkey=MINER,
            poc_base64=base64.b64encode(CRASHING).decode("ascii"),
            trace=_trace(TASK_ID, poc_digest(CRASHING)),
            artifact_digest="sha256:" + hashlib.sha256(MINER_ARTIFACT).hexdigest(),
            attestation=None,
        ),
        authenticated_caller=MINER,
    )
    service.score_epoch(issued_at="2026-07-29T12:00:00.000000Z")

    # The unattested solve really was credited — that is the E2E working as designed.
    assert service._scores.epoch_scores(EPOCH)[MINER] > 0
    assert service._scores.attestation_posture(EPOCH)["enforced"] is False

    common = dict(
        network="finney", netuid=39, source_epoch=EPOCH, producer_hotkey=VALIDATOR
    )
    with pytest.raises(CyberGymScoreReportError, match="NO Intel-TDX"):
        build_score_report(service._scores, **common)
    assert build_score_report(service._scores, allow_unattested=True, **common)[
        "scores"
    ][MINER] > 0


# --------------------------------------------------------------------------- #
# What is NOT proven here, pinned so it cannot be assumed
# --------------------------------------------------------------------------- #

def test_a_cathedral_tdx_worker_receipt_is_not_admissible_here(tmp_path):
    """The real-hardware receipt shape has no route into this acceptance path.

    ``cybergym_cathedral_attest`` understands a genuine Cathedral ``attest.v1``
    Intel-TDX worker receipt — quote bytes, Intel verification flags, artifact
    commitment — and is exercised by its own tests. It is not wired into
    ``process_submission``: the only token this gate parses is the normalized
    ``cathedral_cc_attestation_v1`` document. So a miner that produced a real TDX
    receipt today has nothing to put in ``attestation`` that would verify, and the
    refusal it gets names a schema, not a trust failure.

    That is the honest remaining gap, recorded here rather than left to be
    discovered by whoever brings the rig.
    """
    service = _trusted_service(tmp_path, name="cathedral-receipt")
    dispatch = _dispatch(service)
    task = dispatch.tasks[0]
    digest = poc_digest(CRASHING)
    worker_receipt = {
        "receipt_id": "att-1",
        "receipt_status": "ready",
        "exit_code": 0,
        "kind": "tdx-1.5",
        "started_at": ISSUED,
        "task_policy": {
            "hardware_class": "tdx_cpu",
            "reuse": "forbidden",
            "egress": "none",
        },
        "tee_attestation": {"kind": "tdx-1.5", "quote_b64": "AAAA"},
        "verification": {"intel_verified": True, "report_data_match": True},
        "artifacts": [{"path": "result.txt", "sha256": "00" * 32}],
    }

    outcome = service.submit(
        SubmissionEnvelope(
            batch_id=dispatch.batch_id,
            task_id=task.task_id,
            miner_hotkey=MINER,
            poc_base64=base64.b64encode(CRASHING).decode("ascii"),
            trace=_trace(task.task_id, digest),
            artifact_digest=task.artifact_digest,
            attestation=base64.b64encode(
                json.dumps(worker_receipt).encode("utf-8")
            ).decode("ascii"),
        ),
        authenticated_caller=MINER,
    )

    assert outcome.reason.startswith(
        "rejected_unattested:tdx_attestation_invalid:attestation verification failed: "
        "attestation token missing keys:"
    )
    assert not outcome.attested and outcome.work_units == Decimal(0)


# --------------------------------------------------------------------------- #
# #104: the receipt policy is a SECOND verdict-decider — bind it in the posture
# --------------------------------------------------------------------------- #
def test_a_receipt_policy_only_service_is_recorded_as_enforced(tmp_path):
    """A CathedralReceiptPolicy IS attestation enforcement, not an unattested run.

    Without this the posture reads `enforced=False` for a service that only accepts
    real Cathedral receipts, and the exporter would publish it as unattested.
    """
    from cathedral_distill.cybergym_attest import CathedralReceiptPolicy

    svc = _service(
        tmp_path, policy=None, name="rcpt-only",
        receipt_policy=CathedralReceiptPolicy(expected_workload_sha256="wl-approved"),
    )
    posture = svc._scores.attestation_posture(EPOCH)
    assert posture["enforced"] is True
    assert posture["policy_digest"]  # binds the receipt policy, not empty


def test_a_swapped_approved_workload_cannot_resume_the_epoch(tmp_path):
    """The #99 bypass, reproduced for the receipt path and refused the same way.

    Open the epoch pinning the approved solver `wl-approved`, then restart the SAME
    epoch on the SAME score database with `expected_workload_sha256` swapped to the
    attacker's workload. Before #104 the posture bound only the AttestationPolicy, so
    this swap resumed silently and any receipt from `wl-attacker` earned. Now the
    receipt policy is in the posture digest, so the swap is refused at the door.
    """
    from cathedral_distill.cybergym_attest import CathedralReceiptPolicy

    _service(
        tmp_path, policy=None, name="wl-swap",
        receipt_policy=CathedralReceiptPolicy(expected_workload_sha256="wl-approved"),
    )
    with pytest.raises(ProtocolError) as raised:
        _service(
            tmp_path, policy=None, name="wl-swap",
            receipt_policy=CathedralReceiptPolicy(expected_workload_sha256="wl-attacker"),
        )
    assert "attestation POLICY changed" in str(raised.value)


def test_an_attestation_only_epoch_still_resumes_across_the_receipt_change(tmp_path):
    """No receipt policy -> the posture digest is byte-identical to the prior build,
    so an epoch opened before #104 (or by a plain attestation service) resumes."""
    svc = _service(tmp_path, policy=_policy(trusted={DCAP_ROOT_ID: DCAP_ROOT_PUB}),
                   name="att-only")
    pinned = svc._scores.attestation_posture(EPOCH)["policy_digest"]
    assert pinned == attestation_policy_digest(_policy(trusted={DCAP_ROOT_ID: DCAP_ROOT_PUB}))
    # reopening with the identical attestation policy and no receipt policy is fine
    _service(tmp_path, policy=_policy(trusted={DCAP_ROOT_ID: DCAP_ROOT_PUB}),
             name="att-only")


def test_the_receipt_policy_manifest_fails_closed_on_an_unbound_field():
    """Adding a knob to CathedralReceiptPolicy without encoding it must refuse to
    digest, exactly as AttestationPolicy's manifest does — a digest that omits a
    verdict-deciding field is worse than none."""
    import dataclasses

    from cathedral_distill.cybergym_attest import (
        CathedralReceiptPolicy,
        cathedral_receipt_policy_manifest,
    )

    Extended = dataclasses.make_dataclass(
        "ExtendedReceiptPolicy", [("surprise_knob", int, 0)],
        bases=(CathedralReceiptPolicy,), frozen=True,
    )
    with pytest.raises(Exception) as exc:
        cathedral_receipt_policy_manifest(Extended(expected_workload_sha256="wl"))
    assert "does not bind" in str(exc.value)


def test_the_merged_miner_client_earns_through_the_enforced_gate_and_exports(tmp_path):
    """The attested loop on our side, end to end: the #106 miner client's submission is
    credited by the ENFORCED Intel-TDX gate and exported as a signed report — everything
    real except Cathedral's hardware quote/signature (offline_token stands in). Only
    cathedral-compute#108 (Cathedral signing the token) remains."""
    from cathedral_distill.cybergym_miner_attest import (
        attestation_field, bind, offline_token,
    )
    from cathedral_distill.cybergym_protocol import _trace_from_dict
    from cathedral_distill.cybergym_score_report import build_score_report

    svc = _service(tmp_path, policy=_policy(trusted={DCAP_ROOT_ID: DCAP_ROOT_PUB}),
                   name="miner-client-e2e")
    assert svc._scores.attestation_posture(EPOCH)["enforced"] is True

    disp = _dispatch(svc)
    task = disp.tasks[0]
    digest = poc_digest(CRASHING)
    trace = _trace(task.task_id, digest)
    rd = bind(batch_id=disp.batch_id, task_id=task.task_id, poc_sha256=digest,
              trace_id=_trace_from_dict(trace).trace_id(), miner_hotkey=MINER,
              model_commitment=disp.model_commitment, artifact_digest=task.artifact_digest)
    token = offline_token(report_data=rd, measurement=MEASURE, root_seed=DCAP_ROOT_SEED,
                          signing_key_id=DCAP_ROOT_ID, issued_at=ISSUED)
    env = SubmissionEnvelope(
        batch_id=disp.batch_id, task_id=task.task_id, miner_hotkey=MINER,
        poc_base64=base64.b64encode(CRASHING).decode(), trace=trace,
        artifact_digest=task.artifact_digest, attestation=attestation_field(token))

    out = svc.submit(env, authenticated_caller=MINER)
    assert out.creditable and out.solved  # the ENFORCED gate credited a real attested solve

    svc.score_epoch(issued_at="2026-07-29T12:00:00.000000Z")
    report = build_score_report(svc._scores, network="finney", netuid=39,
                                source_epoch=EPOCH, producer_hotkey=VALIDATOR)
    assert report["scores"] == {MINER: 2.0}
    assert report["complete"] is True
