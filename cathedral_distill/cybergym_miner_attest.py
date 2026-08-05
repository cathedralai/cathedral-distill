"""Miner-side helper: obtain an Intel-TDX attestation bound to a CyberGym submission.

The CyberGym miner runs its bug-finding agent inside a Cathedral TDX enclave and
binds the exact submission — `(batch, task, poc, trace, miner, model[, artifact])` —
into the quote's `report_data` (`cybergym_attest.submission_report_data`). Cathedral
verifies the DCAP quote and returns a normalized, Ed25519-signed
`cathedral_cc_attestation_v1` token; the miner base64s it into
`SubmissionEnvelope.attestation`, and the validator's `verify_submission_attestation`
credits the solve — bound to exactly that submission, so it cannot be replayed for
another task, lifted from another miner, or paired with an out-of-enclave trace.

Why this shape (not the result-envelope / customer-receipt one): the `report_data`
binding is *deterministic from the submission*, so the miner computes it, Cathedral
binds it, and the miner submits the returned TOKEN — nothing has to be retrieved from
a sealed enclave result.

The live binding surface (`POST /api/workers/v1/attest`) is not yet reachable by a
Cathedral API key (cathedral-compute#108). `MinerAttestClient.request_token` targets
that contract and is one config change from live; `offline_token` builds the same
token locally (signed by a caller-held test root) so the miner→gate flow is exercised
end-to-end today, without the platform.
"""
from __future__ import annotations

import base64
import json
import urllib.request
from typing import Any, Mapping

from cathedral_distill.attestation import ATTESTATION_SCHEMA, sign_attestation
from cathedral_distill.cybergym_attest import submission_report_data

# The two binding domains submission_report_data uses: the plain form, and the
# artifact-bound form for a private (sealed-batch) task. bind() picks by presence of
# an artifact_digest, mirroring what the validator re-derives.
REQUIRED_TEE = "intel_tdx"


def bind(
    *,
    batch_id: str,
    task_id: str,
    poc_sha256: str,
    trace_id: str,
    miner_hotkey: str,
    model_commitment: str,
    artifact_digest: str | None = None,
) -> str:
    """The `report_data` the enclave must bind and the validator re-derives.

    A thin, named front door to `submission_report_data` so the miner and the
    validator provably compute the SAME value from the SAME fields.
    """
    return submission_report_data(
        batch_id=batch_id, task_id=task_id, poc_sha256=poc_sha256, trace_id=trace_id,
        miner_hotkey=miner_hotkey, model_commitment=model_commitment,
        artifact_digest=artifact_digest,
    )


def offline_token(
    *,
    report_data: str,
    measurement: str,
    root_seed: bytes,
    signing_key_id: str,
    issued_at: str,
    tee: str = REQUIRED_TEE,
    gpu_measurement: str | None = None,
) -> bytes:
    """Build the `cathedral_cc_attestation_v1` token Cathedral would return, signed by
    a caller-held test root.

    This is exactly the document `verify_submission_attestation` verifies — same
    schema, same `report_data`, same measurement — so a token produced here for a
    real submission binding is accepted by the real gate under a policy that trusts
    `root_seed`'s public key. It exercises the whole miner→gate path with everything
    real except the hardware quote and Cathedral's signature.
    """
    unsigned = {
        "schema": ATTESTATION_SCHEMA, "tee": tee, "measurement": measurement,
        "gpu_measurement": gpu_measurement, "report_data": report_data,
        "issued_at": issued_at, "signing_key_id": signing_key_id,
    }
    return sign_attestation(unsigned, root_seed)


def attestation_field(token: bytes) -> str:
    """The base64 string to put in `SubmissionEnvelope.attestation`."""
    return base64.b64encode(token).decode("ascii")


class MinerAttestClient:
    """Requests a submission-bound Intel-TDX attestation from Cathedral.

    Targets the `report_data`-binding surface. Because that surface is not yet
    reachable by a Cathedral API key (cathedral-compute#108), the exact response
    contract is pending; `request_token` posts the binding and adapts the response to
    the token bytes, and the parsing seam is isolated in `_token_from_response` so it
    is a one-method change when the contract is confirmed.
    """

    def __init__(self, *, base_url: str, api_key: str, path: str = "/api/workers/v1/attest"):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.path = path

    def request_token(
        self, *, report_data: str, image: str, command: list[str],
        e2e_pubkey_b64: str = "", max_spend_usd: float = 1.0, timeout_s: float = 300.0,
    ) -> bytes:
        """Run the agent workload in TDX with `report_data` bound, return the token."""
        body = {
            "profile": "attest.v1",
            "workload": {"image": image, "command": command},
            # The submission binding. e2e_pubkey_b64 is optional per the Polaris recipe
            # (report_data[0:32] = sha256(nonce || e2e_pubkey_b64)); the nonce carries
            # the CyberGym submission binding.
            "report_data": report_data,
            "nonce": report_data,
            "e2e_pubkey_b64": e2e_pubkey_b64,
            "budget": {"max_spend_usd": max_spend_usd, "auto_stop": True},
        }
        response = self._post(self.path, body, timeout_s=timeout_s)
        return self._token_from_response(response)

    @staticmethod
    def _token_from_response(response: Mapping[str, Any]) -> bytes:
        """Extract the `cathedral_cc_attestation_v1` token from the attest response.

        The isolated contract seam (cathedral-compute#108): if the surface returns the
        token directly, use it; if it returns a raw quote we must normalize, that
        normalization lands here.
        """
        token = response.get("attestation") or response.get("token")
        if isinstance(token, str):
            return base64.b64decode(token)
        if isinstance(token, Mapping):
            return json.dumps(token).encode("utf-8")
        raise ValueError(
            "attest response carries no recognizable cathedral_cc_attestation_v1 token "
            f"(keys: {sorted(response)}) — see cathedral-compute#108 for the contract"
        )

    def _post(self, path: str, body: Mapping[str, Any], *, timeout_s: float) -> Mapping[str, Any]:
        request = urllib.request.Request(
            self.base_url + path, method="POST", data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=timeout_s) as handle:  # pragma: no cover
            return json.loads(handle.read())


__all__ = ["REQUIRED_TEE", "bind", "offline_token", "attestation_field", "MinerAttestClient"]
