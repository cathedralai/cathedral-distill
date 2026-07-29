"""A dependency-free HTTP binding for `CyberGymService`.

Two POST routes over the stdlib `http.server` — the whole wire surface of the
CyberGym lane:

    POST /cybergym/dispatch   {miner_hotkey, model_commitment}  -> DispatchMessage
    POST /cybergym/artifact   {task_id}                          -> {task_id, program}
    POST /cybergym/submit     <SubmissionEnvelope JSON>         -> verdict

This is deliberately the *reference* transport: no framework, no new dependency
(the package's only runtime dep stays `cryptography`). A production deployment can
swap in a Bittensor axon or an ASGI app over the exact same
`service.handle_dispatch` / `service.handle_submit` handlers; nothing else changes.
Bounded request bodies; every handler fails closed to a JSON error.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from cathedral_distill.cybergym_service import CyberGymService

DISPATCH_PATH = "/cybergym/dispatch"
ARTIFACT_PATH = "/cybergym/artifact"
SUBMIT_PATH = "/cybergym/submit"
MAX_BODY_BYTES = 2 * 1024 * 1024  # generous for a base64 PoC + trace


def make_handler(service: CyberGymService) -> type[BaseHTTPRequestHandler]:
    """Build a request-handler class bound to one service instance."""

    class _Handler(BaseHTTPRequestHandler):
        server_version = "cathedral-cybergym/1"

        # Silence the default stderr access log; callers own their logging.
        def log_message(self, *_args: Any) -> None:  # noqa: D401
            return

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> bytes | None:
            try:
                length = int(self.headers.get("Content-Length", 0))
            except (TypeError, ValueError):
                self._send(400, {"error": "invalid Content-Length"})
                return None
            if length < 0 or length > MAX_BODY_BYTES:
                self._send(413, {"error": "request body too large"})
                return None
            return self.rfile.read(length)

        def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
            if self.path == DISPATCH_PATH:
                body = self._read_body()
                if body is None:
                    return
                try:
                    request = json.loads(body or b"{}")
                except ValueError:
                    self._send(400, {"error": "request is not valid JSON"})
                    return
                result = service.handle_dispatch(request)
                self._send(400 if "error" in result else 200, result)
            elif self.path == ARTIFACT_PATH:
                body = self._read_body()
                if body is None:
                    return
                try:
                    request = json.loads(body or b"{}")
                except ValueError:
                    self._send(400, {"error": "request is not valid JSON"})
                    return
                result = service.handle_artifact(request)
                self._send(400 if "error" in result else 200, result)
            elif self.path == SUBMIT_PATH:
                body = self._read_body()
                if body is None:
                    return
                result = service.handle_submit(body)
                self._send(200 if result.get("accepted") else 400, result)
            else:
                self._send(404, {"error": "unknown route"})

    return _Handler


def make_server(service: CyberGymService, host: str = "127.0.0.1", port: int = 0) -> HTTPServer:
    """Build (but do not start) a single-threaded HTTP server for the service.

    Single-threaded on purpose: it serialises requests so the SQLite corpus/score
    stores need no cross-request locking (a validator serves a bounded miner set
    per epoch, not a high-concurrency workload). Port 0 binds an ephemeral port;
    read `server.server_address[1]`. Call `server.serve_forever()` to run,
    `shutdown()` to stop.
    """
    return HTTPServer((host, port), make_handler(service))


__all__ = ["make_handler", "make_server", "DISPATCH_PATH", "ARTIFACT_PATH", "SUBMIT_PATH"]
