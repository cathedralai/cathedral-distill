"""A dependency-free HTTP binding for `CyberGymService`.

Three POST routes over the stdlib `http.server` — the whole wire surface of the
CyberGym lane — plus one anonymous GET for dashboards:

    POST /cybergym/dispatch   {miner_hotkey, model_commitment}  -> DispatchMessage
    POST /cybergym/artifact   {task_id}                          -> {task_id, program}
    POST /cybergym/submit     <SubmissionEnvelope JSON>         -> verdict
    GET  /v1/status                                              -> live status
    GET  /v1/keys                                                -> signed key registry

This is deliberately the *reference* transport: no framework, no new dependency
(the package's only runtime dep stays `cryptography`). A production deployment can
swap in a Bittensor axon or an ASGI app over the exact same
`service.handle_dispatch` / `service.handle_submit` handlers; nothing else changes.
Bounded request bodies; every handler fails closed to a JSON error.

`GET /v1/status` is the read surface a status page polls: read-only, cached behind
a short TTL, and CORS-open because a static site is served from another origin.
`GET /v1/keys` serves the root-signed key registry verbatim, so a validator can
resolve a receipt's `signing_key_id` — without it, no live receipt has a resolvable
signer. Both are anonymous reads of signed or already-public data.

The CORS header is on those two routes ALONE — the POST routes stay same-origin,
since they are authenticated and mutating and a browser must never be able to drive
them cross-site. See `cathedral_distill.status` for what the status payload does and
does not disclose, and `cathedral_distill.served_keys` for why the registry is
verified before it is served.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from typing import Any, Mapping

from cathedral_distill.cybergym_service import CyberGymService
from cathedral_distill.served_keys import ServedKeyRegistry, ServedRegistryError
from cathedral_distill.status import StatusCache

DISPATCH_PATH = "/cybergym/dispatch"
ARTIFACT_PATH = "/cybergym/artifact"
SUBMIT_PATH = "/cybergym/submit"
STATUS_PATH = "/v1/status"
KEYS_PATH = "/v1/keys"
MAX_BODY_BYTES = 2 * 1024 * 1024  # generous for a base64 PoC + trace
STATUS_TTL_SECS = 5.0


def make_handler(
    service: CyberGymService,
    *,
    status_cache: StatusCache | None = None,
    key_registry: ServedKeyRegistry | None = None,
) -> type[BaseHTTPRequestHandler]:
    """Build a request-handler class bound to one service instance.

    `status_cache` is the shared cache backing `GET /v1/status`. It is passed in
    rather than built here so every handler instance shares one cache: a new cache
    per request would make the TTL meaningless.

    `key_registry` backs `GET /v1/keys`. Omitted, that route reports 503 rather than
    404: the registry is something an operator is expected to serve, so "not
    configured here" is a deployment state worth naming, not a missing feature.
    """

    class _Handler(BaseHTTPRequestHandler):
        server_version = "cathedral-cybergym/1"

        # Silence the default stderr access log; callers own their logging.
        def log_message(self, *_args: Any) -> None:  # noqa: D401
            return

        def _send(
            self, status: int, payload: dict[str, Any], *, public: bool = False
        ) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if public:
                # Read-only public data, so any origin may read it. Deliberately
                # not set on the mutating POST routes.
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Cache-Control", f"public, max-age={int(STATUS_TTL_SECS)}")
            self.end_headers()
            self.wfile.write(body)

        def _send_registry(self) -> None:
            """The signed registry, verbatim. Not re-serialised: the published
            digest is over these exact bytes."""
            if key_registry is None:
                self._send(
                    503,
                    {"error": "no key registry is configured on this host"},
                    public=True,
                )
                return
            try:
                body = key_registry.body()
            except ServedRegistryError as exc:
                # Fail closed with the reason. Serving a registry that does not
                # verify, or that is stale, only moves the failure to every
                # consumer at once.
                self._send(503, {"error": str(exc)}, public=True)
                return
            etag = key_registry.etag()
            if etag and self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            if etag:
                self.send_header("ETag", etag)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            route = self.path.split("?", 1)[0]
            if route == STATUS_PATH:
                if status_cache is None:
                    self._send(503, {"error": "status is not enabled"}, public=True)
                    return
                try:
                    payload = status_cache.get()
                except Exception as exc:  # noqa: BLE001 - a status read never 500s blind
                    self._send(
                        503,
                        {"error": f"status unavailable: {type(exc).__name__}: {exc}"},
                        public=True,
                    )
                    return
                self._send(200, payload, public=True)
            elif route == KEYS_PATH:
                self._send_registry()
            else:
                self._send(404, {"error": "unknown route"})

        def do_OPTIONS(self) -> None:  # noqa: N802 (stdlib naming)
            """Preflight for the two public read routes only."""
            if self.path.split("?", 1)[0] not in (STATUS_PATH, KEYS_PATH):
                self._send(404, {"error": "unknown route"})
                return
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Content-Length", "0")
            self.end_headers()

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


def make_server(service: CyberGymService, host: str = "127.0.0.1", port: int = 0, *,
                key_registry: ServedKeyRegistry | None = None) -> HTTPServer:
    """Build (but do not start) a single-threaded HTTP server for the service.

    Single-threaded on purpose: it serialises requests so the SQLite corpus/score
    stores need no cross-request locking (a validator serves a bounded miner set
    per epoch, not a high-concurrency workload). Port 0 binds an ephemeral port;
    read `server.server_address[1]`. Call `server.serve_forever()` to run,
    `shutdown()` to stop.

    `GET /v1/status` needs no lock here: the server handles one request at a time,
    so a status build cannot overlap a submit.
    """
    return HTTPServer(
        (host, port),
        make_handler(
            service,
            status_cache=StatusCache.for_service(
                service, ttl_secs=STATUS_TTL_SECS, key_registry=key_registry
            ),
            key_registry=key_registry,
        ),
    )


class _LockingService:
    """Serialise the stateful handlers behind one lock.

    A `ThreadingHTTPServer` accepts connections concurrently, but the SQLite
    corpus/score stores and the real Docker differential are not safe to run in
    parallel (races on the stores; OOM if two heavy verifies land at once). This
    wrapper lets connections thread — so a slow verify never refuses new sockets —
    while dispatch/artifact/submit still run one-at-a-time.
    """

    def __init__(self, service: CyberGymService) -> None:
        self._service = service
        self._lock = threading.Lock()

    @property
    def lock(self) -> threading.Lock:
        """The lock the status build must also hold; it reads the same stores."""
        return self._lock

    def handle_dispatch(self, request: Any) -> dict[str, Any]:
        with self._lock:
            return self._service.handle_dispatch(request)

    def handle_artifact(self, request: Any) -> dict[str, Any]:
        with self._lock:
            return self._service.handle_artifact(request)

    def handle_submit(self, body: Any) -> dict[str, Any]:
        with self._lock:
            return self._service.handle_submit(body)


def make_threaded_server(service: CyberGymService, host: str = "0.0.0.0", port: int = 0, *,
                         healthz: Mapping[str, Any] | None = None,
                         key_registry: ServedKeyRegistry | None = None,
                         ) -> ThreadingHTTPServer:
    """A production `ThreadingHTTPServer` for a real deployment.

    Unlike `make_server`, connections are accepted and threaded so a slow Docker
    differential never blocks new sockets; the stateful POST handlers are still
    serialised (see `_LockingService`), and `GET /healthz` is a lock-free liveness
    probe answering instantly even mid-verify. Port 0 binds an ephemeral port.

    `GET /v1/status` is NOT lock-free: it reads the score and solve stores, whose
    connections are shared across threads on the understanding that the service
    serialises access, so its build takes the same lock the POST handlers use. The
    TTL cache keeps that to at most one contended build per window no matter how
    many dashboards are polling. `/healthz` stays the probe to use for liveness.
    """
    locking = _LockingService(service)
    base = make_handler(
        locking,
        status_cache=StatusCache.for_service(
            service, ttl_secs=STATUS_TTL_SECS, lock=locking.lock,
            key_registry=key_registry,
        ),
        # No lock: the registry is a file read behind its own lock, and it touches
        # none of the SQLite the submit path writes.
        key_registry=key_registry,
    )
    payload = dict(healthz or {"status": "ok"})

    class _Threaded(base):  # type: ignore[valid-type, misc]
        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            if self.path.split("?", 1)[0] == "/healthz":
                self._send(200, dict(payload))
            else:
                # Everything else, including /v1/status, is the base handler's.
                super().do_GET()

    server = ThreadingHTTPServer((host, port), _Threaded)
    server.daemon_threads = True
    return server


__all__ = ["make_handler", "make_server", "make_threaded_server",
           "DISPATCH_PATH", "ARTIFACT_PATH", "SUBMIT_PATH", "STATUS_PATH", "KEYS_PATH"]
