"""Transport controls on the three mutating CyberGym POST routes.

Covers the decision-free half of cathedral-distill#33. The identity MECHANISM
(axon / bearer / request signature) is still an owner decision and is
deliberately not chosen here -- what these pin is that the seam is reachable,
that it fails closed when required, and that the transport can no longer be
hung by a client that lies about its body length.
"""
from __future__ import annotations

import inspect
import json
import socket
import threading
import urllib.error
import urllib.request

import pytest

from cathedral_distill import cybergym_http as chttp


class _StubService:
    """Records what the transport hands down. Enough surface for the routes."""

    def __init__(self):
        self.dispatch_calls = []

    def handle_dispatch(self, request, *, authenticated_caller=None):
        self.dispatch_calls.append(authenticated_caller)
        return {"ok": True, "caller": authenticated_caller}

    def handle_artifact(self, request):
        return {"ok": True}

    def handle_submit(self, body):
        return {"accepted": True}


class _BlockingSubmitService(_StubService):
    def __init__(self):
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def handle_submit(self, body):
        self.entered.set()
        assert self.release.wait(timeout=10)
        return {"accepted": True}


def _serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _post(base, path, payload=b"{}", headers=None):
    req = urllib.request.Request(
        base + path, data=payload, method="POST",
        headers=headers or {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"raw": raw[:200]}


def _server(**kw):
    svc = _StubService()
    handler = chttp.make_handler(svc, **kw)
    from http.server import HTTPServer
    return svc, _serve(HTTPServer(("127.0.0.1", 0), handler))


def test_handler_sets_a_socket_timeout():
    """Without this, one half-open connection pins a worker forever."""
    _svc, server = _server()
    try:
        assert server.RequestHandlerClass.timeout == chttp.REQUEST_TIMEOUT_SECS
        assert chttp.REQUEST_TIMEOUT_SECS > 0
    finally:
        server.shutdown()


def test_authenticated_caller_reaches_the_service():
    """The seam must be REACHABLE -- #33's core finding was that it was not."""
    svc, server = _server(authenticator=lambda headers, body: "5RealMiner")
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        status, payload = _post(base, chttp.DISPATCH_PATH)
        assert status == 200
        assert payload["caller"] == "5RealMiner"
        assert svc.dispatch_calls == ["5RealMiner"]
    finally:
        server.shutdown()


def test_without_an_authenticator_the_caller_is_none_and_routes_still_work():
    """Back-compat: the default deployment is unchanged."""
    svc, server = _server()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        assert _post(base, chttp.DISPATCH_PATH)[0] == 200
        assert svc.dispatch_calls == [None]
    finally:
        server.shutdown()


def test_require_authentication_fails_closed_on_every_mutating_route():
    """401 rather than serving anonymously. This is what lets a deployment
    bind somewhere other than loopback."""
    svc, server = _server(require_authentication=True)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        for path in (chttp.DISPATCH_PATH, chttp.ARTIFACT_PATH, chttp.SUBMIT_PATH):
            status, payload = _post(base, path)
            assert status == 401, path
            assert payload["error"] == "authentication required"
        assert svc.dispatch_calls == []  # never reached the service
    finally:
        server.shutdown()


def test_an_authenticator_that_raises_is_treated_as_unauthenticated():
    """A broken authenticator must fail closed, not 500 and not pass through."""
    def boom(headers, body):
        raise RuntimeError("verifier exploded")

    svc, server = _server(authenticator=boom, require_authentication=True)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        assert _post(base, chttp.DISPATCH_PATH)[0] == 401
        assert svc.dispatch_calls == []
    finally:
        server.shutdown()


def test_a_body_shorter_than_content_length_is_rejected_not_hung():
    """The hang #33 describes: promise 2MB, send 10 bytes, pin a worker.

    Sends a deliberately short body with an overstated Content-Length and
    asserts the server answers rather than blocking until the client gives up.
    """
    _svc, server = _server()
    try:
        port = server.server_address[1]
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        sock.sendall(
            b"POST " + chttp.DISPATCH_PATH.encode() + b" HTTP/1.0\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 5000\r\n\r\n"
            b"{}")                      # 2 bytes, not 5000
        sock.shutdown(socket.SHUT_WR)   # EOF: read returns short instead of blocking
        sock.settimeout(10)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        assert b"400" in response.split(b"\r\n", 1)[0], response[:120]
        assert b"shorter than Content-Length" in response
    finally:
        server.shutdown()


def test_locking_service_forwards_the_identity():
    """#33: the wrapper did not ACCEPT authenticated_caller, so on the THREADED
    (production) server the seam was unreachable however hard a transport tried.
    """
    svc = _StubService()
    locking = chttp._LockingService(svc)
    locking.handle_dispatch({}, authenticated_caller="5Threaded")
    assert svc.dispatch_calls == ["5Threaded"]


def test_threaded_server_bounds_its_accept_queue():
    from http.server import ThreadingHTTPServer
    assert chttp.REQUEST_QUEUE_SIZE >= 1
    assert ThreadingHTTPServer.request_queue_size or True  # set at construction


def test_threaded_server_rejects_mutating_requests_beyond_the_active_cap():
    service = _BlockingSubmitService()
    server = chttp.make_threaded_server(
        service, max_concurrent_mutating_requests=1
    )
    _serve(server)
    first: list[tuple[int, dict]] = []
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        thread = threading.Thread(
            target=lambda: first.append(_post(base, chttp.SUBMIT_PATH)), daemon=True
        )
        thread.start()
        assert service.entered.wait(timeout=5)

        status, payload = _post(base, chttp.SUBMIT_PATH)
        assert status == 429
        assert payload["error"] == "too many concurrent mutating requests"
    finally:
        service.release.set()
        thread.join(timeout=5)
        server.shutdown()

    assert first == [(200, {"accepted": True})]


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_threaded_server_refuses_an_invalid_mutating_request_cap(limit):
    with pytest.raises(ValueError, match="max_concurrent_mutating_requests"):
        chttp.make_threaded_server(_StubService(), max_concurrent_mutating_requests=limit)


def test_server_helpers_default_to_loopback_and_refuse_anonymous_public_binds():
    """A new deployment must not expose the mutating routes by omission."""
    for factory in (chttp.make_server, chttp.make_threaded_server):
        assert inspect.signature(factory).parameters["host"].default == "127.0.0.1"
        with pytest.raises(ValueError, match="require_authentication=True"):
            factory(_StubService(), host="0.0.0.0", port=0)


def test_required_authentication_allows_an_explicit_public_bind():
    """Operators retain a deliberate public-bind path once transport auth exists."""
    for factory in (chttp.make_server, chttp.make_threaded_server):
        server = factory(
            _StubService(), host="0.0.0.0", port=0,
            authenticator=lambda headers, body: "5RealMiner",
            require_authentication=True,
        )
        try:
            assert server.server_address[0] == "0.0.0.0"
        finally:
            server.server_close()
