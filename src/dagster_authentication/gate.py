"""The authentication and authorisation gate.

Deliberately a pure ASGI middleware rather than a Starlette
``BaseHTTPMiddleware``: that base class only handles ``scope["type"] == "http"``,
so Dagster's GraphQL subscription WebSocket at /graphql would bypass the gate
entirely and serve live run data to anyone who asked for it.
"""

from __future__ import annotations

import json
import logging

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from dagster_authentication.config import AuthConfig
from dagster_authentication.rbac import WRITE_ROUTE_PREFIXES, Role, may_call, mutation_names, ws_frame_allowed

logger = logging.getLogger("dagster_authentication")

WS_UNAUTHENTICATED = 4001
WS_FORBIDDEN = 4003

# Cap the body we will buffer to classify a GraphQL request. Dagster's own
# operations are far below this; anything larger is not a query we can vet.
MAX_GRAPHQL_BODY = 4 * 1024 * 1024


class AuthGate:
    """Requires a valid session for every request, and enforces the role."""

    def __init__(self, app: ASGIApp, auth_router: ASGIApp, config: AuthConfig) -> None:
        self.app = app
        self.auth_router = auth_router
        self.config = config

        prefix = config.path_prefix
        self._auth_prefix = f"{prefix}/auth/"
        self._login_path = f"{prefix}/auth/login"
        self._graphql_path = f"{prefix}/graphql"
        self._write_prefixes = tuple(f"{prefix}{route}" for route in WRITE_ROUTE_PREFIXES)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # The sign-in routes are the only unauthenticated surface.
        if path.startswith(self._auth_prefix):
            await self.auth_router(scope, receive, send)
            return

        session = scope.get("session") or {}
        raw_role = session.get("role")
        if not isinstance(raw_role, int):
            await self._reject_unauthenticated(scope, receive, send)
            return

        try:
            role = Role(raw_role)
        except ValueError:
            # Session signed with a role this build no longer knows about.
            await self._reject_unauthenticated(scope, receive, send)
            return

        if role >= Role.ADMIN:
            await self.app(scope, receive, send)
            return

        await self._serve_restricted(role, scope, receive, send, path)

    # ---------------------------------------------------------------- viewers

    async def _serve_restricted(
        self,
        role: Role,
        scope: Scope,
        receive: Receive,
        send: Send,
        path: str,
    ) -> None:
        if scope["type"] == "websocket":
            guard = _RestrictedWebSocket(role, receive, send, scope.get("client"))
            await self.app(scope, guard.receive, guard.send)
            return

        if scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        if path.startswith(self._write_prefixes):
            logger.warning(
                "denied %s for role %s: non-GraphQL write endpoint", path, role.name
            )
            await self._forbid(send, "This session is read-only.")
            return

        if path == self._graphql_path:
            await self._serve_restricted_graphql(role, scope, receive, send)
            return

        await self.app(scope, receive, send)

    async def _serve_restricted_graphql(
        self,
        role: Role,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        body, disconnected = await _read_body(receive)
        if disconnected:
            return
        if body is None:
            await self._forbid(send, "Request body too large to authorise.")
            return

        mutations = mutation_names(body)
        if not may_call(role, mutations):
            logger.warning(
                "denied GraphQL for role %s: %s",
                role.name,
                "unparseable payload" if mutations is None else ", ".join(sorted(mutations)),
            )
            await self._forbid(send, "This session is read-only.")
            return

        await self.app(scope, _replay_body(body), send)

    # ---------------------------------------------------------------- denials

    async def _reject_unauthenticated(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] == "websocket":
            await receive()  # consume websocket.connect before rejecting
            await send({"type": "websocket.close", "code": WS_UNAUTHENTICATED})
            return

        # A browser navigation gets a redirect to the IdP. An XHR gets a 401:
        # a 302 to login.microsoftonline.com inside fetch() surfaces as an
        # opaque CORS failure, not a re-login, which is exactly how proxy-based
        # auth produces its confusing mid-session errors.
        accept = dict(scope.get("headers") or ()).get(b"accept", b"")
        if b"text/html" in accept:
            await _respond(
                send,
                302,
                b"",
                b"text/plain; charset=utf-8",
                [(b"location", self._login_path.encode())],
            )
        else:
            await _respond(
                send,
                401,
                json.dumps({"error": "unauthenticated"}).encode(),
                b"application/json",
            )

    async def _forbid(self, send: Send, message: str) -> None:
        await _respond(
            send,
            403,
            json.dumps({"error": "forbidden", "detail": message}).encode(),
            b"application/json",
        )


class _RestrictedWebSocket:
    """Wraps a WebSocket for a read-only session.

    Dagster's socket endpoint executes whatever operation the frame carries, so
    a mutation can arrive over the subscription transport. Vetting only HTTP
    POSTs would leave that path open.
    """

    def __init__(self, role: Role, receive: Receive, send: Send, client: object) -> None:
        self._role = role
        self._receive = receive
        self._send = send
        self._client = client
        self._closed = False

    async def receive(self) -> Message:
        if self._closed:
            return {"type": "websocket.disconnect", "code": WS_FORBIDDEN}

        message = await self._receive()
        if message.get("type") != "websocket.receive":
            return message

        raw = message.get("text")
        if raw is None:
            raw = message.get("bytes")
        if ws_frame_allowed(self._role, raw):
            return message

        logger.warning(
            "closing WebSocket from %s: mutation attempted by role %s",
            self._client,
            self._role.name,
        )
        self._closed = True
        await self._send({"type": "websocket.close", "code": WS_FORBIDDEN})
        return {"type": "websocket.disconnect", "code": WS_FORBIDDEN}

    async def send(self, message: Message) -> None:
        # Once we have closed the socket, drop anything Dagster still tries to
        # write rather than letting the server raise on a dead connection.
        if self._closed and message.get("type") != "websocket.close":
            return
        await self._send(message)


# --------------------------------------------------------------------- helpers


async def _read_body(receive: Receive) -> tuple[bytes | None, bool]:
    """Buffer an HTTP request body so it can be inspected then replayed.

    Returns ``(body, disconnected)``. ``body`` is ``None`` if the request
    exceeded ``MAX_GRAPHQL_BODY``.
    """
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return None, True
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > MAX_GRAPHQL_BODY:
            return None, False
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks), False


def _replay_body(body: bytes) -> Receive:
    """A receive callable that replays an already-consumed body once."""
    delivered = False

    async def receive() -> Message:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive


async def _respond(
    send: Send,
    status: int,
    body: bytes,
    content_type: bytes,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", content_type),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-store"),
                *(extra_headers or []),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
