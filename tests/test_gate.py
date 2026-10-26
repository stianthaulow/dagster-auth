"""Tests for the HTTP side of the gate.

``test_rbac`` covers how an operation is classified; these cover which requests
reach that classification at all. A viewer must not be able to pick an HTTP
shape the gate forwards unvetted while Dagster still executes it.

The app is driven over raw ASGI so the tests need no HTTP client dependency.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from urllib.parse import urlencode

import pytest

from dagster_authentication.config import AuthConfig
from dagster_authentication.gate import AuthGate
from dagster_authentication.rbac import Role

MUTATION = "mutation { launchRun { __typename } }"
QUERY = "{ runsOrError { __typename } }"

config = AuthConfig(
    tenant_id="tenant",
    client_id="client",
    client_secret="test-only",
    redirect_uri="https://testserver/auth/callback",
    session_secret="x" * 32,
    session_max_age=28800,
    session_cookie="test_session",
    path_prefix="",
)


class Downstream:
    """Stands in for Dagster and records whether a request got through."""

    def __init__(self) -> None:
        self.reached = False

    async def __call__(self, scope, receive, send) -> None:
        self.reached = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def _no_router(scope, receive, send) -> None:
    raise AssertionError("auth router should not be reached")


def request(
    role: Role,
    method: str,
    path: str,
    params: list[tuple[str, str]] | dict[str, str] | None = None,
    headers: list[tuple[bytes, bytes]] | None = None,
    gate_config: AuthConfig = config,
    body: bytes = b"",
) -> tuple[int, bool]:
    """Send one request through the gate. Returns (status, reached Dagster)."""
    downstream = Downstream()
    gate = AuthGate(downstream, _no_router, gate_config)
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": urlencode(params or {}).encode(),
        "headers": headers or [],
        "session": {"role": int(role)},
    }
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(gate(scope, receive, send))
    return sent[0]["status"], downstream.reached


# ------------------------------------------------------------ GraphQL over GET


def test_viewer_may_query_over_get():
    assert request(Role.VIEWER, "GET", "/graphql", {"query": QUERY}) == (200, True)


def test_viewer_may_not_mutate_over_get():
    assert request(Role.VIEWER, "GET", "/graphql", {"query": MUTATION}) == (403, False)


def test_viewer_get_mutation_is_denied_even_when_html_is_accepted():
    headers = [(b"accept", b"text/html")]
    status, reached = request(Role.VIEWER, "GET", "/graphql", {"query": MUTATION}, headers)
    assert (status, reached) == (403, False)


def test_get_operation_name_selects_the_executed_operation():
    document = f"query Safe {QUERY} mutation Bad {{ launchRun {{ __typename }} }}"
    assert request(
        Role.VIEWER, "GET", "/graphql", {"query": document, "operationName": "Safe"}
    ) == (200, True)
    assert request(Role.VIEWER, "GET", "/graphql", {"query": document, "operationName": "Bad"}) == (
        403,
        False,
    )


def test_get_without_operation_name_considers_every_operation():
    document = f"query Safe {QUERY} mutation Bad {{ launchRun {{ __typename }} }}"
    assert request(Role.VIEWER, "GET", "/graphql", {"query": document}) == (403, False)


@pytest.mark.parametrize(
    "params",
    [
        [("query", QUERY), ("query", MUTATION)],
        [("query", MUTATION), ("query", QUERY)],
        [
            ("query", "query Safe { __typename }"),
            ("operationName", "Safe"),
            ("operationName", "Other"),
        ],
    ],
    ids=["query-then-mutation", "mutation-then-query", "repeated-operation-name"],
)
def test_repeated_get_parameters_are_denied(params):
    assert request(Role.VIEWER, "GET", "/graphql", params) == (403, False)


def test_unparseable_get_query_is_denied():
    assert request(Role.VIEWER, "GET", "/graphql", {"query": "mutation {"}) == (403, False)


def test_get_without_a_query_is_forwarded():
    # GraphiQL page load, or a request Dagster itself rejects with 400.
    assert request(Role.VIEWER, "GET", "/graphql") == (200, True)


def test_admin_may_mutate_over_get():
    assert request(Role.ADMIN, "GET", "/graphql", {"query": MUTATION}) == (200, True)


def test_viewer_get_to_other_paths_is_forwarded():
    assert request(Role.VIEWER, "GET", "/runs", {"query": MUTATION}) == (200, True)


def test_path_prefix_applies_to_get_vetting():
    prefixed = replace(config, path_prefix="/dagster")
    params = {"query": MUTATION}
    assert request(Role.VIEWER, "GET", "/dagster/graphql", params, gate_config=prefixed) == (
        403,
        False,
    )


# ----------------------------------------------------------- GraphQL over POST


def post(
    content_type: bytes | None,
    body: bytes = b"",
    params: dict[str, str] | None = None,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> tuple[int, bool]:
    """A viewer POST to /graphql."""
    headers = list(headers or [])
    if content_type is not None:
        headers.insert(0, (b"content-type", content_type))
    return request(Role.VIEWER, "POST", "/graphql", params, headers, body=body)


def json_body(query: str) -> bytes:
    return json.dumps({"query": query}).encode()


def test_viewer_may_query_over_json_post():
    assert post(b"application/json", json_body(QUERY)) == (200, True)


def test_viewer_may_not_mutate_over_json_post():
    assert post(b"application/json", json_body(MUTATION)) == (403, False)


def test_viewer_may_query_over_raw_graphql_post():
    assert post(b"application/graphql", QUERY.encode()) == (200, True)


def test_viewer_may_not_mutate_over_raw_graphql_post():
    assert post(b"application/graphql", MUTATION.encode()) == (403, False)


@pytest.mark.parametrize(
    "content_type", [b"text/plain", b"application/x-www-form-urlencoded", None]
)
def test_post_body_cannot_cover_for_a_url_mutation(content_type):
    # Dagster ignores the body for these content types and runs the URL query.
    assert post(content_type, json_body(QUERY), {"query": MUTATION}) == (403, False)


@pytest.mark.parametrize("content_type", [b"text/plain", None])
def test_viewer_may_query_over_url_post(content_type):
    assert post(content_type, b"", {"query": QUERY}) == (200, True)


def test_json_post_is_vetted_on_its_body_not_its_url():
    # Dagster runs the JSON body and ignores the URL, so the body decides.
    assert post(b"application/json", json_body(MUTATION), {"query": QUERY}) == (403, False)
    assert post(b"application/json", json_body(QUERY), {"query": MUTATION}) == (200, True)


def test_first_content_type_header_decides():
    # Starlette's Headers.get returns the first value, so Dagster parses the
    # URL here and the JSON body must not be what gets vetted.
    headers = [(b"content-type", b"application/json")]
    assert post(b"text/plain", json_body(QUERY), {"query": MUTATION}, headers) == (403, False)


def test_mixed_case_content_type_header_is_ignored():
    # Starlette only matches the lowercase name, so Dagster skips the
    # mixed-case JSON header and parses the URL from the text/plain one.
    headers = [(b"Content-Type", b"application/json"), (b"content-type", b"text/plain")]
    assert post(None, json_body(QUERY), {"query": MUTATION}, headers) == (403, False)


def test_undecodable_raw_graphql_post_is_denied():
    assert post(b"application/graphql", b"\xff") == (403, False)
