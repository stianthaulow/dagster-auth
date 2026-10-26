"""The gate in front of a real Dagster webserver.

``test_gate`` checks the gate against a stand-in. These check it against
Dagster's own request parser, which is what decides the operation that runs:
a viewer request is a bypass exactly when it wipes the probe asset.
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urlencode

import pytest
from dagster import AssetKey, AssetMaterialization, DagsterInstance
from dagster._core.workspace.context import WorkspaceProcessContext
from dagster._core.workspace.load_target import EmptyWorkspaceTarget
from dagster_webserver.app import create_app_from_workspace_process_context

from dagster_authentication.gate import AuthGate
from dagster_authentication.rbac import Role
from test_gate import _no_router, config

PROBE = AssetKey(["review_probe"])
WIPE = (
    'mutation { wipeAssets(assetPartitionRanges: [{assetKey: {path: ["review_probe"]}}]) '
    "{ __typename } }"
)
QUERY = "{ __typename }"


@pytest.fixture(scope="module")
def dagster(tmp_path_factory):
    directory = tmp_path_factory.mktemp("dagster")
    with (
        DagsterInstance.local_temp(str(directory)) as instance,
        WorkspaceProcessContext(instance, EmptyWorkspaceTarget()) as context,
    ):
        yield instance, create_app_from_workspace_process_context(context)


def send(dagster, role, method, params=None, body=b"", content_type=None, extra_headers=()):
    """Materialise the probe, send one request through the gate.

    Returns (status, response body, probe still present).
    """
    instance, app = dagster
    instance.report_runless_asset_event(AssetMaterialization(PROBE))
    headers = [(b"host", b"testserver")]
    if content_type is not None:
        headers.append((b"content-type", content_type))
    headers.extend(extra_headers)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "scheme": "https",
        "server": ("testserver", 443),
        "method": method,
        "path": "/graphql",
        "raw_path": b"/graphql",
        "root_path": "",
        "query_string": urlencode(params or {}).encode(),
        "headers": headers,
        "session": {"role": int(role)},
    }
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    sent: list[dict] = []

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def collect(message):
        sent.append(message)

    asyncio.run(AuthGate(app, _no_router, config)(scope, receive, collect))
    response = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return sent[0]["status"], response, PROBE in instance.get_asset_keys()


def test_admin_get_mutation_wipes_the_probe(dagster):
    # Proves the probe detects a mutation that Dagster executed.
    status, body, present = send(dagster, Role.ADMIN, "GET", {"query": WIPE})
    assert status == 200 and b"AssetWipeSuccess" in body
    assert not present


def test_viewer_get_query_runs(dagster):
    status, body, _ = send(dagster, Role.VIEWER, "GET", {"query": QUERY})
    assert status == 200 and json.loads(body)["data"]["__typename"] == "Query"


@pytest.mark.parametrize(
    ("method", "params", "body", "content_type"),
    [
        ("GET", {"query": WIPE}, b"", None),
        ("POST", {}, json.dumps({"query": WIPE}).encode(), b"application/json"),
        ("POST", {}, WIPE.encode(), b"application/graphql"),
        ("POST", {"query": WIPE}, json.dumps({"query": QUERY}).encode(), b"text/plain"),
        ("POST", {"query": WIPE}, json.dumps({"query": QUERY}).encode(), None),
    ],
    ids=["get", "json-post", "graphql-post", "text-post-url-mutation", "bare-post-url-mutation"],
)
def test_viewer_cannot_wipe(dagster, method, params, body, content_type):
    status, _, present = send(dagster, Role.VIEWER, method, params, body, content_type)
    assert status == 403
    assert present


def test_viewer_cannot_wipe_behind_a_mixed_case_content_type(dagster):
    # Starlette skips the mixed-case JSON header and runs the URL mutation.
    headers = [(b"Content-Type", b"application/json"), (b"content-type", b"text/plain")]
    body = json.dumps({"query": QUERY}).encode()
    status, _, present = send(
        dagster, Role.VIEWER, "POST", {"query": WIPE}, body, extra_headers=headers
    )
    assert status == 403
    assert present
