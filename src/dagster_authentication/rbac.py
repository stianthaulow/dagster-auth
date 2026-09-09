"""Role model and GraphQL operation authorisation.

Dagster OSS has no permission model: any authenticated caller can launch runs,
terminate them and wipe assets. This module adds the smallest useful split -
read-only viewers versus full admins - by classifying the operation before it
reaches Dagster.

Being in-process is the whole point: a reverse proxy sees an opaque POST to
/graphql and cannot tell a run launch from a page load.
"""

from __future__ import annotations

import json
from enum import IntEnum

from graphql import FieldNode, OperationType, parse
from graphql.error import GraphQLError


class Role(IntEnum):
    """Numeric so that checks are plain comparisons: ``role >= Role.ADMIN``."""

    VIEWER = 10
    ADMIN = 40


# Mutations a read-only session may still send. The Dagster UI fires telemetry
# on page load, and blocking it produces console noise for no security gain.
# Everything else is deny-by-default: an unrecognised mutation needs ADMIN.
VIEWER_MUTATIONS = frozenset({"logTelemetry"})

# Dagster writes to the instance from three POST routes that never touch
# GraphQL (see DagsterWebserver.build_routes). A gate that only inspected
# GraphQL would leave a viewer able to forge materialisations and check results.
WRITE_ROUTE_PREFIXES = (
    "/report_asset_materialization/",
    "/report_asset_check/",
    "/report_asset_observation/",
)

# graphql-ws frame types that carry an operation. "subscribe" is the current
# graphql-transport-ws protocol; "start" is the legacy subscriptions-transport-ws
# one. Dagster's socket endpoint will execute whatever operation it is handed,
# so a mutation can arrive this way and not only over HTTP.
WS_OPERATION_FRAMES = frozenset({"subscribe", "start"})


def mutation_names(body: bytes) -> frozenset[str] | None:
    """Top-level mutation field names in a GraphQL request body.

    Returns an empty frozenset for a pure query or subscription, and ``None``
    when the payload cannot be classified with confidence. Callers must treat
    ``None`` as a denial rather than guessing at intent.
    """
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return None

    documents = payload if isinstance(payload, list) else [payload]
    names: set[str] = set()

    for document in documents:
        if not isinstance(document, dict):
            return None
        query = document.get("query")
        if not isinstance(query, str):
            return None
        try:
            ast = parse(query)
        except GraphQLError:
            return None

        # A document may define several operations while executing only the one
        # named by operationName, so narrow to it when it is present.
        wanted = document.get("operationName")
        for definition in ast.definitions:
            if getattr(definition, "operation", None) is not OperationType.MUTATION:
                continue
            if wanted and getattr(definition.name, "value", None) != wanted:
                continue
            for selection in definition.selection_set.selections:
                # Only a FieldNode names a mutation. A fragment spread and an
                # inline fragment also carry a .name, so duck-typing here would
                # let `mutation { ...logTelemetry }` - with a fragment named
                # logTelemetry wrapping launchRun - pass the viewer allowlist
                # while executing anything inside the fragment.
                if not isinstance(selection, FieldNode):
                    return None
                names.add(selection.name.value)

    return frozenset(names)


def may_call(role: Role, mutations: frozenset[str] | None) -> bool:
    """Whether ``role`` may execute an operation carrying ``mutations``."""
    if role >= Role.ADMIN:
        return True
    if mutations is None:
        return False
    return mutations <= VIEWER_MUTATIONS


def ws_frame_allowed(role: Role, raw: str | bytes | None) -> bool:
    """Whether ``role`` may send this graphql-ws frame."""
    if role >= Role.ADMIN:
        return True
    if raw is None:
        return True
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        frame = json.loads(raw)
    except (ValueError, TypeError):
        # Not a JSON frame, so not an operation. Protocol noise (ping, ack).
        return True
    if not isinstance(frame, dict) or frame.get("type") not in WS_OPERATION_FRAMES:
        return True
    payload = frame.get("payload")
    if not isinstance(payload, dict):
        return False
    return may_call(role, mutation_names(json.dumps(payload).encode()))
