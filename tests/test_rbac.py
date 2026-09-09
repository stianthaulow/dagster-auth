"""Tests for the authorisation logic.

This is the security-critical half of the auth layer: a bug in
``mutation_names`` means a read-only session can launch or terminate runs. The
tests deliberately cover the evasion shapes - batched payloads, multiple
operations selected by operationName, aliased fields, fragment spreads - rather
than only the happy path.

    pytest dagster/dagster_authentication/test_rbac.py
"""

from __future__ import annotations

import json

import pytest

from dagster_authentication.rbac import Role, may_call, mutation_names, ws_frame_allowed


def body(**payload: object) -> bytes:
    return json.dumps(payload).encode()


# ------------------------------------------------------------- classification


def test_plain_query_carries_no_mutations():
    assert mutation_names(body(query="query Runs { runsOrError { __typename } }")) == frozenset()


def test_subscription_carries_no_mutations():
    assert mutation_names(body(query="subscription Logs { pipelineRunLogs { __typename } }")) == (
        frozenset()
    )


def test_simple_mutation_is_named():
    assert mutation_names(body(query="mutation { launchRun { __typename } }")) == {"launchRun"}


def test_anonymous_shorthand_query_is_not_a_mutation():
    assert mutation_names(body(query="{ runsOrError { __typename } }")) == frozenset()


def test_aliased_mutation_reports_the_real_field_not_the_alias():
    # An alias must not hide the operation being performed.
    assert mutation_names(body(query="mutation { harmless: terminateRun { __typename } }")) == {
        "terminateRun"
    }


def test_multiple_top_level_mutation_fields_are_all_reported():
    query = "mutation { launchRun { __typename } terminateRun { __typename } }"
    assert mutation_names(body(query=query)) == {"launchRun", "terminateRun"}


def test_operation_name_selects_only_the_executed_operation():
    query = """
        query Safe { runsOrError { __typename } }
        mutation Dangerous { launchRun { __typename } }
    """
    # Only the named operation runs, so a query selection is not a mutation.
    assert mutation_names(body(query=query, operationName="Safe")) == frozenset()
    assert mutation_names(body(query=query, operationName="Dangerous")) == {"launchRun"}


def test_multiple_operations_without_operation_name_are_all_considered():
    query = """
        query Safe { runsOrError { __typename } }
        mutation Dangerous { launchRun { __typename } }
    """
    assert mutation_names(body(query=query)) == {"launchRun"}


def test_batched_payload_reports_mutations_from_every_document():
    payload = [
        {"query": "query { runsOrError { __typename } }"},
        {"query": "mutation { deleteRun { __typename } }"},
    ]
    assert mutation_names(json.dumps(payload).encode()) == {"deleteRun"}


# ----------------------------------------------------- unclassifiable = deny


@pytest.mark.parametrize(
    "raw",
    [
        b"not json at all",
        b"",
        b"null",
        b'{"query": 42}',
        b"{}",
        b'[{"query": "query { a }"}, "not-a-document"]',
        b'{"query": "mutation { unclosed "}',
    ],
    ids=[
        "malformed-json",
        "empty",
        "json-null",
        "query-not-a-string",
        "no-query-key",
        "batch-with-non-object",
        "malformed-graphql",
    ],
)
def test_unclassifiable_payloads_return_none(raw: bytes):
    assert mutation_names(raw) is None


def test_top_level_fragment_spread_is_unclassifiable():
    # The mutation field is hidden behind a fragment, so refuse to guess.
    query = """
        mutation Sneaky { ...Hidden }
        fragment Hidden on Mutation { launchRun { __typename } }
    """
    assert mutation_names(body(query=query)) is None


def test_fragment_named_after_an_allowlisted_mutation_does_not_escalate():
    # Regression: a FragmentSpreadNode also has a .name, so classifying by
    # attribute rather than node type reported the *fragment* name. Naming the
    # fragment logTelemetry then satisfied the viewer allowlist while the
    # fragment body launched runs.
    query = """
        mutation Sneaky { ...logTelemetry }
        fragment logTelemetry on Mutation { launchRun { __typename } }
    """
    assert mutation_names(body(query=query)) is None
    assert may_call(Role.VIEWER, mutation_names(body(query=query))) is False


def test_top_level_inline_fragment_is_unclassifiable():
    query = "mutation { ... on Mutation { launchRun { __typename } } }"
    assert mutation_names(body(query=query)) is None


# -------------------------------------------------------------- role gating


def test_viewer_may_read_but_not_mutate():
    assert may_call(Role.VIEWER, frozenset()) is True
    assert may_call(Role.VIEWER, frozenset({"launchRun"})) is False


def test_viewer_may_send_the_allowlisted_telemetry_mutation():
    assert may_call(Role.VIEWER, frozenset({"logTelemetry"})) is True


def test_allowlisted_mutation_mixed_with_a_real_one_is_denied():
    assert may_call(Role.VIEWER, frozenset({"logTelemetry", "launchRun"})) is False


def test_unknown_mutation_is_denied_for_viewers_by_default():
    assert may_call(Role.VIEWER, frozenset({"someFutureDagsterMutation"})) is False


def test_viewer_is_denied_when_payload_is_unclassifiable():
    assert may_call(Role.VIEWER, None) is False


def test_admin_may_do_anything_including_unclassifiable_payloads():
    assert may_call(Role.ADMIN, frozenset({"wipeAssets"})) is True
    assert may_call(Role.ADMIN, None) is True


# ------------------------------------------------------- websocket framing


def test_viewer_may_open_a_subscription():
    frame = json.dumps(
        {
            "id": "1",
            "type": "subscribe",
            "payload": {"query": "subscription { pipelineRunLogs { __typename } }"},
        }
    )
    assert ws_frame_allowed(Role.VIEWER, frame) is True


@pytest.mark.parametrize("frame_type", ["subscribe", "start"])
def test_viewer_may_not_mutate_over_the_socket(frame_type: str):
    # Dagster's socket endpoint executes whatever operation it is handed, so
    # this is a real escalation path and not a theoretical one.
    frame = json.dumps(
        {
            "id": "1",
            "type": frame_type,
            "payload": {"query": "mutation { launchRun { __typename } }"},
        }
    )
    assert ws_frame_allowed(Role.VIEWER, frame) is False


def test_protocol_frames_pass_through():
    for frame in ('{"type": "connection_init"}', '{"type": "ping"}', '{"type": "complete"}'):
        assert ws_frame_allowed(Role.VIEWER, frame) is True


def test_non_json_socket_traffic_passes_through():
    assert ws_frame_allowed(Role.VIEWER, "not json") is True
    assert ws_frame_allowed(Role.VIEWER, None) is True


def test_operation_frame_without_a_payload_object_is_denied():
    assert ws_frame_allowed(Role.VIEWER, '{"type": "subscribe", "payload": "nope"}') is False


def test_binary_socket_frames_are_decoded_and_checked():
    frame = json.dumps(
        {"type": "subscribe", "payload": {"query": "mutation { deleteRun { __typename } }"}}
    ).encode()
    assert ws_frame_allowed(Role.VIEWER, frame) is False


def test_admin_socket_frames_are_never_blocked():
    frame = json.dumps(
        {"type": "subscribe", "payload": {"query": "mutation { launchRun { __typename } }"}}
    )
    assert ws_frame_allowed(Role.ADMIN, frame) is True
