"""Tests for the authorisation boundary and the allow-list authorizer."""

from __future__ import annotations

import pytest

from dagster_authentication.authorizer import (
    DEFAULT_DENIAL_MESSAGE,
    AllowListAuthorizer,
    Authorizer,
    Decision,
)
from dagster_authentication.rbac import Role

OID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"


def claims(**overrides: object) -> dict[str, object]:
    base = {"oid": OID, "preferred_username": "ada@example.com", "tid": "tenant"}
    base.update(overrides)
    return base


# ------------------------------------------------------------------- Decision


def test_allow_carries_the_role():
    decision = Decision.allow(Role.ADMIN)
    assert decision.allowed is True
    assert decision.role is Role.ADMIN


def test_deny_has_no_role_and_a_default_message():
    decision = Decision.deny("because")
    assert decision.allowed is False
    assert decision.role is None
    assert decision.reason == "because"
    assert decision.message == DEFAULT_DENIAL_MESSAGE


def test_deny_message_can_be_overridden():
    assert Decision.deny("r", "tell the user this").message == "tell the user this"


# ------------------------------------------------------------------ protocol


def test_allow_list_satisfies_the_authorizer_protocol():
    assert isinstance(AllowListAuthorizer(frozenset({"ada@example.com"})), Authorizer)


# ------------------------------------------------------------- allow-listing


def test_admin_by_email():
    authorizer = AllowListAuthorizer(frozenset({"ada@example.com"}))
    assert authorizer.decide(claims()).role is Role.ADMIN


def test_admin_by_object_id():
    authorizer = AllowListAuthorizer(frozenset({OID}))
    assert authorizer.decide(claims(preferred_username=None)).role is Role.ADMIN


def test_viewer_list_grants_viewer():
    authorizer = AllowListAuthorizer(
        frozenset({"grace@example.com"}), frozenset({"ada@example.com"})
    )
    assert authorizer.decide(claims()).role is Role.VIEWER


def test_admin_wins_over_viewer():
    entry = frozenset({"ada@example.com"})
    assert AllowListAuthorizer(entry, entry).decide(claims()).role is Role.ADMIN


def test_matching_is_case_insensitive():
    # Entra casing of preferred_username is not guaranteed to match what an
    # administrator typed into the environment variable.
    authorizer = AllowListAuthorizer(frozenset({"Ada@Example.COM"}))
    assert authorizer.decide(claims(preferred_username="ada@example.com")).role is Role.ADMIN


def test_unlisted_user_is_denied():
    authorizer = AllowListAuthorizer(frozenset({"grace@example.com"}))
    decision = authorizer.decide(claims())
    assert decision.allowed is False
    assert "allow-list" in decision.reason


def test_email_claim_is_also_matched():
    authorizer = AllowListAuthorizer(frozenset({"ada@example.com"}))
    unusual = {"oid": OID, "email": "ada@example.com"}
    assert authorizer.decide(unusual).role is Role.ADMIN


def test_token_without_any_identifier_is_denied():
    decision = AllowListAuthorizer(frozenset({"ada@example.com"})).decide({"tid": "tenant"})
    assert decision.allowed is False
    assert "oid" in decision.reason


def test_empty_allow_list_is_refused_at_construction():
    # Would authorise nobody, so it is a misconfiguration rather than a lockout.
    with pytest.raises(ValueError, match="at least one admin or viewer"):
        AllowListAuthorizer(frozenset(), frozenset())


# --------------------------------------------------------------- environment


def test_from_env_reads_both_lists(monkeypatch: pytest.MonkeyPatch):
    # Whitespace and empty entries are tolerated so the variable can be
    # reformatted by hand without breaking access.
    monkeypatch.setenv("DAGSTER_AUTH_ADMINS", " ada@example.com , " + OID + " ")
    monkeypatch.setenv("DAGSTER_AUTH_VIEWERS", "grace@example.com,,")
    authorizer = AllowListAuthorizer.from_env()

    assert authorizer.decide(claims()).role is Role.ADMIN
    grace = {"oid": "other-oid", "preferred_username": "grace@example.com"}
    assert authorizer.decide(grace).role is Role.VIEWER
    stranger = {"oid": "third-oid", "preferred_username": "eve@example.com"}
    assert authorizer.decide(stranger).allowed is False


def test_from_env_honours_a_custom_prefix(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DAGSTER_AUTH_ADMINS", raising=False)
    monkeypatch.setenv("ACME_ADMINS", "ada@example.com")
    assert AllowListAuthorizer.from_env("ACME").decide(claims()).role is Role.ADMIN
