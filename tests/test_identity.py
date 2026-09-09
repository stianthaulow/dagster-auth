"""Tests for authorisation against the identity app.

The database call is injected, so these exercise the real query construction,
the role mapping and - most importantly - that every failure path denies access
rather than falling open.

    pytest tests/test_identity.py
"""

from __future__ import annotations

import pytest

from dagster_authentication.authorizer import AuthorizationUnavailable, Authorizer
from dagster_authentication.config import ConfigError
from dagster_authentication.identity import (
    DEFAULT_LOGIN_PROVIDER,
    DEFAULT_ODBC_DRIVER,
    IdentityAppAuthorizer,
    IdentityConfig,
    role_from_granted,
)
from dagster_authentication.rbac import Role

ADMIN_APP = "DAGSTER_COMPANY"
VIEWER_APP = "DAGSTER_COMPANY_RO"
OID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

BASE_ENV = {
    "IDENTITY_SERVER": "sql.example.com",
    "IDENTITY_USER": "dagster_reader",
    "IDENTITY_PASSWORD": "secret",
    "DAGSTER_AUTH_IDENTITY_APP_ID": ADMIN_APP,
}

OPTIONAL_KEYS = [
    "DAGSTER_AUTH_IDENTITY_VIEWER_APP_ID",
    "IDENTITY_DATABASE",
    "IDENTITY_ODBC_DRIVER",
    "IDENTITY_LOGIN_PROVIDER",
    "IDENTITY_TIMEOUT",
]


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch):
    def apply(**overrides: str | None):
        for key in list(BASE_ENV) + OPTIONAL_KEYS:
            monkeypatch.delenv(key, raising=False)
        for key, value in {**BASE_ENV, **overrides}.items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, value)

    return apply


def make_config(**overrides) -> IdentityConfig:
    defaults = dict(
        server="sql.example.com",
        database="identity",
        username="dagster_reader",
        password="secret",
        driver=DEFAULT_ODBC_DRIVER,
        admin_app_id=ADMIN_APP,
        viewer_app_id=None,
        login_provider=DEFAULT_LOGIN_PROVIDER,
        timeout=10,
    )
    defaults.update(overrides)
    return IdentityConfig(**defaults)


def claims(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {"oid": OID, "preferred_username": "ada@example.com"}
    base.update(overrides)
    return base


class FakeCursor:
    def __init__(self, rows, raises=None):
        self._rows = rows
        self._raises = raises
        self.executed: list[tuple[str, tuple]] = []
        self.closed = False

    def execute(self, query, params):
        self.executed.append((query, tuple(params)))
        if self._raises:
            raise self._raises

    def fetchall(self):
        return self._rows

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, rows=(), raises=None):
        self.cursor_obj = FakeCursor(list(rows), raises)
        self.exited = False

    def cursor(self):
        return self.cursor_obj

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.exited = True
        return False


# ------------------------------------------------------------- role mapping


def test_admin_application_grants_admin():
    assert role_from_granted(frozenset({ADMIN_APP}), ADMIN_APP, VIEWER_APP) is Role.ADMIN


def test_viewer_application_grants_viewer():
    assert role_from_granted(frozenset({VIEWER_APP}), ADMIN_APP, VIEWER_APP) is Role.VIEWER


def test_admin_wins_when_both_are_granted():
    granted = frozenset({ADMIN_APP, VIEWER_APP})
    assert role_from_granted(granted, ADMIN_APP, VIEWER_APP) is Role.ADMIN


def test_no_grant_means_no_access():
    assert role_from_granted(frozenset(), ADMIN_APP, VIEWER_APP) is None
    assert role_from_granted(frozenset({"SOMETHING_ELSE"}), ADMIN_APP, VIEWER_APP) is None


def test_viewer_app_is_ignored_when_not_configured():
    # Without a viewer application id, holding it must not grant anything.
    assert role_from_granted(frozenset({VIEWER_APP}), ADMIN_APP, None) is None


# ------------------------------------------------------------------ protocol


def test_satisfies_the_authorizer_protocol():
    assert isinstance(IdentityAppAuthorizer(make_config()), Authorizer)


# --------------------------------------------------------- query behaviour


def test_lookup_binds_provider_oid_and_app_ids():
    connection = FakeConnection(rows=[(ADMIN_APP,)])
    authorizer = IdentityAppAuthorizer(
        make_config(viewer_app_id=VIEWER_APP), connect=lambda _cfg: connection
    )

    assert authorizer.decide(claims()).role is Role.ADMIN

    query, params = connection.cursor_obj.executed[0]
    assert params == (DEFAULT_LOGIN_PROVIDER, OID, ADMIN_APP, VIEWER_APP)
    # One placeholder per bound value, so the IN list cannot drift.
    assert query.count("?") == len(params)
    assert connection.cursor_obj.closed
    assert connection.exited


def test_lookup_binds_only_the_admin_app_when_no_viewer_configured():
    connection = FakeConnection(rows=[])
    authorizer = IdentityAppAuthorizer(make_config(), connect=lambda _cfg: connection)

    assert authorizer.decide(claims()).allowed is False
    _query, params = connection.cursor_obj.executed[0]
    assert params == (DEFAULT_LOGIN_PROVIDER, OID, ADMIN_APP)


def test_query_filters_soft_deletes_and_inactive_applications():
    # These predicates are the difference between a revoked grant being honoured
    # and being ignored, so assert they are actually in the statement.
    connection = FakeConnection(rows=[])
    IdentityAppAuthorizer(make_config(), connect=lambda _cfg: connection).decide(claims())
    query = connection.cursor_obj.executed[0][0]

    assert "ISNULL(a.is_deleted, 0) = 0" in query
    assert "ISNULL(u.is_deleted, 0) = 0" in query
    assert "ISNULL(app.is_deleted, 0) = 0" in query
    assert "app.is_active = 1" in query


def test_custom_login_provider_is_honoured():
    connection = FakeConnection(rows=[])
    authorizer = IdentityAppAuthorizer(
        make_config(login_provider="OtherOidc"), connect=lambda _cfg: connection
    )
    authorizer.decide(claims())
    assert connection.cursor_obj.executed[0][1][0] == "OtherOidc"


def test_null_and_duplicate_rows_are_tolerated():
    connection = FakeConnection(rows=[(ADMIN_APP,), (None,), (ADMIN_APP,)])
    authorizer = IdentityAppAuthorizer(make_config(), connect=lambda _cfg: connection)
    assert authorizer.granted_app_ids(OID) == frozenset({ADMIN_APP})


# --------------------------------------------------------------- denial text


def test_denial_names_the_application_so_the_user_can_ask_for_it():
    connection = FakeConnection(rows=[])
    decision = IdentityAppAuthorizer(make_config(), connect=lambda _cfg: connection).decide(claims())
    assert ADMIN_APP in decision.message
    assert ADMIN_APP in decision.reason


def test_missing_oid_is_reported_separately_from_a_missing_grant():
    # The two need different fixes - a token/registration problem versus an
    # access grant - so they must not share a message.
    authorizer = IdentityAppAuthorizer(make_config(), connect=lambda _cfg: FakeConnection())
    decision = authorizer.decide({"preferred_username": "ada@example.com"})
    assert decision.allowed is False
    assert "oid" in decision.reason
    assert "did not identify your directory account" in decision.message


def test_missing_oid_does_not_touch_the_database():
    def explode(_cfg):
        raise AssertionError("should not connect when there is no oid to look up")

    authorizer = IdentityAppAuthorizer(make_config(), connect=explode)
    assert authorizer.decide({}).allowed is False


# ------------------------------------------------------------ failing closed


def test_connection_failure_denies_rather_than_allows():
    def explode(_cfg):
        raise OSError("no route to host")

    authorizer = IdentityAppAuthorizer(make_config(), connect=explode)
    with pytest.raises(AuthorizationUnavailable, match="could not connect"):
        authorizer.decide(claims())


def test_query_failure_denies_rather_than_allows():
    connection = FakeConnection(raises=RuntimeError("invalid object name"))
    authorizer = IdentityAppAuthorizer(make_config(), connect=lambda _cfg: connection)
    with pytest.raises(AuthorizationUnavailable, match="lookup failed"):
        authorizer.decide(claims())


# ------------------------------------------------------------ configuration


def test_config_from_env_defaults(env):
    env()
    config = IdentityConfig.from_env()
    assert config.admin_app_id == ADMIN_APP
    assert config.viewer_app_id is None
    assert config.database == "identity"
    assert config.driver == DEFAULT_ODBC_DRIVER
    assert config.login_provider == DEFAULT_LOGIN_PROVIDER
    assert config.timeout == 10
    assert config.app_ids == (ADMIN_APP,)


def test_config_from_env_with_viewer_app(env):
    env(DAGSTER_AUTH_IDENTITY_VIEWER_APP_ID=VIEWER_APP)
    assert IdentityConfig.from_env().app_ids == (ADMIN_APP, VIEWER_APP)


@pytest.mark.parametrize("missing", sorted(BASE_ENV))
def test_every_required_identity_variable_is_required(env, missing: str):
    env(**{missing: None})
    with pytest.raises(ConfigError, match=missing):
        IdentityConfig.from_env()


def test_viewer_app_equal_to_admin_app_is_rejected(env):
    # Silently collapsing the two would promote every read-only user to admin.
    env(DAGSTER_AUTH_IDENTITY_VIEWER_APP_ID=ADMIN_APP)
    with pytest.raises(ConfigError, match="must differ"):
        IdentityConfig.from_env()


@pytest.mark.parametrize("value", ["not-a-number", "0", "-1"])
def test_bad_timeout_is_rejected(env, value: str):
    env(IDENTITY_TIMEOUT=value)
    with pytest.raises(ConfigError, match="IDENTITY_TIMEOUT"):
        IdentityConfig.from_env()


def test_overrides(env):
    env(
        IDENTITY_ODBC_DRIVER="ODBC Driver 18 for SQL Server",
        IDENTITY_TIMEOUT="30",
        IDENTITY_DATABASE="identity_test",
    )
    config = IdentityConfig.from_env()
    assert config.driver == "ODBC Driver 18 for SQL Server"
    assert config.timeout == 30
    assert config.database == "identity_test"


def test_app_id_honours_a_custom_env_prefix(env, monkeypatch: pytest.MonkeyPatch):
    env(DAGSTER_AUTH_IDENTITY_APP_ID=None)
    monkeypatch.setenv("ACME_IDENTITY_APP_ID", "ACME_DAGSTER")
    assert IdentityConfig.from_env("ACME").admin_app_id == "ACME_DAGSTER"
