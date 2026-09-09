"""Tests for startup configuration validation.

The point of validating eagerly is that a misconfigured webserver must fail to
boot rather than come up serving unauthenticated traffic, so these tests are
mostly about which inputs are rejected.

    pytest tests/test_config.py
"""

from __future__ import annotations

import pytest

from dagster_authentication.config import AuthConfig, ConfigError

BASE_ENV = {
    "DAGSTER_AUTH_TENANT_ID": "tenant-guid",
    "DAGSTER_AUTH_CLIENT_ID": "client-guid",
    "DAGSTER_AUTH_CLIENT_SECRET": "a-secret",
    "DAGSTER_AUTH_REDIRECT_URI": "https://dagster.example.com/auth/callback",
    "DAGSTER_AUTH_SESSION_SECRET": "x" * 32,
}

OPTIONAL_KEYS = ["DAGSTER_AUTH_SESSION_COOKIE", "DAGSTER_AUTH_SESSION_MAX_AGE"]


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch):
    """A clean environment holding only the auth variables under test."""

    def apply(**overrides: str | None):
        for key in list(BASE_ENV) + OPTIONAL_KEYS:
            monkeypatch.delenv(key, raising=False)
        for key, value in {**BASE_ENV, **overrides}.items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, value)

    return apply


# ------------------------------------------------------------------ happy path


def test_minimal_valid_environment(env):
    env()
    config = AuthConfig.from_env()
    assert config.session_max_age == 8 * 3600
    assert config.session_cookie == "dagster_authentication_session"
    assert config.authority == "https://login.microsoftonline.com/tenant-guid"


def test_path_prefix_trailing_slash_is_stripped(env):
    env()
    assert AuthConfig.from_env(path_prefix="/dagster/").path_prefix == "/dagster"


# ------------------------------------------------------------- redirect URIs


@pytest.mark.parametrize(
    "uri",
    [
        "https://dagster.example.com/auth/callback",
        "https://dagster.example.com:8443/auth/callback",
        "http://localhost:3000/auth/callback",
        "http://127.0.0.1:3000/auth/callback",
    ],
    ids=["https", "https-with-port", "http-localhost", "http-loopback-ip"],
)
def test_redirect_uris_entra_accepts(env, uri: str):
    # http is permitted on loopback only, matching Entra's own rule - otherwise
    # --allow-insecure-http could never start locally.
    env(DAGSTER_AUTH_REDIRECT_URI=uri)
    assert AuthConfig.from_env().redirect_uri == uri


@pytest.mark.parametrize(
    "uri",
    [
        "http://dagster.example.com/auth/callback",
        "http://192.168.1.10/auth/callback",
        "ftp://dagster.example.com/auth/callback",
        "dagster.example.com/auth/callback",
        "http://localhost.evil.com/auth/callback",
    ],
    ids=["http-remote-host", "http-lan-ip", "wrong-scheme", "no-scheme", "localhost-lookalike"],
)
def test_redirect_uris_that_must_be_rejected(env, uri: str):
    env(DAGSTER_AUTH_REDIRECT_URI=uri)
    with pytest.raises(ConfigError, match="REDIRECT_URI"):
        AuthConfig.from_env()


# --------------------------------------------------------------- rejections


@pytest.mark.parametrize("missing", sorted(BASE_ENV))
def test_every_required_variable_is_required(env, missing: str):
    env(**{missing: None})
    with pytest.raises(ConfigError, match=missing):
        AuthConfig.from_env()


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_required_variable_is_treated_as_missing(env, blank: str):
    env(DAGSTER_AUTH_CLIENT_SECRET=blank)
    with pytest.raises(ConfigError, match="DAGSTER_AUTH_CLIENT_SECRET"):
        AuthConfig.from_env()


def test_short_session_secret_is_rejected(env):
    env(DAGSTER_AUTH_SESSION_SECRET="x" * 31)
    with pytest.raises(ConfigError, match="at least 32"):
        AuthConfig.from_env()


@pytest.mark.parametrize("value", ["not-a-number", "0", "-60", "3.5"])
def test_bad_session_max_age_is_rejected(env, value: str):
    env(DAGSTER_AUTH_SESSION_MAX_AGE=value)
    with pytest.raises(ConfigError, match="DAGSTER_AUTH_SESSION_MAX_AGE"):
        AuthConfig.from_env()


def test_session_max_age_accepts_a_valid_override(env):
    env(DAGSTER_AUTH_SESSION_MAX_AGE="3600")
    assert AuthConfig.from_env().session_max_age == 3600
