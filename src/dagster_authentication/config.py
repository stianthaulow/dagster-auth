"""Environment-driven configuration for the authentication layer.

Everything is read and validated once at startup: a misconfigured webserver
should fail to boot loudly rather than come up serving unauthenticated traffic.

This module covers *authentication* only. Authorisation - who may use Dagster
and at what level - is decided by an :class:`~dagster_authentication.authorizer.Authorizer`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_ENV_PREFIX = "DAGSTER_AUTH"
DEFAULT_SESSION_MAX_AGE = 8 * 3600
DEFAULT_SESSION_COOKIE = "dagster_authentication_session"
MIN_SESSION_SECRET_LEN = 32

# Hosts for which Entra permits a plain-http redirect URI.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class ConfigError(RuntimeError):
    """Raised at startup when configuration is missing or unusable."""


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is not set - refusing to start without it")
    return value


def positive_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None
    if value <= 0:
        raise ConfigError(f"{name} must be positive, got {value}")
    return value


def csv_env(name: str) -> frozenset[str]:
    """A comma-separated environment variable as a set of trimmed entries."""
    return frozenset(part.strip() for part in os.environ.get(name, "").split(",") if part.strip())


def _redirect_uri_allowed(uri: str) -> bool:
    """Entra accepts https anywhere, and http only on the loopback host.

    Mirroring that rule here means --allow-insecure-http is actually usable for
    local development instead of failing validation before startup.
    """
    if uri.startswith("https://"):
        return True
    if not uri.startswith("http://"):
        return False
    return urlsplit(uri).hostname in LOOPBACK_HOSTS


@dataclass(frozen=True)
class AuthConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    redirect_uri: str
    session_secret: str
    session_max_age: int
    session_cookie: str
    path_prefix: str
    env_prefix: str = DEFAULT_ENV_PREFIX

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"

    @classmethod
    def from_env(cls, path_prefix: str = "", env_prefix: str = DEFAULT_ENV_PREFIX) -> AuthConfig:
        """Read and validate the authentication settings.

        ``env_prefix`` lets a project namespace its variables; the default
        expects ``DAGSTER_AUTH_TENANT_ID`` and friends.
        """
        def var(suffix: str) -> str:
            return f"{env_prefix}_{suffix}"

        config = cls(
            tenant_id=required_env(var("TENANT_ID")),
            client_id=required_env(var("CLIENT_ID")),
            client_secret=required_env(var("CLIENT_SECRET")),
            redirect_uri=required_env(var("REDIRECT_URI")),
            session_secret=required_env(var("SESSION_SECRET")),
            session_max_age=positive_int_env(var("SESSION_MAX_AGE"), DEFAULT_SESSION_MAX_AGE),
            session_cookie=os.environ.get(var("SESSION_COOKIE"), "").strip()
            or DEFAULT_SESSION_COOKIE,
            path_prefix=path_prefix.rstrip("/"),
            env_prefix=env_prefix,
        )

        if len(config.session_secret) < MIN_SESSION_SECRET_LEN:
            raise ConfigError(
                f"{var('SESSION_SECRET')} must be at least {MIN_SESSION_SECRET_LEN} characters"
            )
        if not _redirect_uri_allowed(config.redirect_uri):
            raise ConfigError(
                f"{var('REDIRECT_URI')} must be https, or http on localhost - those are the "
                f"only redirect URIs Entra accepts. Got {config.redirect_uri!r}"
            )
        return config
