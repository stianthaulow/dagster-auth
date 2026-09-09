"""Authorisation against the Flowbyte identity app.

Access is granted by a live row in ``dbo.application_user_access`` - the same
login gate the chat, backend and relay apps use (see
``identity/db/002_application_access_backfill.sql`` in that repo).

The join key is the Entra **object id**. The identity app deliberately replaces
the OIDC ``sub`` with ``oid`` before storing the external login::

    // CRITICAL: Use Object ID (oid) as NameIdentifier instead of sub
    identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, oidClaim.Value));

That matters here because ``sub`` is *pairwise*: Entra issues a different
``sub`` per application, so a webserver's ``sub`` would never match a row
written by the identity app. ``oid`` is the same value for a given user across
every app registration in the tenant.

A connection is opened per check rather than pooled. Sign-in happens once per
session lifetime (8h by default), so the cost is irrelevant and it avoids
holding a pyodbc connection - which is not thread-safe to share - across the
threadpool that serves these requests.

Requires the ``identity`` extra::

    pip install "dagster-authentication[identity]"
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from dagster_authentication.authorizer import AuthorizationUnavailable, Decision
from dagster_authentication.config import ConfigError, required_env
from dagster_authentication.rbac import Role

logger = logging.getLogger("dagster_authentication")

DEFAULT_ODBC_DRIVER = "ODBC Driver 17 for SQL Server"
DEFAULT_LOGIN_PROVIDER = "MicrosoftOidc"
DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_DATABASE = "identity"

# Only rows that are live on every hop count as access: the grant, the user and
# the application row itself. Mirrors the pre-flight checks in identity's
# 002_application_access_backfill.sql, which require the application row to be
# both is_deleted = 0 and is_active = 1.
ACCESS_QUERY = """
SELECT a.application_id
FROM   dbo.user_login l
JOIN   dbo.application_user u
       ON u.id = l.user_id
JOIN   dbo.application_user_access a
       ON a.application_user_id = l.user_id
JOIN   dbo.application app
       ON app.id = a.application_id
WHERE  l.login_provider = ?
  AND  l.provider_key = ?
  AND  a.application_id IN ({placeholders})
  AND  ISNULL(a.is_deleted, 0) = 0
  AND  ISNULL(u.is_deleted, 0) = 0
  AND  ISNULL(app.is_deleted, 0) = 0
  AND  app.is_active = 1
"""


@dataclass(frozen=True)
class IdentityConfig:
    server: str
    database: str
    username: str
    password: str
    driver: str
    admin_app_id: str
    viewer_app_id: str | None
    login_provider: str
    timeout: int

    @property
    def app_ids(self) -> tuple[str, ...]:
        """The application ids worth querying, admin first."""
        if self.viewer_app_id:
            return (self.admin_app_id, self.viewer_app_id)
        return (self.admin_app_id,)

    @classmethod
    def from_env(cls, env_prefix: str = "DAGSTER_AUTH") -> IdentityConfig:
        """Read the identity settings.

        The database connection follows the ``{PREFIX}_SERVER`` /
        ``_DATABASE`` / ``_USER`` / ``_PASSWORD`` shape used across Flowbyte
        projects, under the fixed ``IDENTITY`` prefix so several apps on one
        host can share it. The application ids are namespaced by
        ``env_prefix``, because they differ per app.
        """
        raw_timeout = os.environ.get("IDENTITY_TIMEOUT", "").strip()
        try:
            timeout = int(raw_timeout) if raw_timeout else DEFAULT_TIMEOUT_SECONDS
        except ValueError:
            raise ConfigError(f"IDENTITY_TIMEOUT must be an integer, got {raw_timeout!r}") from None
        if timeout <= 0:
            raise ConfigError(f"IDENTITY_TIMEOUT must be positive, got {timeout}")

        admin_var = f"{env_prefix}_IDENTITY_APP_ID"
        viewer_var = f"{env_prefix}_IDENTITY_VIEWER_APP_ID"
        admin = required_env(admin_var)
        viewer = os.environ.get(viewer_var, "").strip() or None
        if viewer == admin:
            raise ConfigError(
                f"{viewer_var} must differ from {admin_var}; as written, everyone with "
                "read-only access would also be an admin"
            )

        return cls(
            server=required_env("IDENTITY_SERVER"),
            database=os.environ.get("IDENTITY_DATABASE", "").strip() or DEFAULT_DATABASE,
            username=required_env("IDENTITY_USER"),
            password=required_env("IDENTITY_PASSWORD"),
            driver=os.environ.get("IDENTITY_ODBC_DRIVER", "").strip() or DEFAULT_ODBC_DRIVER,
            admin_app_id=admin,
            viewer_app_id=viewer,
            login_provider=os.environ.get("IDENTITY_LOGIN_PROVIDER", "").strip()
            or DEFAULT_LOGIN_PROVIDER,
            timeout=timeout,
        )


def role_from_granted(
    granted: frozenset[str],
    admin_app_id: str,
    viewer_app_id: str | None,
) -> Role | None:
    """Map the application ids a user holds onto a role.

    Admin wins when both are held. ``None`` means no access at all.
    """
    if admin_app_id in granted:
        return Role.ADMIN
    if viewer_app_id and viewer_app_id in granted:
        return Role.VIEWER
    return None


def _default_connect(config: IdentityConfig):
    # Imported lazily so the pure logic in this module stays importable (and
    # testable) without a database driver, and so projects that use a different
    # authorizer need not install the identity extra.
    try:
        import pyodbc
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise AuthorizationUnavailable(
            "pyodbc is not installed; install dagster-authentication[identity] to use the "
            "identity authorizer"
        ) from exc

    return pyodbc.connect(
        f"DRIVER={{{config.driver}}};SERVER={config.server};DATABASE={config.database};"
        f"UID={config.username};PWD={config.password};CHARSET=UTF8",
        timeout=config.timeout,
    )


class IdentityAppAuthorizer:
    """Resolves an Entra object id to a role using the identity database."""

    name = "identity"

    def __init__(self, config: IdentityConfig, connect=None) -> None:
        self.config = config
        self._connect = connect or _default_connect

    @classmethod
    def from_env(cls, env_prefix: str = "DAGSTER_AUTH") -> IdentityAppAuthorizer:
        return cls(IdentityConfig.from_env(env_prefix))

    def granted_app_ids(self, oid: str) -> frozenset[str]:
        """Application ids the user holds live access to, of those configured."""
        app_ids = self.config.app_ids
        query = ACCESS_QUERY.format(placeholders=", ".join("?" for _ in app_ids))
        params = (self.config.login_provider, oid, *app_ids)

        try:
            connection = self._connect(self.config)
        except AuthorizationUnavailable:
            raise
        except Exception as exc:
            raise AuthorizationUnavailable(
                f"could not connect to the identity database: {exc}"
            ) from exc

        try:
            with connection:
                cursor = connection.cursor()
                try:
                    cursor.execute(query, params)
                    rows = cursor.fetchall()
                finally:
                    cursor.close()
        except AuthorizationUnavailable:
            raise
        except Exception as exc:
            raise AuthorizationUnavailable(f"identity access lookup failed: {exc}") from exc

        return frozenset(str(row[0]) for row in rows if row and row[0] is not None)

    def decide(self, claims: Mapping[str, Any]) -> Decision:
        oid = claims.get("oid")
        if not oid:
            return Decision.deny(
                f"the ID token carried no oid claim, so the account cannot be matched to an "
                f"identity user; claims present: {sorted(claims)}",
                "Sign-in succeeded, but the token did not identify your directory account, "
                "so your access could not be checked.",
            )

        granted = self.granted_app_ids(str(oid))
        role = role_from_granted(granted, self.config.admin_app_id, self.config.viewer_app_id)
        if role is None:
            return Decision.deny(
                f"oid {oid} holds no live access row for application "
                f"{self.config.admin_app_id!r} (granted: {sorted(granted)})",
                f"You do not have access to this application "
                f"({self.config.admin_app_id}). Ask an administrator to grant it in Identity.",
            )

        logger.debug(
            "identity lookup for oid %s: granted %s -> %s", oid, sorted(granted), role.name
        )
        return Decision.allow(role)
