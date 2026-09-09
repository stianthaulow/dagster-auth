"""The authorisation boundary.

Entra proves *who* signed in. An ``Authorizer`` decides what they may do, so a
project can gate on whatever it already uses - a central identity app, a list of
addresses in the environment, or something of its own - without touching the
sign-in flow or the request gate.

Two rules every implementation must follow:

1. Return ``Decision.deny(...)`` when the user has no access.
2. Raise :class:`AuthorizationUnavailable` when the answer cannot be
   determined. Callers turn that into a 503. Treating an unreachable
   authorisation store as "no access" is the only safe reading - the
   alternative is that an outage silently opens the server to everyone who can
   authenticate.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from dagster_authentication.config import DEFAULT_ENV_PREFIX, csv_env
from dagster_authentication.rbac import Role

logger = logging.getLogger("dagster_authentication")

DEFAULT_DENIAL_MESSAGE = "You do not have access to this application."


class AuthorizationUnavailable(RuntimeError):
    """The authorisation store could not be consulted, so access is refused."""


@dataclass(frozen=True)
class Decision:
    """The outcome of an authorisation check.

    ``reason`` is for the service log and may name identifiers; ``message`` is
    shown to the user and should stay free of internal detail.
    """

    role: Role | None
    reason: str = ""
    message: str = ""

    @property
    def allowed(self) -> bool:
        return self.role is not None

    @classmethod
    def allow(cls, role: Role, reason: str = "") -> Decision:
        return cls(role=role, reason=reason)

    @classmethod
    def deny(cls, reason: str, message: str = DEFAULT_DENIAL_MESSAGE) -> Decision:
        return cls(role=None, reason=reason, message=message)


@runtime_checkable
class Authorizer(Protocol):
    """Decides the role for an authenticated user."""

    name: str

    def decide(self, claims: Mapping[str, Any]) -> Decision:
        """Map ID-token claims onto a role, or deny."""
        ...


class AllowListAuthorizer:
    """Authorises against explicit lists of addresses or object ids.

    For projects with no central access store. Entries are matched against the
    Entra object id (``oid``) and the sign-in name (``preferred_username``),
    case-insensitively, so either form works::

        DAGSTER_AUTH_ADMINS=ada@example.com,3f2504e0-4f89-11d3-9a0c-0305e82c3301
        DAGSTER_AUTH_VIEWERS=grace@example.com

    Admin wins when an identifier appears in both lists.
    """

    name = "allowlist"

    def __init__(self, admins: frozenset[str], viewers: frozenset[str] = frozenset()) -> None:
        self.admins = frozenset(entry.casefold() for entry in admins)
        self.viewers = frozenset(entry.casefold() for entry in viewers)
        if not self.admins and not self.viewers:
            # Guarded here as well as at startup: an empty allow-list authorises
            # nobody, which is never what the operator meant.
            raise ValueError("an allow-list authorizer needs at least one admin or viewer")

    @classmethod
    def from_env(cls, env_prefix: str = DEFAULT_ENV_PREFIX) -> AllowListAuthorizer:
        return cls(csv_env(f"{env_prefix}_ADMINS"), csv_env(f"{env_prefix}_VIEWERS"))

    def _identifiers(self, claims: Mapping[str, Any]) -> set[str]:
        values = (claims.get("oid"), claims.get("preferred_username"), claims.get("email"))
        return {str(value).casefold() for value in values if value}

    def decide(self, claims: Mapping[str, Any]) -> Decision:
        identifiers = self._identifiers(claims)
        if not identifiers:
            return Decision.deny(
                "the ID token carried neither an oid nor a sign-in name",
                "Sign-in succeeded, but the token did not identify your account.",
            )
        if identifiers & self.admins:
            return Decision.allow(Role.ADMIN)
        if identifiers & self.viewers:
            return Decision.allow(Role.VIEWER)
        return Decision.deny(f"none of {sorted(identifiers)} is on the allow-list")
