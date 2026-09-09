"""Microsoft Entra ID authentication and role-based authorisation for Dagster OSS.

Dagster OSS ships no authentication. This package adds Entra sign-in inside the
webserver process - no reverse proxy, no extra service - and enforces a role on
every request, including the GraphQL subscription WebSocket.

Usual use is the console script, a drop-in for ``dagster-webserver``::

    dagster-authentication -w workspace.yaml -h 0.0.0.0 -p 443 \\
        --ssl-certfile cert.pem --ssl-keyfile key.pem

To embed it in your own entrypoint instead, wrap the Dagster ASGI app
yourself::

    from dagster_authentication import AuthConfig, build_app, build_authorizer

    config = AuthConfig.from_env()
    app = build_app(context, config, build_authorizer("identity"))

Authorisation is pluggable: implement the ``Authorizer`` protocol to gate on
whatever store you already have.
"""

from typing import TYPE_CHECKING

from dagster_authentication.authorizer import (
    AllowListAuthorizer,
    AuthorizationUnavailable,
    Authorizer,
    Decision,
)
from dagster_authentication.config import AuthConfig, ConfigError
from dagster_authentication.rbac import Role

# Importing these pulls in Dagster and Starlette, which is a second or two and
# a large dependency tree. Deferring them keeps `dagster_authentication.rbac` and the
# authorizers usable - and testable - on their own.
_LAZY = {
    "AuthGate": "dagster_authentication.gate",
    "build_app": "dagster_authentication.serve",
    "build_authorizer": "dagster_authentication.serve",
    "main": "dagster_authentication.serve",
}

if TYPE_CHECKING:  # pragma: no cover
    from dagster_authentication.gate import AuthGate
    from dagster_authentication.serve import build_app, build_authorizer, main

__all__ = [
    "AllowListAuthorizer",
    "AuthConfig",
    "AuthGate",
    "AuthorizationUnavailable",
    "Authorizer",
    "ConfigError",
    "Decision",
    "Role",
    "build_app",
    "build_authorizer",
    "main",
]


def __getattr__(name: str):
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    return getattr(import_module(module_name), name)


def __dir__() -> list[str]:
    return sorted(__all__)
