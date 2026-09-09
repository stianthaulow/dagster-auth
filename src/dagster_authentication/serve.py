"""Entrypoint: the Dagster webserver with Entra ID authentication built in.

A drop-in replacement for ``dagster-webserver``. It reuses Dagster's own
workspace CLI options, so the arguments an existing service passes (-w / -f /
-m / -a / -d, --host, --port, --path-prefix, --read-only) keep working::

    dagster-authentication -w workspace.yaml -h 0.0.0.0 -p 443 \\
        --ssl-certfile cert.pem --ssl-keyfile key.pem

Nothing is monkey-patched. ``create_app_from_workspace_process_context``
returns a plain Starlette app, so the auth layer is ordinary ASGI wrapping:

    SessionMiddleware        decodes the signed cookie (http and websocket)
      -> AuthGate            requires a session; enforces the role
        -> Dagster app
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncIterator
from pathlib import Path

import click
import uvicorn
from dagster._cli.utils import assert_no_remaining_opts, get_possibly_temporary_instance_for_cli
from dagster._cli.workspace.cli_target import WorkspaceOpts, workspace_opts_to_load_target
from dagster._core.workspace.context import IWorkspaceProcessContext, WorkspaceProcessContext
from dagster._utils.interrupts import setup_interrupt_handlers
from dagster._utils.log import configure_loggers
from dagster_shared.cli import workspace_options
from dagster_webserver.app import create_app_from_workspace_process_context
from dagster_webserver.version import __version__ as dagster_webserver_version
from dotenv import load_dotenv
from starlette.middleware.sessions import SessionMiddleware
from starlette.types import ASGIApp

from dagster_authentication.authorizer import AllowListAuthorizer, Authorizer
from dagster_authentication.config import DEFAULT_ENV_PREFIX, AuthConfig, ConfigError
from dagster_authentication.entra import build_auth_router
from dagster_authentication.gate import AuthGate

LOGGER_NAME = "dagster_authentication"
logger = logging.getLogger(LOGGER_NAME)

AUTHORIZERS = ("identity", "allowlist")


@contextlib.asynccontextmanager
async def _lifespan(_app: ASGIApp) -> AsyncIterator[None]:
    # Mirrors dagster_webserver.cli: uvicorn raises CancelledError when the
    # service is stopped, and without this the shutdown is logged as a crash.
    try:
        yield
    except asyncio.exceptions.CancelledError:
        logger.info("Dagster webserver shut down.")


def build_authorizer(kind: str, env_prefix: str = DEFAULT_ENV_PREFIX) -> Authorizer:
    """Construct the configured authorizer, validating its settings eagerly."""
    if kind == "identity":
        # Imported here so projects using the allow-list never need pyodbc.
        from dagster_authentication.identity import IdentityAppAuthorizer

        return IdentityAppAuthorizer.from_env(env_prefix)
    if kind == "allowlist":
        try:
            return AllowListAuthorizer.from_env(env_prefix)
        except ValueError as exc:
            raise ConfigError(
                f"{exc}. Set {env_prefix}_ADMINS (and optionally {env_prefix}_VIEWERS) to a "
                "comma-separated list of sign-in names or Entra object ids."
            ) from None
    raise ConfigError(f"unknown authorizer {kind!r}; choose one of {', '.join(AUTHORIZERS)}")


def build_app(
    context: IWorkspaceProcessContext,
    config: AuthConfig,
    authorizer: Authorizer,
    *,
    live_data_poll_rate: int | None = None,
    https_only: bool = True,
) -> ASGIApp:
    """Wrap the Dagster ASGI app in the session and auth layers."""
    dagster_app = create_app_from_workspace_process_context(
        context,
        config.path_prefix,
        live_data_poll_rate,
        lifespan=_lifespan,
    )
    gated = AuthGate(dagster_app, build_auth_router(config, authorizer), config)
    return SessionMiddleware(
        gated,
        secret_key=config.session_secret,
        session_cookie=config.session_cookie,
        max_age=config.session_max_age,
        same_site="lax",
        https_only=https_only,
    )


@click.command(
    name="dagster-authentication",
    help="Run the Dagster webserver with Microsoft Entra ID authentication.",
)
@click.option("--host", "-h", default="0.0.0.0", show_default=True, help="Host to bind.")
@click.option("--port", "-p", type=int, default=443, show_default=True, help="Port to bind.")
@click.option("--path-prefix", "-l", default="", help="Path prefix to host the UI under.")
@click.option("--read-only", is_flag=True, help="Disable all mutations, for every user.")
@click.option(
    "--authorizer",
    "authorizer_kind",
    type=click.Choice(AUTHORIZERS),
    default=lambda: os.environ.get("DAGSTER_AUTH_AUTHORIZER", "identity"),
    show_default="identity, or $DAGSTER_AUTH_AUTHORIZER",
    help="Where authorisation decisions come from.",
)
@click.option(
    "--env-prefix",
    default=DEFAULT_ENV_PREFIX,
    show_default=True,
    help="Prefix for this package's environment variables.",
)
@click.option("--live-data-poll-rate", type=int, default=2000, show_default=True)
@click.option("--db-statement-timeout", type=int, default=15000, show_default=True)
@click.option("--db-pool-recycle", type=int, default=3600, show_default=True)
@click.option("--db-pool-max-overflow", type=int, default=20, show_default=True)
@click.option("--uvicorn-log-level", default="warning", show_default=True)
@click.option("--dagster-log-level", default="INFO", show_default=True)
@click.option("--log-format", default="colored", show_default=True)
@click.option("--code-server-log-level", default="info", show_default=True)
@click.option(
    "--ssl-certfile",
    envvar="DAGSTER_AUTH_TLS_CERT",
    default=None,
    help="PEM certificate chain. Required unless --allow-insecure-http is passed.",
)
@click.option(
    "--ssl-keyfile",
    envvar="DAGSTER_AUTH_TLS_KEY",
    default=None,
    help="PEM private key, unencrypted.",
)
@click.option(
    "--allow-insecure-http",
    is_flag=True,
    help=(
        "Serve plain HTTP and drop the Secure flag from the session cookie. "
        "For local development only - Entra rejects non-localhost HTTP redirect URIs."
    ),
)
@click.version_option(package_name="dagster-authentication", prog_name="dagster-authentication")
@workspace_options
def main(
    host: str,
    port: int,
    path_prefix: str,
    read_only: bool,
    authorizer_kind: str,
    env_prefix: str,
    live_data_poll_rate: int,
    db_statement_timeout: int,
    db_pool_recycle: int,
    db_pool_max_overflow: int,
    uvicorn_log_level: str,
    dagster_log_level: str,
    log_format: str,
    code_server_log_level: str,
    ssl_certfile: str | None,
    ssl_keyfile: str | None,
    allow_insecure_http: bool,
    **other_opts: object,
) -> None:
    workspace_opts = WorkspaceOpts.extract_from_cli_options(other_opts)
    assert_no_remaining_opts(other_opts)

    configure_loggers(formatter=log_format, log_level=dagster_log_level.upper())

    # Dagster loads .env from the working directory too, but only once it builds
    # the instance - which happens well after the auth config is read below. So
    # load it here first, from the same place Dagster looks (cwd, no upward
    # search). override=False means a real environment variable always beats
    # the file, which is the precedence you want in production.
    env_file = Path.cwd() / ".env"
    if env_file.is_file():
        load_dotenv(env_file, override=False)
        logger.info("Loaded %s", env_file)

    if allow_insecure_http:
        logger.warning(
            "Serving plain HTTP with a non-Secure session cookie. Never do this off localhost."
        )
    elif not (ssl_certfile and ssl_keyfile):
        raise click.UsageError(
            "TLS is required: pass --ssl-certfile and --ssl-keyfile (or set "
            "DAGSTER_AUTH_TLS_CERT and DAGSTER_AUTH_TLS_KEY). Entra will not accept a "
            "plain-HTTP redirect URI, and the session cookie is issued Secure. Use "
            "--allow-insecure-http for local development."
        )

    for label, path in (("--ssl-certfile", ssl_certfile), ("--ssl-keyfile", ssl_keyfile)):
        if path and not os.path.isfile(path):
            raise click.UsageError(f"{label} does not exist: {path}")

    try:
        config = AuthConfig.from_env(path_prefix=path_prefix, env_prefix=env_prefix)
        authorizer = build_authorizer(authorizer_kind, env_prefix)
    except ConfigError as exc:
        raise click.UsageError(str(exc)) from None

    logger.info(
        "Entra sign-in enabled; authorisation via the %r authorizer; sessions last %dh",
        authorizer.name,
        config.session_max_age // 3600,
    )
    if read_only:
        logger.info("--read-only is set: Dagster will reject mutations from every user.")

    setup_interrupt_handlers()

    with get_possibly_temporary_instance_for_cli(cli_command="dagster-authentication", logger=logger) as (
        instance
    ):
        instance.optimize_for_webserver(
            db_statement_timeout, db_pool_recycle, db_pool_max_overflow
        )
        with WorkspaceProcessContext(
            instance,
            version=dagster_webserver_version,
            read_only=read_only,
            workspace_load_target=workspace_opts_to_load_target(workspace_opts),
            code_server_log_level=code_server_log_level,
        ) as context:
            app = build_app(
                context,
                config,
                authorizer,
                live_data_poll_rate=live_data_poll_rate,
                https_only=not allow_insecure_http,
            )
            scheme = "http" if allow_insecure_http else "https"
            logger.info(
                "Serving Dagster on %s://%s:%d%s in process %d",
                scheme,
                host,
                port,
                path_prefix,
                os.getpid(),
            )
            uvicorn.run(
                app,
                host=host,
                port=port,
                log_level=uvicorn_log_level,
                ssl_certfile=ssl_certfile,
                ssl_keyfile=ssl_keyfile,
            )


if __name__ == "__main__":
    main()
