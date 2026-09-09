"""Entra ID (Azure AD) OpenID Connect sign-in, via MSAL.

MSAL owns the parts of the authorisation-code flow that are easy to get subtly
wrong - the state parameter, the nonce, and the PKCE verifier - so this module
only persists the flow between the two requests and maps claims onto a session.

Entra proves *who* the user is. What they may do is decided by the configured
:class:`~dagster_authentication.authorizer.Authorizer`.

The route handlers are deliberately synchronous. MSAL performs blocking network
calls (OIDC discovery, the token exchange) and an authorizer may hit a
database; Starlette runs non-async endpoints in a threadpool, so declaring them
``async def`` would stall the event loop for every other request during a
sign-in.
"""

from __future__ import annotations

import logging

import msal
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route, Router

from dagster_authentication.authorizer import AuthorizationUnavailable, Authorizer
from dagster_authentication.config import AuthConfig

logger = logging.getLogger("dagster_authentication")

# No groups claim is needed on the app registration: authorisation is the
# authorizer's job, not a token claim. MSAL adds the reserved
# openid/profile/offline_access scopes itself.
SCOPES: list[str] = []

_SIGNED_OUT_PAGE = """<!doctype html>
<title>Signed out</title>
<style>
  body {{ font: 15px/1.6 system-ui, sans-serif; margin: 15vh auto; max-width: 28rem;
         padding: 0 1.5rem; color: #1a1a1a; }}
  a {{ color: #0b6bcb; }}
</style>
<h1>Signed out</h1>
<p>Your session has ended.</p>
<p><a href="{login}">Sign in again</a></p>
<p style="color:#666;font-size:.9em">You are still signed in to Microsoft. Sign
out of your Microsoft account too if you are on a shared machine.</p>
"""


def build_auth_router(config: AuthConfig, authorizer: Authorizer) -> Router:
    """The /auth routes: the only unauthenticated surface of the server."""
    # Built once. Constructing a ConfidentialClientApplication performs OIDC
    # discovery, so doing it per request would add a round trip to every login.
    client = msal.ConfidentialClientApplication(
        config.client_id,
        authority=config.authority,
        client_credential=config.client_secret,
    )

    prefix = config.path_prefix
    login_path = f"{prefix}/auth/login"
    home_path = prefix or "/"

    def login(request: Request) -> Response:
        flow = client.initiate_auth_code_flow(SCOPES, redirect_uri=config.redirect_uri)
        request.session.clear()
        request.session["flow"] = flow
        return RedirectResponse(url=flow["auth_uri"], status_code=302)

    def callback(request: Request) -> Response:
        flow = request.session.pop("flow", None)
        if not isinstance(flow, dict):
            # No flow in the session: a bookmarked callback, a replay, or the
            # cookie expired mid-sign-in. Start over rather than erroring.
            return RedirectResponse(url=login_path, status_code=302)

        try:
            result = client.acquire_token_by_auth_code_flow(flow, dict(request.query_params))
        except ValueError as exc:
            # MSAL raises this on a state mismatch or a replayed callback.
            logger.warning("rejected auth callback: %s", exc)
            return PlainTextResponse("Sign-in could not be verified. Please try again.", 400)

        if "error" in result:
            detail = result.get("error_description") or result["error"]
            logger.warning("Entra returned an error: %s", detail)
            return PlainTextResponse(f"Sign-in failed: {detail}", 403)

        claims = result.get("id_token_claims") or {}
        user = claims.get("preferred_username")

        if claims.get("tid") != config.tenant_id:
            logger.warning("rejected token from tenant %s", claims.get("tid"))
            return PlainTextResponse("This account is from an unrecognised tenant.", 403)

        try:
            decision = authorizer.decide(claims)
        except AuthorizationUnavailable as exc:
            # Fail closed: an unreachable authorisation store must not mean
            # "allow everyone who can authenticate".
            logger.error("denied %s: %s", user, exc)
            return PlainTextResponse(
                "Your access could not be verified because the authorisation service is "
                "unavailable. Please try again shortly.",
                503,
            )

        if not decision.allowed:
            logger.warning("denied %s via %s: %s", user, authorizer.name, decision.reason)
            return PlainTextResponse(decision.message, 403)

        assert decision.role is not None  # narrowed by decision.allowed
        request.session.clear()
        request.session.update(
            {
                "role": int(decision.role),
                "sub": claims.get("sub"),
                "oid": claims.get("oid"),
                "email": user,
                "name": claims.get("name"),
            }
        )
        logger.info("signed in %s as %s", user, decision.role.name)
        return RedirectResponse(url=home_path, status_code=302)

    def logout(request: Request) -> Response:
        user = request.session.get("email")
        request.session.clear()
        if user:
            logger.info("signed out %s", user)
        return HTMLResponse(_SIGNED_OUT_PAGE.format(login=login_path))

    def health(_: Request) -> Response:
        # Public by design so an uptime monitor can poll without a session.
        # Returns nothing about versions or workspace contents.
        return PlainTextResponse("ok")

    return Router(
        routes=[
            Route(f"{prefix}/auth/login", login, methods=["GET"]),
            Route(f"{prefix}/auth/callback", callback, methods=["GET"]),
            Route(f"{prefix}/auth/logout", logout, methods=["GET"]),
            Route(f"{prefix}/auth/health", health, methods=["GET"]),
        ]
    )
