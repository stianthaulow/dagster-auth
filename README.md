# dagster-authentication

Microsoft Entra ID sign-in and role-based authorisation for the **self-hosted
Dagster webserver** — in-process, with no reverse proxy and no extra service.

Dagster OSS ships no authentication: anyone who can reach the port can launch
runs, terminate them and wipe assets. This package adds Entra sign-in and
enforces a role on every request — including the GraphQL subscription
WebSocket, which is the part a proxy cannot see into.

```
uvicorn (terminates TLS)
  └── SessionMiddleware        signed cookie, decoded for http AND websocket
        └── AuthGate           requires a session; enforces the role
              └── Dagster app  create_app_from_workspace_process_context()

sign-in:  Entra ID   ──▶ who you are
          Authorizer ──▶ what you may do
```

Nothing is monkey-patched. `create_app_from_workspace_process_context` returns a
plain Starlette app, so the auth layer is ordinary ASGI wrapping.

## Install

```bash
pip install dagster-authentication
```

For the identity-app authorizer, which needs a database driver:

```bash
pip install "dagster-authentication[identity]"
```

## Use

`dagster-authentication` is a drop-in replacement for `dagster-webserver`. It reuses
Dagster's own workspace options, so `-w` / `-f` / `-m` / `-a` / `-d`,
`--path-prefix`, `--read-only` and the `--db-*` pool settings all behave
identically:

```bash
dagster-authentication -w workspace.yaml -h 0.0.0.0 -p 443 \
    --ssl-certfile cert.pem --ssl-keyfile key.pem
```

There is no proxy, so **uvicorn terminates TLS**. Entra will not accept a
plain-HTTP redirect URI and the session cookie is issued `Secure`, so TLS is
required unless you pass `--allow-insecure-http` (localhost only).

The daemon is unchanged — it serves no HTTP, so there is nothing to
authenticate:

```bash
dagster-daemon run
```

> `dagster dev` **bypasses this package**. It spawns `python -m
> dagster_webserver` as a subprocess, so you get the stock unauthenticated
> webserver. Run `dagster-authentication` directly to exercise sign-in.

## Configure

Every variable is read once at startup and validated eagerly: a misconfigured
server fails to boot rather than coming up unauthenticated. A `.env` in the
working directory is loaded first (no upward search); a real environment
variable always wins over the file.

| Variable | Notes |
|---|---|
| `DAGSTER_AUTH_TENANT_ID` | Directory (tenant) ID |
| `DAGSTER_AUTH_CLIENT_ID` | Application (client) ID |
| `DAGSTER_AUTH_CLIENT_SECRET` | Client secret value |
| `DAGSTER_AUTH_REDIRECT_URI` | `https://<host>/auth/callback`; must match the registration exactly |
| `DAGSTER_AUTH_SESSION_SECRET` | ≥32 random chars. **Different per instance** — see below |
| `DAGSTER_AUTH_SESSION_COOKIE` | Optional, default `dagster_authentication_session` |
| `DAGSTER_AUTH_SESSION_MAX_AGE` | Optional, default `28800` (8h) |
| `DAGSTER_AUTH_TLS_CERT` / `_TLS_KEY` | Alternative to `--ssl-certfile` / `--ssl-keyfile` |
| `DAGSTER_AUTH_AUTHORIZER` | `identity` (default) or `allowlist` |

`--env-prefix` changes the `DAGSTER_AUTH` prefix if a project needs its own
namespace.

**Two servers on one hostname must use different `DAGSTER_AUTH_SESSION_SECRET`
values.** Cookies are scoped by host and ignore the port, so a shared secret
lets a session minted for one server validate on the other and inherit its
role. Give them distinct `DAGSTER_AUTH_SESSION_COOKIE` names too.

### Entra app registration

- **Supported account types**: *Accounts in this organizational directory only*
- **Redirect URI**: platform **Web**, `https://<host>/auth/callback`

The **Web** platform is not optional. This is a confidential client that
authenticates with a secret, and a redirect URI under *Mobile and desktop
applications* or *Single-page application* makes Entra treat the app as a
*public* client and reject the secret with
`AADSTS700025: Client is public...`. Also set **Authentication → Advanced
settings → Allow public client flows** to **No**.

The portal steers `localhost` URIs toward the desktop platform — don't let it.
`http://localhost` is valid under **Web** thanks to Entra's loopback exception.

**No groups claim is required.** Authorisation is the authorizer's job, not a
token claim, which also avoids Entra's ~200-group overage limit entirely.

## Roles

| Role | Can |
|---|---|
| `VIEWER` | Read everything. All GraphQL mutations blocked except `logTelemetry`. The three non-GraphQL write endpoints (`/report_asset_materialization/`, `/report_asset_check/`, `/report_asset_observation/`) are blocked. Mutations sent over the subscription WebSocket are blocked and the socket closed |
| `ADMIN` | Everything, as stock Dagster |

Unknown mutations require `ADMIN` — deny-by-default. A Dagster upgrade that adds
mutations will therefore 403 for viewers until they are added to
`VIEWER_MUTATIONS` in `rbac.py`; every denial is logged with the mutation name,
so the log says exactly what to add.

## Authorizers

Authorisation is pluggable. Both built-ins fail **closed**: if the store cannot
be consulted, sign-in returns 503 rather than admitting everyone who can
authenticate.

### `allowlist`

No extra dependencies. Matches the Entra object id, `preferred_username` or
`email`, case-insensitively.

```bash
DAGSTER_AUTH_AUTHORIZER=allowlist
DAGSTER_AUTH_ADMINS=ada@example.com,3f2504e0-4f89-11d3-9a0c-0305e82c3301
DAGSTER_AUTH_VIEWERS=grace@example.com
```

### `identity` (default)

Gates on a live grant in the Flowbyte identity app's
`dbo.application_user_access` — the same login gate its other apps use.

```bash
DAGSTER_AUTH_IDENTITY_APP_ID=DAGSTER_COMPANY
DAGSTER_AUTH_IDENTITY_VIEWER_APP_ID=          # optional read-only tier
IDENTITY_SERVER=sql.internal
IDENTITY_DATABASE=identity
IDENTITY_USER=dagster_reader                  # read-only login is enough
IDENTITY_PASSWORD=...
# IDENTITY_ODBC_DRIVER=ODBC Driver 17 for SQL Server
# IDENTITY_LOGIN_PROVIDER=MicrosoftOidc
# IDENTITY_TIMEOUT=10
```

The join key is the Entra **object id**, because the identity app deliberately
stores `oid` rather than the OIDC `sub` as the external login's `provider_key`.
That matters: `sub` is *pairwise*, so Entra issues a different value per app
registration and a webserver's `sub` would never match a row written by
identity. `oid` is the same value tenant-wide.

`application_user_access` has no role column, so the read-only tier is a second
application id rather than an attribute of the grant. Leave the viewer variable
unset and everyone with access is an admin.

### Your own

Implement the `Authorizer` protocol:

```python
from collections.abc import Mapping
from typing import Any

from dagster_authentication import AuthorizationUnavailable, Decision, Role


class TeamAuthorizer:
    name = "team"

    def decide(self, claims: Mapping[str, Any]) -> Decision:
        try:
            team = lookup_team(claims["oid"])
        except TimeoutError as exc:
            # Must raise, not deny: an unavailable store is not "no access".
            raise AuthorizationUnavailable(f"team service timed out: {exc}") from exc

        if team == "platform":
            return Decision.allow(Role.ADMIN)
        if team:
            return Decision.allow(Role.VIEWER)
        return Decision.deny(f"oid {claims['oid']} is in no team", "You have no access.")
```

`reason` goes to the service log and may name identifiers; `message` is shown to
the user. Then build the app yourself:

```python
from dagster_authentication import AuthConfig, build_app

app = build_app(context, AuthConfig.from_env(), TeamAuthorizer())
```

## Deploying as a Windows service

With NSSM, point the existing webserver service at the console script and keep
its workspace arguments:

```bat
nssm set dagster_webserver Application "F:\apps\.venv\Scripts\dagster-authentication.exe"
nssm set dagster_webserver AppDirectory "F:\apps\dagster"
nssm set dagster_webserver AppParameters "-w workspace.yaml -h 0.0.0.0 -p 443 --ssl-certfile F:\certs\cert.pem --ssl-keyfile F:\certs\key.pem"
nssm set dagster_webserver AppEnvironmentExtra "DAGSTER_AUTH_TENANT_ID=..." "DAGSTER_AUTH_CLIENT_ID=..." "DAGSTER_AUTH_CLIENT_SECRET=..." "DAGSTER_AUTH_REDIRECT_URI=https://host/auth/callback" "DAGSTER_AUTH_SESSION_SECRET=..."
```

Secrets belong in the service environment block, not in a file next to the code.

## Verify a deployment

The WebSocket and read-only checks are the ones people skip.

1. Unauthenticated navigation redirects to Entra.
2. Sign-in works and the UI loads.
3. **Open a run and confirm logs stream.** If the page renders but logs never
   arrive, the WebSocket upgrade is being dropped.
4. `POST /graphql` without a session does not return 200.
5. A viewer cannot launch a run; the log shows
   `denied GraphQL for role VIEWER: launchRun`.
6. `/auth/health` returns `ok` without a session, for uptime monitoring.

## Compatibility

Verified against **dagster 1.12.19**. The entrypoint imports from Dagster's
private modules, which carry no compatibility guarantee, so the dependency
range is deliberately narrow. After a Dagster upgrade, check these still resolve:

| Import | From |
|---|---|
| `create_app_from_workspace_process_context` | `dagster_webserver.app` |
| `WorkspaceProcessContext`, `IWorkspaceProcessContext` | `dagster._core.workspace.context` |
| `get_possibly_temporary_instance_for_cli`, `assert_no_remaining_opts` | `dagster._cli.utils` |
| `WorkspaceOpts`, `workspace_opts_to_load_target` | `dagster._cli.workspace.cli_target` |
| `workspace_options` | `dagster_shared.cli` |
| `configure_loggers` | `dagster._utils.log` |
| `setup_interrupt_handlers` | `dagster._utils.interrupts` |

A rename breaks startup loudly rather than silently disabling auth, which is
the failure mode you want. Also re-check `VIEWER_MUTATIONS` and
`WRITE_ROUTE_PREFIXES` in `rbac.py` against `DagsterWebserver.build_routes` —
new write endpoints outside GraphQL would otherwise not be gated for viewers.

## What this does not give you

Per-asset or per-job permissions. The split is read-only versus full control,
which is what can be enforced by classifying GraphQL operations. Anything finer
needs Dagster+.

Schedules and sensors launch runs through the **daemon**, not the webserver, so
roles have no effect on them. A viewer cannot click "Launch run" but every
schedule keeps firing.

## Develop

```bash
pip install -e ".[identity]" --group dev
pytest
```

The tests cover the security-critical logic — GraphQL classification, role
mapping, and that every failure path denies — and need neither Dagster nor a
database.

## Licence

Apache-2.0
