"""Tests that a .env in the working directory feeds the CLI's own options.

Click resolves environment-backed options before the command body runs, so the
file must be loaded before parsing. These run the real command and stop it at
authorizer construction, before any instance or server is started.

    pytest tests/test_cli_env.py
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from dagster_authentication import serve

AUTH_ENV = {
    "DAGSTER_AUTH_TENANT_ID": "tenant-guid",
    "DAGSTER_AUTH_CLIENT_ID": "client-guid",
    "DAGSTER_AUTH_CLIENT_SECRET": "a-secret",
    "DAGSTER_AUTH_REDIRECT_URI": "https://dagster.example.com/auth/callback",
    "DAGSTER_AUTH_SESSION_SECRET": "x" * 32,
}

CLI_KEYS = ["DAGSTER_AUTH_AUTHORIZER", "DAGSTER_AUTH_TLS_CERT", "DAGSTER_AUTH_TLS_KEY"]


class _Stop(Exception):
    pass


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty cwd, with every variable the tests touch unset and restored afterwards."""
    for key in [*AUTH_ENV, *CLI_KEYS]:
        # setenv first so monkeypatch records the key, and undoes what
        # load_dotenv writes, even when it was unset to begin with.
        monkeypatch.setenv(key, "")
        monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def authorizer_kinds(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Records the authorizer the CLI asks for, then stops it before startup."""
    kinds: list[str] = []

    def fake_build_authorizer(kind: str, env_prefix: str = "") -> None:
        kinds.append(kind)
        raise _Stop

    monkeypatch.setattr(serve, "build_authorizer", fake_build_authorizer)
    return kinds


def _write_env(directory: Path, values: dict[str, str]) -> None:
    lines = [f"{key}={value}" for key, value in {**AUTH_ENV, **values}.items()]
    (directory / ".env").write_text("\n".join(lines) + "\n")


def _tls_files(directory: Path) -> dict[str, str]:
    cert, key = directory / "cert.pem", directory / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    return {"DAGSTER_AUTH_TLS_CERT": str(cert), "DAGSTER_AUTH_TLS_KEY": str(key)}


def _invoke(*args: str):
    return CliRunner().invoke(serve.main, list(args))


def test_tls_paths_from_env_file(workdir: Path, authorizer_kinds: list[str]) -> None:
    _write_env(workdir, _tls_files(workdir))
    result = _invoke()
    assert isinstance(result.exception, _Stop), result.output
    assert "TLS is required" not in result.output


def test_authorizer_from_env_file(workdir: Path, authorizer_kinds: list[str]) -> None:
    _write_env(workdir, {"DAGSTER_AUTH_AUTHORIZER": "allowlist"})
    result = _invoke("--allow-insecure-http")
    assert isinstance(result.exception, _Stop), result.output
    assert authorizer_kinds == ["allowlist"]


def test_real_env_beats_env_file(
    workdir: Path, authorizer_kinds: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_env(workdir, {"DAGSTER_AUTH_AUTHORIZER": "allowlist"})
    monkeypatch.setenv("DAGSTER_AUTH_AUTHORIZER", "identity")
    _invoke("--allow-insecure-http")
    assert authorizer_kinds == ["identity"]


def test_cli_flag_beats_env_file(workdir: Path, authorizer_kinds: list[str]) -> None:
    _write_env(workdir, {"DAGSTER_AUTH_AUTHORIZER": "allowlist"})
    _invoke("--allow-insecure-http", "--authorizer", "identity")
    assert authorizer_kinds == ["identity"]


def test_without_env_file_tls_still_required(workdir: Path, authorizer_kinds: list[str]) -> None:
    result = _invoke()
    assert result.exit_code == 2
    assert "TLS is required" in result.output
    assert authorizer_kinds == []
