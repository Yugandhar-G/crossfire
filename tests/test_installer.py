"""Tests for MCP installer helpers."""

import sys

import pytest

from proxy.installer import (
    PROXY_COMMAND,
    command_is_crossfire_proxy,
    install_proxy,
    iter_unique_config_files,
    resolve_proxy_command,
)


def test_proxy_command_constant() -> None:
    assert PROXY_COMMAND == "crossfire-proxy"


def test_command_is_crossfire_proxy_bare_and_path() -> None:
    assert command_is_crossfire_proxy("crossfire-proxy") is True
    assert command_is_crossfire_proxy("/opt/homebrew/bin/crossfire-proxy") is True
    assert command_is_crossfire_proxy("/usr/local/bin/figma-developer-mcp") is False
    assert command_is_crossfire_proxy("") is False


def test_resolve_proxy_command_prefers_interpreter_adjacent(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    fake_py = bin_dir / "python3"
    fake_py.write_text("")
    fake_py.chmod(0o755)
    proxy_bin = bin_dir / "crossfire-proxy"
    proxy_bin.write_text("#!/bin/sh\necho\n")
    proxy_bin.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(fake_py))
    assert resolve_proxy_command(quiet=True) == str(proxy_bin)


def test_install_proxy_skips_empty_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from proxy import installer as installer_mod

    p = tmp_path / "mcp.json"
    p.write_text("")
    monkeypatch.setattr(
        installer_mod,
        "iter_unique_config_files",
        lambda: [("test", p)],
    )
    assert install_proxy(dry_run=True, quiet=True) == (0, 0)


def test_install_proxy_skips_invalid_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from proxy import installer as installer_mod

    p = tmp_path / "mcp.json"
    p.write_text("{ not json")
    monkeypatch.setattr(
        installer_mod,
        "iter_unique_config_files",
        lambda: [("test", p)],
    )
    assert install_proxy(dry_run=True, quiet=True) == (0, 0)


def test_iter_unique_config_files_no_duplicate_resolved_paths() -> None:
    paths = [p for _, p in iter_unique_config_files()]
    resolved = []
    for p in paths:
        try:
            resolved.append(str(p.resolve()))
        except OSError:
            resolved.append(str(p))
    assert len(resolved) == len(set(resolved))
