"""Tests for crossfire.yaml discovery (CWD, package root, CROSSFIRE_CONFIG)."""

from pathlib import Path

import pytest

import proxy.config as config_mod


@pytest.fixture(autouse=True)
def reset_config_cache():
    """Isolate config loading between tests."""
    config_mod._config = None
    yield
    config_mod._config = None


def test_crossfire_config_env_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CROSSFIRE_CONFIG pointing at a file loads that YAML."""
    yml = tmp_path / "my.yaml"
    yml.write_text(
        "version: 1\ndashboard:\n  url: http://explicit-config:7777\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CROSSFIRE_CONFIG", str(yml))
    monkeypatch.delenv("CROSSFIRE_DASHBOARD_URL", raising=False)
    cfg = config_mod.load_config()
    assert (cfg.get("dashboard") or {}).get("url") == "http://explicit-config:7777"


def test_crossfire_config_env_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CROSSFIRE_CONFIG pointing at a directory loads crossfire.yaml inside it."""
    d = tmp_path / "cfg"
    d.mkdir()
    (d / "crossfire.yaml").write_text(
        "version: 1\ndashboard:\n  url: http://from-dir:8888\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CROSSFIRE_CONFIG", str(d))
    monkeypatch.delenv("CROSSFIRE_DASHBOARD_URL", raising=False)
    cfg = config_mod.load_config()
    assert (cfg.get("dashboard") or {}).get("url") == "http://from-dir:8888"


def test_dashboard_url_prefers_env_over_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CROSSFIRE_DASHBOARD_URL overrides file dashboard.url."""
    yml = tmp_path / "x.yaml"
    yml.write_text(
        "version: 1\ndashboard:\n  url: http://file:9999\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CROSSFIRE_CONFIG", str(yml))
    monkeypatch.setenv("CROSSFIRE_DASHBOARD_URL", "http://env-override:1111")
    assert config_mod.get_dashboard_url() == "http://env-override:1111"
