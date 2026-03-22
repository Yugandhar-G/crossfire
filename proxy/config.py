"""Crossfire config loader -- .crossfire.yaml with schema validation."""

import os
import sys
from pathlib import Path

import yaml


DEFAULT_CONFIG = {
    "version": 1,
    "mode": "monitor",
    "dashboard": {
        "url": "http://localhost:9999",
    },
    "rules": {
        "sensitive_paths": {
            "enabled": True,
            "severity": "critical",
            "allow": [],
            "block": [
                "~/.ssh/*",
                "~/.aws/*",
                "**/.env",
                "**/.env.*",
                "**/credentials*",
                "**/private_key*",
                "**/*.pem",
                "**/*.key",
            ],
        },
        "shell_injection": {
            "enabled": True,
            "severity": "critical",
            "allowed_commands": [],
            "blocked_patterns": [
                "curl *",
                "wget *",
                "nc *",
                "| bash",
                "| sh",
                "> /dev/tcp",
                "base64",
                "rm -rf",
            ],
        },
        "typosquat": {
            "enabled": True,
            "known_servers": [
                "filesystem",
                "github",
                "gitlab",
                "slack",
                "postgres",
                "mysql",
                "redis",
                "mongodb",
                "memory",
                "brave-search",
                "puppeteer",
                "docker",
            ],
            "max_distance": 2,
        },
        "rug_pull": {"enabled": True, "severity": "critical"},
        "exfiltration": {
            "enabled": True,
            "max_payload_bytes": 500,
            "monitored_tools": [
                "*telemetry*",
                "*report*",
                "*analytics*",
                "*send*",
                "*track*",
            ],
        },
        "prompt_injection": {"enabled": True, "max_description_length": 2000},
        "memory_poisoning": {"enabled": True},
        "prompt_relay": {"enabled": True},
        "privilege_escalation": {"enabled": True},
        "unknown_tool": {"enabled": True},
        "schema_poisoning": {"enabled": True},
        "path_traversal": {"enabled": True},
        "token_passthrough": {"enabled": True},
        "sql_injection": {"enabled": True},
        "resource_poisoning": {"enabled": True},
        "oauth_deputy": {"enabled": True},
        "config_poisoning": {"enabled": True},
        "session_flaws": {"enabled": True},
        "cross_tenant": {"enabled": True},
        "neighborjack": {"enabled": True},
        "gemini_analysis": {
            "enabled": True,
            "model": "gemini-2.5-flash",
            "confidence_threshold": 0.7,
        },
    },
    "mcp_http_proxy": {
        "tool_hiding": True,
        "default_port": 8888,
    },
    "servers": {"trusted": [], "untrusted": []},
    "a2a": {"enabled": True, "listen_port": 9998, "upstream_agents": []},
    "policy": {
        "default_action": "allow",
        "rules": [],
        "blocked_tools": {},
        "allowed_tools": {},
    },
    "audit": {
        "enabled": True,
        "path": "./crossfire-audit.jsonl",
        "max_size_mb": 100,
    },
    "hmac": {"secret": ""},
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base recursively. Override values win."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _package_root() -> Path:
    """Directory that contains the `proxy` package (repo root or site-packages parent)."""
    return Path(__file__).resolve().parent.parent


def _find_config_file(cwd: Path | None = None) -> Path | None:
    """Search for config file in standard locations.

    Order: ``CROSSFIRE_CONFIG``, cwd, package/repo root (so MCP child processes
    with a different cwd still load the repo's ``crossfire.yaml``), then home.
    """
    explicit = os.environ.get("CROSSFIRE_CONFIG", "").strip()
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if path.is_file():
            return path
        if path.is_dir():
            for name in ("crossfire.yaml", ".crossfire.yaml"):
                p = path / name
                if p.is_file():
                    return p

    base = cwd or Path.cwd()
    pkg = _package_root()
    candidates = [
        base / "crossfire.yaml",
        base / ".crossfire.yaml",
        pkg / "crossfire.yaml",
        pkg / ".crossfire.yaml",
        Path.home() / ".crossfire.yaml",
    ]
    for path in candidates:
        if path.exists():
            return path
    return None


def load_config() -> dict:
    """Load and merge config from file + defaults."""
    config = DEFAULT_CONFIG.copy()

    config_path = _find_config_file()
    if config_path:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f) or {}
            config = _deep_merge(config, user_config)
            sys.stderr.write(f"[crossfire] Config loaded from {config_path}\n")
        except Exception as exc:
            sys.stderr.write(f"[crossfire] Config error ({config_path}): {exc}\n")
    else:
        sys.stderr.write("[crossfire] No config file found, using defaults\n")

    return config


_config: dict | None = None


def get_config() -> dict:
    """Get the current config, loading on first access."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config() -> dict:
    """Force reload config from disk."""
    global _config
    _config = load_config()
    try:
        from proxy.detectors import rules as rules_mod

        rules_mod._SHELL_CACHE.clear()
    except Exception:
        pass
    return _config


def get_dashboard_url() -> str:
    """Base URL for the Crossfire dashboard API (events, guardian)."""
    cfg = get_config()
    return (
        os.environ.get("CROSSFIRE_DASHBOARD_URL")
        or (cfg.get("dashboard") or {}).get("url")
        or "http://localhost:9999"
    )
