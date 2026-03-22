"""crossfire doctor — inspect MCP configs and Crossfire wiring."""

from __future__ import annotations

import json
import sys

from proxy.config import get_dashboard_url
from proxy.http_util import http_get_json
from proxy.installer import command_is_crossfire_proxy, iter_unique_config_files


def _is_proxied(server_config: dict) -> bool:
    cmd = server_config.get("command", "")
    args = server_config.get("args", [])
    return command_is_crossfire_proxy(cmd) or "crossfire" in str(args)


def _classify_server(server_name: str, server_config: dict) -> str:
    if _is_proxied(server_config):
        return "proxied"
    url = server_config.get("url")
    cmd = server_config.get("command")
    if url and not cmd:
        return "url_only"
    if cmd:
        return "stdio_raw"
    if url:
        return "url_plus_command"
    return "unknown"


def run_doctor() -> None:
    """Print MCP config locations, per-server status, and dashboard health."""
    base = get_dashboard_url().rstrip("/")
    sys.stderr.write("Crossfire doctor\n")
    sys.stderr.write("================\n\n")

    sys.stderr.write(f"Dashboard URL: {base}\n")
    health = http_get_json(f"{base}/health", quiet=True)
    if health:
        sys.stderr.write("  Dashboard: reachable (GET /health OK)\n")
    else:
        sys.stderr.write(
            "  Dashboard: not reachable (start with: crossfire dashboard)\n"
        )

    guardian = http_get_json(f"{base}/api/guardian", quiet=True)
    if guardian:
        sys.stderr.write(f"  Guardian mode: {guardian.get('mode', '?')}\n")
    else:
        sys.stderr.write("  Guardian: (unknown — dashboard API unreachable)\n")

    sys.stderr.write("\nMCP config files (known locations)\n")
    sys.stderr.write("-----------------------------------\n")

    for label, config_path in iter_unique_config_files():
        sys.stderr.write(f"\n[{label}]\n  Path: {config_path}\n")
        if not config_path.exists():
            sys.stderr.write("  Status: (file not found)\n")
            continue

        sys.stderr.write("  Status: found\n")
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            sys.stderr.write(f"  Error: could not parse JSON — {exc}\n")
            continue

        servers = data.get("mcpServers", {})
        if not servers:
            sys.stderr.write("  Servers: (none)\n")
            continue

        for name, cfg in servers.items():
            kind = _classify_server(name, cfg)
            if kind == "proxied":
                line = "    proxied (via Crossfire)"
            elif kind == "url_only":
                line = "    URL-only — Crossfire stdio proxy does NOT sit in this path (use HTTP MCP support / manual review)"
            elif kind == "stdio_raw":
                line = "    stdio (command) — not proxied yet; run: crossfire install"
            elif kind == "url_plus_command":
                line = "    mixed url+command — review manually"
            else:
                line = f"    unknown shape: {cfg!r}"
            sys.stderr.write(f"  • {name}: {line}\n")

    sys.stderr.write("\n")
    sys.stderr.write("Notes\n")
    sys.stderr.write("-----\n")
    sys.stderr.write(
        "- Crossfire only inspects traffic for MCP servers launched through "
        "`crossfire-proxy` (stdio JSON-RPC).\n"
    )
    sys.stderr.write(
        "- Remote URL-based MCP (no local process) is not wrapped by the same mechanism.\n"
    )
    sys.stderr.write(
        "- Run `crossfire install` from a directory whose project `.cursor` / `.vscode` MCP file you use, "
        "or rely on user-level configs (~/.cursor/mcp.json, Windsurf/Antigravity paths above, etc.).\n"
    )
