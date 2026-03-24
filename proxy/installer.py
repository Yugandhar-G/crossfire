"""Crossfire installer -- auto-detect and rewrite MCP configs."""

import json
import os
import shutil
import sys
from pathlib import Path


def _windows_paths() -> dict[str, Path]:
    appdata = os.environ.get("APPDATA")
    paths: dict[str, Path] = {}
    if appdata:
        paths["claude_desktop_windows"] = (
            Path(appdata) / "Claude" / "claude_desktop_config.json"
        )
    return paths


def _all_config_paths() -> dict[str, Path]:
    """Known MCP config locations (macOS/Linux/Windows via Path.home()).

    - Cursor / VS Code: ``mcp.json`` (user or project cwd).
    - Windsurf (Codeium): ``~/.codeium/windsurf/mcp_config.json``.
    - Google Antigravity: ``~/.gemini/antigravity/mcp_config.json``.
    - Claude Desktop: OS-specific ``claude_desktop_config.json``.
    All use a top-level ``mcpServers`` object where present.
    """
    home = Path.home()
    cwd = Path.cwd()
    paths: dict[str, Path] = {
        "cursor_user": home / ".cursor" / "mcp.json",
        "cursor_project": cwd / ".cursor" / "mcp.json",
        "vscode_user": home / ".vscode" / "mcp.json",
        "vscode_project": cwd / ".vscode" / "mcp.json",
        "windsurf_user": home / ".codeium" / "windsurf" / "mcp_config.json",
        "antigravity_user": home / ".gemini" / "antigravity" / "mcp_config.json",
        "claude_desktop_mac": home
        / "Library"
        / "Application Support"
        / "Claude"
        / "claude_desktop_config.json",
        "claude_desktop_linux": home
        / ".config"
        / "Claude"
        / "claude_desktop_config.json",
    }
    paths.update(_windows_paths())
    return paths


def iter_unique_config_files() -> list[tuple[str, Path]]:
    """Label + path, de-duplicated by resolved path (same file may appear as cursor_user + cursor_project)."""
    seen: set[str] = set()
    out: list[tuple[str, Path]] = []
    for name, path in CONFIG_PATHS.items():
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append((name, path))
    return out


CONFIG_PATHS = _all_config_paths()

PROXY_COMMAND = "crossfire-proxy"


def server_entry_to_argv(server_config: dict) -> list[str] | None:
    """Build argv to spawn the real MCP server (unwrap Crossfire proxy if present).

    Returns ``None`` for URL-only servers (no stdio ``command``).
    """
    if server_config.get("url") and not server_config.get("command"):
        return None
    cmd = server_config.get("command", "")
    args = server_config.get("args", [])
    if not cmd:
        return None
    if command_is_crossfire_proxy(cmd):
        if "_crossfire_original_command" in server_config:
            oc = server_config["_crossfire_original_command"]
            oa = server_config.get("_crossfire_original_args") or []
            return [str(oc)] + [str(a) for a in oa]
        try:
            idx = args.index("--")
        except ValueError:
            return None
        rest = args[idx + 1 :]
        if not rest:
            return None
        return [str(rest[0])] + [str(a) for a in rest[1:]]
    return [str(cmd)] + [str(a) for a in args]


def _server_entry_env(entry: dict) -> dict[str, str] | None:
    """Extract the effective env block (prefer original if Crossfire-wrapped)."""
    env = entry.get("_crossfire_original_env") or entry.get("env")
    if isinstance(env, dict):
        return {str(k): str(v) for k, v in env.items()}
    return None


def find_server_command(server_name: str) -> tuple[list[str], str] | None:
    """Look up ``server_name`` in MCP config files.

    Returns ``(argv, config_path)`` for the underlying stdio server, or ``None``.
    """
    for _label, config_path in iter_unique_config_files():
        if not config_path.exists():
            continue
        try:
            raw = config_path.read_text(encoding="utf-8")
            if not raw.strip():
                continue
            config = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(config, dict):
            continue
        servers = config.get("mcpServers", {})
        if server_name not in servers or not isinstance(servers[server_name], dict):
            continue
        argv = server_entry_to_argv(servers[server_name])
        if argv:
            return (argv, str(config_path))
    return None


def find_server_command_with_env(
    server_name: str,
) -> tuple[list[str], dict[str, str] | None, str] | None:
    """Like ``find_server_command`` but also returns the ``env`` block.

    Returns ``(argv, env_dict_or_None, config_path)`` or ``None``.
    """
    for _label, config_path in iter_unique_config_files():
        if not config_path.exists():
            continue
        try:
            raw = config_path.read_text(encoding="utf-8")
            if not raw.strip():
                continue
            config = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(config, dict):
            continue
        servers = config.get("mcpServers", {})
        if server_name not in servers or not isinstance(servers[server_name], dict):
            continue
        entry = servers[server_name]
        argv = server_entry_to_argv(entry)
        if argv:
            return (argv, _server_entry_env(entry), str(config_path))
    return None


def list_configured_stdio_servers() -> list[
    tuple[str, list[str], dict[str, str] | None, str]
]:
    """All stdio servers: ``(name, argv, env, config_path)`` (dedupe by name, first wins)."""
    seen: set[str] = set()
    out: list[tuple[str, list[str], dict[str, str] | None, str]] = []
    for _label, config_path in iter_unique_config_files():
        if not config_path.exists():
            continue
        try:
            raw = config_path.read_text(encoding="utf-8")
            if not raw.strip():
                continue
            config = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(config, dict):
            continue
        servers = config.get("mcpServers", {})
        if not isinstance(servers, dict):
            continue
        for name, entry in servers.items():
            if name in seen:
                continue
            if not isinstance(entry, dict):
                continue
            argv = server_entry_to_argv(entry)
            if not argv:
                continue
            seen.add(name)
            out.append((name, argv, _server_entry_env(entry), str(config_path)))
    return out


def command_is_crossfire_proxy(cmd: str) -> bool:
    """True if ``cmd`` is the Crossfire MCP proxy (bare name or absolute path to the shim)."""
    if not cmd or not isinstance(cmd, str):
        return False
    try:
        base = Path(cmd).name
    except OSError:
        return False
    if os.name == "nt" and base.lower().endswith(".exe"):
        base = base[:-4]
    if base == PROXY_COMMAND:
        return True
    if os.name == "nt" and base.lower() == f"{PROXY_COMMAND}.cmd":
        return True
    return False


def proxy_path_next_to_interpreter() -> str | None:
    """Absolute path to the pip-installed ``crossfire-proxy`` next to ``sys.executable`` (preferred for IDEs)."""
    exe_dir = Path(sys.executable).resolve().parent
    name = "crossfire-proxy.exe" if os.name == "nt" else "crossfire-proxy"
    candidate = exe_dir / name
    if candidate.is_file():
        return str(candidate)
    return None


def resolve_proxy_command(quiet: bool = False) -> str:
    """Return absolute path to ``crossfire-proxy`` when available (IDEs often have a minimal ``PATH``).

    Prefer the console script next to the current Python (same venv as ``pip install`` / ``crossfire``).
    Then ``shutil.which``. Falls back to the bare name ``crossfire-proxy`` with a warning unless ``quiet``.
    """
    pip_local = proxy_path_next_to_interpreter()
    if pip_local:
        return pip_local
    resolved = shutil.which(PROXY_COMMAND)
    if resolved:
        return resolved
    if not quiet:
        sys.stderr.write(
            "[crossfire] WARNING: 'crossfire-proxy' was not found next to this Python or on PATH.\n"
            "          Install from a git clone:  pip install -e .  (see README)\n"
            "          Then re-run:  crossfire install\n"
            "          Optional (Node): npm link in repo root, or see README for npm prefix / EACCES.\n"
            "          Without a resolvable proxy, Cursor may fail to start MCP servers.\n"
        )
    return PROXY_COMMAND


def install_proxy(dry_run: bool = False, quiet: bool = False) -> tuple[int, int]:
    """Rewrite MCP configs to route stdio servers through Crossfire.

    Returns ``(config_files_found, total_servers_proxied)``.
    ``config_files_found`` counts MCP config files that were valid JSON and processed.
    ``total_servers_proxied`` counts stdio servers rewritten (or that would be in dry-run).
    """
    config_files_found = 0
    servers_proxied = 0
    files_existed = 0
    proxy_cmd = resolve_proxy_command(quiet=quiet)
    for name, config_path in iter_unique_config_files():
        if not config_path.exists():
            continue

        files_existed += 1
        if not quiet:
            sys.stderr.write(f"Found config [{name}]: {config_path}\n")

        config_text = config_path.read_text(encoding="utf-8")
        if not config_text.strip():
            if not quiet:
                sys.stderr.write(
                    f"  Skipping empty file — add valid JSON or remove: {config_path}\n"
                )
            continue
        try:
            config = json.loads(config_text)
        except json.JSONDecodeError as e:
            if not quiet:
                sys.stderr.write(f"  Invalid JSON ({e!s}) — skipping {config_path}\n")
            continue
        if not isinstance(config, dict):
            if not quiet:
                sys.stderr.write(
                    f"  Expected a JSON object at top level — skipping {config_path}\n"
                )
            continue

        config_files_found += 1

        backup_path = config_path.with_suffix(".json.crossfire-backup")
        if not backup_path.exists():
            if not dry_run:
                shutil.copy2(config_path, backup_path)
                if not quiet:
                    sys.stderr.write(f"  Backed up to: {backup_path}\n")
            elif not quiet:
                sys.stderr.write(f"  [dry-run] would back up to: {backup_path}\n")

        servers = config.get("mcpServers", {})
        modified = 0

        for server_name, server_config in servers.items():
            if server_config.get("url") and not server_config.get("command"):
                if not quiet:
                    sys.stderr.write(
                        f"  {server_name}: URL-based MCP (skipped — use stdio `command` servers for Crossfire proxy)\n"
                    )
                continue

            original_command = server_config.get("command", "")
            original_args = server_config.get("args", [])

            if command_is_crossfire_proxy(original_command) or "crossfire" in str(
                original_args
            ):
                if not quiet:
                    sys.stderr.write(f"  {server_name}: already proxied, skipping\n")
                continue

            server_config["_crossfire_original_command"] = original_command
            server_config["_crossfire_original_args"] = original_args
            if "env" in server_config:
                server_config["_crossfire_original_env"] = server_config["env"]
            server_config["command"] = proxy_cmd
            server_config["args"] = [
                "--server-name",
                server_name,
                "--",
                original_command,
                *original_args,
            ]
            modified += 1
            if not quiet:
                sys.stderr.write(
                    f"  {server_name}: {'[dry-run] would proxy' if dry_run else 'proxied'}\n"
                )

        if modified > 0 and not dry_run:
            config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

        servers_proxied += modified

        if not quiet:
            sys.stderr.write(
                f"  {modified} server(s) "
                f"{'would be ' if dry_run else ''}routed through Crossfire\n\n"
            )

    if files_existed == 0:
        if not quiet:
            sys.stderr.write("No MCP configs found. Supported locations:\n")
            for name, path in iter_unique_config_files():
                sys.stderr.write(f"  {name}: {path}\n")
            sys.stderr.write(
                "\nMake sure at least one IDE has an MCP config (Cursor, VS Code, Windsurf, Antigravity, or Claude Desktop).\n"
            )
        return (0, 0)

    if config_files_found == 0 and not quiet:
        sys.stderr.write(
            "[crossfire] No valid MCP config to update (files were empty or invalid JSON).\n"
        )

    if not quiet:
        if dry_run:
            sys.stderr.write("[dry-run] No config files were modified.\n")
        else:
            sys.stderr.write("Done! Restart your IDE for changes to take effect.\n")
        sys.stderr.write(
            "Run 'crossfire dashboard' to open the monitoring dashboard.\n"
        )

    return (config_files_found, servers_proxied)


def uninstall_proxy(quiet: bool = False) -> int:
    """Restore MCP configs from ``*.json.crossfire-backup``. Returns number of configs restored."""
    restored = 0
    for name, config_path in iter_unique_config_files():
        backup_path = config_path.with_suffix(".json.crossfire-backup")
        if not backup_path.exists():
            continue

        shutil.copy2(backup_path, config_path)
        if not quiet:
            sys.stderr.write(f"Restored: {config_path}\n")
        restored += 1

    if restored == 0:
        if not quiet:
            sys.stderr.write("No backups found. Nothing to restore.\n")
    elif not quiet:
        sys.stderr.write(f"\nRestored {restored} config(s). Restart your IDE.\n")

    return restored
