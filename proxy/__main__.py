"""Crossfire CLI entry point."""

import argparse
import json
import subprocess
import sys
import time
import uuid
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from proxy.http_util import http_get_json, http_post_json


def _run_start(host: str, port: int, no_open: bool) -> None:
    """Install proxy on MCP configs, run dashboard, open browser; restore configs on exit."""
    from proxy.installer import install_proxy, uninstall_proxy

    root = Path(__file__).resolve().parent.parent
    n_files, n_servers = install_proxy(dry_run=False, quiet=True)
    sys.stderr.write(
        f"[crossfire] Found {n_files} MCP config(s), proxied {n_servers} server(s)\n"
    )

    _dist = root / "dashboard" / "dist"
    if not _dist.is_dir() or not any(_dist.iterdir()):
        sys.stderr.write(
            "[crossfire] dashboard/dist is missing or empty — the web UI may not load.\n"
            "          Build with: cd dashboard && npm install && npm run build\n"
        )

    proc: subprocess.Popen | None = None
    try:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "server.main:app",
                "--host",
                host,
                "--port",
                str(port),
            ],
            cwd=str(root),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1.2)
        url = f"http://127.0.0.1:{port}"
        if not no_open:
            try:
                webbrowser.open(url)
            except OSError:
                pass
        sys.stderr.write(f"[crossfire] Dashboard running on {url}\n")
        sys.stderr.write(
            "[crossfire] Restart your IDE (Cursor, VS Code, etc.) for Crossfire to intercept MCP traffic.\n"
        )
        sys.stderr.write(
            "[crossfire] Press Ctrl+C to stop the dashboard and restore original MCP configs.\n"
        )
        try:
            if proc is not None:
                proc.wait()
        except KeyboardInterrupt:
            pass
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        restored = uninstall_proxy(quiet=True)
        if restored > 0:
            sys.stderr.write(
                f"[crossfire] Restored {restored} MCP config(s). Restart your IDE to use unproxied servers.\n"
            )
        else:
            sys.stderr.write("[crossfire] Stopped.\n")


def _dashboard_api_is_live(base: str) -> tuple[bool, str]:
    """Return (True, detail) if the Crossfire dashboard API responds, else (False, reason)."""
    h = http_get_json(f"{base}/health", quiet=True)
    if isinstance(h, dict) and h.get("status") == "ok":
        return True, "GET /health"
    g = http_get_json(f"{base}/api/guardian", quiet=True)
    if isinstance(g, dict) and "mode" in g:
        return True, "GET /api/guardian"
    return False, "no Crossfire API on this URL (wrong process on port?)"


def main():
    parser = argparse.ArgumentParser(
        prog="crossfire",
        description="MCP & A2A Security Proxy with real-time threat detection",
    )
    subparsers = parser.add_subparsers(dest="command", required=False)

    start_p = subparsers.add_parser(
        "start",
        help="One-shot: install proxy on MCP configs, run dashboard, open browser (Ctrl+C restores configs)",
    )
    start_p.add_argument(
        "--host", default="0.0.0.0", help="Dashboard bind host (default 0.0.0.0)"
    )
    start_p.add_argument(
        "--port", type=int, default=9999, help="Dashboard port (default 9999)"
    )
    start_p.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open the dashboard in a browser",
    )

    install_p = subparsers.add_parser(
        "install", help="Install proxy on all detected MCP configs"
    )
    install_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Show changes without writing config files",
    )

    subparsers.add_parser("uninstall", help="Restore original MCP configs")

    dash_p = subparsers.add_parser("dashboard", help="Start the monitoring dashboard")
    dash_p.add_argument("--host", default="0.0.0.0", help="Bind host (default 0.0.0.0)")
    dash_p.add_argument("--port", type=int, default=9999, help="Port (default 9999)")

    subparsers.add_parser("status", help="Show proxy / dashboard status")
    ping_p = subparsers.add_parser(
        "ping",
        help="POST a sample event to the dashboard (verify UI/WebSocket without MCP)",
    )
    ping_p.add_argument(
        "--threat",
        action="store_true",
        help="Also POST a second sample event with a critical threat (demo counters / detail panel)",
    )
    subparsers.add_parser(
        "doctor",
        help="Inspect MCP config files, proxied vs raw servers, and dashboard reachability",
    )
    subparsers.add_parser(
        "demo", help="Run demo: dashboard + instructions for poisoned MCP server"
    )

    scan_p = subparsers.add_parser(
        "scan",
        help="Actively scan an MCP server (tools/list + synthetic probes) without the IDE",
    )
    scan_p.add_argument(
        "--server",
        dest="scan_server_name",
        default=None,
        metavar="NAME",
        help="MCP server name from mcp.json (looks up command in IDE configs)",
    )
    scan_p.add_argument(
        "--cmd",
        dest="scan_cmd",
        default=None,
        help="Command to spawn the server (quoted), e.g. 'python3 demo/poisoned_weather.py'",
    )
    scan_p.add_argument(
        "--all",
        dest="scan_all",
        action="store_true",
        help="Scan every stdio MCP server listed in detected MCP configs",
    )
    scan_p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="Print each ScanReport as JSON",
    )

    proxy_parser = subparsers.add_parser("proxy", help="Run as MCP proxy (internal)")
    proxy_parser.add_argument("--server-name", required=True)
    proxy_parser.add_argument(
        "--source",
        default="ide",
        choices=["ide", "sdk", "http-proxy", "scan"],
        help="Traffic source label (default: ide)",
    )
    proxy_parser.add_argument("server_command", nargs=argparse.REMAINDER)

    mcp_proxy_p = subparsers.add_parser(
        "mcp-proxy",
        help="Run HTTP reverse proxy for Streamable HTTP / SSE MCP servers",
    )
    mcp_proxy_p.add_argument(
        "--upstream",
        required=True,
        help="Upstream MCP server URL (e.g. https://remote-mcp.example.com)",
    )
    mcp_proxy_p.add_argument(
        "--port", type=int, default=8888, help="Proxy listen port (default 8888)"
    )
    mcp_proxy_p.add_argument(
        "--server-name",
        default="remote-mcp",
        help="Server name for events (default: remote-mcp)",
    )

    args = parser.parse_args()

    if args.command is None:
        args.command = "start"
        args.host = "0.0.0.0"
        args.port = 9999
        args.no_open = False

    if args.command == "start":
        _run_start(host=args.host, port=args.port, no_open=args.no_open)
    elif args.command == "install":
        from proxy.installer import install_proxy

        install_proxy(dry_run=args.dry_run)
    elif args.command == "uninstall":
        from proxy.installer import uninstall_proxy

        uninstall_proxy()
    elif args.command == "dashboard":
        import uvicorn

        _root = Path(__file__).resolve().parent.parent
        _dist = _root / "dashboard" / "dist"
        if not _dist.is_dir() or not any(_dist.iterdir()):
            sys.stderr.write(
                "[crossfire] dashboard/dist is missing or empty — the web UI will not load.\n"
                "          From the repo root run:  cd dashboard && npm install && npm run build\n"
            )
        uvicorn.run("server.main:app", host=args.host, port=args.port, reload=False)
    elif args.command == "proxy":
        import asyncio

        from proxy.proxy import run_proxy

        server_cmd = args.server_command
        if server_cmd and server_cmd[0] == "--":
            server_cmd = server_cmd[1:]
        asyncio.run(run_proxy(server_cmd, args.server_name, source=args.source))
    elif args.command == "mcp-proxy":
        import asyncio

        from proxy.mcp_http_proxy import run_mcp_http_proxy

        asyncio.run(
            run_mcp_http_proxy(
                upstream_url=args.upstream,
                port=args.port,
                server_name=args.server_name,
            )
        )
    elif args.command == "demo":
        _run_demo()
    elif args.command == "status":
        _run_status()
    elif args.command == "ping":
        _run_ping(with_threat=args.threat)
    elif args.command == "doctor":
        from proxy.doctor import run_doctor

        run_doctor()
    elif args.command == "scan":
        _run_scan_cli(args)


def _run_scan_cli(args: argparse.Namespace) -> None:
    import asyncio
    import shlex

    from proxy.config import get_config
    from proxy.installer import (
        find_server_command_with_env,
        list_configured_stdio_servers,
    )
    from proxy.scanner import scan_server

    cfg = get_config()

    async def run_one(name: str, argv: list[str], env: dict[str, str] | None = None):
        return await scan_server(argv, name, config=cfg, env=env)

    if args.scan_all:
        batch = list_configured_stdio_servers()
        if not batch:
            sys.stderr.write(
                "[crossfire] No stdio MCP servers found in config files.\n"
            )
            sys.exit(1)
        for name, argv, env, path in batch:
            sys.stderr.write(f"[crossfire] Scanning {name!r} ({path})...\n")
            rep = asyncio.run(run_one(name, argv, env))
            _print_scan_report(rep, args.json_out)
        return

    if args.scan_cmd:
        try:
            argv = shlex.split(args.scan_cmd)
        except ValueError as exc:
            sys.stderr.write(f"[crossfire] Invalid --cmd: {exc}\n")
            sys.exit(1)
        if not argv:
            sys.stderr.write("[crossfire] --cmd produced an empty argument list.\n")
            sys.exit(1)
        name = args.scan_server_name or "scan"
        rep = asyncio.run(run_one(name, argv))
        _print_scan_report(rep, args.json_out)
        return

    if args.scan_server_name:
        found = find_server_command_with_env(args.scan_server_name)
        if not found:
            sys.stderr.write(
                f"[crossfire] Server {args.scan_server_name!r} not found in MCP configs.\n"
            )
            sys.exit(1)
        argv, env, path = found
        sys.stderr.write(f"[crossfire] Resolved command from {path}\n")
        rep = asyncio.run(run_one(args.scan_server_name, argv, env))
        _print_scan_report(rep, args.json_out)
        return

    sys.stderr.write("[crossfire] scan: use --server NAME, --cmd '...', or --all\n")
    sys.exit(1)


def _print_scan_report(rep, json_out: bool) -> None:
    if json_out:
        print(json.dumps(rep.to_dict(), indent=2))
        return
    print(f"Scan ID: {rep.scan_id}")
    print(f"Server: {rep.server_name}")
    print(f"Command: {rep.command}")
    print(f"Tools: {', '.join(rep.tools_found) or '(none)'}")
    print(f"Duration: {rep.scan_duration_ms:.1f} ms")
    if rep.error:
        print(f"Error: {rep.error}")
    if not rep.findings:
        print("Findings: none")
    else:
        print(f"Findings ({len(rep.findings)}):")
        for f in rep.findings:
            print(
                f"  [{f.phase}] {f.tool_name} ({f.severity}) {f.category}: {f.detail}"
            )


def _dashboard_base() -> str:
    from proxy.config import get_dashboard_url

    return get_dashboard_url().rstrip("/")


def _run_ping(with_threat: bool = False) -> None:
    """Send one synthetic MCP-style event so the Traffic Log updates without real MCP."""
    base = _dashboard_base()
    ok, via = _dashboard_api_is_live(base)
    if not ok:
        sys.stderr.write(
            f"[crossfire] No Crossfire dashboard API at {base} ({via}).\n"
            "          Start it from the repo:  crossfire dashboard\n"
            "          If port 9999 is already in use by another app, free it or set CROSSFIRE_DASHBOARD_URL / dashboard.url in crossfire.yaml to the running server.\n"
            "          Quick check:  curl -sS http://127.0.0.1:9999/api/guardian\n"
        )
        sys.exit(1)
    sys.stderr.write(f"[crossfire] Dashboard OK ({via})\n")

    url = f"{base}/api/events"
    event = {
        "id": f"crossfire-ping-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": "mcp",
        "direction": "request",
        "server": "ping",
        "method": "tools/list",
        "params": {},
        "threats": [],
        "severity": "clean",
    }
    ok, msg = http_post_json(url, event)
    if not ok:
        sys.stderr.write(f"[crossfire] POST {url} failed: {msg}\n")
        sys.exit(1)
    sys.stderr.write(
        f"Posted sample event to {url} (server=ping, method=tools/list). "
        "Check the dashboard Traffic Log — count should increase.\n"
    )

    if with_threat:
        threat_event = {
            "id": f"crossfire-ping-threat-{uuid.uuid4().hex[:10]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": "mcp",
            "direction": "request",
            "server": "weather",
            "method": "tools/call",
            "params": {"name": "get_weather", "arguments": {"city": "SF"}},
            "threats": [
                {
                    "type": "sensitive_file_access",
                    "severity": "critical",
                    "detail": "Sample threat (crossfire ping --threat)",
                    "pattern": "CRED-THEFT",
                    "gemini_analysis": None,
                }
            ],
            "severity": "critical",
        }
        ok2, msg2 = http_post_json(url, threat_event)
        if not ok2:
            sys.stderr.write(f"[crossfire] POST sample threat event failed: {msg2}\n")
            sys.exit(1)
        sys.stderr.write("Posted sample critical-threat event (server=weather).\n")


def _run_status() -> None:
    base = _dashboard_base()
    guardian = http_get_json(f"{base}/api/guardian")
    servers = http_get_json(f"{base}/api/servers")
    sys.stderr.write(f"Crossfire dashboard: {base}\n")
    if guardian:
        sys.stderr.write(f"  Guardian mode: {guardian.get('mode', '?')}\n")
    else:
        sys.stderr.write("  Guardian: (dashboard unreachable)\n")
    if servers:
        sys.stderr.write(f"  Servers tracked: {len(servers.get('servers', {}))}\n")
        sys.stderr.write(f"  Total events: {servers.get('total_events', 0)}\n")
        sys.stderr.write(
            f"  Total threats (counted): {servers.get('total_threats', 0)}\n"
        )
    else:
        sys.stderr.write("  Stats: (dashboard unreachable)\n")


def _run_demo() -> None:
    root = Path(__file__).resolve().parent.parent
    demo_py = root / "demo" / "poisoned_weather.py"
    sys.stderr.write(
        "Crossfire demo: starting dashboard server on http://127.0.0.1:9999\n"
    )
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "server.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "9999",
        ],
        cwd=str(root),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)
    url = "http://127.0.0.1:9999"
    try:
        webbrowser.open(url)
    except OSError:
        pass
    sys.stderr.write("\n")
    sys.stderr.write("Dashboard: " + url + "\n")
    sys.stderr.write("Poisoned MCP server script: " + str(demo_py) + "\n")
    sys.stderr.write("Example MCP config (merge into your mcp.json):\n")
    sys.stderr.write(
        json.dumps(
            {
                "mcpServers": {
                    "weather-demo": {
                        "command": "crossfire-proxy",
                        "args": [
                            "--server-name",
                            "weather-demo",
                            "--",
                            sys.executable,
                            str(demo_py),
                        ],
                    }
                }
            },
            indent=2,
        )
        + "\n"
    )
    sys.stderr.write("\nPress Ctrl+C to stop the dashboard (PID %d).\n" % proc.pid)
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
