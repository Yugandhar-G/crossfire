"""MCP stdio proxy entry point for the ``crossfire-proxy`` pip console script.

IDEs invoke this executable (no Node required). Mirrors ``crossfire proxy --server-name ... -- ...``.
"""

from __future__ import annotations

import argparse
import asyncio


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="crossfire-proxy",
        description="Crossfire MCP stdio proxy (between IDE and MCP server)",
    )
    parser.add_argument(
        "--server-name", required=True, help="MCP server name from mcp.json"
    )
    parser.add_argument(
        "--source",
        default="ide",
        choices=["ide", "sdk", "http-proxy", "scan"],
        help="Traffic source label (default: ide)",
    )
    parser.add_argument(
        "server_command",
        nargs=argparse.REMAINDER,
        help="Command and args for the real MCP server (after --)",
    )
    args = parser.parse_args()

    server_cmd = list(args.server_command)
    if server_cmd and server_cmd[0] == "--":
        server_cmd = server_cmd[1:]

    from proxy.proxy import run_proxy

    asyncio.run(run_proxy(server_cmd, args.server_name, source=args.source))


if __name__ == "__main__":
    main()
