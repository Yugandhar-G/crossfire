"""Framework-agnostic helpers for wrapping MCP server commands through Crossfire.

Works with any agent framework (Google ADK, LangChain, CrewAI, OpenAI Agents SDK)
that accepts a command + args for stdio MCP server connections.  Does NOT import
any framework -- returns plain (command, args) tuples.

Usage with Google ADK::

    from proxy.sdk_helper import crossfire_wrap_command
    cmd, args = crossfire_wrap_command("npx", ["-y", "@brightdata/mcp"], "brightdata")
    agent = LlmAgent(tools=[MCPToolset(
        connection_params=StdioServerParameters(command=cmd, args=args)
    )])

Usage with LangChain::

    cmd, args = crossfire_wrap_command("python", ["server.py"], "my-server")
    client = MultiServerMCPClient({
        "my-server": {"transport": "stdio", "command": cmd, "args": args}
    })

Usage with CrewAI::

    cmd, args = crossfire_wrap_command("npx", ["-y", "@stripe/mcp"], "stripe")
    # pass cmd and args into CrewAI's dict config
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path


def _resolve_proxy_command() -> str:
    """Find the crossfire-proxy executable."""
    venv_bin = Path(sys.executable).parent / "crossfire-proxy"
    if venv_bin.exists():
        return str(venv_bin)

    found = shutil.which("crossfire-proxy")
    if found:
        return found

    return sys.executable + " -m proxy proxy"


def crossfire_wrap_command(
    command: str,
    args: list[str] | None = None,
    server_name: str = "mcp-server",
    source: str = "sdk",
) -> tuple[str, list[str]]:
    """Wrap an MCP server command to run through crossfire-proxy.

    Returns (proxy_command, proxy_args) suitable for any framework's
    StdioServerParameters or equivalent.
    """
    proxy_cmd = _resolve_proxy_command()
    real_args = list(args or [])
    wrapped_args = [
        "--server-name",
        server_name,
        "--source",
        source,
        "--",
        command,
        *real_args,
    ]
    return proxy_cmd, wrapped_args


def crossfire_http_url(
    upstream_url: str,
    proxy_port: int = 8888,
) -> str:
    """Return the local Crossfire HTTP proxy URL for a remote MCP server.

    Point your agent's HTTP/SSE MCP client at this URL instead of the
    upstream server.  Requires ``crossfire mcp-proxy --upstream <url>``
    to be running.
    """
    return f"http://localhost:{proxy_port}/mcp"
