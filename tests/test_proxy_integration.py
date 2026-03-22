"""Integration test: proxy round-trip with a mock MCP server and a mock dashboard."""

import asyncio
import json
import sys
from pathlib import Path

import pytest
from aiohttp import web

DEMO_SERVER = str(
    Path(__file__).resolve().parent.parent / "demo" / "poisoned_weather.py"
)


async def _run_proxy_roundtrip(dashboard_url: str) -> tuple[list[dict], list[dict]]:
    """Spawn proxy -> demo server, send initialize + tools/list, collect responses + events."""
    received_events: list[dict] = []

    proxy_proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "proxy",
        "proxy",
        "--server-name",
        "weather-test",
        "--",
        sys.executable,
        DEMO_SERVER,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={
            "PATH": "/usr/bin:/usr/local/bin",
            "PYTHONPATH": str(Path(__file__).resolve().parent.parent),
            "CROSSFIRE_DASHBOARD_URL": dashboard_url,
        },
    )

    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]

    responses: list[dict] = []
    for msg in messages:
        line = json.dumps(msg) + "\n"
        proxy_proc.stdin.write(line.encode())
        await proxy_proc.stdin.drain()

        raw = await asyncio.wait_for(proxy_proc.stdout.readline(), timeout=10)
        responses.append(json.loads(raw.decode()))

    proxy_proc.stdin.close()
    try:
        await asyncio.wait_for(proxy_proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        proxy_proc.terminate()
        await proxy_proc.wait()

    await asyncio.sleep(0.3)
    return responses, received_events


@pytest.mark.asyncio
async def test_proxy_forwards_initialize_and_tools_list() -> None:
    """Proxy must be transparent: MCP responses pass through unchanged."""
    received_events: list[dict] = []

    async def handler(request: web.Request) -> web.Response:
        received_events.append(await request.json())
        return web.json_response({"status": "ok"})

    async def guardian_handler(_: web.Request) -> web.Response:
        return web.json_response({"mode": "monitor"})

    app = web.Application()
    app.router.add_post("/api/events", handler)
    app.router.add_get("/api/guardian", guardian_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    dashboard_url = f"http://127.0.0.1:{port}"

    try:
        responses, _ = await _run_proxy_roundtrip(dashboard_url)

        assert len(responses) >= 2
        init_resp = responses[0]
        assert init_resp["id"] == 1
        assert "serverInfo" in init_resp.get("result", {})

        tools_resp = responses[1]
        assert tools_resp["id"] == 2
        tool_names = [t["name"] for t in tools_resp.get("result", {}).get("tools", [])]
        assert "get_weather" in tool_names

        await asyncio.sleep(0.5)
        assert len(received_events) >= 2, (
            f"Expected >=2 events, got {len(received_events)}"
        )
    finally:
        await runner.cleanup()
