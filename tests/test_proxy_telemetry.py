"""Integration tests for dashboard telemetry (broadcast) and logging."""

import logging

import pytest
from aiohttp import web

from proxy import proxy as proxy_module


@pytest.mark.asyncio
async def test_broadcast_delivers_event_to_dashboard(
    caplog: pytest.LogCaptureFixture,
) -> None:
    received: list[dict] = []

    async def handler(request: web.Request) -> web.Response:
        received.append(await request.json())
        return web.json_response({"status": "ok"})

    app = web.Application()
    app.router.add_post("/api/events", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    prev = proxy_module.DASHBOARD_URL
    try:
        proxy_module.DASHBOARD_URL = url
        await proxy_module.broadcast({"id": "evt-test", "protocol": "mcp"})
    finally:
        proxy_module.DASHBOARD_URL = prev
        await runner.cleanup()

    assert len(received) == 1
    assert received[0]["protocol"] == "mcp"


@pytest.mark.asyncio
async def test_broadcast_logs_on_unreachable_dashboard(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="crossfire.telemetry")
    prev = proxy_module.DASHBOARD_URL
    try:
        proxy_module.DASHBOARD_URL = "http://127.0.0.1:1"
        await proxy_module.broadcast({"id": "x"})
    finally:
        proxy_module.DASHBOARD_URL = prev

    assert any(
        r.name == "crossfire.telemetry" and "Dashboard telemetry failed" in r.message
        for r in caplog.records
    )
