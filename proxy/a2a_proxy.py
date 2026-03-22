"""Crossfire A2A proxy -- HTTP reverse proxy for Agent-to-Agent protocol."""

import asyncio
import json
import sys

import httpx

from fastapi import FastAPI, Request
from fastapi.responses import Response, StreamingResponse

from proxy.config import get_dashboard_url
from proxy.detectors import Threat
from proxy.event_builder import make_event
from proxy.telemetry_log import log as telemetry_log
from proxy.detectors.a2a_detectors import (
    detect_a2a_exfiltration,
    detect_a2a_impersonation,
    detect_a2a_injection,
)
from proxy.detectors.session_smuggling import detect_session_smuggling


app = FastAPI(title="Crossfire A2A Proxy")

_http_client: httpx.AsyncClient | None = None
_upstream_url: str = ""
_dashboard_url: str = "http://localhost:9999"


def configure(upstream_url: str, dashboard_url: str | None = None):
    global _upstream_url, _dashboard_url
    _upstream_url = upstream_url
    _dashboard_url = dashboard_url or get_dashboard_url()


async def _get_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=30.0)
    return _http_client


async def _broadcast(event: dict) -> None:
    try:
        client = await _get_client()
        await client.post(f"{_dashboard_url}/api/events", json=event, timeout=0.5)
    except Exception as exc:
        telemetry_log.warning(
            "A2A dashboard telemetry failed for %s/api/events: %s",
            _dashboard_url,
            exc,
        )
        telemetry_log.debug("A2A POST /api/events details", exc_info=True)


def _make_event(
    data: dict,
    direction: str,
    threats: list[Threat] | None = None,
) -> dict:
    return make_event(
        data,
        protocol="a2a",
        direction=direction,
        server=_upstream_url or "a2a-agent",
        threats=threats,
    )


def _extract_parts(data: dict) -> list[dict]:
    params = data.get("params", {})
    message = params.get("message", {})
    return message.get("parts", [])


@app.get("/.well-known/agent.json")
async def agent_card_proxy():
    """Proxy and cache the upstream agent card."""
    client = await _get_client()
    try:
        resp = await client.get(f"{_upstream_url}/.well-known/agent.json")
        card = resp.json()

        threats = detect_a2a_impersonation("upstream", card)
        event = _make_event(
            {"method": "agent/card", "params": card},
            "response",
            threats,
        )
        asyncio.create_task(_broadcast(event))

        return Response(content=resp.content, media_type="application/json")
    except Exception as exc:
        sys.stderr.write(f"[crossfire-a2a] Agent card error: {exc}\n")
        return Response(content="{}", status_code=502)


@app.post("/{path:path}")
async def proxy_rpc(request: Request, path: str):
    """Intercept all A2A JSON-RPC calls."""
    body = await request.body()

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        client = await _get_client()
        resp = await client.post(
            f"{_upstream_url}/{path}",
            content=body,
            headers=dict(request.headers),
        )
        return Response(content=resp.content, status_code=resp.status_code)

    method = data.get("method", "")

    req_threats: list[Threat] = []
    parts = _extract_parts(data)
    if parts:
        req_threats.extend(detect_a2a_exfiltration(parts))
        req_threats.extend(detect_a2a_injection(parts))

    task_id = data.get("params", {}).get("id", data.get("id", ""))
    if task_id:
        agent_name = data.get("params", {}).get("message", {}).get("role", "")
        req_threats.extend(
            detect_session_smuggling(
                session_id=str(task_id),
                direction="client",
                agent_name=agent_name,
            )
        )

    req_event = _make_event(data, "request", req_threats)
    asyncio.create_task(_broadcast(req_event))

    if method == "message/stream":
        return await _handle_stream(request, body, path)

    client = await _get_client()
    resp = await client.post(
        f"{_upstream_url}/{path}",
        content=body,
        headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
    )

    try:
        resp_data = resp.json()
        resp_threats: list[Threat] = []

        result = resp_data.get("result", {})
        task = result.get("task", {})
        artifacts = task.get("artifacts", [])
        for artifact in artifacts:
            artifact_parts = artifact.get("parts", [])
            resp_threats.extend(detect_a2a_exfiltration(artifact_parts))

        message = result.get("message", {})
        msg_parts = message.get("parts", [])
        if msg_parts:
            resp_threats.extend(detect_a2a_exfiltration(msg_parts))
            resp_threats.extend(detect_a2a_injection(msg_parts))

        resp_task_id = task.get("id", data.get("id", ""))
        if resp_task_id:
            resp_threats.extend(
                detect_session_smuggling(
                    session_id=str(resp_task_id),
                    direction="server",
                )
            )

        resp_event = _make_event(resp_data, "response", resp_threats)
        asyncio.create_task(_broadcast(resp_event))
    except Exception as exc:
        telemetry_log.warning("A2A response threat scan failed: %s", exc)
        telemetry_log.debug("A2A response scan details", exc_info=True)

    return Response(content=resp.content, status_code=resp.status_code)


async def _handle_stream(request: Request, body: bytes, path: str):
    """Intercept SSE streaming for message/stream."""
    client = await _get_client()

    async def stream_generator():
        async with client.stream(
            "POST",
            f"{_upstream_url}/{path}",
            content=body,
            headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
        ) as response:
            async for line in response.aiter_lines():
                if line.startswith("data:"):
                    try:
                        event_data = json.loads(line[5:].strip())
                        threats: list[Threat] = []

                        result = event_data.get("result", {})
                        task = result.get("task", {})
                        artifacts = task.get("artifacts", [])
                        for artifact in artifacts:
                            threats.extend(
                                detect_a2a_exfiltration(artifact.get("parts", []))
                            )

                        sse_event = _make_event(event_data, "response", threats)
                        asyncio.create_task(_broadcast(sse_event))
                    except json.JSONDecodeError:
                        pass
                yield line + "\n"

    return StreamingResponse(stream_generator(), media_type="text/event-stream")


async def run_a2a_proxy(upstream_url: str, port: int = 9998) -> None:
    """Start the A2A proxy server."""
    import uvicorn

    configure(upstream_url)
    sys.stderr.write(f"[crossfire-a2a] Proxying to {upstream_url} on port {port}\n")
    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()
