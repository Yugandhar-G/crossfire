"""Crossfire MCP HTTP reverse proxy -- intercepts Streamable HTTP and SSE MCP traffic.

Sits between code-based agents (Google ADK, LangChain, CrewAI, OpenAI Agents SDK,
raw MCP SDK) and remote MCP servers.  Runs all 28 threat detectors, Guardian
blocking, policy engine, Gemini AI enrichment, and broadcasts to the dashboard.

Usage:
    crossfire mcp-proxy --upstream https://remote-mcp.example.com --port 8888
"""

import asyncio
import json
import sys

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse

from proxy.config import get_config, get_dashboard_url
from proxy.detectors import Threat
from proxy.detectors.rules import detect_request_threats as _detect_rules
from proxy.detectors.path_traversal import detect_path_traversal
from proxy.detectors.token_passthrough import detect_token_passthrough
from proxy.detectors.sql_injection import detect_sql_injection
from proxy.detectors.oauth_confused_deputy import detect_oauth_confused_deputy
from proxy.detectors.config_poisoning import detect_config_poisoning
from proxy.detectors.session_flaws import detect_session_flaws
from proxy.detectors.cross_tenant import detect_cross_tenant
from proxy.detectors.neighborjack import detect_neighborjack
from proxy.detectors.tool_scanner import scan_all_tool_descriptions
from proxy.detectors.rug_pull import check_rug_pull
from proxy.detectors.schema_poisoning import scan_all_schemas
from proxy.detectors.sensitive_data import detect_sensitive_data
from proxy.detectors.resource_poisoning import detect_resource_poisoning
from proxy.detectors.gemini_agent import record_context, analyze_and_enrich
from proxy.event_builder import make_event
from proxy.metrics import metrics
from proxy.policy import build_policy_from_config
from proxy.unicode_normalize import normalize_text, normalize_arguments

app = FastAPI(title="Crossfire MCP HTTP Proxy")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:9999",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:9999",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

_http_client: httpx.AsyncClient | None = None
_upstream_url: str = ""
_dashboard_url: str = "http://localhost:9999"
_server_name: str = "remote-mcp"
_cfg: dict = {}
_policy_engine = None
_tools_registry: dict = {}
_guardian_mode: str = "monitor"


def configure(
    upstream_url: str,
    server_name: str = "remote-mcp",
    dashboard_url: str | None = None,
) -> None:
    global _upstream_url, _server_name, _dashboard_url, _cfg, _policy_engine
    _upstream_url = upstream_url.rstrip("/")
    _server_name = server_name
    _cfg = get_config()
    _dashboard_url = dashboard_url or get_dashboard_url()
    _policy_engine = build_policy_from_config(_cfg)


async def _get_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(timeout=30.0)
    return _http_client


async def _broadcast(event: dict) -> None:
    try:
        client = await _get_client()
        resp = await client.post(
            f"{_dashboard_url.rstrip('/')}/api/events",
            json=event,
            timeout=2.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            new_mode = data.get("guardian_mode")
            if new_mode and new_mode in ("monitor", "block"):
                global _guardian_mode
                _guardian_mode = new_mode
    except Exception as exc:
        sys.stderr.write(f"[crossfire-mcp-http] broadcast error: {exc}\n")


def _make_event(
    data: dict,
    direction: str,
    threats: list[Threat] | None = None,
    extra: dict | None = None,
    blocked: bool | None = None,
) -> dict:
    return make_event(
        data,
        protocol="mcp",
        direction=direction,
        server=_server_name,
        threats=threats,
        extra=extra,
        blocked=blocked,
        source="http-proxy",
    )


def _should_block(threats: list[Threat]) -> bool:
    if not threats:
        return False
    if _cfg.get("mode") == "block" or _guardian_mode == "block":
        sevs = {t.severity for t in threats}
        if sevs & {"critical", "high"}:
            return True
    return False


def _detect_request_threats(method: str, params: dict) -> list[Threat]:
    """Run all request-path detectors."""
    threats: list[Threat] = []

    if method != "tools/call":
        return threats

    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})
    tool_name_n = normalize_text(tool_name)
    arguments_n = normalize_arguments(arguments)

    try:
        threats = _detect_rules(
            tool_name=tool_name_n,
            arguments=arguments_n,
            tools_registry=_tools_registry,
            server_name=_server_name,
            config=_cfg,
        )
    except Exception as exc:
        sys.stderr.write(f"[crossfire-mcp-http] detection error: {exc}\n")

    try:
        threats.extend(detect_path_traversal(tool_name_n, arguments_n, config=_cfg))
        threats.extend(detect_token_passthrough(tool_name_n, arguments_n, config=_cfg))
        threats.extend(detect_sql_injection(tool_name_n, arguments_n, config=_cfg))
        threats.extend(
            detect_oauth_confused_deputy(tool_name_n, arguments_n, config=_cfg)
        )
        threats.extend(detect_config_poisoning(tool_name_n, arguments_n, config=_cfg))
        threats.extend(detect_session_flaws(tool_name_n, arguments_n, config=_cfg))
        threats.extend(
            detect_cross_tenant(tool_name_n, arguments_n, _server_name, config=_cfg)
        )
        threats.extend(detect_neighborjack(tool_name_n, arguments_n, config=_cfg))
    except Exception as exc:
        sys.stderr.write(f"[crossfire-mcp-http] extended detection error: {exc}\n")

    try:
        record_context(
            _server_name,
            {
                "tool": tool_name_n,
                "arguments": {k: str(v)[:200] for k, v in arguments_n.items()},
            },
        )
    except Exception:
        pass

    return threats


def _detect_response_threats(method: str, result: dict) -> tuple[list[Threat], dict]:
    """Run response-path detectors. Returns (threats, extra)."""
    threats: list[Threat] = []
    extra: dict = {}

    if method == "tools/list":
        tools = result.get("tools", [])
        for tool in tools:
            _tools_registry[tool.get("name", "")] = tool
        extra["tools_discovered"] = [t.get("name", "") for t in tools]

        try:
            poisoning = scan_all_tool_descriptions(tools, config=_cfg)
            if poisoning:
                extra["tool_poisoning"] = poisoning
        except Exception as exc:
            sys.stderr.write(f"[crossfire-mcp-http] tool scan error: {exc}\n")

        try:
            rug = check_rug_pull(_server_name, tools, config=_cfg)
            threats.extend(rug)
        except Exception as exc:
            sys.stderr.write(f"[crossfire-mcp-http] rug-pull error: {exc}\n")

        try:
            schema = scan_all_schemas(tools, config=_cfg)
            if schema:
                threats.extend(schema)
                extra["schema_poisoning"] = [
                    {"tool": t.detail, "pattern": t.pattern} for t in schema
                ]
        except Exception as exc:
            sys.stderr.write(f"[crossfire-mcp-http] schema poisoning error: {exc}\n")

        blocked_tools = _cfg.get("policy", {}).get("blocked_tools", [])
        if blocked_tools and _cfg.get("mcp_http_proxy", {}).get("tool_hiding", True):
            original_count = len(tools)
            result["tools"] = [t for t in tools if t.get("name") not in blocked_tools]
            hidden = original_count - len(result["tools"])
            if hidden > 0:
                extra["tools_hidden"] = hidden

    if method == "tools/call":
        result_text = json.dumps(result)
        try:
            sensitive = detect_sensitive_data(result_text)
            if sensitive:
                extra["sensitive_data"] = sensitive
                threats.extend(
                    [
                        Threat(
                            type="sensitive_data_exposure",
                            severity="critical",
                            detail=f"Sensitive data in response: {s['data_type']}",
                            pattern="CRED-THEFT",
                        )
                        for s in sensitive
                    ]
                )
        except Exception as exc:
            sys.stderr.write(f"[crossfire-mcp-http] sensitive data error: {exc}\n")

        try:
            poison = detect_resource_poisoning(
                result_text, source_type="tool_response", config=_cfg
            )
            if poison:
                threats.extend(poison)
                extra["resource_poisoning"] = [
                    {"detail": t.detail, "pattern": t.pattern} for t in poison
                ]
        except Exception as exc:
            sys.stderr.write(f"[crossfire-mcp-http] resource poisoning error: {exc}\n")

    return threats, extra


@app.post("/mcp")
@app.post("/sse")
@app.post("/{path:path}")
async def proxy_post(request: Request, path: str = "mcp"):
    """Intercept MCP JSON-RPC POST requests."""
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
    params = data.get("params", {})

    req_threats = _detect_request_threats(method, params)

    blocked = _should_block(req_threats)
    req_event = _make_event(data, "request", req_threats, blocked=blocked)

    gem = _cfg.get("rules", {}).get("gemini_analysis", {})
    if req_threats and gem.get("enabled", True):
        try:
            req_event = await analyze_and_enrich(req_event, _server_name)
            metrics.record_gemini(success=True)
        except Exception as exc:
            metrics.record_gemini(success=False)
            sys.stderr.write(f"[crossfire-mcp-http] Gemini error: {exc}\n")

    asyncio.create_task(_broadcast(req_event))

    if blocked:
        error_resp = {
            "jsonrpc": "2.0",
            "id": data.get("id"),
            "error": {
                "code": -32000,
                "message": "[Crossfire] Blocked: critical/high severity threat detected",
                "data": {"threats": req_event.get("threats", [])},
            },
        }
        return JSONResponse(error_resp)

    accept = request.headers.get("accept", "")
    if "text/event-stream" in accept:
        return await _handle_sse(request, body, path, method)

    client = await _get_client()
    fwd_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length")
    }
    resp = await client.post(
        f"{_upstream_url}/{path}", content=body, headers=fwd_headers
    )

    try:
        resp_data = resp.json()
        result = resp_data.get("result", {})
        resp_threats, extra = _detect_response_threats(method, result)

        resp_event = _make_event(
            {**resp_data, "method": method},
            "response",
            resp_threats,
            extra=extra,
        )

        if resp_threats and gem.get("enabled", True):
            try:
                resp_event = await analyze_and_enrich(resp_event, _server_name)
            except Exception:
                pass

        asyncio.create_task(_broadcast(resp_event))

        resp_body = json.dumps(resp_data).encode()
        return Response(
            content=resp_body,
            status_code=resp.status_code,
            media_type="application/json",
        )
    except Exception:
        return Response(content=resp.content, status_code=resp.status_code)


@app.get("/mcp")
@app.get("/sse")
async def proxy_sse_get(request: Request):
    """Proxy SSE endpoint for server-initiated notifications."""
    return await _handle_sse_get(request)


async def _handle_sse(request: Request, body: bytes, path: str, method: str):
    """Intercept SSE streaming responses."""
    client = await _get_client()
    fwd_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length")
    }

    async def stream():
        async with client.stream(
            "POST", f"{_upstream_url}/{path}", content=body, headers=fwd_headers
        ) as response:
            async for line in response.aiter_lines():
                if line.startswith("data:"):
                    try:
                        event_data = json.loads(line[5:].strip())
                        result = event_data.get("result", {})
                        resp_threats, extra = _detect_response_threats(method, result)
                        sse_event = _make_event(
                            {**event_data, "method": method},
                            "response",
                            resp_threats,
                            extra=extra,
                        )
                        asyncio.create_task(_broadcast(sse_event))
                    except json.JSONDecodeError:
                        pass
                yield line + "\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


async def _handle_sse_get(request: Request):
    """Proxy GET-based SSE connections (server notifications)."""
    client = await _get_client()
    fwd_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in ("host",)
    }

    async def stream():
        async with client.stream(
            "GET", f"{_upstream_url}/mcp", headers=fwd_headers
        ) as response:
            async for line in response.aiter_lines():
                if line.startswith("data:"):
                    try:
                        event_data = json.loads(line[5:].strip())
                        ev = _make_event(event_data, "response")
                        asyncio.create_task(_broadcast(ev))
                    except json.JSONDecodeError:
                        pass
                yield line + "\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


async def run_mcp_http_proxy(
    upstream_url: str,
    port: int = 8888,
    server_name: str = "remote-mcp",
) -> None:
    """Start the MCP HTTP reverse proxy."""
    import uvicorn

    configure(upstream_url, server_name=server_name)
    sys.stderr.write(f"[crossfire-mcp-http] Proxying MCP traffic to {upstream_url}\n")
    sys.stderr.write(f"[crossfire-mcp-http] Listening on http://0.0.0.0:{port}\n")
    sys.stderr.write(f"[crossfire-mcp-http] Dashboard: {_dashboard_url}\n")
    sys.stderr.write(f"[crossfire-mcp-http] Server name: {server_name}\n")
    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()
