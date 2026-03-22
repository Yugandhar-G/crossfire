"""Crossfire Dashboard Server -- FastAPI with WebSocket broadcast.

Production features:
 - Rate limiting on event ingestion (~200 events/sec)
 - Guardian mode returned in /api/events response for proxy sync
 - MCP vulnerability scan API (POST /api/scan) with WebSocket progress
 - Metrics and health endpoints
"""

import json
import logging
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Literal

import yaml
from fastapi import (
    BackgroundTasks,
    FastAPI,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from server.events import EventStore
from server.guardian import Guardian

ws_log = logging.getLogger("crossfire.ws")

_rate_windows: dict[str, deque[float]] = {}
RATE_LIMIT_PER_SECOND = 200

scan_results: deque[dict] = deque(maxlen=50)


class ThreatIn(BaseModel):
    type: str
    severity: Literal["critical", "high", "medium", "low"]
    detail: str
    pattern: str
    gemini_analysis: dict | None = None


class EventIn(BaseModel):
    id: str
    timestamp: str
    protocol: Literal["mcp", "a2a"]
    direction: Literal["request", "response"]
    server: str
    method: str = ""
    params: dict = Field(default_factory=dict)
    threats: list[ThreatIn] = Field(default_factory=list)
    severity: Literal["critical", "high", "medium", "low", "clean"] = "clean"
    blocked: bool | None = None
    tools_discovered: list[str] | None = None
    tool_poisoning: list[dict] | None = None
    sensitive_data: list[dict] | None = None
    chain_id: str | None = None
    source: Literal["ide", "sdk", "http-proxy", "scan"] | None = None


class GuardianIn(BaseModel):
    mode: Literal["monitor", "block"] = "monitor"


class ScanIn(BaseModel):
    """Start a background MCP scan (same engine as ``crossfire scan``)."""

    server_name: str | None = None
    command: list[str] | None = None


app = FastAPI(title="Crossfire Dashboard API")

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

store = EventStore()
guardian = Guardian()


class ConnectionManager:
    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, data: dict):
        dead: list[WebSocket] = []
        for ws in self.connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.connections.remove(ws)


manager = ConnectionManager()


@app.get("/health")
async def health():
    return {"status": "ok"}


def _check_rate_limit(client_ip: str) -> bool:
    now = time.time()
    cutoff = now - 1.0
    window = _rate_windows.get(client_ip)
    if window is None:
        window = deque()
        _rate_windows[client_ip] = window
    while window and window[0] < cutoff:
        window.popleft()
    if len(window) >= RATE_LIMIT_PER_SECOND:
        return False
    window.append(now)
    return True


@app.post("/api/events")
async def receive_event(event: EventIn, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        return JSONResponse(status_code=429, content={"error": "rate_limited"})
    data = event.model_dump(exclude_none=True)
    store.add(data)
    await manager.broadcast(data)
    return {"status": "ok", "guardian_mode": guardian.mode}


@app.get("/api/events")
async def get_events(
    server: str | None = None,
    severity: str | None = None,
    protocol: str | None = None,
    source: str | None = None,
    limit: int = 100,
):
    return store.query(
        server=server, severity=severity, protocol=protocol, source=source, limit=limit
    )


@app.get("/api/servers")
async def get_servers():
    return store.get_stats()


@app.post("/api/guardian")
async def set_guardian(body: GuardianIn):
    mode = guardian.set_mode(body.mode)
    update = {"type": "guardian_update", "mode": mode}
    await manager.broadcast(update)
    return guardian.to_dict()


@app.get("/api/guardian")
async def get_guardian():
    return guardian.to_dict()


@app.get("/api/stats")
async def get_stats():
    return store.get_stats()


@app.get("/api/health")
async def health_check():
    stats = store.get_stats()
    return {
        "status": "healthy",
        "total_events": stats["total_events"],
        "total_threats": stats["total_threats"],
        "servers_active": len(stats["servers"]),
        "guardian_mode": guardian.mode,
    }


@app.post("/api/scan")
async def start_scan(body: ScanIn, background_tasks: BackgroundTasks):
    """Run ``proxy.scanner.scan_server`` in the background; progress on WebSocket."""
    from proxy.config import get_config
    from proxy.installer import find_server_command_with_env
    from proxy.scanner import scan_server

    scan_id = str(uuid.uuid4())
    cfg = get_config()
    server_env: dict[str, str] | None = None

    if body.command:
        argv = list(body.command)
        display_name = body.server_name or "scan"
    elif body.server_name:
        found = find_server_command_with_env(body.server_name)
        if not found:
            raise HTTPException(
                status_code=404, detail=f"Server {body.server_name!r} not found"
            )
        argv, server_env, _path = found
        display_name = body.server_name
    else:
        raise HTTPException(status_code=400, detail="Provide server_name or command")

    async def run_scan() -> None:
        async def on_progress(payload: dict) -> None:
            await manager.broadcast(payload)

        try:
            report = await scan_server(
                argv,
                display_name,
                config=cfg,
                on_progress=on_progress,
                scan_id=scan_id,
                env=server_env,
            )
            scan_results.appendleft(report.to_dict())
        except Exception as exc:
            await manager.broadcast(
                {
                    "type": "scan_error",
                    "scan_id": scan_id,
                    "server": display_name,
                    "error": str(exc),
                }
            )

    background_tasks.add_task(run_scan)
    return {"status": "started", "scan_id": scan_id, "server": display_name}


@app.get("/api/scan/results")
async def list_scan_results(limit: int = 20):
    lim = max(1, min(limit, 100))
    return list(scan_results)[:lim]


@app.get("/api/config")
async def read_crossfire_yaml():
    config_paths = [
        Path.cwd() / "crossfire.yaml",
        Path.cwd() / ".crossfire.yaml",
        Path.home() / ".crossfire.yaml",
    ]
    for path in config_paths:
        if path.exists():
            return {
                "path": str(path),
                "content": path.read_text(encoding="utf-8"),
                "parsed": yaml.safe_load(path.read_text(encoding="utf-8")),
            }
    return {"path": None, "content": "", "parsed": {}}


@app.post("/api/config/reload")
async def reload_config():
    config = await read_crossfire_yaml()
    await manager.broadcast(
        {"type": "config_reload", "config": config.get("parsed", {})}
    )
    return {"status": "reloaded", "config": config}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
            try:
                msg = json.loads(data)
                command = msg.get("command")
                if command == "set_guardian":
                    mode = guardian.set_mode(msg.get("mode", "monitor"))
                    await manager.broadcast({"type": "guardian_update", "mode": mode})
            except json.JSONDecodeError:
                ws_log.warning("Malformed WebSocket command: %s", data[:200])
    except WebSocketDisconnect:
        manager.disconnect(ws)


def _resolve_dashboard_dist() -> Path:
    """Prefer packaged static files (wheel); fall back to repo ``dashboard/dist`` (editable install)."""
    here = Path(__file__).resolve().parent
    packaged = here / "web_dist"
    if packaged.is_dir() and any(packaged.iterdir()):
        return packaged
    return (here.parent / "dashboard" / "dist").resolve()


DASHBOARD_DIST = _resolve_dashboard_dist()

_DASHBOARD_NOT_BUILT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Crossfire — build the dashboard UI</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #08080c; color: #e4e4e7; margin: 0; padding: 2rem; line-height: 1.5; }
    code { background: #18181b; padding: 0.2em 0.45em; border-radius: 4px; font-size: 0.95em; }
    pre { background: #111118; padding: 1rem; border-radius: 8px; overflow-x: auto; border: 1px solid #27272a; }
    a { color: #38bdf8; }
    h1 { margin-top: 0; }
  </style>
</head>
<body>
  <h1>Dashboard UI not built</h1>
  <p>The API is running, but <code>dashboard/dist</code> is missing. Build the React app, then restart the server.</p>
  <pre><code>cd dashboard
npm install
npm run build</code></pre>
  <p>For development with hot reload, run <code>npm run dev</code> in <code>dashboard/</code> and open <a href="http://localhost:5173">http://localhost:5173</a> (Vite proxies API/WebSocket to this server).</p>
  <p>API check: <a href="/health">/health</a></p>
</body>
</html>"""


if DASHBOARD_DIST.exists():
    app.mount("/", StaticFiles(directory=str(DASHBOARD_DIST), html=True))
else:

    @app.get("/")
    async def dashboard_not_built() -> HTMLResponse:
        return HTMLResponse(content=_DASHBOARD_NOT_BUILT_HTML, status_code=503)
