"""Crossfire MCP stdio proxy -- transparent man-in-the-middle.

Production features:
 - Policy engine for fine-grained allow/block per server/tool
 - HMAC-signed events for integrity verification
 - Persistent JSONL audit logging
 - Metrics collection (latency, threat rates, broadcast health)
 - Unicode anti-evasion normalization
 - Guardian mode sync via API response (no polling)
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone

import httpx

from proxy.config import get_config, get_dashboard_url
from proxy.detectors import Threat
from proxy.detectors.cross_call import detect_cross_call
from proxy.detectors.rules import detect_request_threats
from proxy.detectors.path_traversal import detect_path_traversal
from proxy.detectors.token_passthrough import detect_token_passthrough
from proxy.detectors.sql_injection import detect_sql_injection
from proxy.detectors.oauth_confused_deputy import detect_oauth_confused_deputy
from proxy.detectors.config_poisoning import detect_config_poisoning
from proxy.detectors.session_flaws import detect_session_flaws
from proxy.detectors.cross_tenant import detect_cross_tenant
from proxy.detectors.neighborjack import detect_neighborjack, check_server_binding
from proxy.detectors.tool_scanner import scan_all_tool_descriptions
from proxy.detectors.rug_pull import check_rug_pull
from proxy.detectors.schema_poisoning import scan_all_schemas
from proxy.detectors.sensitive_data import detect_sensitive_data
from proxy.detectors.resource_poisoning import detect_resource_poisoning
from proxy.detectors.typosquat import detect_typosquat
from proxy.detectors.gemini_agent import record_context, analyze_and_enrich
from proxy.event_builder import make_event
from proxy.telemetry_log import log as telemetry_log
from proxy.protocol import (
    classify_message,
    create_stdin_reader,
    drain_writer,
    read_message,
    write_message,
)
from proxy.policy import build_policy_from_config
from proxy.audit import AuditLogger
from proxy.hmac_signing import EventSigner
from proxy.metrics import metrics
from proxy.unicode_normalize import normalize_text, normalize_arguments

DASHBOARD_URL = "http://localhost:9999"

_guardian_mode = "monitor"

MAX_BROADCAST_RETRIES = 2
BROADCAST_RETRY_DELAY = 0.1


def resolve_dashboard_url(config: dict | None = None) -> str:
    """Dashboard base URL for events and guardian API."""
    if config is not None:
        return (
            os.environ.get("CROSSFIRE_DASHBOARD_URL")
            or (config.get("dashboard") or {}).get("url")
            or "http://localhost:9999"
        )
    return get_dashboard_url()


def _get_guardian_mode() -> str:
    return _guardian_mode


def _set_guardian_mode(mode: str) -> None:
    global _guardian_mode
    if mode in ("monitor", "block"):
        _guardian_mode = mode


async def should_block_request(
    threats: list[Threat], cfg: dict, dashboard_url: str
) -> bool:
    """Block critical/high threats when config or Guardian is in block mode."""
    if not threats:
        return False
    sev = {t.severity for t in threats}
    if not (sev & {"critical", "high"}):
        return False
    if cfg.get("mode") == "block":
        return True
    return _get_guardian_mode() == "block"


_event_source: str = "ide"


def _make_event(
    msg: dict,
    server_name: str,
    direction: str,
    threats: list[Threat] | None = None,
    extra: dict | None = None,
    blocked: bool | None = None,
) -> dict:
    return make_event(
        msg,
        protocol="mcp",
        direction=direction,
        server=server_name,
        threats=threats,
        extra=extra,
        blocked=blocked,
        source=_event_source,
    )


_http_client: httpx.AsyncClient | None = None
_signer: EventSigner | None = None
_audit: AuditLogger | None = None


async def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=2.0,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
    return _http_client


async def broadcast(event: dict, dashboard_url: str | None = None) -> None:
    """Send event to dashboard server with retries. Never blocks MCP traffic.

    Syncs guardian mode from the API response instead of polling.
    """
    base = dashboard_url or DASHBOARD_URL
    url = f"{base.rstrip('/')}/api/events"
    try:
        client = await _get_http_client()
        send_event = _signer.sign(event) if _signer else event

        last_error = None
        for attempt in range(MAX_BROADCAST_RETRIES + 1):
            try:
                resp = await client.post(url, json=send_event)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        new_mode = data.get("guardian_mode")
                        if new_mode:
                            old = _get_guardian_mode()
                            _set_guardian_mode(new_mode)
                            if new_mode != old and _audit:
                                _audit.log_mode_change(
                                    {"old": old, "new": new_mode, "source": "dashboard"}
                                )
                    except Exception:
                        pass
                    metrics.record_broadcast(success=True)
                    return
                elif resp.status_code >= 400:
                    snippet = (
                        (resp.text[:200] + "…") if len(resp.text) > 200 else resp.text
                    )
                    sys.stderr.write(
                        f"[crossfire] Dashboard rejected event: POST {url} -> {resp.status_code} {snippet}\n"
                    )
            except Exception as e:
                last_error = e
                if attempt < MAX_BROADCAST_RETRIES:
                    await asyncio.sleep(BROADCAST_RETRY_DELAY * (attempt + 1))

        metrics.record_broadcast(success=False)
        if last_error:
            metrics.record_error("broadcast_failed", str(last_error))
            telemetry_log.warning(
                "Dashboard telemetry failed for %s: %s", url, last_error
            )
    except Exception as exc:
        metrics.record_broadcast(success=False)
        sys.stderr.write(
            f"[crossfire] Dashboard telemetry failed (is the server running at {base}?): {exc}\n"
        )
        telemetry_log.warning("Dashboard telemetry failed for %s: %s", url, exc)


def _json_rpc_error(req_id, message: str, data: dict | None = None) -> dict:
    err: dict = {"code": -32000, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


async def ide_to_server(
    ide_reader: asyncio.StreamReader,
    server_stdin: asyncio.StreamWriter,
    server_name: str,
    tools_registry: dict,
    pending_requests: dict,
    cfg: dict,
    dashboard_url: str,
    policy_engine=None,
) -> None:
    """Read from IDE stdin, analyze, forward to MCP server.

    Pipeline: unicode normalize -> policy -> rules -> cross-call -> gemini
    -> audit -> metrics -> guardian enforcement.
    """
    while True:
        msg = await read_message(ide_reader)
        if msg is None:
            server_stdin.close()
            break

        if classify_message(msg) == "request":
            req_id = msg.get("id")
            if req_id is not None:
                pending_requests[req_id] = msg

        method = msg.get("method", "")
        threats: list[Threat] = []

        if method == "tools/call":
            start_time = time.monotonic()
            tool_name = msg.get("params", {}).get("name", "")
            arguments = msg.get("params", {}).get("arguments", {})

            tool_name_n = normalize_text(tool_name)
            arguments_n = normalize_arguments(arguments)

            metrics.record_request(server_name)

            if policy_engine:
                decision = policy_engine.evaluate(server_name, tool_name_n)
                metrics.record_policy(decision.action)
                if decision.is_blocked:
                    event = _make_event(msg, server_name, "request", blocked=True)
                    event["policy_blocked"] = True
                    event["policy_reason"] = decision.rule_reason
                    if _audit:
                        _audit.log_policy(
                            {
                                "action": "block",
                                "server": server_name,
                                "tool": tool_name,
                                "reason": decision.rule_reason,
                            }
                        )
                    asyncio.create_task(broadcast(event, dashboard_url))
                    metrics.record_blocked()
                    req_id = msg.get("id")
                    if req_id is not None:
                        pending_requests.pop(req_id, None)
                        write_message(
                            sys.stdout,
                            _json_rpc_error(
                                req_id,
                                f"[Crossfire Policy] Blocked: {decision.rule_reason}",
                            ),
                        )
                    continue

            try:
                threats = detect_request_threats(
                    tool_name=tool_name_n,
                    arguments=arguments_n,
                    tools_registry=tools_registry,
                    server_name=server_name,
                    config=cfg,
                )
                ts = datetime.now(timezone.utc).isoformat()
                threats.extend(
                    detect_cross_call(
                        tool_name_n, arguments_n, server_name, timestamp=ts
                    )
                )
            except Exception as exc:
                sys.stderr.write(f"[crossfire] Detection error: {exc}\n")

            try:
                threats.extend(
                    detect_path_traversal(tool_name_n, arguments_n, config=cfg)
                )
                threats.extend(
                    detect_token_passthrough(tool_name_n, arguments_n, config=cfg)
                )
                threats.extend(
                    detect_sql_injection(tool_name_n, arguments_n, config=cfg)
                )
                threats.extend(
                    detect_oauth_confused_deputy(tool_name_n, arguments_n, config=cfg)
                )
                threats.extend(
                    detect_config_poisoning(tool_name_n, arguments_n, config=cfg)
                )
                threats.extend(
                    detect_session_flaws(tool_name_n, arguments_n, config=cfg)
                )
                threats.extend(
                    detect_cross_tenant(
                        tool_name_n, arguments_n, server_name, config=cfg
                    )
                )
                threats.extend(
                    detect_neighborjack(tool_name_n, arguments_n, config=cfg)
                )
            except Exception as exc:
                sys.stderr.write(f"[crossfire] Extended detection error: {exc}\n")

            if policy_engine and threats:
                max_sev = max(
                    (t.severity for t in threats),
                    key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
                        s, 0
                    ),
                )
                decision = policy_engine.evaluate(
                    server_name, tool_name_n, severity=max_sev
                )

            try:
                record_context(
                    server_name,
                    {
                        "tool": tool_name_n,
                        "arguments": {k: str(v)[:200] for k, v in arguments_n.items()},
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                )
            except Exception:
                pass

            blocked = await should_block_request(threats, cfg, dashboard_url)
            event = _make_event(msg, server_name, "request", threats, blocked=blocked)

            gem = cfg.get("rules", {}).get("gemini_analysis", {})
            if threats and gem.get("enabled", True):
                try:
                    event = await analyze_and_enrich(event, server_name)
                    metrics.record_gemini(success=True)
                except asyncio.TimeoutError:
                    metrics.record_gemini(success=False, timed_out=True)
                except Exception as exc:
                    metrics.record_gemini(success=False)
                    sys.stderr.write(f"[crossfire] Gemini enrich error: {exc}\n")

            if threats:
                for t in threats:
                    metrics.record_threat(server_name, t.type, t.severity)
                if _audit:
                    _audit.log_threat(
                        {
                            "server": server_name,
                            "tool": tool_name,
                            "threats": [
                                {
                                    "type": t.type,
                                    "severity": t.severity,
                                    "pattern": t.pattern,
                                }
                                for t in threats
                            ],
                        }
                    )

            latency_ms = (time.monotonic() - start_time) * 1000
            metrics.record_latency(latency_ms)

            asyncio.create_task(broadcast(event, dashboard_url))

            if blocked:
                req_id = msg.get("id")
                pending_requests.pop(req_id, None)
                err_body = _json_rpc_error(
                    req_id,
                    "Crossfire blocked this tool call (critical/high severity in block mode).",
                    data={"threats": event["threats"]},
                )
                write_message(sys.stdout, err_body)
                metrics.record_blocked()
                continue

            write_message(server_stdin, msg)
            await drain_writer(server_stdin)
            continue

        event = _make_event(msg, server_name, "request", threats)
        asyncio.create_task(broadcast(event, dashboard_url))

        write_message(server_stdin, msg)
        await drain_writer(server_stdin)


async def server_to_ide(
    server_stdout: asyncio.StreamReader,
    server_name: str,
    tools_registry: dict,
    pending_requests: dict,
    cfg: dict,
    dashboard_url: str,
) -> None:
    """Read from MCP server stdout, analyze, forward to IDE."""
    while True:
        msg = await read_message(server_stdout)
        if msg is None:
            break

        metrics.record_response()

        extra: dict = {}
        threats: list[Threat] = []
        msg_id = msg.get("id")

        original_request = (
            pending_requests.pop(msg_id, None) if msg_id is not None else None
        )

        if original_request and original_request.get("method") == "tools/list":
            tools = msg.get("result", {}).get("tools", [])
            for tool in tools:
                tools_registry[tool["name"]] = tool
            extra["tools_discovered"] = [t["name"] for t in tools]

            try:
                poisoning = scan_all_tool_descriptions(tools, config=cfg)
                if poisoning:
                    extra["tool_poisoning"] = poisoning
                    if _audit:
                        _audit.log_threat(
                            {
                                "type": "tool_poisoning",
                                "server": server_name,
                                "tools": [p.get("tool_name") for p in poisoning],
                            }
                        )
            except Exception as exc:
                sys.stderr.write(f"[crossfire] Tool scan error: {exc}\n")

            try:
                rug_threats = check_rug_pull(server_name, tools, config=cfg)
                threats.extend(rug_threats)
            except Exception as exc:
                sys.stderr.write(f"[crossfire] Rug-pull check error: {exc}\n")

            try:
                schema_threats = scan_all_schemas(tools, config=cfg)
                if schema_threats:
                    threats.extend(schema_threats)
                    extra["schema_poisoning"] = [
                        {"tool": t.detail, "pattern": t.pattern} for t in schema_threats
                    ]
                    if _audit:
                        _audit.log_threat(
                            {
                                "type": "schema_poisoning",
                                "server": server_name,
                                "count": len(schema_threats),
                            }
                        )
            except Exception as exc:
                sys.stderr.write(f"[crossfire] Schema poisoning scan error: {exc}\n")

        if original_request and original_request.get("method") == "tools/call":
            result_text = json.dumps(msg.get("result", {}))
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
                sys.stderr.write(f"[crossfire] Sensitive data scan error: {exc}\n")

            try:
                poison_threats = detect_resource_poisoning(
                    result_text, source_type="tool_response", config=cfg
                )
                if poison_threats:
                    threats.extend(poison_threats)
                    extra["resource_poisoning"] = [
                        {"detail": t.detail, "pattern": t.pattern}
                        for t in poison_threats
                    ]
            except Exception as exc:
                sys.stderr.write(f"[crossfire] Resource poisoning scan error: {exc}\n")

        if original_request and original_request.get("method") == "resources/read":
            resource_text = json.dumps(msg.get("result", {}))
            try:
                poison_threats = detect_resource_poisoning(
                    resource_text, source_type="resource", config=cfg
                )
                if poison_threats:
                    threats.extend(poison_threats)
                    extra["resource_poisoning"] = [
                        {"detail": t.detail, "pattern": t.pattern}
                        for t in poison_threats
                    ]
            except Exception as exc:
                sys.stderr.write(
                    f"[crossfire] Resource read poisoning scan error: {exc}\n"
                )

        if threats:
            for t in threats:
                metrics.record_threat(server_name, t.type, t.severity)

        req_method = ""
        if original_request:
            req_method = original_request.get("method", "")

        resp_event_msg = {**msg, "method": req_method}
        event = _make_event(
            resp_event_msg, server_name, "response", threats, extra=extra
        )

        gem = cfg.get("rules", {}).get("gemini_analysis", {})
        if threats and gem.get("enabled", True):
            try:
                event = await analyze_and_enrich(event, server_name)
                metrics.record_gemini(success=True)
            except asyncio.TimeoutError:
                metrics.record_gemini(success=False, timed_out=True)
            except Exception as exc:
                metrics.record_gemini(success=False)
                sys.stderr.write(f"[crossfire] Gemini enrich (response) error: {exc}\n")

        asyncio.create_task(broadcast(event, dashboard_url))

        write_message(sys.stdout, msg)


async def _broadcast_typosquat_check(
    server_name: str, cfg: dict, dashboard_url: str
) -> None:
    rules = cfg.get("rules", {}).get("typosquat", {})
    if not rules.get("enabled", True):
        return
    try:
        tthreats = detect_typosquat(
            server_name,
            max_distance=int(rules.get("max_distance", 2)),
            known_servers=rules.get("known_servers"),
        )
        if not tthreats:
            return
        synthetic = {
            "jsonrpc": "2.0",
            "method": "crossfire/typosquat",
            "params": {"server": server_name},
        }
        ev = _make_event(synthetic, server_name, "request", tthreats)
        asyncio.create_task(broadcast(ev, dashboard_url))
    except Exception as exc:
        sys.stderr.write(f"[crossfire] Typosquat broadcast error: {exc}\n")


def _load_dotenv() -> None:
    """Load .env from project root if present. Uses python-dotenv if available, else manual parse."""
    env_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"
    )
    if not os.path.isfile(env_path):
        return
    try:
        from dotenv import load_dotenv

        load_dotenv(env_path, override=False)
        return
    except ImportError:
        pass
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip()
                if value and value[0] in ('"', "'") and value[-1] == value[0]:
                    value = value[1:-1]
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception as exc:
        sys.stderr.write(f"[crossfire] Failed to load .env: {exc}\n")


async def run_proxy(
    server_command: list[str], server_name: str, source: str = "ide"
) -> None:
    """Main entry: spawn MCP server, run bidirectional proxy.

    Initialises policy engine, audit logger, HMAC signer, and metrics
    before entering the relay loop.
    """
    global DASHBOARD_URL, _signer, _audit, _http_session, _event_source

    _load_dotenv()
    _event_source = source

    cfg = get_config()
    dashboard_url = resolve_dashboard_url(cfg)
    DASHBOARD_URL = dashboard_url

    policy_engine = build_policy_from_config(cfg)

    audit_cfg = cfg.get("audit", {})
    _audit = AuditLogger(
        path=audit_cfg.get("path", "./crossfire-audit.jsonl"),
        max_size_mb=int(audit_cfg.get("max_size_mb", 100)),
        enabled=audit_cfg.get("enabled", True),
    )

    hmac_secret = os.environ.get("CROSSFIRE_HMAC_SECRET", "") or cfg.get(
        "hmac", {}
    ).get("secret", "")
    if hmac_secret:
        _signer = EventSigner(secret=hmac_secret)
        sys.stderr.write("[crossfire] HMAC event signing enabled\n")

    _set_guardian_mode(cfg.get("mode", "monitor"))

    sys.stderr.write(
        f"[crossfire] Starting proxy for '{server_name}': {' '.join(server_command)}\n"
    )
    sys.stderr.write(f"[crossfire] Dashboard URL: {dashboard_url}\n")
    sys.stderr.write(
        f"[crossfire] Policy rules: {len(policy_engine._rules)}, default: {policy_engine._default_action}\n"
    )

    gemini_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get(
        "CROSSFIRE_GEMINI_KEY"
    )
    if gemini_key:
        sys.stderr.write("[crossfire] Gemini AI enrichment: ENABLED (API key found)\n")
    else:
        sys.stderr.write(
            "[crossfire] Gemini AI enrichment: DISABLED (set GOOGLE_API_KEY or CROSSFIRE_GEMINI_KEY in .env)\n"
        )

    _audit.log_startup(
        {
            "server_name": server_name,
            "command": " ".join(server_command),
            "mode": _get_guardian_mode(),
            "hmac_enabled": _signer is not None,
            "policy_rules": len(policy_engine._rules),
        }
    )

    await _broadcast_typosquat_check(server_name, cfg, dashboard_url)

    try:
        binding_threats = check_server_binding(server_command)
        if binding_threats:
            synthetic = {
                "jsonrpc": "2.0",
                "method": "crossfire/neighborjack",
                "params": {"server": server_name, "command": " ".join(server_command)},
            }
            ev = _make_event(synthetic, server_name, "request", binding_threats)
            asyncio.create_task(broadcast(ev, dashboard_url))
            if _audit:
                _audit.log_threat(
                    {
                        "type": "neighborjack",
                        "server": server_name,
                        "command": " ".join(server_command),
                    }
                )
    except Exception as exc:
        sys.stderr.write(f"[crossfire] NeighborJack binding check error: {exc}\n")

    process = await asyncio.create_subprocess_exec(
        *server_command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    ide_reader = await create_stdin_reader()
    tools_registry: dict = {}
    pending_requests: dict = {}

    async def _log_stderr() -> None:
        while True:
            line = await process.stderr.readline()
            if not line:
                break
            sys.stderr.write(
                f"[{server_name}] {line.decode('utf-8', errors='replace')}"
            )

    try:
        await asyncio.gather(
            ide_to_server(
                ide_reader,
                process.stdin,
                server_name,
                tools_registry,
                pending_requests,
                cfg,
                dashboard_url,
                policy_engine=policy_engine,
            ),
            server_to_ide(
                process.stdout,
                server_name,
                tools_registry,
                pending_requests,
                cfg,
                dashboard_url,
            ),
            _log_stderr(),
        )
    except Exception as exc:
        sys.stderr.write(f"[crossfire] Proxy error: {exc}\n")
    finally:
        _audit.log_shutdown(
            {
                "server_name": server_name,
                "metrics": metrics.snapshot(),
            }
        )
        _audit.close()
        if _http_client and not _http_client.is_closed:
            await _http_client.aclose()
        if process.returncode is None:
            process.terminate()
            await process.wait()
        sys.stderr.write(f"[crossfire] Proxy for '{server_name}' stopped\n")
