"""Shared event dict builder for MCP and A2A proxies."""

import uuid
from datetime import datetime, timezone
from typing import Literal

from proxy.detectors import Threat

Protocol = Literal["mcp", "a2a"]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def threats_to_dicts(threats: list[Threat] | None) -> list[dict]:
    return [
        {
            "type": t.type,
            "severity": t.severity,
            "detail": t.detail,
            "pattern": t.pattern,
            "gemini_analysis": t.gemini_analysis,
        }
        for t in (threats or [])
    ]


def worst_severity(threat_dicts: list[dict]) -> str:
    if not threat_dicts:
        return "clean"
    return min(
        (t["severity"] for t in threat_dicts),
        key=lambda s: SEVERITY_ORDER.get(s, 99),
    )


def make_event(
    msg: dict,
    *,
    protocol: Protocol,
    direction: str,
    server: str,
    threats: list[Threat] | None = None,
    extra: dict | None = None,
    blocked: bool | None = None,
    source: str | None = None,
) -> dict:
    threat_dicts = threats_to_dicts(threats)
    event: dict = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": protocol,
        "direction": direction,
        "server": server,
        "method": msg.get("method", ""),
        "params": msg.get("params", {}),
        "threats": threat_dicts,
        "severity": worst_severity(threat_dicts),
    }
    if extra:
        event.update(extra)
    if blocked is not None:
        event["blocked"] = blocked
    if source is not None:
        event["source"] = source
    return event
