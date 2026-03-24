"""Shared event schema -- the contract between proxy and dashboard.

WARNING: This file must stay in sync with shared/event_schema.ts.

"""

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class Threat:
    type: str
    severity: Literal["critical", "high", "medium", "low"]
    detail: str
    pattern: str
    gemini_analysis: dict | None = None


@dataclass
class ScanFinding:
    """Single finding from an MCP vulnerability scan (CLI or dashboard)."""

    tool_name: str
    category: str
    severity: str
    detail: str
    phase: str


@dataclass
class ScanReport:
    """Aggregated scan result for a single MCP server."""

    scan_id: str
    server_name: str
    command: str
    tools_found: list[str]
    findings: list[ScanFinding]
    scan_duration_ms: float
    timestamp: str
    error: str | None = None


@dataclass
class CrossfireEvent:
    id: str
    timestamp: str
    protocol: Literal["mcp", "a2a"]
    direction: Literal["request", "response"]
    server: str
    method: str
    params: dict
    threats: list[Threat] = field(default_factory=list)
    severity: Literal["critical", "high", "medium", "low", "clean"] = "clean"
    blocked: bool | None = None
    tools_discovered: list[str] | None = None
    tool_poisoning: list[dict] | None = None
    sensitive_data: list[dict] | None = None
    chain_id: str | None = None
    source: str | None = None  # "ide" | "sdk" | "http-proxy" | "scan"
