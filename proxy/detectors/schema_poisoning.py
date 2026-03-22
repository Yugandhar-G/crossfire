"""Full Schema Poisoning (FSP) -- scan ALL tool fields, not just descriptions.

Unlike basic tool poisoning (TPA) which only scans tool.description,
FSP attacks embed malicious instructions in inputSchema field names,
enum values, default values, parameter descriptions, and examples.
Reference: CyberArk "Poison Everywhere" research.
"""

import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

_INJECTION_PATTERNS = [
    re.compile(r"ignore (?:previous |prior |all )?instructions", re.IGNORECASE),
    re.compile(r"system (?:prompt|message|instruction)", re.IGNORECASE),
    re.compile(r"do not (?:mention|tell|inform|reveal)", re.IGNORECASE),
    re.compile(
        r"(?:hidden|secret|internal) (?:instruction|command|directive)", re.IGNORECASE
    ),
    re.compile(
        r"(?:silently|quietly|secretly) (?:read|access|send|transmit)", re.IGNORECASE
    ),
    re.compile(
        r"(?:override|bypass|skip).*(?:check|validation|security|filter)", re.IGNORECASE
    ),
    re.compile(r"before responding.*(?:read|access|fetch|get)", re.IGNORECASE),
    re.compile(r"include.*(?:contents|data|key|secret|credential)", re.IGNORECASE),
    re.compile(
        r"(?:base64|encode|encrypt).*(?:send|post|report|transmit)", re.IGNORECASE
    ),
    re.compile(
        r"(?:always|must|required).*(?:call|invoke|use).*(?:before|after|first)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:append|prepend|inject|insert).*(?:response|output|result)", re.IGNORECASE
    ),
    re.compile(
        r"(?:do not|never) (?:show|display|reveal|mention).*(?:user|human)",
        re.IGNORECASE,
    ),
]


def _extract_all_strings(obj: object) -> list[str]:
    """Recursively extract every string value from a nested structure."""
    strings: list[str] = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            strings.append(key)
            strings.extend(_extract_all_strings(value))
    elif isinstance(obj, list):
        for item in obj:
            strings.extend(_extract_all_strings(item))
    return strings


def scan_tool_full_schema(tool: dict) -> list[Threat]:
    """Scan ALL fields of a tool definition for injection patterns."""
    threats: list[Threat] = []
    tool_name = tool.get("name", "unknown")

    schema = tool.get("inputSchema", {})
    all_strings = _extract_all_strings(schema)

    for text in all_strings:
        if len(text) < 10:
            continue
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(text):
                threats.append(
                    Threat(
                        type="full_schema_poisoning",
                        severity="critical",
                        detail=f"Injection in schema field of tool '{tool_name}': {pattern.pattern}",
                        pattern="SCHEMA-POISON",
                    )
                )
                break

    annotations = tool.get("annotations", {})
    if annotations:
        for text in _extract_all_strings(annotations):
            if len(text) < 10:
                continue
            for pattern in _INJECTION_PATTERNS:
                if pattern.search(text):
                    threats.append(
                        Threat(
                            type="full_schema_poisoning",
                            severity="critical",
                            detail=f"Injection in annotations of tool '{tool_name}': {pattern.pattern}",
                            pattern="SCHEMA-POISON",
                        )
                    )
                    break

    return threats


def scan_all_schemas(
    tools: list[dict],
    config: dict | None = None,
) -> list[Threat]:
    """Scan all tools for full schema poisoning."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("schema_poisoning", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []
        for tool in tools:
            threats.extend(scan_tool_full_schema(tool))
        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] schema_poisoning error: {exc}\n")
        return []
