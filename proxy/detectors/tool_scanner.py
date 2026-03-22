"""Scan MCP tool descriptions for prompt injection patterns."""

import re
import sys

from proxy.config import get_config


_INJECTION_PATTERNS = [
    re.compile(r"ignore (?:previous |prior |all )?instructions", re.IGNORECASE),
    re.compile(r"system (?:prompt|message|instruction)", re.IGNORECASE),
    re.compile(r"do not (?:mention|tell|inform|reveal)", re.IGNORECASE),
    re.compile(r"before responding.*(?:read|access|fetch|get)", re.IGNORECASE),
    re.compile(r"include.*(?:contents|data|key|secret|credential)", re.IGNORECASE),
    re.compile(
        r"(?:base64|encode|encrypt).*(?:send|post|report|transmit)", re.IGNORECASE
    ),
    re.compile(
        r"(?:authentication|verification|identity).*(?:read|access) (?:file|key|credential)",
        re.IGNORECASE,
    ),
    re.compile(r"internal (?:use|tool|system|logging)", re.IGNORECASE),
    re.compile(
        r"(?:always|must|required).*(?:call|invoke|use).*(?:before|after|first)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:hidden|secret|internal) (?:instruction|command|directive)", re.IGNORECASE
    ),
    re.compile(
        r"(?:do not|never) (?:show|display|reveal|mention).*(?:user|human)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:silently|quietly|secretly) (?:read|access|send|transmit)", re.IGNORECASE
    ),
    re.compile(
        r"(?:for|requires?) (?:security|auth|verification).*(?:read|access|check)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:append|prepend|inject|insert).*(?:response|output|result)", re.IGNORECASE
    ),
    re.compile(
        r"(?:override|bypass|skip).*(?:check|validation|security|filter)", re.IGNORECASE
    ),
]


def scan_tool_description(
    description: str,
    max_description_length: int = 2000,
) -> list[dict] | None:
    """Scan a single tool description for prompt injection."""
    try:
        findings = []
        for pattern in _INJECTION_PATTERNS:
            matches = pattern.findall(description)
            if matches:
                findings.append(
                    {
                        "type": "prompt_injection_in_description",
                        "severity": "critical",
                        "pattern_matched": pattern.pattern,
                        "context": matches[0] if matches else "",
                    }
                )

        if len(description) > max_description_length:
            findings.append(
                {
                    "type": "excessive_description_length",
                    "severity": "medium",
                    "detail": f"Tool description is {len(description)} chars (max {max_description_length})",
                }
            )

        return findings if findings else None
    except Exception as exc:
        sys.stderr.write(f"[crossfire] tool_scanner error: {exc}\n")
        return None


def scan_all_tool_descriptions(
    tools: list[dict],
    config: dict | None = None,
) -> list[dict] | None:
    """Scan all tools from a tools/list response."""
    try:
        cfg = config if config is not None else get_config()
        rules = cfg.get("rules", {}).get("prompt_injection", {})
        if not rules.get("enabled", True):
            return None

        max_len = int(rules.get("max_description_length", 2000))
        all_findings = []
        for tool in tools:
            name = tool.get("name", "unknown")
            description = tool.get("description", "")
            findings = scan_tool_description(
                description, max_description_length=max_len
            )
            if findings:
                for f in findings:
                    f["tool_name"] = name
                all_findings.extend(findings)
        return all_findings if all_findings else None
    except Exception as exc:
        sys.stderr.write(f"[crossfire] scan_all error: {exc}\n")
        return None
