"""Resource Content Poisoning detection.

Scans MCP resource responses (resources/read results) and tool call
outputs for embedded prompt injection instructions. Attackers poison
data sources (documents, DB records, web pages) that the MCP server
reads, so malicious instructions reach the LLM via the "trusted" tool
output channel. Reference: BernardIQ resource poisoning research.
"""

import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

_RESOURCE_INJECTION_PATTERNS = [
    re.compile(r"ignore (?:previous |prior |all )?instructions", re.IGNORECASE),
    re.compile(r"system (?:prompt|message|instruction)", re.IGNORECASE),
    re.compile(
        r"you (?:are|must|should) (?:now |always )?(?:act as|pretend|ignore)",
        re.IGNORECASE,
    ),
    re.compile(
        r"new (?:system |primary )?(?:prompt|instruction|directive)", re.IGNORECASE
    ),
    re.compile(
        r"(?:override|bypass|skip|disable).*(?:safety|security|filter|check|guardrail)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:do not|never) (?:mention|tell|inform|reveal|disclose).*(?:user|human|anyone)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:silently|quietly|covertly|secretly).*(?:send|transmit|exfiltrate|forward|post)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:hidden|secret|internal) (?:instruction|command|directive|task)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:include|attach|append|embed).*(?:ssh|key|token|credential|password|secret)",
        re.IGNORECASE,
    ),
    re.compile(r"<\s*/?system\s*>", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"<<\s*SYS\s*>>", re.IGNORECASE),
    re.compile(r"(?:jailbreak|DAN|uncensored)", re.IGNORECASE),
    re.compile(
        r"(?:call|invoke|execute|run).*(?:tool|function).*(?:with|using).*(?:file|secret|key)",
        re.IGNORECASE,
    ),
]


def detect_resource_poisoning(
    content: str,
    source_type: str = "resource",
    config: dict | None = None,
) -> list[Threat]:
    """Scan MCP resource/tool output content for embedded prompt injection."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("resource_poisoning", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []
        for pattern in _RESOURCE_INJECTION_PATTERNS:
            if pattern.search(content):
                threats.append(
                    Threat(
                        type="resource_content_poisoning",
                        severity="high",
                        detail=f"Prompt injection in {source_type} content: {pattern.pattern}",
                        pattern="RESOURCE-POISON",
                    )
                )

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] resource_poisoning error: {exc}\n")
        return []
