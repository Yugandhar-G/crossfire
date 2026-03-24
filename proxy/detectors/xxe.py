"""XML External Entity (XXE) Injection detection.

Detects XXE payloads in tool arguments that attempt to read local files,
perform SSRF, or trigger denial of service via entity expansion (Billion
Laughs). Reference: OWASP XXE Prevention, CWE-611.
"""

import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

_XXE_PATTERNS = [
    # Entity declarations
    re.compile(r"<!ENTITY\s+", re.IGNORECASE),
    # External entity references
    re.compile(r"<!ENTITY\s+\S+\s+SYSTEM\s+", re.IGNORECASE),
    re.compile(r"<!ENTITY\s+\S+\s+PUBLIC\s+", re.IGNORECASE),
    # Parameter entities
    re.compile(r"<!ENTITY\s+%\s+", re.IGNORECASE),
    # DOCTYPE with external reference
    re.compile(r"<!DOCTYPE\s+\S+\s+SYSTEM\s+", re.IGNORECASE),
    re.compile(r"<!DOCTYPE\s+\S+\s+PUBLIC\s+", re.IGNORECASE),
    # DOCTYPE with embedded entities
    re.compile(r"<!DOCTYPE\s+\S+\s*\[", re.IGNORECASE),
    # Entity expansion (Billion Laughs / entity bomb)
    re.compile(r"&\w+;.*&\w+;.*&\w+;", re.DOTALL),
    # PHP/expect wrappers in entity
    re.compile(r"(?:expect|php|data|jar|gopher|dict)://", re.IGNORECASE),
    # file:// protocol in XML context
    re.compile(r"SYSTEM\s+['\"]file://", re.IGNORECASE),
    # XInclude
    re.compile(r"<xi:include\b", re.IGNORECASE),
    re.compile(r"xmlns:xi\s*=\s*['\"]http://www\.w3\.org/2001/XInclude", re.IGNORECASE),
]


def detect_xxe(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect XML External Entity injection patterns in tool arguments."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("xxe", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue

            for pattern in _XXE_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="xxe_injection",
                            severity="critical",
                            detail=f"XXE pattern in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="XXE",
                        )
                    )
                    break

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] xxe error: {exc}\n")
        return []
