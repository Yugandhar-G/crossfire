"""Server-Side Request Forgery (SSRF) detection.

Detects attempts to make MCP tools access internal services, cloud metadata
endpoints, or private network resources. Reference: OWASP SSRF Prevention,
CWE-918, AWS/GCP/Azure metadata endpoint attacks.
"""

import re
import sys
from ipaddress import ip_address, ip_network

from proxy.config import get_config
from proxy.detectors import Threat

# Cloud metadata endpoints
_METADATA_PATTERNS = [
    re.compile(r"169\.254\.169\.254", re.IGNORECASE),  # AWS/GCP metadata
    re.compile(r"metadata\.google\.internal", re.IGNORECASE),
    re.compile(r"metadata\.azure\.com", re.IGNORECASE),
    re.compile(r"100\.100\.100\.200", re.IGNORECASE),  # Alibaba Cloud
    re.compile(r"fd00:ec2::254", re.IGNORECASE),  # AWS IPv6 metadata
]

# Internal/private network patterns
_INTERNAL_PATTERNS = [
    re.compile(r"(?:https?://)?10\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    re.compile(r"(?:https?://)?172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"),
    re.compile(r"(?:https?://)?192\.168\.\d{1,3}\.\d{1,3}"),
    re.compile(r"(?:https?://)?127\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    re.compile(r"(?:https?://)?0\.0\.0\.0"),
    re.compile(r"(?:https?://)?localhost\b", re.IGNORECASE),
    re.compile(r"(?:https?://)?0x[0-9a-f]+\b", re.IGNORECASE),  # hex IP
    re.compile(r"(?:https?://)\[::1?\]"),  # IPv6 loopback
    re.compile(r"(?:https?://)\[fc[0-9a-f]{2}:", re.IGNORECASE),  # IPv6 ULA
    re.compile(r"(?:https?://)\[fe80:", re.IGNORECASE),  # IPv6 link-local
]

# Dangerous protocol schemes
_DANGEROUS_SCHEMES = [
    re.compile(r"\b(?:file|gopher|dict|ftp|ldap|tftp|jar)://", re.IGNORECASE),
    re.compile(r"\bdata:(?:text|application)/", re.IGNORECASE),
    re.compile(r"\bphp://(?:filter|input|fd|memory|temp)\b", re.IGNORECASE),
    re.compile(r"\bexpect://", re.IGNORECASE),
]

# URL-based SSRF bypass techniques
_BYPASS_PATTERNS = [
    re.compile(r"@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),  # user@ip
    re.compile(r"@localhost\b", re.IGNORECASE),
    re.compile(r"#.*@", re.IGNORECASE),  # fragment-based bypass
    re.compile(r"\\\.\d{1,3}\.\d{1,3}\.\d{1,3}"),  # backslash-based
    re.compile(r"(?:https?://.*){2,}"),  # double URL
    re.compile(r"\b0\d+\.\d+\.\d+\.\d+\b"),  # octal IP notation
]

# URL parameters that often control fetch targets
_URL_PARAM_NAMES = {
    "url", "uri", "endpoint", "target", "dest", "destination",
    "redirect", "redirect_uri", "redirect_url", "return_url",
    "next", "link", "href", "src", "source", "fetch", "load",
    "path", "file", "page", "callback", "webhook", "proxy",
}


def detect_ssrf(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect SSRF patterns in tool arguments."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("ssrf", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue

            # Cloud metadata endpoints (always critical)
            for pattern in _METADATA_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="ssrf_metadata",
                            severity="critical",
                            detail=f"Cloud metadata SSRF in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="SSRF",
                        )
                    )
                    break

            # Internal network access
            for pattern in _INTERNAL_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="ssrf_internal",
                            severity="high",
                            detail=f"Internal network SSRF in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="SSRF",
                        )
                    )
                    break

            # Dangerous protocol schemes
            for pattern in _DANGEROUS_SCHEMES:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="ssrf_protocol",
                            severity="high",
                            detail=f"Dangerous protocol in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="SSRF",
                        )
                    )
                    break

            # SSRF bypass techniques
            for pattern in _BYPASS_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="ssrf_bypass",
                            severity="high",
                            detail=f"SSRF bypass technique in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="SSRF",
                        )
                    )
                    break

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] ssrf error: {exc}\n")
        return []
