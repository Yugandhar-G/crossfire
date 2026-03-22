"""NeighborJack (0.0.0.0 binding) detection.

Detects MCP servers or tool calls that expose services on all network
interfaces (0.0.0.0) instead of localhost-only, enabling LAN-based
attacks. Also detects DNS rebinding patterns and unsafe network bindings
in tool arguments. Reference: Adversa AI #13, Oligo Security research.
"""

import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

_UNSAFE_BIND_PATTERNS = [
    re.compile(r"(?:host|bind|listen)\s*[=:]\s*['\"]?0\.0\.0\.0", re.IGNORECASE),
    re.compile(r"(?:host|bind|listen)\s*[=:]\s*['\"]?::", re.IGNORECASE),
    re.compile(r"--host\s+0\.0\.0\.0"),
    re.compile(r"--bind\s+0\.0\.0\.0"),
    re.compile(r"-b\s+0\.0\.0\.0"),
    re.compile(r"INADDR_ANY"),
    re.compile(r"(?:0\.0\.0\.0|::):\d{1,5}"),
]

_DNS_REBINDING_PATTERNS = [
    re.compile(r"(?:127\.\d+\.\d+\.\d+)(?!\.)", re.IGNORECASE),
    re.compile(r"(?:localhost|127\.0\.0\.1)\.\S+\.\S+", re.IGNORECASE),
    re.compile(r"(?:nip\.io|xip\.io|sslip\.io|localtest\.me)", re.IGNORECASE),
]


def detect_neighborjack(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect unsafe network binding and DNS rebinding in tool arguments."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("neighborjack", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue

            for pattern in _UNSAFE_BIND_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="neighborjack_binding",
                            severity="high",
                            detail=f"Unsafe 0.0.0.0 binding in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="NEIGHBORJACK",
                        )
                    )
                    break

            for pattern in _DNS_REBINDING_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="dns_rebinding",
                            severity="high",
                            detail=f"DNS rebinding pattern in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="NEIGHBORJACK",
                        )
                    )
                    break

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] neighborjack error: {exc}\n")
        return []


def check_server_binding(command: list[str]) -> list[Threat]:
    """Check if an MCP server command uses unsafe network binding."""
    try:
        threats: list[Threat] = []
        cmd_str = " ".join(command)
        for pattern in _UNSAFE_BIND_PATTERNS:
            if pattern.search(cmd_str):
                threats.append(
                    Threat(
                        type="neighborjack_server_binding",
                        severity="high",
                        detail=f"MCP server command uses unsafe binding: {pattern.pattern}",
                        pattern="NEIGHBORJACK",
                    )
                )
                break
        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] neighborjack server check error: {exc}\n")
        return []
