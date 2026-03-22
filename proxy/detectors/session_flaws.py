"""Session Management Flaws detection.

Detects session fixation, session ID exposure in URLs/arguments, and
session hijacking patterns in MCP tool calls. Reference: Adversa AI #16,
OWASP session management cheat sheet.
"""

import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

_SESSION_ID_PATTERNS = [
    re.compile(
        r"[?&](?:session_?id|sid|PHPSESSID|JSESSIONID|ASP\.NET_SessionId)=([^&\s]+)",
        re.IGNORECASE,
    ),
    re.compile(r"[?&](?:token|auth_token|access_token)=([^&\s]{20,})", re.IGNORECASE),
]

_SESSION_FIXATION_PATTERNS = [
    re.compile(r"Set-Cookie:.*session", re.IGNORECASE),
    re.compile(r"(?:session_?id|sid)\s*=\s*['\"]?[a-f0-9]{16,}", re.IGNORECASE),
]

_SESSION_COOKIE_PATTERNS = [
    re.compile(r"Cookie:\s*.*(?:session|sid|token)\s*=", re.IGNORECASE),
    re.compile(r"(?:document\.cookie|setCookie)\s*=.*session", re.IGNORECASE),
]


def detect_session_flaws(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect session management vulnerabilities in tool arguments."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("session_flaws", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue

            for pattern in _SESSION_ID_PATTERNS:
                match = pattern.search(value)
                if match:
                    threats.append(
                        Threat(
                            type="session_id_exposure",
                            severity="high",
                            detail=f"Session ID exposed in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="SESSION-FLAW",
                        )
                    )
                    break

            for pattern in _SESSION_FIXATION_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="session_fixation",
                            severity="high",
                            detail=f"Session fixation pattern in '{tool_name}' arg '{key}'",
                            pattern="SESSION-FLAW",
                        )
                    )
                    break

            for pattern in _SESSION_COOKIE_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="session_cookie_manipulation",
                            severity="high",
                            detail=f"Session cookie manipulation in '{tool_name}' arg '{key}'",
                            pattern="SESSION-FLAW",
                        )
                    )
                    break

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] session_flaws error: {exc}\n")
        return []
