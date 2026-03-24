"""Cross-Site Scripting (XSS) detection in tool arguments and responses.

Detects XSS payloads that could be injected through tool arguments or
returned in tool responses that may be rendered in a browser context.
Reference: OWASP XSS Prevention, CWE-79.
"""

import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

_XSS_PATTERNS = [
    # Script tags
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"</\s*script\s*>", re.IGNORECASE),
    # Event handlers
    re.compile(
        r"\bon(?:load|error|click|mouseover|mouseout|focus|blur|submit|change|input"
        r"|keydown|keyup|keypress|dblclick|contextmenu|wheel|copy|cut|paste"
        r"|drag|drop|animationend|transitionend|resize|scroll|touchstart"
        r"|pointerdown|message|hashchange|popstate|beforeunload|unload"
        r"|storage|pageshow|pagehide|abort)\s*=",
        re.IGNORECASE,
    ),
    # JavaScript URI scheme
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"vbscript\s*:", re.IGNORECASE),
    re.compile(r"livescript\s*:", re.IGNORECASE),
    # Data URI with script
    re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
    # SVG-based XSS
    re.compile(r"<\s*svg\b[^>]*\bon\w+\s*=", re.IGNORECASE),
    re.compile(r"<\s*svg\b.*<\s*script\b", re.IGNORECASE | re.DOTALL),
    # iframe injection
    re.compile(r"<\s*iframe\b", re.IGNORECASE),
    # Object/embed/applet
    re.compile(r"<\s*(?:object|embed|applet)\b", re.IGNORECASE),
    # img with event handler
    re.compile(r"<\s*img\b[^>]*\bon\w+\s*=", re.IGNORECASE),
    # body/div/input with event handler
    re.compile(r"<\s*(?:body|div|input|form|select|textarea|button|a|details|marquee|video|audio|source|meta)\b[^>]*\bon\w+\s*=", re.IGNORECASE),
    # Expression/eval in CSS
    re.compile(r"expression\s*\(", re.IGNORECASE),
    re.compile(r"(?:behavior|binding)\s*:", re.IGNORECASE),
    # Template literals used for XSS
    re.compile(r"\$\{.*(?:document|window|alert|confirm|prompt|fetch|XMLHttpRequest)\b"),
    # DOM manipulation
    re.compile(r"(?:document\.(?:write|writeln|cookie|location|domain)|window\.(?:location|open)|\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|eval\s*\()", re.IGNORECASE),
    # Angular/Vue template injection
    re.compile(r"\{\{.*(?:constructor|__proto__|prototype)\b"),
    re.compile(r"ng-\w+\s*=\s*['\"].*(?:\$eval|constructor)\b", re.IGNORECASE),
]


def detect_xss(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect XSS patterns in tool arguments."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("xss", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue

            for pattern in _XSS_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="xss",
                            severity="high",
                            detail=f"XSS pattern in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="XSS",
                        )
                    )
                    break

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] xss error: {exc}\n")
        return []


def detect_xss_in_response(
    content: str,
    config: dict | None = None,
) -> list[Threat]:
    """Detect XSS patterns in tool response content."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("xss", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []
        for pattern in _XSS_PATTERNS:
            if pattern.search(content):
                threats.append(
                    Threat(
                        type="xss_in_response",
                        severity="high",
                        detail=f"XSS pattern in response content: {pattern.pattern}",
                        pattern="XSS",
                    )
                )

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] xss response error: {exc}\n")
        return []
