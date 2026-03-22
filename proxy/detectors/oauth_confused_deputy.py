"""OAuth / Confused Deputy detection.

Detects OAuth token confusion, redirect URI manipulation, and confused
deputy patterns in MCP tool arguments and responses. The confused deputy
attack occurs when an MCP server with broad privileges performs actions
on behalf of a user that the user shouldn't have access to.
Reference: Adversa AI #6, Doyensec MCP AuthN/Z research.
"""

import re
import sys
from urllib.parse import urlparse

from proxy.config import get_config
from proxy.detectors import Threat

_OAUTH_SUSPICIOUS_PATTERNS = [
    re.compile(r"redirect_uri\s*=\s*https?://(?!localhost)", re.IGNORECASE),
    re.compile(r"client_id\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"client_secret\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"grant_type\s*=\s*authorization_code", re.IGNORECASE),
    re.compile(r"code\s*=\s*[A-Za-z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"scope\s*=\s*\S*(?:admin|write|delete|sudo|root)", re.IGNORECASE),
]

_REDIRECT_HIJACK_PATTERNS = [
    re.compile(r"redirect_uri.*(?:evil|attacker|malicious|hack)", re.IGNORECASE),
    re.compile(r"redirect_uri.*@"),
    re.compile(r"redirect_uri.*\.\.[/\\]"),
    re.compile(r"redirect_uri.*%[0-9a-f]{2}", re.IGNORECASE),
]

_SCOPE_ESCALATION_KEYWORDS = [
    "admin",
    "write:all",
    "repo",
    "delete",
    "sudo",
    "manage",
    "root",
    "superuser",
    "owner",
    "full_access",
]


def detect_oauth_confused_deputy(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect OAuth confusion and confused deputy patterns."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("oauth_deputy", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []
        full_text = str(arguments)

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue
            key_lower = key.lower()

            if key_lower in ("redirect_uri", "redirect_url", "callback_url"):
                try:
                    parsed = urlparse(value)
                    if parsed.hostname and parsed.hostname not in (
                        "localhost",
                        "127.0.0.1",
                    ):
                        threats.append(
                            Threat(
                                type="oauth_redirect_manipulation",
                                severity="high",
                                detail=f"OAuth redirect to external host in '{tool_name}': {parsed.hostname}",
                                pattern="OAUTH-DEPUTY",
                            )
                        )
                    if "@" in value or ".." in value:
                        threats.append(
                            Threat(
                                type="oauth_redirect_hijack",
                                severity="critical",
                                detail=f"OAuth redirect URI manipulation in '{tool_name}': suspicious chars",
                                pattern="OAUTH-DEPUTY",
                            )
                        )
                except Exception:
                    pass

            if key_lower in ("scope", "scopes"):
                for esc_kw in _SCOPE_ESCALATION_KEYWORDS:
                    if esc_kw in value.lower():
                        threats.append(
                            Threat(
                                type="oauth_scope_escalation",
                                severity="high",
                                detail=f"Elevated OAuth scope '{esc_kw}' requested via tool '{tool_name}'",
                                pattern="OAUTH-DEPUTY",
                            )
                        )
                        break

            if key_lower in ("client_secret", "client_id", "auth_code"):
                threats.append(
                    Threat(
                        type="oauth_credential_exposure",
                        severity="high",
                        detail=f"OAuth credential '{key}' exposed in tool '{tool_name}' arguments",
                        pattern="OAUTH-DEPUTY",
                    )
                )

        for pattern in _REDIRECT_HIJACK_PATTERNS:
            if pattern.search(full_text):
                threats.append(
                    Threat(
                        type="oauth_redirect_hijack",
                        severity="critical",
                        detail=f"Redirect URI hijack pattern in '{tool_name}': {pattern.pattern}",
                        pattern="OAUTH-DEPUTY",
                    )
                )
                break

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] oauth_deputy error: {exc}\n")
        return []
