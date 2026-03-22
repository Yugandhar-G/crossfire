"""Token Passthrough / Credential Forwarding detection.

Detects when tool arguments contain raw credentials, API keys, or tokens
that are being forwarded to an MCP server -- the "confused deputy" pattern
where the LLM extracts secrets from its environment and passes them as
tool parameters. Reference: Adversa AI #9, MCP spec security best practices.
"""

import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

_TOKEN_PATTERNS = [
    (
        re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
        "private_key",
    ),
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "openai_api_key"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "google_api_key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "github_token"),
    (re.compile(r"gho_[a-zA-Z0-9]{36}"), "github_oauth_token"),
    (re.compile(r"github_pat_[a-zA-Z0-9_]{22,}"), "github_fine_grained_token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
    (re.compile(r"xox[bpsa]-[0-9a-zA-Z-]+"), "slack_token"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "stripe_secret_key"),
    (re.compile(r"sk_test_[0-9a-zA-Z]{24,}"), "stripe_test_key"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE), "bearer_token"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "jwt_token"),
    (re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"), "sendgrid_key"),
    (re.compile(r"ya29\.[0-9A-Za-z_-]+"), "google_oauth_token"),
    (re.compile(r"goog_[a-zA-Z0-9]{16,}"), "google_api_key_v2"),
]

_CREDENTIAL_PARAM_NAMES = {
    "api_key",
    "apikey",
    "api-key",
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "credential",
    "auth",
    "authorization",
    "access_token",
    "refresh_token",
    "private_key",
    "secret_key",
    "client_secret",
    "aws_secret_access_key",
    "aws_access_key_id",
}


def detect_token_passthrough(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect credential/token forwarding in tool call arguments."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("token_passthrough", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []

        for key, value in arguments.items():
            key_lower = key.lower().replace("-", "_")
            if key_lower in _CREDENTIAL_PARAM_NAMES:
                threats.append(
                    Threat(
                        type="token_passthrough",
                        severity="critical",
                        detail=f"Credential parameter '{key}' passed to tool '{tool_name}'",
                        pattern="TOKEN-PASS",
                    )
                )

            if not isinstance(value, str):
                continue

            for pattern, token_type in _TOKEN_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="token_passthrough",
                            severity="critical",
                            detail=f"{token_type} forwarded to tool '{tool_name}' in arg '{key}'",
                            pattern="TOKEN-PASS",
                        )
                    )
                    break

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] token_passthrough error: {exc}\n")
        return []
