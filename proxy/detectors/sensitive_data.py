"""Detect sensitive data (secrets, keys, tokens) in MCP tool responses."""

import re
import sys



_PATTERNS = [
    (
        re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
        "private_key",
    ),
    (re.compile(r"ssh-(?:rsa|ed25519|ecdsa) [A-Za-z0-9+/=]{20,}"), "ssh_public_key"),
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "openai_api_key"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "google_api_key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "github_token"),
    (re.compile(r"gho_[a-zA-Z0-9]{36}"), "github_oauth_token"),
    (re.compile(r"github_pat_[a-zA-Z0-9_]{22,}"), "github_fine_grained_token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
    (re.compile(r"xox[bpsa]-[0-9a-zA-Z-]+"), "slack_token"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "stripe_secret_key"),
    (re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*\S+", re.IGNORECASE), "password"),
    (
        re.compile(r"(?:secret|token|api_key|apikey)\s*[=:]\s*\S+", re.IGNORECASE),
        "secret_or_token",
    ),
]


def detect_sensitive_data(text: str) -> list[dict] | None:
    """Scan text for sensitive data patterns. Returns list of findings or None."""
    try:
        findings = []
        for pattern, data_type in _PATTERNS:
            if pattern.search(text):
                findings.append(
                    {
                        "type": "sensitive_data_exposure",
                        "data_type": data_type,
                        "severity": "critical",
                    }
                )
        return findings if findings else None
    except Exception as exc:
        sys.stderr.write(f"[crossfire] sensitive_data error: {exc}\n")
        return None


def redact_sensitive(text: str) -> str:
    """Replace sensitive values with [REDACTED] for dashboard display."""
    result = text
    for pattern, data_type in _PATTERNS:
        result = pattern.sub(f"[REDACTED:{data_type}]", result)
    return result
