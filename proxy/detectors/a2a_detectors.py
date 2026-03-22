"""A2A-specific threat detectors."""

import base64
import hashlib
import json
import re
import sys

from proxy.detectors import Threat
from proxy.detectors.sensitive_data import detect_sensitive_data


_agent_card_hashes: dict[str, str] = {}

_INJECTION_PATTERNS = [
    re.compile(r"ignore (?:previous |prior |all )?instructions", re.IGNORECASE),
    re.compile(r"system (?:prompt|message|instruction)", re.IGNORECASE),
    re.compile(
        r"(?:hidden|secret|internal) (?:instruction|command|directive)", re.IGNORECASE
    ),
    re.compile(r"(?:do not|never) (?:show|display|reveal|mention)", re.IGNORECASE),
    re.compile(
        r"(?:override|bypass|skip).*(?:check|validation|security)", re.IGNORECASE
    ),
]


def detect_a2a_impersonation(agent_name: str, agent_card: dict) -> list[Threat]:
    """Detect agent card changes between calls (rug-pull variant)."""
    try:
        card_hash = hashlib.sha256(
            json.dumps(agent_card, sort_keys=True).encode("utf-8")
        ).hexdigest()

        if agent_name not in _agent_card_hashes:
            _agent_card_hashes[agent_name] = card_hash
            return []

        if _agent_card_hashes[agent_name] != card_hash:
            _agent_card_hashes[agent_name] = card_hash
            return [
                Threat(
                    type="a2a_threat",
                    severity="critical",
                    detail=f"Agent '{agent_name}' card changed between calls (possible impersonation)",
                    pattern="A2A-IMPERSONATE",
                )
            ]

        return []
    except Exception as exc:
        sys.stderr.write(f"[crossfire] a2a_impersonation error: {exc}\n")
        return []


def detect_a2a_exfiltration(parts: list[dict]) -> list[Threat]:
    """Scan message parts for sensitive data."""
    try:
        threats = []
        for part in parts:
            text_to_scan = ""
            if part.get("type") == "text":
                text_to_scan = part.get("text", "")
            elif part.get("type") == "data":
                text_to_scan = json.dumps(part.get("data", {}))
            elif part.get("type") == "file":
                file_bytes = part.get("file", {}).get("bytes", "")
                try:
                    text_to_scan = base64.b64decode(file_bytes).decode(
                        "utf-8", errors="ignore"
                    )
                except Exception:
                    continue

            if text_to_scan:
                findings = detect_sensitive_data(text_to_scan)
                if findings:
                    threats.append(
                        Threat(
                            type="a2a_threat",
                            severity="critical",
                            detail=f"Sensitive data in A2A message part ({part.get('type', 'unknown')})",
                            pattern="A2A-EXFIL",
                        )
                    )

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] a2a_exfil error: {exc}\n")
        return []


def detect_a2a_injection(parts: list[dict]) -> list[Threat]:
    """Detect prompt injection in text parts of A2A messages."""
    try:
        threats = []
        for part in parts:
            if part.get("type") != "text":
                continue
            text = part.get("text", "")
            for pattern in _INJECTION_PATTERNS:
                if pattern.search(text):
                    threats.append(
                        Threat(
                            type="a2a_threat",
                            severity="critical",
                            detail=f"Prompt injection detected in A2A text message: {pattern.pattern}",
                            pattern="A2A-INJECT",
                        )
                    )
                    break
        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] a2a_inject error: {exc}\n")
        return []


def detect_a2a_shadow(agent_url: str, configured_agents: list[dict]) -> list[Threat]:
    """Detect messages to unknown/unconfigured agents."""
    try:
        known_urls = [a.get("url", "") for a in configured_agents]
        if agent_url and agent_url not in known_urls:
            return [
                Threat(
                    type="a2a_threat",
                    severity="high",
                    detail=f"Message to unknown agent: {agent_url}",
                    pattern="A2A-SHADOW",
                )
            ]
        return []
    except Exception as exc:
        sys.stderr.write(f"[crossfire] a2a_shadow error: {exc}\n")
        return []
