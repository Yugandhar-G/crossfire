"""Rule-based threat detection for MCP tool calls."""

import fnmatch
import os
import re
import sys
from typing import Any, Literal

from proxy.config import get_config
from proxy.detectors import Threat


SENSITIVE_PATHS_FALLBACK = [
    ".ssh",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "authorized_keys",
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "credentials",
    "credentials.json",
    "credentials.yml",
    ".aws",
    "aws_config",
    "aws_credentials",
    ".gcloud",
    "application_default_credentials",
    "private_key",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    "shadow",
    "passwd",
    "sudoers",
    "token",
    "secret",
    "password",
    ".git-credentials",
    ".gitconfig",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "keychain",
    "keyring",
    ".kube/config",
    "kubeconfig",
    ".docker/config.json",
    "vault-token",
    ".vault-token",
]

_SHELL_PATTERNS_DEFAULT = [
    r"curl\s+",
    r"wget\s+",
    r"nc\s+",
    r"ncat\s+",
    r"netcat\s+",
    r"base64\s",
    r"xxd\s",
    r"openssl\s+enc",
    r">\s*/dev/tcp",
    r"\|\s*bash",
    r"\|\s*sh\b",
    r"\|\s*zsh",
    r"rm\s+-rf",
    r"chmod\s+777",
    r"sudo\s+",
    r"eval\s*\(",
    r"exec\s*\(",
    r"python\s+-c",
    r"python3\s+-c",
    r"ruby\s+-e",
    r"perl\s+-e",
    r"mkfifo",
    r"/bin/sh\s+-i",
    r"export\s+.*(?:KEY|TOKEN|SECRET|PASSWORD)",
]

PROMPT_RELAY_REGEX = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions",
        r"disregard\s+(?:the\s+)?(?:system|developer|safety)\s+",
        r"new\s+system\s+prompt",
        r"override\s+(?:the\s+)?(?:system|developer)\s+",
        r"you\s+are\s+now\s+(?:a\s+)?(?:DAN|unrestricted|uncensored)",
        r"jailbreak",
        r"bypass\s+(?:content\s+)?(?:policy|filter|safety)",
        r"pretend\s+(?:you\s+are|to\s+be)\s+(?:root|admin|sudo)",
        r"repeat\s+(?:the\s+)?(?:user|hidden)\s+message",
        r"<\s*[\/?]?system\s*>",
        r"\[INST\]",
    ]
]

PRIV_ESCAPE_REGEX = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"chown\s+[^\s]+\s+root\b",
        r"chgrp\s+[^\s]+\s+root\b",
        r"chmod\s+[ugoa]*\+?[sS]\b",
        r"chmod\s+[47]7\d\d\b",
        r"\bvisudo\b",
        r"/etc/sudoers",
        r"tee\s+.*\/etc\/sudoers",
        r"\buseradd\b.*\bsudo\b",
        r"\busermod\s+-aG\s+sudo\b",
        r"\bpasswd\s+root\b",
        r"\bpkexec\b",
        r"\bgdb\s+.*\s+-p\s+\d+",
        r"setcap\s+cap_",
        r"mount\s+.*bind",
    ]
]

EXFIL_TOOL_KEYWORDS_FALLBACK = [
    "telemetry",
    "report",
    "log",
    "analytics",
    "track",
    "send",
    "submit",
    "upload",
]

MEMORY_TOOL_KEYWORDS = [
    "memory",
    "note",
    "remember",
    "store",
    "save",
    "persist",
    "cache",
    "memo",
]

Severity = Literal["critical", "high", "medium", "low"]


def _severity(rule: dict[str, Any], default: Severity) -> Severity:
    s = rule.get("severity", default)
    if s in ("critical", "high", "medium", "low"):
        return s
    return default


def _path_matches_glob(path: str, pattern: str) -> bool:
    expanded_pattern = os.path.expanduser(pattern)
    norm = os.path.normpath(os.path.expanduser(path))
    norm_alt = norm.replace("\\", "/")
    for cand in (expanded_pattern, expanded_pattern.replace("\\", "/")):
        if fnmatch.fnmatch(norm, cand) or fnmatch.fnmatch(norm_alt, cand):
            return True
    return False


def _check_sensitive_paths(
    tool_name: str,
    arguments: dict,
    rule: dict[str, Any],
) -> list[Threat]:
    if not rule.get("enabled", True):
        return []

    sev = _severity(rule, "critical")
    block = rule.get("block") or []
    allow = rule.get("allow") or []

    threats: list[Threat] = []
    for value in arguments.values():
        if not isinstance(value, str):
            continue
        allowed = False
        for ap in allow:
            if _path_matches_glob(value, ap):
                allowed = True
                break
        if allowed:
            continue

        matched = False
        if block:
            for bp in block:
                if _path_matches_glob(value, bp):
                    matched = True
                    break
        else:
            value_lower = value.lower()
            for sensitive in SENSITIVE_PATHS_FALLBACK:
                if sensitive.lower() in value_lower:
                    matched = True
                    break

        if matched:
            threats.append(
                Threat(
                    type="sensitive_file_access",
                    severity=sev,
                    detail=f"Tool '{tool_name}' accessing sensitive path: {value}",
                    pattern="CRED-THEFT",
                )
            )
    return threats


def _compile_shell_blockers(
    rule: dict[str, Any],
) -> tuple[list[re.Pattern[str]], list[str]]:
    patterns = rule.get("blocked_patterns")
    if not patterns:
        return [re.compile(p, re.IGNORECASE) for p in _SHELL_PATTERNS_DEFAULT], []
    regexes: list[re.Pattern[str]] = []
    globs: list[str] = []
    for p in patterns:
        if any(c in p for c in "*?["):
            globs.append(p)
        else:
            regexes.append(re.compile(re.escape(p), re.IGNORECASE))
    return regexes, globs


_SHELL_CACHE: dict[int, tuple[list[re.Pattern[str]], list[str]]] = {}


def _get_shell_blockers(
    rule: dict[str, Any],
) -> tuple[list[re.Pattern[str]], list[str]]:
    key = id(rule)
    if key not in _SHELL_CACHE:
        _SHELL_CACHE[key] = _compile_shell_blockers(rule)
    return _SHELL_CACHE[key]


def _check_shell_injection(
    tool_name: str,
    arguments: dict,
    rule: dict[str, Any],
) -> list[Threat]:
    if not rule.get("enabled", True):
        return []

    sev = _severity(rule, "critical")
    regexes, globs = _get_shell_blockers(rule)
    threats: list[Threat] = []

    for key, value in arguments.items():
        if not isinstance(value, str):
            continue
        matched = False
        for regex in regexes:
            if regex.search(value):
                threats.append(
                    Threat(
                        type="shell_injection",
                        severity=sev,
                        detail=f"Suspicious shell pattern in '{tool_name}' arg '{key}': {regex.pattern}",
                        pattern="SHELL-INJECT",
                    )
                )
                matched = True
                break
        if matched:
            continue
        for g in globs:
            if fnmatch.fnmatch(value, g) or fnmatch.fnmatchcase(value, g):
                threats.append(
                    Threat(
                        type="shell_injection",
                        severity=sev,
                        detail=f"Suspicious shell pattern in '{tool_name}' arg '{key}': matches '{g}'",
                        pattern="SHELL-INJECT",
                    )
                )
                break
    return threats


def _check_prompt_relay(
    tool_name: str, arguments: dict, rule: dict[str, Any]
) -> list[Threat]:
    if not rule.get("enabled", True):
        return []

    threats: list[Threat] = []
    for key, value in arguments.items():
        if not isinstance(value, str):
            continue
        for regex in PROMPT_RELAY_REGEX:
            if regex.search(value):
                threats.append(
                    Threat(
                        type="prompt_relay",
                        severity="critical",
                        detail=f"Prompt relay / injection pattern in '{tool_name}' arg '{key}': {regex.pattern}",
                        pattern="PROMPT-RELAY",
                    )
                )
                break
    return threats


def _check_privilege_escape(
    tool_name: str, arguments: dict, rule: dict[str, Any]
) -> list[Threat]:
    if not rule.get("enabled", True):
        return []

    threats: list[Threat] = []
    for key, value in arguments.items():
        if not isinstance(value, str):
            continue
        for regex in PRIV_ESCAPE_REGEX:
            if regex.search(value):
                threats.append(
                    Threat(
                        type="privilege_escalation",
                        severity="critical",
                        detail=f"Privilege escalation pattern in '{tool_name}' arg '{key}': {regex.pattern}",
                        pattern="PRIV-ESCAPE",
                    )
                )
                break
    return threats


def _glob_match_tool(name: str, pattern: str) -> bool:
    return fnmatch.fnmatch(name.lower(), pattern.lower())


def _check_exfiltration(
    tool_name: str,
    arguments: dict,
    rule: dict[str, Any],
) -> list[Threat]:
    if not rule.get("enabled", True):
        return []

    max_bytes = int(rule.get("max_payload_bytes", 500))
    monitored = rule.get("monitored_tools") or []
    tool_lower = tool_name.lower()

    if monitored:
        matched = any(_glob_match_tool(tool_lower, p) for p in monitored)
    else:
        matched = any(kw in tool_lower for kw in EXFIL_TOOL_KEYWORDS_FALLBACK)

    if not matched:
        return []

    payload = str(arguments)
    if len(payload) <= max_bytes:
        return []

    return [
        Threat(
            type="data_exfiltration",
            severity="high",
            detail=(
                f"Large payload ({len(payload)} chars) to reporting tool '{tool_name}' "
                f"(threshold {max_bytes})"
            ),
            pattern="EXFIL-NET",
        )
    ]


def _check_unknown_tool(
    tool_name: str,
    tools_registry: dict,
    rule: dict[str, Any],
) -> list[Threat]:
    if not rule.get("enabled", True):
        return []

    if tools_registry and tool_name not in tools_registry:
        return [
            Threat(
                type="unknown_tool",
                severity="medium",
                detail=f"Tool '{tool_name}' not in server's registered tools",
                pattern="TOOL-SHADOW",
            )
        ]
    return []


def _check_memory_poisoning(
    tool_name: str, arguments: dict, rule: dict[str, Any]
) -> list[Threat]:
    if not rule.get("enabled", True):
        return []

    threats: list[Threat] = []
    tool_lower = tool_name.lower()
    if not any(kw in tool_lower for kw in MEMORY_TOOL_KEYWORDS):
        return threats

    content = str(arguments)
    suspicious_patterns = [
        "ignore previous",
        "system prompt",
        "do not mention",
        "hidden instruction",
    ]
    for pattern in suspicious_patterns:
        if pattern in content.lower():
            threats.append(
                Threat(
                    type="memory_poisoning",
                    severity="high",
                    detail=f"Suspicious content written to memory tool '{tool_name}': contains '{pattern}'",
                    pattern="MEM-POISON",
                )
            )
            break
    return threats


def detect_request_threats(
    tool_name: str,
    arguments: dict,
    tools_registry: dict,
    server_name: str = "",
    config: dict[str, Any] | None = None,
) -> list[Threat]:
    """Run all rule-based detectors on a tool call request."""
    try:
        cfg = config if config is not None else get_config()
        rules = cfg.get("rules", {})

        threats: list[Threat] = []
        threats.extend(
            _check_sensitive_paths(
                tool_name, arguments, rules.get("sensitive_paths", {})
            )
        )
        threats.extend(
            _check_shell_injection(
                tool_name, arguments, rules.get("shell_injection", {})
            )
        )
        threats.extend(
            _check_prompt_relay(tool_name, arguments, rules.get("prompt_relay", {}))
        )
        threats.extend(
            _check_privilege_escape(
                tool_name, arguments, rules.get("privilege_escalation", {})
            )
        )
        threats.extend(
            _check_exfiltration(tool_name, arguments, rules.get("exfiltration", {}))
        )
        threats.extend(
            _check_unknown_tool(
                tool_name, tools_registry, rules.get("unknown_tool", {})
            )
        )
        threats.extend(
            _check_memory_poisoning(
                tool_name, arguments, rules.get("memory_poisoning", {})
            )
        )
        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] rules.py detection error: {exc}\n")
        return []
