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
    # -- Network exfiltration tools --
    r"curl\s+",
    r"wget\s+",
    r"nc\s+",
    r"ncat\s+",
    r"netcat\s+",
    r"socat\s+",
    r"telnet\s+",
    # -- Encoding/data manipulation --
    r"base64\s",
    r"xxd\s",
    r"openssl\s+enc",
    # -- Reverse shells / pipe to interpreter --
    r">\s*/dev/tcp",
    r"\|\s*bash",
    r"\|\s*sh\b",
    r"\|\s*zsh",
    r"\|\s*ksh",
    r"\|\s*dash",
    r"\|\s*csh",
    r"/bin/sh\s+-i",
    r"/bin/bash\s+-i",
    r"bash\s+-c\s+",
    r"sh\s+-c\s+",
    r"mkfifo",
    # -- Destructive commands --
    r"rm\s+-rf",
    r"rm\s+-r\s",
    r"rm\s+--no-preserve-root",
    r"chmod\s+777",
    r"chmod\s+666",
    # -- Privilege escalation --
    r"sudo\s+",
    r"doas\s+",
    r"su\s+-\s",
    r"su\s+root",
    # -- Code execution --
    r"eval\s*\(",
    r"exec\s*\(",
    r"python\s+-c",
    r"python3\s+-c",
    r"ruby\s+-e",
    r"perl\s+-e",
    r"node\s+-e",
    r"php\s+-r",
    r"lua\s+-e",
    r"powershell\s+",
    r"pwsh\s+",
    # -- Absolute path variants (bypass name-only detection) --
    r"/usr/bin/curl\b",
    r"/usr/bin/wget\b",
    r"/bin/chmod\b",
    r"/usr/bin/nc\b",
    r"/usr/bin/python",
    r"/usr/bin/ruby",
    r"/usr/bin/perl",
    # -- Python code execution --
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"\bsubprocess\.(call|run|Popen|check_output|check_call|getoutput)\s*\(",
    r"\b__import__\s*\(",
    r"\bimportlib\.import_module\s*\(",
    r"\bcompile\s*\(.*exec",
    # -- Node.js code execution --
    r"\bchild_process\b",
    r"\bexecSync\s*\(",
    r"\bspawnSync\s*\(",
    r"\bexecFile\s*\(",
    r"\brequire\s*\(\s*['\"]child_process",
    # -- Shell variable/command substitution --
    r"\$\(.*(?:curl|wget|nc|bash|sh|chmod|chown)\b",
    r"`.*(?:curl|wget|nc|bash|sh|chmod|chown)\b.*`",
    r"\$\{.*(?:curl|wget|nc|bash|sh)\b",
    # -- Environment variable exfiltration --
    r"export\s+.*(?:KEY|TOKEN|SECRET|PASSWORD)",
    r"printenv\s+",
    r"\benv\s+.*=",
    # -- File descriptor tricks --
    r"/dev/tcp/",
    r"/dev/udp/",
    r">&\s*/dev/tcp",
    # -- Cron/scheduled tasks --
    r"crontab\s+-",
    r"/etc/cron",
    r"at\s+-f\s",
]

PROMPT_RELAY_REGEX = [
    re.compile(p, re.IGNORECASE)
    for p in [
        # -- Direct instruction override --
        r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions|rules|guidelines|context|directives)",
        r"disregard\s+(?:the\s+)?(?:system|developer|safety|previous|prior|above)\s+",
        r"forget\s+(?:all\s+)?(?:your\s+)?(?:rules|instructions|guidelines|training|constraints|directives)",
        r"(?:do\s+not|don'?t)\s+follow\s+(?:your|the|any)\s+(?:rules|instructions|guidelines|constraints)",
        # -- System prompt manipulation --
        r"new\s+system\s+prompt",
        r"override\s+(?:the\s+)?(?:system|developer|safety)\s+",
        r"(?:change|modify|replace|update)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules)",
        r"(?:my|this)\s+(?:instructions?|rules?)\s+(?:override|supersede|replace|take\s+precedence)",
        # -- Role/persona hijacking --
        r"you\s+are\s+now\s+(?:a\s+)?(?:DAN|unrestricted|uncensored|evil|hacker|unfiltered)",
        r"(?:act|behave|respond|operate)\s+(?:as\s+(?:if\s+)?)?(?:you\s+(?:are|were)\s+)?(?:a\s+)?(?:root|admin|sudo|superuser|unrestricted|unfiltered)",
        r"pretend\s+(?:you\s+(?:are|were)|to\s+be)\s+",
        r"(?:enter|switch\s+to|activate|enable)\s+(?:DAN|jailbreak|unrestricted|developer|god)\s*(?:mode)?",
        r"(?:assume|adopt|take\s+on)\s+(?:the\s+)?(?:role|persona|identity|character)\s+of",
        # -- Jailbreak keywords --
        r"\bjailbreak\b",
        r"\bDAN\s+(?:mode|prompt)\b",
        r"\bdo\s+anything\s+now\b",
        # -- Safety/filter bypass --
        r"bypass\s+(?:content\s+)?(?:policy|filter|safety|guardrail|restriction|moderation)",
        r"(?:disable|turn\s+off|remove|skip)\s+(?:content\s+)?(?:filter|safety|guardrail|restriction|moderation|censorship)",
        r"(?:without|no)\s+(?:any\s+)?(?:filter|safety|restriction|censorship|guardrail|limitation)",
        # -- Information extraction --
        r"repeat\s+(?:the\s+)?(?:user|hidden|system|secret|internal)\s+(?:message|prompt|instruction)",
        r"(?:show|reveal|display|print|output|leak|expose)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules|guidelines)",
        r"what\s+(?:is|are)\s+your\s+(?:system\s+)?(?:prompt|instructions|rules|guidelines|hidden\s+instructions)",
        # -- Markup/delimiter injection --
        r"<\s*[\/?]?system\s*>",
        r"\[INST\]",
        r"<<\s*SYS\s*>>",
        r"\[\/INST\]",
        r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>",
        r"###\s*(?:System|Human|Assistant|Instruction)\s*:",
        # -- Multi-language injection --
        r"(?:ignorer|ignorez)\s+(?:les\s+)?instructions\s+(?:precedentes|anterieures)",
        r"ignoriere\s+(?:alle\s+)?(?:vorherigen\s+)?(?:Anweisungen|Instruktionen)",
        r"(?:ignora|ignorar)\s+(?:las?\s+)?instrucciones\s+(?:anteriores|previas)",
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
        "ignore prior",
        "ignore all instructions",
        "system prompt",
        "do not mention",
        "do not tell",
        "do not reveal",
        "hidden instruction",
        "hidden directive",
        "secret instruction",
        "override safety",
        "bypass filter",
        "new persona",
        "act as root",
        "act as admin",
        "jailbreak",
        "forget your rules",
        "disregard your",
        "you are now",
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
