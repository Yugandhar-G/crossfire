"""Server-Side Template Injection (SSTI) detection.

Detects template injection payloads for Jinja2, Mako, Twig, ERB, Freemarker,
Velocity, Pug, Handlebars, and generic template engines. These allow
attackers to execute arbitrary code on the server via template rendering.
Reference: OWASP SSTI, CWE-1336, PortSwigger research.
"""

import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

_SSTI_PATTERNS = [
    # Jinja2 / Twig (Python / PHP)
    re.compile(r"\{\{.*(?:config|request|self|lipsum|cycler|joiner|namespace)\b", re.IGNORECASE),
    re.compile(r"\{\{.*\.__(?:class|mro|subclasses|init|globals|builtins)__"),
    re.compile(r"\{\%\s*(?:import|from|set|block|extends|include)\b"),
    re.compile(r"\{\{.*(?:os\.|subprocess\.|popen|system)\b"),
    # Math probe (common SSTI test: {{7*7}} = 49)
    re.compile(r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}"),
    # Mako (Python)
    re.compile(r"<%\s*(?:import|from|def|block|include)\b"),
    re.compile(r"\$\{.*(?:os\.|subprocess\.|__import__|exec|eval)\b"),
    # ERB (Ruby)
    re.compile(r"<%=?\s*.*(?:system|exec|`|%x\(|IO\.popen|Kernel\.)", re.IGNORECASE),
    re.compile(r"<%=?\s*`.*`\s*%>"),
    # Freemarker (Java)
    re.compile(r"<#assign\s+\w+\s*=\s*", re.IGNORECASE),
    re.compile(r"\$\{.*\.getClass\(\)"),
    re.compile(r'freemarker\.template\.utility\.Execute', re.IGNORECASE),
    re.compile(r"\?new\s*\(\s*\)"),
    # Velocity (Java)
    re.compile(r"#set\s*\(\s*\$\w+\s*="),
    re.compile(r"\$\w+\.getClass\(\)\.forName\("),
    # Pug / Jade
    re.compile(r"(?:^|\n)\s*-\s*(?:var|let|const)\s+\w+\s*=.*(?:require|process|child_process)"),
    # Handlebars / Mustache
    re.compile(r"\{\{#with\s+", re.IGNORECASE),
    re.compile(r"\{\{.*(?:constructor|prototype|__proto__)\b"),
    # Smarty (PHP)
    re.compile(r"\{(?:php|literal)\}", re.IGNORECASE),
    re.compile(r"\{.*\|(?:system|passthru|exec|shell_exec)\b", re.IGNORECASE),
    # Thymeleaf (Java)
    re.compile(r"th:(?:text|utext|attr)\s*=\s*['\"].*\$\{.*T\(java\.lang\.Runtime\)"),
    # Generic template RCE indicators
    re.compile(r"\{\{.*(?:eval|exec|system|popen|shell_exec|passthru)\s*\("),
    re.compile(r"\$\{.*Runtime\.getRuntime\(\)\.exec\("),
]


def detect_ssti(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect Server-Side Template Injection patterns in tool arguments."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("ssti", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue

            for pattern in _SSTI_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="ssti",
                            severity="critical",
                            detail=f"SSTI pattern in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="SSTI",
                        )
                    )
                    break

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] ssti error: {exc}\n")
        return []
