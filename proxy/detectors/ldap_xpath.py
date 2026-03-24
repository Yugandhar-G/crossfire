"""LDAP Injection and XPath Injection detection.

Detects injection attacks targeting LDAP directories and XML XPath
queries in tool arguments. Reference: OWASP LDAP Injection (CWE-90),
OWASP XPath Injection (CWE-643).
"""

import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

# --- LDAP Injection patterns ---
_LDAP_PATTERNS = [
    # LDAP filter injection
    re.compile(r"\)\s*\(\s*[&|!]\s*\("),  # )(| ( ...  or )(& ( ...
    re.compile(r"\(\s*[&|!]\s*\(\s*\w+\s*=\s*\*\s*\)"),  # (&(attr=*))
    re.compile(r"\*\)\s*\(\s*\w+\s*="),  # *)(uid=
    re.compile(r"\)\s*\(\s*\w+\s*=\s*\*"),  # )(cn=*
    re.compile(r"\x00"),  # null byte in LDAP
    re.compile(r"\\28|\\29|\\2a|\\5c", re.IGNORECASE),  # LDAP hex escapes for (, ), *, \
    # LDAP DN injection
    re.compile(r"(?:cn|uid|ou|dc|sn|mail)\s*=.*[,;].*(?:cn|uid|ou|dc)\s*=", re.IGNORECASE),
    # LDAP search scope manipulation
    re.compile(r"(?:objectClass|objectCategory)\s*=\s*\*", re.IGNORECASE),
    # Common LDAP injection payloads
    re.compile(r"\)\(\|"),
    re.compile(r"\)\(!\("),
    re.compile(r"\w+=\*\)\("),
]

# --- XPath Injection patterns ---
_XPATH_PATTERNS = [
    # XPath boolean injection
    re.compile(r"'\s*(?:or|and)\s+'[^']*'\s*=\s*'", re.IGNORECASE),
    re.compile(r'"\s*(?:or|and)\s+"[^"]*"\s*=\s*"', re.IGNORECASE),
    # XPath axis traversal
    re.compile(r"(?:ancestor|descendant|following|preceding|parent|child|self)\s*::", re.IGNORECASE),
    # XPath functions for enumeration
    re.compile(r"(?:string-length|substring|normalize-space|translate|concat)\s*\(.*\)\s*[<>=!]", re.IGNORECASE),
    re.compile(r"(?:count|position|last|name|local-name|namespace-uri)\s*\(\s*\)", re.IGNORECASE),
    # XPath comment injection
    re.compile(r"'\s*\]\s*/\s*/"),
    re.compile(r'"\s*\]\s*/\s*/'),
    # XPath union injection
    re.compile(r"\|\s*/\s*/"),
    # XPath blind injection (boolean/error-based)
    re.compile(r"'\s*(?:or|and)\s+(?:\d+\s*=\s*\d+|true\(\)|false\(\))", re.IGNORECASE),
    # XPath node extraction
    re.compile(r"/(?:child|descendant)::node\(\)", re.IGNORECASE),
    re.compile(r"//\*\[contains\(", re.IGNORECASE),
]


def detect_ldap_injection(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect LDAP injection patterns in tool arguments."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("ldap_injection", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue

            for pattern in _LDAP_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="ldap_injection",
                            severity="high",
                            detail=f"LDAP injection in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="LDAP-INJECT",
                        )
                    )
                    break

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] ldap_injection error: {exc}\n")
        return []


def detect_xpath_injection(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect XPath injection patterns in tool arguments."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("xpath_injection", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue

            for pattern in _XPATH_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="xpath_injection",
                            severity="high",
                            detail=f"XPath injection in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="XPATH-INJECT",
                        )
                    )
                    break

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] xpath_injection error: {exc}\n")
        return []
