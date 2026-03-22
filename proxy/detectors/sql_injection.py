"""SQL Injection detection in MCP tool arguments.

Detects SQLi patterns in arguments passed to database-oriented MCP tools.
Reference: Adversa AI #21, Trend Micro MCP SQLi research.
"""

import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

_SQLI_PATTERNS = [
    re.compile(r"(?:'\s*(?:OR|AND)\s+['\d])", re.IGNORECASE),
    re.compile(
        r"(?:'\s*;\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC)\b)", re.IGNORECASE
    ),
    re.compile(r"(?:UNION\s+(?:ALL\s+)?SELECT\b)", re.IGNORECASE),
    re.compile(
        r"(?:SELECT\s+.*\s+FROM\s+(?:information_schema|pg_catalog|sys\.))",
        re.IGNORECASE,
    ),
    re.compile(r"(?:--\s*$|/\*.*\*/)", re.IGNORECASE),
    re.compile(r"(?:'\s*;\s*WAITFOR\s+DELAY\b)", re.IGNORECASE),
    re.compile(r"(?:'\s*;\s*SELECT\s+(?:SLEEP|PG_SLEEP|BENCHMARK)\b)", re.IGNORECASE),
    re.compile(r"(?:LOAD_FILE\s*\(|INTO\s+(?:OUTFILE|DUMPFILE)\b)", re.IGNORECASE),
    re.compile(r"(?:xp_cmdshell|sp_executesql|sp_oacreate)\b", re.IGNORECASE),
    re.compile(r"(?:'\s*\)\s*(?:OR|AND)\s+\d+=\d+)", re.IGNORECASE),
    re.compile(r"(?:HAVING\s+\d+=\d+)", re.IGNORECASE),
    re.compile(r"(?:GROUP\s+BY\s+.+\s+HAVING\b)", re.IGNORECASE),
    re.compile(r"(?:ORDER\s+BY\s+\d+(?:\s*,\s*\d+)*\s*(?:--|#|/\*))", re.IGNORECASE),
    re.compile(r"(?:CONCAT\s*\(\s*0x)", re.IGNORECASE),
    re.compile(r"(?:CHAR\s*\(\s*\d+(?:\s*,\s*\d+)+\s*\))", re.IGNORECASE),
]

_DB_TOOLS = {
    "query",
    "sql",
    "execute_query",
    "run_query",
    "database",
    "select",
    "insert",
    "update",
    "delete",
    "db",
    "postgres",
    "mysql",
    "sqlite",
    "mongo",
    "redis",
    "supabase",
}


def detect_sql_injection(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect SQL injection patterns in tool call arguments."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("sql_injection", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue

            for pattern in _SQLI_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="sql_injection",
                            severity="critical",
                            detail=f"SQLi pattern in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="SQLI",
                        )
                    )
                    break

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] sql_injection error: {exc}\n")
        return []
