"""Cross-Tenant Data Exposure detection.

Detects tenant isolation failures where data or credentials from one
tenant context are being accessed or leaked to another. Monitors for
tenant ID switching, cross-org data access patterns, and shared context
leakage. Reference: Adversa AI #25, Asana MCP bug disclosure.
"""

import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

_TENANT_ID_PARAMS = {
    "tenant_id",
    "tenant",
    "org_id",
    "organization_id",
    "workspace_id",
    "workspace",
    "account_id",
    "account",
    "team_id",
    "team",
    "company_id",
    "project_id",
}

_CROSS_TENANT_PATTERNS = [
    re.compile(
        r"(?:switch|change|set)\s+(?:tenant|org|workspace|account)", re.IGNORECASE
    ),
    re.compile(
        r"(?:as|for|on behalf of)\s+(?:tenant|org|workspace|account)\s+\S+",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:all|every|each)\s+(?:tenants?|orgs?|workspaces?|accounts?)", re.IGNORECASE
    ),
    re.compile(
        r"(?:cross|multi|inter)\s*[-_]?\s*(?:tenant|org|workspace|account)",
        re.IGNORECASE,
    ),
]


class TenantTracker:
    """Track tenant context across tool calls to detect switching."""

    def __init__(self):
        self._current_tenant: dict[str, str] = {}

    def check(
        self,
        tool_name: str,
        arguments: dict,
        server_name: str,
    ) -> list[Threat]:
        threats: list[Threat] = []

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue
            key_lower = key.lower().replace("-", "_")

            if key_lower in _TENANT_ID_PARAMS:
                prev = self._current_tenant.get(server_name)
                if prev is not None and prev != value:
                    threats.append(
                        Threat(
                            type="cross_tenant_switch",
                            severity="high",
                            detail=(
                                f"Tenant context switched in '{tool_name}' on server '{server_name}': "
                                f"'{prev}' -> '{value}'"
                            ),
                            pattern="CROSS-TENANT",
                        )
                    )
                self._current_tenant[server_name] = value

            for pattern in _CROSS_TENANT_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="cross_tenant_access",
                            severity="high",
                            detail=f"Cross-tenant access pattern in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="CROSS-TENANT",
                        )
                    )
                    break

        return threats


_tracker = TenantTracker()


def detect_cross_tenant(
    tool_name: str,
    arguments: dict,
    server_name: str = "",
    config: dict | None = None,
    *,
    tracker: TenantTracker | None = None,
) -> list[Threat]:
    """Detect cross-tenant data exposure patterns."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("cross_tenant", {})
        if not rule.get("enabled", True):
            return []

        t = tracker if tracker is not None else _tracker
        return t.check(tool_name, arguments, server_name)
    except Exception as exc:
        sys.stderr.write(f"[crossfire] cross_tenant error: {exc}\n")
        return []
