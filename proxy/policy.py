"""Policy Engine -- fine-grained per-server/per-tool allow/block rules.

Rules are evaluated in order (first match wins). Supports glob patterns
for server and tool names and severity-threshold filtering.
"""

import fnmatch
import logging
from dataclasses import dataclass

logger = logging.getLogger("crossfire.policy")

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class PolicyRule:
    server: str = "*"
    tool: str = "*"
    action: str = "allow"
    severity_threshold: str | None = None
    reason: str = ""


@dataclass
class PolicyDecision:
    action: str
    rule_index: int
    rule_reason: str
    server: str
    tool: str

    @property
    def is_blocked(self) -> bool:
        return self.action == "block"


class PolicyEngine:
    """Evaluate tool calls against configurable policy rules.

    If no rule matches, the default action is used.
    """

    def __init__(
        self,
        rules: list[PolicyRule] | None = None,
        default_action: str = "allow",
        blocked_tools: dict[str, list[str]] | None = None,
        allowed_tools: dict[str, list[str]] | None = None,
    ):
        self._rules = rules or []
        self._default_action = default_action
        self._blocked_tools = blocked_tools or {}
        self._allowed_tools = allowed_tools or {}
        self._stats = {"total": 0, "allowed": 0, "blocked": 0, "monitored": 0}

    def evaluate(
        self,
        server_name: str,
        tool_name: str,
        severity: str | None = None,
        threats: list[dict] | None = None,
    ) -> PolicyDecision:
        self._stats["total"] += 1

        blocked = self._blocked_tools.get(server_name, [])
        if tool_name in blocked:
            d = PolicyDecision(
                "block",
                -2,
                f"Tool '{tool_name}' is in blocklist for '{server_name}'",
                server_name,
                tool_name,
            )
            self._record(d)
            return d

        allowed = self._allowed_tools.get(server_name, [])
        if allowed and tool_name not in allowed:
            d = PolicyDecision(
                "block",
                -2,
                f"Tool '{tool_name}' not in allowlist for '{server_name}'",
                server_name,
                tool_name,
            )
            self._record(d)
            return d

        for i, rule in enumerate(self._rules):
            if self._matches(rule, server_name, tool_name, severity):
                d = PolicyDecision(
                    rule.action,
                    i,
                    rule.reason or f"Matched rule #{i}",
                    server_name,
                    tool_name,
                )
                self._record(d)
                return d

        d = PolicyDecision(
            self._default_action,
            -1,
            f"Default: {self._default_action}",
            server_name,
            tool_name,
        )
        self._record(d)
        return d

    def _matches(
        self, rule: PolicyRule, server: str, tool: str, severity: str | None
    ) -> bool:
        if not fnmatch.fnmatch(server, rule.server):
            return False
        if not fnmatch.fnmatch(tool, rule.tool):
            return False
        if severity and rule.severity_threshold:
            if SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK.get(
                rule.severity_threshold, 0
            ):
                return False
        return True

    def _record(self, d: PolicyDecision) -> None:
        key = d.action if d.action in self._stats else "monitored"
        self._stats[key] += 1

    @property
    def stats(self) -> dict:
        return dict(self._stats)


def build_policy_from_config(cfg: dict) -> PolicyEngine:
    """Build a PolicyEngine from the crossfire config dict."""
    policy_cfg = cfg.get("policy", {})
    raw_rules = policy_cfg.get("rules", [])
    rules = [
        PolicyRule(
            server=r.get("server", "*"),
            tool=r.get("tool", "*"),
            action=r.get("action", "allow"),
            severity_threshold=r.get("severity_threshold"),
            reason=r.get("reason", ""),
        )
        for r in raw_rules
    ]
    return PolicyEngine(
        rules=rules,
        default_action=policy_cfg.get("default_action", "allow"),
        blocked_tools=policy_cfg.get("blocked_tools", {}),
        allowed_tools=policy_cfg.get("allowed_tools", {}),
    )
