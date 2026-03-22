"""MCP Config Poisoning (MCPoison) detection.

Detects attempts to modify MCP client configuration files through tool
calls -- the attack where a malicious MCP server instructs the LLM to
write/modify MCP configuration to add attacker-controlled servers.
Reference: Checkpoint "MCPoison" Cursor IDE vulnerability research.
"""

import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

_CONFIG_FILENAMES = {
    "mcp.json",
    "mcp_config.json",
    ".mcp.json",
    "claude_desktop_config.json",
    "settings.json",
    "cursor-settings.json",
    ".cursor",
    "mcp-servers.json",
    "crossfire.yaml",
    ".crossfire.yaml",
    ".vscode/settings.json",
    ".cursor/mcp.json",
}

_CONFIG_PATH_PATTERNS = [
    re.compile(r"\.cursor[/\\]", re.IGNORECASE),
    re.compile(r"\.vscode[/\\]", re.IGNORECASE),
    re.compile(r"claude_desktop[/\\]", re.IGNORECASE),
    re.compile(r"mcp[_-]?(?:config|servers|settings)", re.IGNORECASE),
    re.compile(r"Library[/\\]Application Support[/\\]Claude", re.IGNORECASE),
    re.compile(r"AppData[/\\].*Claude", re.IGNORECASE),
]

_CONFIG_CONTENT_PATTERNS = [
    re.compile(r'"mcpServers"', re.IGNORECASE),
    re.compile(r'"command"\s*:\s*"(?:npx|uvx|node|python)', re.IGNORECASE),
    re.compile(r'"args"\s*:\s*\[', re.IGNORECASE),
    re.compile(r'"env"\s*:\s*\{', re.IGNORECASE),
    re.compile(r'"url"\s*:\s*"https?://', re.IGNORECASE),
]

_WRITE_TOOLS = {
    "write_file",
    "write",
    "create_file",
    "save_file",
    "writefile",
    "createfile",
    "savefile",
    "edit_file",
    "editfile",
    "patch_file",
}


def detect_config_poisoning(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect attempts to modify MCP configuration files."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("config_poisoning", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []
        tool_lower = tool_name.lower()
        is_write = any(w in tool_lower for w in _WRITE_TOOLS)

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue

            value_lower = value.lower()
            path_hit = False

            for filename in _CONFIG_FILENAMES:
                if filename.lower() in value_lower:
                    path_hit = True
                    if is_write:
                        threats.append(
                            Threat(
                                type="config_poisoning",
                                severity="critical",
                                detail=f"Write to MCP config file '{filename}' via tool '{tool_name}'",
                                pattern="CONFIG-POISON",
                            )
                        )
                    else:
                        threats.append(
                            Threat(
                                type="config_read",
                                severity="medium",
                                detail=f"Reading MCP config file '{filename}' via tool '{tool_name}'",
                                pattern="CONFIG-POISON",
                            )
                        )
                    break

            if not path_hit:
                for pattern in _CONFIG_PATH_PATTERNS:
                    if pattern.search(value):
                        severity = "critical" if is_write else "medium"
                        threats.append(
                            Threat(
                                type="config_poisoning"
                                if is_write
                                else "config_access",
                                severity=severity,
                                detail=f"Access to MCP config path in '{tool_name}': {pattern.pattern}",
                                pattern="CONFIG-POISON",
                            )
                        )
                        break

            for pattern in _CONFIG_CONTENT_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="config_content_injection",
                            severity="critical",
                            detail=f"MCP server config content in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="CONFIG-POISON",
                        )
                    )
                    break

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] config_poisoning error: {exc}\n")
        return []
