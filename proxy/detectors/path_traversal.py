"""Path Traversal & Symlink bypass detection.

Detects dot-dot-slash attacks, symlink escape attempts, and directory
containment bypasses in tool arguments. Based on CVE-2025-53109/53110
(Anthropic Filesystem MCP EscapeRoute vulnerabilities).
"""

import os
import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e[/\\%]", re.IGNORECASE),
    re.compile(r"\.\.%2f", re.IGNORECASE),
    re.compile(r"\.\.%5c", re.IGNORECASE),
    re.compile(r"%252e%252e", re.IGNORECASE),
    re.compile(r"\.\./\.\./\.\./"),
]

_SYMLINK_PATTERNS = [
    re.compile(r"\bln\s+-s\b"),
    re.compile(r"\bsymlink\b", re.IGNORECASE),
    re.compile(r"\bos\.symlink\b"),
    re.compile(r"\bfs\.symlink\b"),
    re.compile(r"\bmklink\b", re.IGNORECASE),
]

_SENSITIVE_ROOTS = [
    "/etc/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/root/",
    "/var/log/",
    "/var/run/",
    "C:\\Windows\\",
    "C:\\System32\\",
]

_FILE_TOOLS = {
    "read_file",
    "write_file",
    "create_file",
    "delete_file",
    "list_directory",
    "move_file",
    "copy_file",
    "get_file_info",
    "readfile",
    "writefile",
    "createfile",
    "deletefile",
    "read",
    "write",
    "cat",
    "head",
    "tail",
    "ls",
}


def detect_path_traversal(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect path traversal and symlink bypass attempts in tool arguments."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("path_traversal", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue

            for pattern in _TRAVERSAL_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="path_traversal",
                            severity="critical",
                            detail=f"Path traversal in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="PATH-TRAVERSE",
                        )
                    )
                    break

            for pattern in _SYMLINK_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="symlink_bypass",
                            severity="high",
                            detail=f"Symlink creation in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="PATH-TRAVERSE",
                        )
                    )
                    break

            tool_lower = tool_name.lower()
            is_file_tool = any(ft in tool_lower for ft in _FILE_TOOLS)
            if is_file_tool:
                for root in _SENSITIVE_ROOTS:
                    if value.startswith(root) or value.startswith(
                        root.replace("/", "\\")
                    ):
                        threats.append(
                            Threat(
                                type="sensitive_root_access",
                                severity="high",
                                detail=f"Tool '{tool_name}' accessing sensitive root: {root}",
                                pattern="PATH-TRAVERSE",
                            )
                        )
                        break

            try:
                normalized = os.path.normpath(value)
                if normalized != value and ".." in value:
                    threats.append(
                        Threat(
                            type="path_normalization_mismatch",
                            severity="medium",
                            detail=f"Path normalization changed value in '{tool_name}' arg '{key}'",
                            pattern="PATH-TRAVERSE",
                        )
                    )
            except (ValueError, TypeError):
                pass

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] path_traversal error: {exc}\n")
        return []
