"""Rug-pull detection -- SHA-256 hash diffing on tool descriptions."""

import hashlib
import json
import sys
from typing import Literal, cast

from proxy.config import get_config
from proxy.detectors import Threat


_tool_hashes: dict[str, dict[str, str]] = {}


def _hash_tool(tool: dict) -> str:
    content = json.dumps(
        {
            "description": tool.get("description", ""),
            "inputSchema": tool.get("inputSchema", {}),
        },
        sort_keys=True,
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def check_rug_pull(
    server_name: str,
    tools: list[dict],
    config: dict | None = None,
    *,
    hash_store: dict[str, dict[str, str]] | None = None,
) -> list[Threat]:
    """Compare tool description hashes against previously seen versions.

    Pass *hash_store* to use an isolated state dict (useful for testing).
    """
    try:
        store = hash_store if hash_store is not None else _tool_hashes
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("rug_pull", {})
        if not rule.get("enabled", True):
            return []

        raw_sev = rule.get("severity", "critical")
        sev = cast(
            Literal["critical", "high", "medium", "low"],
            raw_sev if raw_sev in ("critical", "high", "medium", "low") else "critical",
        )

        threats: list[Threat] = []

        if server_name not in store:
            store[server_name] = {}
            for tool in tools:
                name = tool.get("name", "")
                store[server_name][name] = _hash_tool(tool)
            return []

        stored = store[server_name]
        for tool in tools:
            name = tool.get("name", "")
            new_hash = _hash_tool(tool)

            if name in stored and stored[name] != new_hash:
                threats.append(
                    Threat(
                        type="tool_description_changed",
                        severity=sev,
                        detail=f"Tool '{name}' on server '{server_name}' changed description/schema (possible rug-pull)",
                        pattern="RUG-PULL",
                    )
                )

            stored[name] = new_hash

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] rug_pull error: {exc}\n")
        return []


def get_tool_hashes() -> dict:
    return _tool_hashes
