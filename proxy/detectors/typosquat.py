"""Typosquat detection using Levenshtein distance."""

import sys

from Levenshtein import distance as levenshtein_distance

from proxy.detectors import Threat


KNOWN_MCP_SERVERS = [
    "filesystem",
    "github",
    "gitlab",
    "slack",
    "postgres",
    "postgresql",
    "mysql",
    "sqlite",
    "redis",
    "mongodb",
    "memory",
    "brave-search",
    "google-maps",
    "puppeteer",
    "playwright",
    "docker",
    "kubernetes",
    "aws",
    "gcloud",
    "azure",
    "cloudflare",
    "vercel",
    "supabase",
    "notion",
    "linear",
    "jira",
    "confluence",
    "obsidian",
    "fetch",
    "everything",
    "sequential-thinking",
    "time",
]


def detect_typosquat(
    server_name: str,
    max_distance: int = 2,
    known_servers: list[str] | None = None,
) -> list[Threat]:
    """Check if a server name is suspiciously similar to a known legitimate server."""
    try:
        registry = known_servers or KNOWN_MCP_SERVERS
        name_lower = server_name.lower()

        if name_lower in [s.lower() for s in registry]:
            return []

        threats = []
        for known in registry:
            dist = levenshtein_distance(name_lower, known.lower())
            if 0 < dist <= max_distance:
                threats.append(
                    Threat(
                        type="typosquat_detected",
                        severity="high",
                        detail=f"Server '{server_name}' is {dist} edit(s) away from known server '{known}'",
                        pattern="TYPOSQUAT",
                    )
                )

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] typosquat error: {exc}\n")
        return []
