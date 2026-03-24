"""Zip Slip / Archive Extraction Path Traversal detection.

Detects archive extraction attacks where crafted filenames contain
directory traversal sequences (../../) to write files outside the
intended directory. Also detects symlink-based archive attacks.
Reference: Snyk Zip Slip research, CWE-22.
"""

import re
import sys

from proxy.config import get_config
from proxy.detectors import Threat

_ARCHIVE_TOOLS = {
    "extract", "unzip", "untar", "decompress", "unpack",
    "archive", "zip", "tar", "gzip", "gunzip", "bunzip2",
    "7z", "rar", "unrar", "expand", "inflate",
}

_ZIP_SLIP_PATTERNS = [
    # Traversal in archive member names
    re.compile(r"\.\.[\\/]"),
    re.compile(r"%2e%2e[\\/]", re.IGNORECASE),
    # Archive extraction commands with traversal
    re.compile(r"(?:tar|unzip|7z|unrar)\s+.*\.\./"),
    # Python zipfile/tarfile extraction without path validation
    re.compile(r"(?:zipfile|tarfile)\.(?:extractall|extract)\s*\("),
    re.compile(r"ZipFile\s*\(.*\.extractall\s*\("),
    re.compile(r"TarFile\s*\(.*\.extractall\s*\("),
    # Node.js archive extraction
    re.compile(r"(?:adm-zip|yauzl|unzipper|tar-stream)\b"),
    # Java archive extraction
    re.compile(r"ZipEntry\s*.*getName\s*\("),
    re.compile(r"ZipInputStream\b"),
    # Symlink in archive (tar with symlink preservation)
    re.compile(r"tar\s+.*--(?:dereference|hard-dereference)\b"),
    re.compile(r"tar\s+.*-h\b"),
]

_ARCHIVE_EXTENSIONS = re.compile(
    r"\.(zip|tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|7z|rar|gz|bz2|xz|jar|war|ear|apk|ipa)\b",
    re.IGNORECASE,
)


def detect_zip_slip(
    tool_name: str,
    arguments: dict,
    config: dict | None = None,
) -> list[Threat]:
    """Detect Zip Slip and archive extraction vulnerabilities."""
    try:
        cfg = config if config is not None else get_config()
        rule = cfg.get("rules", {}).get("zip_slip", {})
        if not rule.get("enabled", True):
            return []

        threats: list[Threat] = []
        tool_lower = tool_name.lower()
        is_archive_tool = any(t in tool_lower for t in _ARCHIVE_TOOLS)

        for key, value in arguments.items():
            if not isinstance(value, str):
                continue

            for pattern in _ZIP_SLIP_PATTERNS:
                if pattern.search(value):
                    threats.append(
                        Threat(
                            type="zip_slip",
                            severity="critical" if is_archive_tool else "high",
                            detail=f"Zip Slip in '{tool_name}' arg '{key}': {pattern.pattern}",
                            pattern="ZIP-SLIP",
                        )
                    )
                    break

            # Archive file being extracted with traversal in path
            if is_archive_tool and _ARCHIVE_EXTENSIONS.search(value) and ".." in value:
                threats.append(
                    Threat(
                        type="zip_slip_path",
                        severity="critical",
                        detail=f"Archive extraction with traversal in '{tool_name}' arg '{key}'",
                        pattern="ZIP-SLIP",
                    )
                )

        return threats
    except Exception as exc:
        sys.stderr.write(f"[crossfire] zip_slip error: {exc}\n")
        return []
