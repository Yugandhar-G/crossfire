"""Audit Logger -- persistent JSONL audit trail with rotation and redaction.

Atomic writes, bounded file size, and automatic secret scrubbing.
"""

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Optional

logger = logging.getLogger("crossfire.audit")

REDACT_FIELDS = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth_token",
    "access_token",
    "private_key",
    "_hmac_signature",
    "_hmac_nonce",
}

MAX_LINE_SIZE = 100_000


class AuditLogger:
    def __init__(
        self,
        path: str = "./crossfire-audit.jsonl",
        max_size_mb: int = 100,
        max_rotated_files: int = 5,
        enabled: bool = True,
    ):
        self._path = Path(path)
        self._max_size_bytes = max_size_mb * 1024 * 1024
        self._max_rotated = max_rotated_files
        self._enabled = enabled
        self._lock = threading.Lock()
        self._seq = 0
        self._file: Optional[IO] = None
        self._current_size = 0
        if enabled:
            self._open()

    def _open(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(self._path, "a", encoding="utf-8")
            self._current_size = self._path.stat().st_size if self._path.exists() else 0
        except Exception as e:
            logger.error("Failed to open audit log %s: %s", self._path, e)
            self._enabled = False

    def log(self, event: dict, event_type: str = "event") -> None:
        if not self._enabled or self._file is None:
            return
        with self._lock:
            try:
                self._seq += 1
                entry = {
                    "audit_seq": self._seq,
                    "audit_type": event_type,
                    "audit_timestamp": datetime.now(timezone.utc).isoformat(),
                    **_redact(event),
                }
                line = json.dumps(entry, default=str, separators=(",", ":"))
                if len(line) > MAX_LINE_SIZE:
                    line = line[: MAX_LINE_SIZE - 50] + ',"_truncated":true}'
                self._file.write(line + "\n")
                self._file.flush()
                self._current_size += len(line) + 1
                if self._current_size >= self._max_size_bytes:
                    self._rotate()
            except Exception as e:
                logger.error("Audit write failed: %s", e)

    def log_threat(self, event: dict) -> None:
        self.log(event, "threat")

    def log_startup(self, info: dict) -> None:
        self.log(info, "startup")

    def log_shutdown(self, info: dict) -> None:
        self.log(info, "shutdown")

    def log_policy(self, action: dict) -> None:
        self.log(action, "policy_action")

    def log_mode_change(self, change: dict) -> None:
        self.log(change, "mode_change")

    def _rotate(self) -> None:
        try:
            if self._file:
                self._file.close()
                self._file = None
            for i in range(self._max_rotated - 1, 0, -1):
                src = self._path.with_suffix(f".jsonl.{i}")
                dst = self._path.with_suffix(f".jsonl.{i + 1}")
                if src.exists():
                    if i + 1 >= self._max_rotated:
                        src.unlink()
                    else:
                        src.rename(dst)
            if self._path.exists():
                self._path.rename(self._path.with_suffix(".jsonl.1"))
            self._open()
        except Exception as e:
            logger.error("Audit rotation failed: %s", e)
            self._open()

    def close(self) -> None:
        with self._lock:
            if self._file:
                try:
                    self._file.flush()
                    self._file.close()
                except Exception:
                    pass
                self._file = None

    @property
    def entry_count(self) -> int:
        return self._seq


def _redact(data: dict, depth: int = 0) -> dict:
    if depth > 5:
        return data
    result = {}
    for key, value in data.items():
        if any(rf in key.lower() for rf in REDACT_FIELDS):
            result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            result[key] = _redact(value, depth + 1)
        elif isinstance(value, list):
            result[key] = [
                _redact(item, depth + 1) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            result[key] = value
    return result
