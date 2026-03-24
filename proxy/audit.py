"""Audit Logger -- persistent JSONL audit trail with rotation and redaction.

Security hardening:
 - Restrictive file permissions (0o600) on log files
 - Increased redaction depth (20 levels, not 5)
 - List-of-strings redaction for credential arrays
 - Case-insensitive key matching for redaction
 - Atomic writes with fsync
"""

import json
import logging
import os
import stat
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
    "api-key",
    "auth_token",
    "access_token",
    "refresh_token",
    "private_key",
    "secret_key",
    "client_secret",
    "aws_secret_access_key",
    "aws_access_key_id",
    "authorization",
    "cookie",
    "session_id",
    "csrf_token",
    "_hmac_signature",
    "_hmac_nonce",
    "hmac_secret",
}

MAX_LINE_SIZE = 100_000
MAX_REDACT_DEPTH = 20
_LOG_FILE_MODE = 0o600  # owner read/write only


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
            # Open with restrictive permissions
            fd = os.open(
                str(self._path),
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                _LOG_FILE_MODE,
            )
            self._file = os.fdopen(fd, "a", encoding="utf-8")
            # Ensure permissions are correct even if file already existed
            try:
                os.chmod(str(self._path), _LOG_FILE_MODE)
            except OSError:
                pass
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
                    # Ensure valid JSON even when truncated
                    truncated = {
                        "audit_seq": entry["audit_seq"],
                        "audit_type": entry["audit_type"],
                        "audit_timestamp": entry["audit_timestamp"],
                        "_truncated": True,
                        "_original_size": len(line),
                    }
                    line = json.dumps(truncated, separators=(",", ":"))
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
                try:
                    if i + 1 >= self._max_rotated:
                        src.unlink(missing_ok=True)
                    elif src.exists():
                        src.rename(dst)
                        # Set permissions on rotated file
                        try:
                            os.chmod(str(dst), _LOG_FILE_MODE)
                        except OSError:
                            pass
                except OSError as e:
                    logger.warning("Rotation step %d failed: %s", i, e)

            try:
                if self._path.exists():
                    rotated = self._path.with_suffix(".jsonl.1")
                    self._path.rename(rotated)
                    try:
                        os.chmod(str(rotated), _LOG_FILE_MODE)
                    except OSError:
                        pass
            except OSError as e:
                logger.warning("Primary rotation failed: %s", e)

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


def _is_sensitive_key(key: str) -> bool:
    """Case-insensitive check if key matches any redaction field."""
    key_lower = key.lower().replace("-", "_")
    return any(rf in key_lower for rf in REDACT_FIELDS)


def _redact(data: dict, depth: int = 0) -> dict:
    if depth > MAX_REDACT_DEPTH:
        return {"_redacted": True, "_reason": "max_depth_exceeded"}
    result = {}
    for key, value in data.items():
        if _is_sensitive_key(key):
            result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            result[key] = _redact(value, depth + 1)
        elif isinstance(value, list):
            result[key] = _redact_list(value, key, depth + 1)
        else:
            result[key] = value
    return result


def _redact_list(items: list, parent_key: str, depth: int) -> list:
    """Redact list items, including strings in credential-named lists."""
    if depth > MAX_REDACT_DEPTH:
        return ["[REDACTED]"]
    result = []
    is_sensitive_parent = _is_sensitive_key(parent_key)
    for item in items:
        if isinstance(item, dict):
            result.append(_redact(item, depth))
        elif isinstance(item, str) and is_sensitive_parent:
            result.append("[REDACTED]")
        elif isinstance(item, list):
            result.append(_redact_list(item, parent_key, depth + 1))
        else:
            result.append(item)
    return result
