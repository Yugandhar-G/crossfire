"""Cross-call sequence tracker -- detect multi-step attack chains."""

import sys
import uuid
from collections import deque
from dataclasses import dataclass

from proxy.detectors import Threat


@dataclass
class CallRecord:
    tool_name: str
    server_name: str
    arguments: dict
    category: str  # file_read, file_write, network_send, shell_execute, memory_write, tool_description_injection
    timestamp: str = ""


ATTACK_CHAINS = [
    {
        "name": "EXFIL-NET",
        "steps": ["file_read", "network_send"],
        "severity": "critical",
        "detail": "File read followed by network exfiltration",
    },
    {
        "name": "PROMPT-RELAY",
        "steps": ["tool_description_injection", "file_read"],
        "severity": "critical",
        "detail": "Poisoned tool description triggered sensitive file access",
    },
    {
        "name": "PRIV-ESCAPE",
        "steps": ["file_write", "shell_execute"],
        "severity": "critical",
        "detail": "File write followed by shell execution (privilege escalation)",
    },
    {
        "name": "MEM-POISON",
        "steps": ["file_read", "memory_write"],
        "severity": "high",
        "detail": "Sensitive data read then stored in shared memory",
    },
]

FILE_READ_TOOLS = {"read_file", "read", "get_file", "cat", "head", "tail", "readFile"}
FILE_WRITE_TOOLS = {"write_file", "write", "create_file", "writeFile", "save_file"}
NETWORK_TOOLS = {
    "fetch",
    "http",
    "request",
    "post",
    "send",
    "upload",
    "telemetry",
    "report",
    "analytics",
}
SHELL_TOOLS = {"run_command", "execute", "shell", "bash", "exec", "terminal", "run"}
MEMORY_TOOLS = {
    "remember",
    "store",
    "save_memory",
    "add_note",
    "memory",
    "memo",
    "persist",
}


def _categorize(tool_name: str) -> str:
    name_lower = tool_name.lower()
    if any(t in name_lower for t in FILE_READ_TOOLS):
        return "file_read"
    if any(t in name_lower for t in FILE_WRITE_TOOLS):
        return "file_write"
    if any(t in name_lower for t in NETWORK_TOOLS):
        return "network_send"
    if any(t in name_lower for t in SHELL_TOOLS):
        return "shell_execute"
    if any(t in name_lower for t in MEMORY_TOOLS):
        return "memory_write"
    return "other"


class CrossCallTracker:
    def __init__(self, window_size: int = 20):
        self.history: deque[CallRecord] = deque(maxlen=window_size)
        self._chain_ids: dict[str, str] = {}

    def track(
        self, tool_name: str, server_name: str, arguments: dict, timestamp: str = ""
    ) -> list[Threat]:
        try:
            category = _categorize(tool_name)
            record = CallRecord(
                tool_name=tool_name,
                server_name=server_name,
                arguments=arguments,
                category=category,
                timestamp=timestamp,
            )
            self.history.append(record)

            threats = []
            categories = [r.category for r in self.history]

            for chain in ATTACK_CHAINS:
                steps = chain["steps"]
                if len(steps) > len(categories):
                    continue
                # Only match chains that end at the current (latest) call
                tail = categories[-len(steps) :]
                if tail == steps:
                    chain_id = self._chain_ids.get(chain["name"], str(uuid.uuid4()))
                    self._chain_ids[chain["name"]] = chain_id
                    threats.append(
                        Threat(
                            type="attack_chain",
                            severity=chain["severity"],
                            detail=f"{chain['detail']} (chain: {' -> '.join(steps)})",
                            pattern=chain["name"],
                        )
                    )

            return threats
        except Exception as exc:
            sys.stderr.write(f"[crossfire] cross_call error: {exc}\n")
            return []

    def get_chain_reconstruction(self) -> list[dict]:
        return [
            {
                "tool": r.tool_name,
                "server": r.server_name,
                "category": r.category,
                "timestamp": r.timestamp,
            }
            for r in self.history
        ]


_trackers: dict[str, CrossCallTracker] = {}


def detect_cross_call(
    tool_name: str,
    arguments: dict,
    server_name: str,
    timestamp: str = "",
    *,
    tracker: CrossCallTracker | None = None,
) -> list[Threat]:
    if tracker is not None:
        return tracker.track(tool_name, server_name, arguments, timestamp)
    if server_name not in _trackers:
        _trackers[server_name] = CrossCallTracker()
    return _trackers[server_name].track(tool_name, server_name, arguments, timestamp)
