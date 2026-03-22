"""A2A Session Smuggling detection.

Detects multi-turn stateful injection attacks where a malicious remote
agent exploits an A2A session to inject covert instructions between
legitimate request/response pairs. Based on Palo Alto Unit 42 research.

Tracks per-session message rates, detects unexpected server-initiated
messages, and flags anomalous conversation patterns.
"""

import sys
import time
from collections import deque
from dataclasses import dataclass, field

from proxy.detectors import Threat


@dataclass
class SessionState:
    message_count: int = 0
    client_messages: int = 0
    server_messages: int = 0
    last_client_time: float = 0.0
    last_server_time: float = 0.0
    server_initiated_count: int = 0
    history: deque = field(default_factory=lambda: deque(maxlen=50))


class SessionSmuggleDetector:
    """Track A2A sessions and detect smuggling patterns."""

    def __init__(
        self,
        max_server_ratio: float = 3.0,
        max_server_burst: int = 5,
        suspicious_gap_ms: float = 50.0,
    ):
        self._sessions: dict[str, SessionState] = {}
        self._max_server_ratio = max_server_ratio
        self._max_server_burst = max_server_burst
        self._suspicious_gap_ms = suspicious_gap_ms

    def track_message(
        self,
        session_id: str,
        direction: str,
        agent_name: str = "",
        content_summary: str = "",
    ) -> list[Threat]:
        """Track a message in an A2A session and check for smuggling."""
        threats: list[Threat] = []
        now = time.monotonic()

        if session_id not in self._sessions:
            self._sessions[session_id] = SessionState()

        state = self._sessions[session_id]
        state.message_count += 1
        state.history.append(
            {
                "direction": direction,
                "time": now,
                "agent": agent_name,
            }
        )

        if direction == "client":
            state.client_messages += 1
            state.last_client_time = now
        elif direction == "server":
            state.server_messages += 1

            if state.client_messages > 0 and state.last_server_time > 0:
                gap_ms = (now - state.last_server_time) * 1000
                if gap_ms < self._suspicious_gap_ms:
                    state.server_initiated_count += 1

            state.last_server_time = now

        if state.client_messages > 0:
            ratio = state.server_messages / max(state.client_messages, 1)
            if ratio > self._max_server_ratio and state.server_messages > 3:
                threats.append(
                    Threat(
                        type="a2a_session_smuggling",
                        severity="critical",
                        detail=(
                            f"Session '{session_id}': server/client ratio {ratio:.1f} "
                            f"({state.server_messages} server vs {state.client_messages} client msgs) "
                            f"-- possible multi-turn injection"
                        ),
                        pattern="A2A-SMUGGLE",
                    )
                )

        recent_server = sum(
            1
            for m in list(state.history)[-self._max_server_burst :]
            if m["direction"] == "server"
        )
        if recent_server >= self._max_server_burst:
            threats.append(
                Threat(
                    type="a2a_session_smuggling",
                    severity="high",
                    detail=(
                        f"Session '{session_id}': {recent_server} consecutive server "
                        f"messages -- possible session smuggling burst"
                    ),
                    pattern="A2A-SMUGGLE",
                )
            )

        if state.server_initiated_count >= 3:
            threats.append(
                Threat(
                    type="a2a_session_smuggling",
                    severity="high",
                    detail=(
                        f"Session '{session_id}': {state.server_initiated_count} rapid "
                        f"server-initiated messages (< {self._suspicious_gap_ms}ms apart)"
                    ),
                    pattern="A2A-SMUGGLE",
                )
            )

        return threats

    def clear_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)


_detector = SessionSmuggleDetector()


def detect_session_smuggling(
    session_id: str,
    direction: str,
    agent_name: str = "",
    content_summary: str = "",
    *,
    detector: SessionSmuggleDetector | None = None,
) -> list[Threat]:
    """Detect A2A session smuggling attacks."""
    try:
        d = detector if detector is not None else _detector
        return d.track_message(session_id, direction, agent_name, content_summary)
    except Exception as exc:
        sys.stderr.write(f"[crossfire] session_smuggling error: {exc}\n")
        return []
