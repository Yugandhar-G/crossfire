"""Metrics Collector -- production observability for Crossfire.

Thread-safe counters for tool calls, threats, latency percentiles,
broadcast health, and Gemini API stats. No PII or tool content.
"""

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class _Counter:
    _value: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def increment(self, n: int = 1) -> None:
        with self._lock:
            self._value += n

    @property
    def value(self) -> int:
        with self._lock:
            return self._value


class MetricsCollector:
    def __init__(self):
        self._lock = threading.Lock()
        self._start_time = time.time()

        self._total_requests = _Counter()
        self._total_responses = _Counter()
        self._total_threats = _Counter()
        self._total_blocked = _Counter()
        self._broadcast_ok = _Counter()
        self._broadcast_fail = _Counter()
        self._gemini_calls = _Counter()
        self._gemini_timeouts = _Counter()
        self._policy_blocks = _Counter()
        self._policy_allows = _Counter()

        self._server_calls: dict[str, int] = defaultdict(int)
        self._server_threats: dict[str, int] = defaultdict(int)
        self._threat_types: dict[str, int] = defaultdict(int)

        self._latencies: list[float] = []
        self._max_latency_samples = 1000

        self._last_event_time: float | None = None
        self._errors: list[dict] = []

    def record_request(self, server: str) -> None:
        self._total_requests.increment()
        with self._lock:
            self._server_calls[server] += 1
            self._last_event_time = time.time()

    def record_response(self) -> None:
        self._total_responses.increment()

    def record_threat(self, server: str, threat_type: str, severity: str) -> None:
        self._total_threats.increment()
        with self._lock:
            self._server_threats[server] += 1
            self._threat_types[threat_type] += 1

    def record_blocked(self) -> None:
        self._total_blocked.increment()

    def record_broadcast(self, success: bool) -> None:
        if success:
            self._broadcast_ok.increment()
        else:
            self._broadcast_fail.increment()

    def record_gemini(self, success: bool, timed_out: bool = False) -> None:
        self._gemini_calls.increment()
        if timed_out:
            self._gemini_timeouts.increment()

    def record_policy(self, action: str) -> None:
        if action == "block":
            self._policy_blocks.increment()
        else:
            self._policy_allows.increment()

    def record_latency(self, ms: float) -> None:
        with self._lock:
            self._latencies.append(ms)
            if len(self._latencies) > self._max_latency_samples:
                self._latencies = self._latencies[-self._max_latency_samples :]

    def record_error(self, error_type: str, detail: str) -> None:
        with self._lock:
            self._errors.append(
                {"type": error_type, "detail": detail[:200], "timestamp": time.time()}
            )
            if len(self._errors) > 100:
                self._errors = self._errors[-100:]

    def snapshot(self) -> dict:
        with self._lock:
            lats = list(self._latencies)
        avg = sum(lats) / len(lats) if lats else 0
        sorted_lats = sorted(lats)
        p95 = sorted_lats[int(len(sorted_lats) * 0.95)] if lats else 0
        p99 = sorted_lats[int(len(sorted_lats) * 0.99)] if lats else 0

        b_ok = self._broadcast_ok.value
        b_fail = self._broadcast_fail.value
        return {
            "uptime_seconds": round(time.time() - self._start_time, 1),
            "total_requests": self._total_requests.value,
            "total_responses": self._total_responses.value,
            "total_threats": self._total_threats.value,
            "total_blocked": self._total_blocked.value,
            "threat_rate": self._total_threats.value
            / max(self._total_requests.value, 1),
            "broadcast": {
                "success": b_ok,
                "failed": b_fail,
                "success_rate": b_ok / max(b_ok + b_fail, 1),
            },
            "gemini": {
                "calls": self._gemini_calls.value,
                "timeouts": self._gemini_timeouts.value,
            },
            "policy": {
                "blocks": self._policy_blocks.value,
                "allows": self._policy_allows.value,
            },
            "latency_ms": {
                "avg": round(avg, 2),
                "p95": round(p95, 2),
                "p99": round(p99, 2),
                "samples": len(lats),
            },
            "per_server": {
                name: {
                    "calls": self._server_calls.get(name, 0),
                    "threats": self._server_threats.get(name, 0),
                }
                for name in set(list(self._server_calls) + list(self._server_threats))
            },
            "threat_types": dict(self._threat_types),
            "recent_errors": self._errors[-10:],
        }

    def health_check(self) -> dict:
        issues = []
        b_total = self._broadcast_ok.value + self._broadcast_fail.value
        if b_total > 0:
            rate = self._broadcast_ok.value / b_total
            if rate < 0.5:
                issues.append("Dashboard broadcast success rate below 50%")
            elif rate < 0.9:
                issues.append("Dashboard broadcast success rate below 90%")
        with self._lock:
            recent_errs = [e for e in self._errors if time.time() - e["timestamp"] < 60]
        if len(recent_errs) > 10:
            issues.append(f"{len(recent_errs)} errors in last 60s")
        status = (
            "healthy"
            if not issues
            else ("degraded" if len(issues) <= 1 else "unhealthy")
        )
        return {
            "status": status,
            "issues": issues,
            "uptime_seconds": round(time.time() - self._start_time, 1),
            "total_requests": self._total_requests.value,
            "total_threats": self._total_threats.value,
        }


metrics = MetricsCollector()
