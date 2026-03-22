"""In-memory event store with filtering and server stats."""

from collections import deque


class EventStore:
    def __init__(self, maxlen: int = 10000):
        self.events: deque[dict] = deque(maxlen=maxlen)
        self.server_stats: dict[str, dict] = {}

    def add(self, event: dict) -> None:
        self.events.appendleft(event)
        server = event.get("server", "unknown")
        if server not in self.server_stats:
            self.server_stats[server] = {
                "name": server,
                "protocol": event.get("protocol", "mcp"),
                "tools": 0,
                "threats": 0,
                "calls": 0,
                "last_seen": event.get("timestamp", ""),
                "sources": [],
            }
        stats = self.server_stats[server]
        stats["calls"] += 1
        stats["last_seen"] = event.get("timestamp", "")

        source = event.get("source")
        if source and source not in stats.get("sources", []):
            stats.setdefault("sources", []).append(source)

        if event.get("threats"):
            stats["threats"] += len(event["threats"])

        discovered = event.get("tools_discovered")
        if discovered:
            stats["tools"] = len(discovered)

    def query(
        self,
        server: str | None = None,
        severity: str | None = None,
        protocol: str | None = None,
        source: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        results = list(self.events)
        if server:
            results = [e for e in results if e.get("server") == server]
        if severity:
            results = [e for e in results if e.get("severity") == severity]
        if protocol:
            results = [e for e in results if e.get("protocol") == protocol]
        if source:
            results = [e for e in results if e.get("source") == source]
        return results[:limit]

    def get_stats(self) -> dict:
        total_calls = sum(s["calls"] for s in self.server_stats.values())
        total_threats = sum(s["threats"] for s in self.server_stats.values())
        return {
            "servers": self.server_stats,
            "total_calls": total_calls,
            "total_threats": total_threats,
            "total_events": len(self.events),
        }
