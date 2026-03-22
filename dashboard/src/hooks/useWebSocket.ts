import { useState, useEffect, useRef, useCallback } from 'react';
import type { CrossfireEvent } from '@shared/event_schema';

export type GuardianMode = 'monitor' | 'block';

export interface UseWebSocketOptions {
  onGuardianUpdate?: (mode: GuardianMode) => void;
  onConfigReload?: (config: unknown) => void;
}

function isCrossfireEvent(data: unknown): data is CrossfireEvent {
  if (!data || typeof data !== 'object') {
    return false;
  }
  const o = data as Record<string, unknown>;
  return (
    typeof o.id === 'string' &&
    typeof o.timestamp === 'string' &&
    typeof o.protocol === 'string' &&
    typeof o.server === 'string'
  );
}

export function useWebSocket(url: string, options?: UseWebSocketOptions) {
  const { onGuardianUpdate, onConfigReload } = options ?? {};
  const [events, setEvents] = useState<CrossfireEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef(1000);

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        retryRef.current = 1000;
        // Hydrate from server — events only arrived via WS before, so reloads / missed broadcasts showed nothing.
        void (async () => {
          try {
            const res = await fetch(`${window.location.origin}/api/events?limit=500`);
            if (!res.ok) return;
            const list: unknown = await res.json();
            if (!Array.isArray(list)) return;
            const parsed = list.filter(isCrossfireEvent) as CrossfireEvent[];
            setEvents((prev) => {
              const byId = new Map<string, CrossfireEvent>();
              for (const e of parsed) byId.set(e.id, e);
              for (const e of prev) byId.set(e.id, e);
              return Array.from(byId.values()).sort(
                (a, b) =>
                  new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
              );
            });
          } catch {
            /* ignore */
          }
        })();
      };

      ws.onmessage = (e) => {
        try {
          const data: unknown = JSON.parse(e.data);
          if (data && typeof data === 'object' && 'type' in data) {
            const msg = data as { type?: string; mode?: string; config?: unknown };
            if (msg.type === 'guardian_update') {
              const mode = msg.mode === 'block' ? 'block' : 'monitor';
              onGuardianUpdate?.(mode);
              return;
            }
            if (msg.type === 'config_reload') {
              onConfigReload?.(msg.config);
              return;
            }
          }
          if (isCrossfireEvent(data)) {
            setEvents((prev) => {
              const next = [data, ...prev.filter((e) => e.id !== data.id)];
              return next.slice(0, 1000);
            });
          }
        } catch {
          /* ignore malformed */
        }
      };

      ws.onclose = () => {
        setConnected(false);
        const delay = retryRef.current;
        retryRef.current = Math.min(delay * 2, 30_000);
        setTimeout(connect, delay);
      };

      ws.onerror = () => ws.close();
    } catch {
      /* ignore */
    }
  }, [url, onGuardianUpdate, onConfigReload]);

  useEffect(() => {
    connect();
    return () => wsRef.current?.close();
  }, [connect]);

  const sendCommand = useCallback((command: string, data?: Record<string, unknown>) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ command, ...data }));
    }
  }, []);

  return { events, connected, sendCommand };
}
