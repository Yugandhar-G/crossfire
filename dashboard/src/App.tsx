import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { MouseEvent as ReactMouseEvent } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { GripVertical, PanelLeftOpen } from 'lucide-react';
import { useWebSocket } from './hooks/useWebSocket';
import Header from './components/Header';
import TrafficLog from './components/TrafficLog';
import ThreatDetail from './components/ThreatDetail';
import FlowGraph, { type GraphFilter } from './components/FlowGraph';
import type { CrossfireEvent } from '@shared/event_schema';

const LOG_MIN = 280;
const LOG_MAX = 640;
const LOG_DEFAULT = 400;
const LOG_COLLAPSE_THRESHOLD = 200;
const LOG_WIDTH_STORAGE_KEY = 'crossfire-log-width';

function websocketUrl(): string {
  const fromEnv = import.meta.env.VITE_WS_URL;
  if (fromEnv) {
    return fromEnv;
  }
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}/ws`;
}

export default function App() {
  const [guardianMode, setGuardianMode] = useState<'monitor' | 'block'>('monitor');
  const [sourceFilter, setSourceFilter] = useState<string | null>(null);
  const [serverFilter, setServerFilter] = useState<string | null>(null);
  const [logPanelOpen, setLogPanelOpen] = useState(true);
  const [logWidth, setLogWidth] = useState(LOG_DEFAULT);
  const [resizing, setResizing] = useState(false);

  const logWidthRef = useRef(LOG_DEFAULT);
  logWidthRef.current = logWidth;
  const dragActive = useRef(false);
  const panelScrollRef = useRef<HTMLDivElement>(null);

  const onGuardianUpdate = useCallback((mode: 'monitor' | 'block') => {
    setGuardianMode(mode);
  }, []);

  const wsUrl = useMemo(() => websocketUrl(), []);
  const { events, connected, sendCommand } = useWebSocket(wsUrl, { onGuardianUpdate });

  const [selectedEvent, setSelectedEvent] = useState<CrossfireEvent | null>(null);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(LOG_WIDTH_STORAGE_KEY);
      if (raw) {
        const w = parseInt(raw, 10);
        if (!Number.isNaN(w)) {
          setLogWidth(Math.min(LOG_MAX, Math.max(LOG_MIN, w)));
        }
      }
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (!dragActive.current) return;
      const w = window.innerWidth - e.clientX;
      const next = Math.min(LOG_MAX, Math.max(120, w));
      logWidthRef.current = next;
      setLogWidth(next);
    };
    const onUp = () => {
      if (!dragActive.current) return;
      dragActive.current = false;
      setResizing(false);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';

      const w = logWidthRef.current;
      if (w < LOG_COLLAPSE_THRESHOLD) {
        setLogPanelOpen(false);
        try {
          const saved = localStorage.getItem(LOG_WIDTH_STORAGE_KEY);
          if (saved) {
            const parsed = parseInt(saved, 10);
            if (!Number.isNaN(parsed)) {
              const next = Math.min(LOG_MAX, Math.max(LOG_MIN, parsed));
              logWidthRef.current = next;
              setLogWidth(next);
              return;
            }
          }
        } catch {
          /* ignore */
        }
        logWidthRef.current = LOG_DEFAULT;
        setLogWidth(LOG_DEFAULT);
        return;
      }
      const clamped = Math.min(LOG_MAX, Math.max(LOG_MIN, w));
      logWidthRef.current = clamped;
      setLogWidth(clamped);
      try {
        localStorage.setItem(LOG_WIDTH_STORAGE_KEY, String(clamped));
      } catch {
        /* ignore */
      }
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, []);

  const startResize = useCallback((e: ReactMouseEvent) => {
    e.preventDefault();
    dragActive.current = true;
    setResizing(true);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }, []);

  useEffect(() => {
    if (!connected) return;
    const base = window.location.origin;
    fetch(`${base}/api/guardian`)
      .then((r) => r.json())
      .then((d: { mode?: string }) => {
        if (d.mode === 'block' || d.mode === 'monitor') {
          setGuardianMode(d.mode);
        }
      })
      .catch((err) => {
        console.warn('[crossfire] Guardian API unreachable:', err);
      });
  }, [connected]);

  const toggleGuardian = useCallback(() => {
    setGuardianMode((prev) => {
      const newMode = prev === 'monitor' ? 'block' : 'monitor';
      sendCommand('set_guardian', { mode: newMode });
      return newMode;
    });
  }, [sendCommand]);

  const threatCount = events.filter((e) => e.severity !== 'clean').length;
  const servers = [...new Set(events.map((e) => e.server))];

  const clearFilters = useCallback(() => {
    setSourceFilter(null);
    setServerFilter(null);
  }, []);

  const onGraphFilter = useCallback(
    (filter: GraphFilter) => {
      if (filter.kind === 'clear') {
        clearFilters();
        return;
      }
      setLogPanelOpen(true);
      setSelectedEvent(null);
      if (filter.kind === 'source') {
        setSourceFilter(filter.source);
        setServerFilter(null);
        return;
      }
      if (filter.kind === 'server') {
        setServerFilter(filter.server);
        setSourceFilter(null);
      }
    },
    [clearFilters],
  );

  return (
    <div className="mesh-bg flex h-dvh min-h-0 flex-col overflow-hidden text-text-primary">
      <Header
        connected={connected}
        serverCount={servers.length}
        eventCount={events.length}
        threatCount={threatCount}
        guardianMode={guardianMode}
        onToggleGuardian={toggleGuardian}
      />
      <div className="relative flex min-h-0 flex-1 overflow-hidden">
        <div className="relative min-h-0 min-w-0 flex-1">
          <FlowGraph events={events} guardianMode={guardianMode} onGraphFilter={onGraphFilter} />
          <AnimatePresence>
            {!logPanelOpen ? (
              <motion.button
                key="log-expand"
                type="button"
                initial={{ opacity: 0, x: 24 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 24 }}
                transition={{ type: 'spring', stiffness: 420, damping: 34 }}
                className="absolute right-3 top-1/2 z-20 flex -translate-y-1/2 flex-col items-center gap-1.5 rounded-l-xl border border-white/10 border-r-0 bg-zinc-900/95 px-2.5 py-4 text-zinc-200 shadow-2xl backdrop-blur-md"
                onClick={() => setLogPanelOpen(true)}
                aria-label="Open traffic log"
              >
                <PanelLeftOpen className="h-4 w-4 shrink-0 text-violet-300" strokeWidth={2} />
                <span className="select-none text-[9px] font-bold uppercase tracking-[0.2em] text-zinc-500 [writing-mode:vertical-rl]">
                  Logs
                </span>
                {events.length > 0 ? (
                  <span className="rounded-full bg-violet-500/25 px-1.5 py-0.5 font-mono-ui text-[10px] text-violet-200">
                    {events.length}
                  </span>
                ) : null}
              </motion.button>
            ) : null}
          </AnimatePresence>
        </div>

        <motion.aside
          initial={false}
          animate={{
            width: logPanelOpen ? logWidth : 0,
            opacity: logPanelOpen ? 1 : 0,
          }}
          transition={
            resizing
              ? { width: { duration: 0 }, opacity: { duration: 0.15 } }
              : {
                  width: { type: 'spring', stiffness: 420, damping: 38, mass: 0.85 },
                  opacity: { duration: 0.2 },
                }
          }
          className="relative flex min-h-0 shrink-0 flex-col overflow-hidden border-l border-white/[0.08] bg-zinc-950/55 backdrop-blur-md"
          style={{ pointerEvents: logPanelOpen ? 'auto' : 'none' }}
          aria-hidden={!logPanelOpen}
        >
          {logPanelOpen ? (
            <>
              <div
                role="separator"
                aria-orientation="vertical"
                aria-label="Resize or drag left to collapse traffic log"
                title="Drag to resize — drag narrow to hide"
                className="absolute left-0 top-0 z-30 flex w-4 -translate-x-1/2 cursor-col-resize items-center justify-center rounded hover:bg-violet-500/15 active:bg-violet-500/25"
                onMouseDown={startResize}
              >
                <GripVertical className="pointer-events-none h-5 w-5 text-zinc-500" aria-hidden />
              </div>
              <div
                ref={panelScrollRef}
                className="flex min-h-0 min-w-0 flex-1 flex-col overflow-y-auto overflow-x-hidden overscroll-contain pl-1 [scrollbar-gutter:stable]"
              >
                <TrafficLog
                  events={events}
                  onSelectEvent={setSelectedEvent}
                  selectedId={selectedEvent?.id}
                  sourceFilter={sourceFilter}
                  serverFilter={serverFilter}
                  onSourceFilter={setSourceFilter}
                  onServerFilter={setServerFilter}
                  onClearFilters={clearFilters}
                  onCollapsePanel={() => setLogPanelOpen(false)}
                  scrollContainerRef={panelScrollRef}
                />
                <AnimatePresence mode="wait">
                  {selectedEvent && selectedEvent.threats.length > 0 ? (
                    <ThreatDetail key={selectedEvent.id} event={selectedEvent} />
                  ) : null}
                </AnimatePresence>
              </div>
            </>
          ) : null}
        </motion.aside>
      </div>
    </div>
  );
}
