import { useEffect, useMemo, useState, type RefObject } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { ChevronRight, Filter, Server, X } from 'lucide-react';
import type { CrossfireEvent } from '@shared/event_schema';

interface TrafficLogProps {
  events: CrossfireEvent[];
  onSelectEvent: (event: CrossfireEvent) => void;
  selectedId?: string;
  sourceFilter?: string | null;
  serverFilter?: string | null;
  onSourceFilter?: (source: string | null) => void;
  onServerFilter?: (server: string | null) => void;
  onClearFilters?: () => void;
  onCollapsePanel?: () => void;
  /** Parent scroll container (single scroll for log + threat detail). */
  scrollContainerRef?: RefObject<HTMLDivElement | null>;
}

const severityAccent: Record<string, string> = {
  critical: 'border-l-red-500 shadow-[inset_4px_0_0_0_rgba(239,68,68,0.85)]',
  high: 'border-l-amber-500 shadow-[inset_4px_0_0_0_rgba(245,158,11,0.85)]',
  medium: 'border-l-yellow-400 shadow-[inset_4px_0_0_0_rgba(250,204,21,0.75)]',
  low: 'border-l-sky-500 shadow-[inset_4px_0_0_0_rgba(56,189,248,0.75)]',
  clean: 'border-l-zinc-600',
};

const sourceStyles: Record<string, string> = {
  ide: 'bg-sky-500/15 text-sky-300 ring-sky-500/25',
  sdk: 'bg-violet-500/15 text-violet-300 ring-violet-500/25',
  'http-proxy': 'bg-amber-500/15 text-amber-300 ring-amber-500/25',
  scan: 'bg-cyan-500/15 text-cyan-300 ring-cyan-500/25',
};

const sourceLabel: Record<string, string> = {
  ide: 'IDE',
  sdk: 'SDK',
  'http-proxy': 'HTTP',
  scan: 'SCAN',
};

export default function TrafficLog({
  events,
  onSelectEvent,
  selectedId,
  sourceFilter,
  serverFilter,
  onSourceFilter,
  onServerFilter,
  onClearFilters,
  onCollapsePanel,
  scrollContainerRef,
}: TrafficLogProps) {
  const [autoScroll, setAutoScroll] = useState(true);

  const filtered = useMemo(() => {
    let list = events;
    if (sourceFilter) {
      list = list.filter((e) => (e.source ?? 'ide') === sourceFilter);
    }
    if (serverFilter) {
      list = list.filter((e) => e.server === serverFilter);
    }
    return list;
  }, [events, sourceFilter, serverFilter]);

  useEffect(() => {
    const el = scrollContainerRef?.current;
    if (!el) return;
    const onScroll = () => {
      setAutoScroll(el.scrollTop < 12);
    };
    el.addEventListener('scroll', onScroll, { passive: true });
    return () => el.removeEventListener('scroll', onScroll);
  }, [scrollContainerRef]);

  useEffect(() => {
    if (autoScroll && scrollContainerRef?.current) {
      scrollContainerRef.current.scrollTop = 0;
    }
  }, [filtered, autoScroll, scrollContainerRef]);

  const hasFilter = Boolean(sourceFilter || serverFilter);

  return (
    <div className="flex shrink-0 flex-col">
      <div className="glass sticky top-0 z-10 border-b border-white/[0.06] px-3 py-2.5 backdrop-blur-md">
        <div className="mb-2 flex items-center justify-between gap-2">
          <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">Traffic log</span>
          <div className="flex items-center gap-2">
            <span className="font-mono-ui text-[10px] tabular-nums text-zinc-500">
              {filtered.length}
              {hasFilter ? ` / ${events.length}` : ''} events
            </span>
            {onCollapsePanel ? (
              <button
                type="button"
                onClick={onCollapsePanel}
                className="nodrag nopan rounded-lg border border-white/10 bg-white/5 p-1 text-zinc-400 transition hover:bg-white/10 hover:text-zinc-100"
                title="Hide panel"
                aria-label="Collapse traffic log panel"
              >
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            ) : null}
          </div>
        </div>
        {serverFilter ? (
          <div className="mb-2 flex items-center gap-1.5 rounded-lg border border-emerald-500/25 bg-emerald-500/10 px-2 py-1.5 text-[10px] text-emerald-200">
            <Server className="h-3 w-3 shrink-0 text-emerald-400" aria-hidden />
            <span className="font-medium text-emerald-100/90">MCP server</span>
            <span className="min-w-0 flex-1 truncate font-mono-ui text-emerald-50" title={serverFilter}>
              {serverFilter}
            </span>
          </div>
        ) : null}
        <div className="flex flex-wrap items-center gap-2">
          <Filter className="h-3 w-3 shrink-0 text-zinc-600" aria-hidden />
          <select
            className="nodrag nopan max-w-[140px] cursor-pointer rounded-lg border border-white/10 bg-zinc-900/80 px-2 py-1 text-[10px] text-zinc-300 outline-none focus:ring-1 focus:ring-violet-500/50"
            value={sourceFilter ?? ''}
            onChange={(e) => onSourceFilter?.(e.target.value || null)}
            aria-label="Filter by source"
          >
            <option value="">All sources</option>
            <option value="ide">IDE</option>
            <option value="sdk">SDK</option>
            <option value="http-proxy">HTTP</option>
            <option value="scan">Scan</option>
          </select>
          <input
            className="nodrag nopan min-w-0 flex-1 rounded-lg border border-white/10 bg-zinc-900/80 px-2 py-1 font-mono-ui text-[10px] text-zinc-300 outline-none placeholder:text-zinc-600 focus:ring-1 focus:ring-violet-500/50"
            placeholder="Server name…"
            value={serverFilter ?? ''}
            onChange={(e) => onServerFilter?.(e.target.value || null)}
            aria-label="Filter by server"
          />
          {hasFilter ? (
            <button
              type="button"
              onClick={() => onClearFilters?.()}
              className="nodrag nopan flex items-center gap-1 rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-[10px] text-zinc-400 transition hover:bg-white/10 hover:text-zinc-200"
            >
              <X className="h-3 w-3" />
              Clear
            </button>
          ) : null}
        </div>
      </div>

      <div className="space-y-1.5 p-2 pb-4">
        <AnimatePresence initial={false} mode="sync">
          {filtered.map((event) => (
            <motion.div
              key={event.id}
              layout
              role="button"
              tabIndex={0}
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, height: 0, marginBottom: 0 }}
              transition={{ type: 'spring', stiffness: 440, damping: 34 }}
              onClick={() => onSelectEvent(event)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  onSelectEvent(event);
                }
              }}
              className={`group cursor-pointer rounded-xl border border-white/[0.06] bg-gradient-to-br from-white/[0.05] to-transparent pl-1 transition hover:border-white/15 hover:shadow-lg hover:shadow-black/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-violet-500/60 ${
                severityAccent[event.severity] ?? severityAccent.clean
              } ${selectedId === event.id ? 'ring-1 ring-violet-400/50 ring-offset-2 ring-offset-zinc-950' : ''}`}
            >
              <div className="rounded-r-xl px-2.5 py-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex min-w-0 flex-1 items-center gap-1.5">
                    <span className="shrink-0 font-mono-ui text-[10px] text-zinc-500">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </span>
                    <span
                      className={`shrink-0 rounded-md px-1.5 py-0.5 font-mono-ui text-[9px] font-semibold uppercase ring-1 ${
                        event.protocol === 'mcp' ? 'bg-violet-500/15 text-violet-300 ring-violet-500/25' : 'bg-cyan-500/15 text-cyan-300 ring-cyan-500/25'
                      }`}
                    >
                      {event.protocol}
                    </span>
                    {event.source ? (
                      <span
                        className={`shrink-0 rounded-md px-1.5 py-0.5 font-mono-ui text-[9px] font-semibold uppercase ring-1 ${
                          sourceStyles[event.source] ?? 'bg-zinc-500/15 text-zinc-400 ring-zinc-500/20'
                        }`}
                      >
                        {sourceLabel[event.source] ?? event.source}
                      </span>
                    ) : null}
                    {event.blocked ? (
                      <span className="shrink-0 rounded-md bg-red-500/20 px-1.5 py-0.5 font-mono-ui text-[9px] font-bold uppercase text-red-300 ring-1 ring-red-500/30">
                        Blocked
                      </span>
                    ) : null}
                    <span className="truncate text-xs font-medium text-zinc-200">{event.method || '(response)'}</span>
                  </div>
                  <span className="shrink-0 font-mono-ui text-[10px] text-zinc-500">{event.server}</span>
                </div>
                {event.threats.length > 0 ? (
                  <p className="mt-1 line-clamp-2 font-mono-ui text-[10px] leading-snug text-red-300/80">
                    {event.threats[0].detail}
                  </p>
                ) : null}
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
        {filtered.length === 0 ? (
          <div className="py-12 text-center text-xs text-zinc-500">
            {events.length === 0 ? 'Waiting for MCP traffic…' : 'No events match filters.'}
          </div>
        ) : null}
      </div>
    </div>
  );
}
