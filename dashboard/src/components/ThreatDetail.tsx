import { useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { ChevronDown, Sparkles } from 'lucide-react';
import type { CrossfireEvent } from '@shared/event_schema';

interface ThreatDetailProps {
  event: CrossfireEvent;
}

const sourceLabel: Record<string, string> = {
  ide: 'IDE',
  sdk: 'SDK',
  'http-proxy': 'HTTP',
  scan: 'SCAN',
};

export default function ThreatDetail({ event }: ThreatDetailProps) {
  const [openIdx, setOpenIdx] = useState<number | null>(0);

  return (
    <motion.div
      className="glass-strong shrink-0 border-t border-red-500/25"
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 8 }}
      transition={{ type: 'spring', stiffness: 360, damping: 32 }}
    >
      <div className="p-3">
        <div className="mb-3 flex items-center justify-between gap-2">
          <h3 className="text-[10px] font-bold uppercase tracking-[0.2em] text-red-400">Threat detail</h3>
          {event.source ? (
            <span className="rounded-full bg-white/5 px-2 py-0.5 font-mono-ui text-[9px] text-zinc-400 ring-1 ring-white/10">
              via {sourceLabel[event.source] ?? event.source}
            </span>
          ) : null}
        </div>
        <div className="space-y-2">
          {event.threats.map((threat, i) => {
            const hasGemini = Boolean(threat.gemini_analysis);
            const expanded = openIdx === i;
            return (
              <motion.div
                key={i}
                layout
                className="rounded-xl border border-red-500/20 bg-gradient-to-br from-red-950/40 to-zinc-950/60 p-2.5"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-md bg-red-500/20 px-1.5 py-0.5 font-mono-ui text-[9px] font-bold text-red-300">
                    {threat.pattern}
                  </span>
                  <span className="text-[9px] font-semibold uppercase tracking-wide text-zinc-500">{threat.severity}</span>
                </div>
                <p className="mt-1.5 text-xs leading-relaxed text-zinc-200">{threat.detail}</p>
                {hasGemini ? (
                  <div className="mt-2">
                    <button
                      type="button"
                      onClick={() => setOpenIdx(expanded ? null : i)}
                      aria-expanded={expanded}
                      aria-controls={`gemini-detail-${i}`}
                      className="flex w-full items-center justify-between gap-2 rounded-lg border border-violet-500/20 bg-violet-500/10 px-2 py-1.5 text-left text-[10px] font-semibold text-violet-200 transition hover:bg-violet-500/15"
                    >
                      <span className="flex items-center gap-1.5">
                        <Sparkles className="h-3 w-3 shrink-0" />
                        Gemini analysis
                        {threat.gemini_analysis ? (
                          <span className="font-mono-ui text-zinc-400">
                            ({Math.round((threat.gemini_analysis.confidence ?? 0) * 100)}%)
                          </span>
                        ) : null}
                      </span>
                      <ChevronDown className={`h-3.5 w-3.5 shrink-0 transition ${expanded ? 'rotate-180' : ''}`} />
                    </button>
                    <AnimatePresence>
                      {expanded && threat.gemini_analysis ? (
                        <motion.div
                          id={`gemini-detail-${i}`}
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="overflow-hidden"
                        >
                          <p className="mt-2 rounded-lg border border-white/5 bg-black/30 p-2 text-[10px] leading-relaxed text-zinc-400">
                            {threat.gemini_analysis.explanation}
                          </p>
                        </motion.div>
                      ) : null}
                    </AnimatePresence>
                  </div>
                ) : null}
              </motion.div>
            );
          })}
        </div>
      </div>
    </motion.div>
  );
}
