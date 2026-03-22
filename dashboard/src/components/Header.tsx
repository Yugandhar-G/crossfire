import { motion, useMotionValueEvent, useSpring } from 'motion/react';
import { useEffect, useState } from 'react';
import { Shield } from 'lucide-react';

interface HeaderProps {
  connected: boolean;
  serverCount: number;
  eventCount: number;
  threatCount: number;
  guardianMode: 'monitor' | 'block';
  onToggleGuardian: () => void;
}

function AnimatedNumber({ value }: { value: number }) {
  const spring = useSpring(value, { stiffness: 120, damping: 22, mass: 0.4 });
  const [display, setDisplay] = useState(value);

  useEffect(() => {
    spring.set(value);
  }, [value, spring]);

  useMotionValueEvent(spring, 'change', (v) => {
    setDisplay(Math.round(v));
  });

  return <span className="tabular-nums">{display}</span>;
}

export default function Header({
  connected,
  serverCount,
  eventCount,
  threatCount,
  guardianMode,
  onToggleGuardian,
}: HeaderProps) {
  const isBlock = guardianMode === 'block';

  return (
    <motion.header
      className="glass-strong flex shrink-0 items-center gap-6 border-b border-white/[0.08] px-5 py-3.5"
      initial={{ opacity: 0, y: -12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ type: 'spring', stiffness: 260, damping: 28 }}
    >
      <div className="flex items-center gap-3">
        <motion.div
          className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-600/40 to-fuchsia-600/25 ring-1 ring-white/15"
          whileHover={{ scale: 1.05 }}
          transition={{ type: 'spring', stiffness: 400, damping: 20 }}
        >
          <Shield className="h-5 w-5 text-violet-100" strokeWidth={1.75} />
        </motion.div>
        <div>
          <h1 className="bg-gradient-to-r from-zinc-100 to-zinc-400 bg-clip-text text-lg font-bold tracking-tight text-transparent">
            Crossfire
          </h1>
          <p className="text-[10px] font-medium uppercase tracking-[0.2em] text-zinc-500">MCP security</p>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <span className="relative flex h-2.5 w-2.5">
          {connected ? (
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400/60 opacity-60" />
          ) : null}
          <span
            className={`relative inline-flex h-2.5 w-2.5 rounded-full ring-2 ring-zinc-950 ${
              connected ? 'bg-emerald-400' : 'bg-red-500'
            }`}
          />
        </span>
        <span className="text-xs font-medium text-zinc-400">{connected ? 'Live' : 'Offline'}</span>
      </div>

      <div className="flex flex-wrap items-center gap-2 md:gap-3">
        <StatPill label="Servers" value={serverCount} accent="from-sky-500/20 to-sky-500/5" />
        <StatPill label="Events" value={eventCount} accent="from-violet-500/20 to-violet-500/5" />
        <StatPill
          label="Threats"
          value={threatCount}
          accent={
            threatCount > 0
              ? 'from-red-500/30 to-red-600/10 ring-red-500/25'
              : 'from-emerald-500/15 to-emerald-600/5'
          }
          emphasize={threatCount > 0}
        />
      </div>

      <div className="ml-auto flex items-center gap-3">
        <span className="hidden text-xs text-zinc-500 sm:inline">Guardian</span>
        <button
          type="button"
          onClick={onToggleGuardian}
          className={`group relative h-9 overflow-hidden rounded-full px-1 transition-shadow focus:outline-none focus-visible:ring-2 focus-visible:ring-violet-500/60 ${
            isBlock ? 'shadow-[0_0_24px_-4px_rgba(239,68,68,0.5)]' : 'shadow-[0_0_20px_-4px_rgba(56,189,248,0.35)]'
          }`}
          aria-pressed={isBlock}
          aria-label={isBlock ? 'Switch to monitor mode' : 'Switch to block mode'}
        >
          <motion.div
            className={`absolute inset-0 rounded-full ${
              isBlock
                ? 'bg-gradient-to-r from-red-600/90 to-rose-700/90'
                : 'bg-gradient-to-r from-sky-600/90 to-indigo-600/90'
            }`}
            layout
            transition={{ type: 'spring', stiffness: 400, damping: 32 }}
          />
          <span className="relative z-10 flex h-full items-center gap-2 px-4">
            <motion.span
              className="text-[10px] font-bold uppercase tracking-wider text-white drop-shadow-sm"
              key={guardianMode}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
            >
              {isBlock ? 'Block' : 'Monitor'}
            </motion.span>
            <span
              className={`flex h-6 w-6 items-center justify-center rounded-full bg-white/95 text-[10px] font-bold shadow ${
                isBlock ? 'text-red-600' : 'text-sky-600'
              }`}
            >
              {isBlock ? '■' : '◉'}
            </span>
          </span>
        </button>
      </div>
    </motion.header>
  );
}

function StatPill({
  label,
  value,
  accent,
  emphasize,
}: {
  label: string;
  value: number;
  accent: string;
  emphasize?: boolean;
}) {
  return (
    <div
      className={`rounded-xl bg-gradient-to-br px-3 py-2 ring-1 ring-white/10 ${accent} ${
        emphasize ? 'ring-red-500/30' : ''
      }`}
    >
      <div className="text-[9px] font-semibold uppercase tracking-wider text-zinc-500">{label}</div>
      <div
        className={`font-mono-ui text-lg font-bold leading-none tabular-nums ${
          emphasize ? 'text-red-300' : 'text-zinc-100'
        }`}
      >
        <AnimatedNumber value={value} />
      </div>
    </div>
  );
}
