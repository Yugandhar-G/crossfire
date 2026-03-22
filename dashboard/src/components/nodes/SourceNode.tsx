import { memo, useState } from 'react';
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react';
import { motion } from 'motion/react';
import { Bot, Globe, Monitor, ScanSearch } from 'lucide-react';

export type SourceNodeData = {
  label: string;
  sourceKey: string;
  accent: string;
  eventCount: number;
  lastMethod?: string;
  lastTime?: string;
};

const ICONS: Record<string, typeof Monitor> = {
  ide: Monitor,
  sdk: Bot,
  'http-proxy': Globe,
  scan: ScanSearch,
};

type SourceNodeType = Node<SourceNodeData, 'source'>;

function SourceNode({ data, selected }: NodeProps<SourceNodeType>) {
  const [hovered, setHovered] = useState(false);
  const Icon = ICONS[data.sourceKey] ?? Monitor;

  return (
    <motion.div
      className="relative cursor-pointer rounded-xl px-3 py-2.5 min-w-[196px] max-w-[220px]"
      style={{
        borderLeftWidth: 3,
        borderLeftColor: data.accent,
      }}
      initial={false}
      animate={{
        scale: selected ? 1.03 : hovered ? 1.02 : 1,
        boxShadow: hovered || selected
          ? `0 0 0 1px ${data.accent}44, 0 12px 40px -8px rgba(0,0,0,0.55), 0 0 28px -4px ${data.accent}55`
          : '0 8px 32px -8px rgba(0,0,0,0.45)',
      }}
      transition={{ type: 'spring', stiffness: 400, damping: 28 }}
      onPointerEnter={() => setHovered(true)}
      onPointerLeave={() => setHovered(false)}
    >
      <div className="glass rounded-xl overflow-hidden">
        <div className="flex items-start gap-2.5">
          <div
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg"
            style={{
              background: `linear-gradient(135deg, ${data.accent}33, ${data.accent}12)`,
              color: data.accent,
            }}
          >
            <Icon className="h-4 w-4" strokeWidth={2} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-[11px] font-semibold uppercase tracking-wide text-zinc-300 truncate">
              {data.label}
            </div>
            <div className="mt-0.5 flex items-baseline gap-2">
              <span className="font-mono-ui text-lg font-bold tabular-nums text-zinc-100">{data.eventCount}</span>
              <span className="text-[10px] text-zinc-500">events</span>
            </div>
            {hovered && (data.lastMethod || data.lastTime) ? (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                className="mt-1.5 border-t border-white/10 pt-1.5 text-[10px] text-zinc-400"
              >
                {data.lastMethod ? (
                  <div className="font-mono-ui truncate text-cyan-200/90">{data.lastMethod}</div>
                ) : null}
                {data.lastTime ? <div className="text-zinc-500">{data.lastTime}</div> : null}
              </motion.div>
            ) : null}
          </div>
        </div>
      </div>
      <Handle
        type="source"
        position={Position.Right}
        className="!h-2.5 !w-2.5 !border-2 !border-zinc-700 !bg-zinc-900"
        style={{ boxShadow: `0 0 8px ${data.accent}` }}
      />
    </motion.div>
  );
}

export default memo(SourceNode);
