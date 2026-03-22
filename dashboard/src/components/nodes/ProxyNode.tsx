import { memo, useState } from 'react';
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react';
import { motion } from 'motion/react';
import { Shield } from 'lucide-react';

export type ProxyNodeData = {
  totalEvents: number;
  totalThreats: number;
  guardianMode: 'monitor' | 'block';
  hasThreats: boolean;
};

type ProxyNodeType = Node<ProxyNodeData, 'proxy'>;

function ProxyNode({ data, selected }: NodeProps<ProxyNodeType>) {
  const [hovered, setHovered] = useState(false);
  const isBlock = data.guardianMode === 'block';

  return (
    <motion.div
      className="relative cursor-pointer rounded-2xl px-1 py-1 min-w-[220px] max-w-[260px]"
      initial={false}
      animate={{
        scale: selected ? 1.04 : hovered ? 1.02 : 1,
      }}
      transition={{ type: 'spring', stiffness: 380, damping: 26 }}
      onPointerEnter={() => setHovered(true)}
      onPointerLeave={() => setHovered(false)}
    >
      <div
        className={`glass-border-animated rounded-2xl ${data.hasThreats ? 'glow-pulse' : ''}`}
        style={
          data.hasThreats
            ? { borderRadius: '1rem' }
            : undefined
        }
      >
        <div className="relative z-10 m-[1px] rounded-[15px] bg-zinc-950/80 px-3 py-3 backdrop-blur-xl">
          <div className="flex items-center gap-3">
            <motion.div
              className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl"
              animate={{
                boxShadow: data.hasThreats
                  ? [
                      '0 0 12px rgba(239,68,68,0.35)',
                      '0 0 28px rgba(239,68,68,0.6)',
                      '0 0 12px rgba(239,68,68,0.35)',
                    ]
                  : '0 0 20px rgba(34,197,94,0.35)',
              }}
              transition={{ duration: data.hasThreats ? 2 : 0.4, repeat: data.hasThreats ? Infinity : 0 }}
              style={{
                background: data.hasThreats
                  ? 'linear-gradient(145deg, rgba(239,68,68,0.35), rgba(239,68,68,0.1))'
                  : 'linear-gradient(145deg, rgba(34,197,94,0.35), rgba(34,197,94,0.1))',
              }}
            >
              <Shield
                className={`h-6 w-6 ${data.hasThreats ? 'text-red-300' : 'text-emerald-300'}`}
                strokeWidth={1.75}
              />
            </motion.div>
            <div className="min-w-0 flex-1">
              <div className="font-mono-ui text-[11px] font-bold uppercase tracking-[0.2em] text-violet-200/90">
                Crossfire
              </div>
              <div className="mt-0.5 text-xs font-medium text-zinc-400">Security proxy</div>
              <div className="mt-2 flex flex-wrap gap-2 text-[10px]">
                <span className="rounded-full bg-white/5 px-2 py-0.5 font-mono-ui text-zinc-300">
                  {data.totalEvents} evt
                </span>
                <span
                  className={`rounded-full px-2 py-0.5 font-mono-ui ${
                    data.totalThreats > 0 ? 'bg-red-500/20 text-red-300' : 'bg-white/5 text-zinc-500'
                  }`}
                >
                  {data.totalThreats} thr
                </span>
                <span
                  className={`rounded-full px-2 py-0.5 font-semibold uppercase ${
                    isBlock ? 'bg-red-500/25 text-red-200' : 'bg-sky-500/20 text-sky-200'
                  }`}
                >
                  {isBlock ? 'Block' : 'Monitor'}
                </span>
              </div>
              {hovered ? (
                <motion.p
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="mt-2 text-[10px] leading-snug text-zinc-500"
                >
                  Click to clear traffic filters
                </motion.p>
              ) : null}
            </div>
          </div>
        </div>
      </div>
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border-2 !border-violet-500/50 !bg-zinc-950"
        style={{ boxShadow: '0 0 10px rgba(139,92,246,0.5)' }}
      />
      <Handle
        type="source"
        position={Position.Right}
        className="!h-2.5 !w-2.5 !border-2 !border-emerald-500/50 !bg-zinc-950"
        style={{ boxShadow: '0 0 10px rgba(34,197,94,0.45)' }}
      />
    </motion.div>
  );
}

export default memo(ProxyNode);
