import { memo, useState } from 'react';
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react';
import { motion } from 'motion/react';
import { Server } from 'lucide-react';

export type ServerNodeData = {
  serverName: string;
  toolCount: number;
  threatCount: number;
  toolNames: string[];
  healthy: boolean;
};

type ServerNodeType = Node<ServerNodeData, 'server'>;

function ServerNode({ data, selected }: NodeProps<ServerNodeType>) {
  const [hovered, setHovered] = useState(false);
  const preview = data.toolNames.slice(0, 4);
  const more = data.toolNames.length > preview.length ? `+${data.toolNames.length - preview.length}` : '';

  return (
    <motion.div
      className="relative cursor-pointer rounded-xl px-3 py-2.5 min-w-[200px] max-w-[240px]"
      initial={false}
      animate={{
        scale: selected ? 1.03 : hovered ? 1.02 : 1,
        boxShadow:
          data.threatCount > 0
            ? hovered || selected
              ? '0 0 0 1px rgba(239,68,68,0.35), 0 14px 40px -10px rgba(239,68,68,0.25)'
              : '0 8px 28px -8px rgba(239,68,68,0.15)'
            : hovered || selected
              ? '0 0 0 1px rgba(34,197,94,0.25), 0 14px 40px -10px rgba(0,0,0,0.5)'
              : '0 8px 32px -8px rgba(0,0,0,0.45)',
      }}
      transition={{ type: 'spring', stiffness: 400, damping: 28 }}
      onPointerEnter={() => setHovered(true)}
      onPointerLeave={() => setHovered(false)}
    >
      <div className="glass rounded-xl">
        <div className="flex items-start gap-2.5">
          <div className="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-white/[0.06] text-zinc-300">
            <Server className="h-4 w-4" strokeWidth={2} />
            <span
              className={`absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full ring-2 ring-zinc-950 ${
                data.threatCount > 0 ? 'bg-red-500' : data.healthy ? 'bg-emerald-400' : 'bg-amber-400'
              }`}
              title={data.threatCount > 0 ? 'Threats detected' : 'Clean'}
            />
          </div>
          <div className="min-w-0 flex-1">
            <div className="truncate font-mono-ui text-[12px] font-semibold text-zinc-100" title={data.serverName}>
              {data.serverName}
            </div>
            <div className="mt-0.5 flex items-center gap-2 text-[10px] text-zinc-500">
              <span>{data.toolCount} tools</span>
              {data.threatCount > 0 ? (
                <span className="font-semibold text-red-400">{data.threatCount} threats</span>
              ) : (
                <span className="text-emerald-500/80">clean</span>
              )}
            </div>
            {hovered && preview.length > 0 ? (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                className="mt-2 flex flex-wrap gap-1 border-t border-white/10 pt-2"
              >
                {preview.map((t) => (
                  <span
                    key={t}
                    className="max-w-[88px] truncate rounded-md bg-white/5 px-1.5 py-0.5 font-mono-ui text-[9px] text-zinc-400"
                    title={t}
                  >
                    {t}
                  </span>
                ))}
                {more ? (
                  <span className="rounded-md bg-white/5 px-1.5 py-0.5 text-[9px] text-zinc-500">{more}</span>
                ) : null}
              </motion.div>
            ) : null}
          </div>
        </div>
      </div>
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border-2 !border-zinc-600 !bg-zinc-950"
      />
    </motion.div>
  );
}

export default memo(ServerNode);
