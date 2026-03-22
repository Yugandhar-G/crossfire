import { memo } from 'react';
import { BaseEdge, getSmoothStepPath, type EdgeProps } from '@xyflow/react';

export type GradientEdgeData = {
  strokeStart?: string;
  strokeEnd?: string;
  threat?: boolean;
  animated?: boolean;
};

function GradientEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style,
  markerEnd,
  data,
}: EdgeProps) {
  const [path] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const d = (data ?? {}) as GradientEdgeData;
  const strokeStart = d.strokeStart ?? '#6366f1';
  const strokeEnd = d.strokeEnd ?? '#22c55e';
  const isThreat = Boolean(d.threat);
  const gid = `grad-${String(id).replace(/[^a-zA-Z0-9]/g, '')}`;

  return (
    <>
      <defs>
        <linearGradient id={gid} x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor={strokeStart} stopOpacity={isThreat ? 1 : 0.85} />
          <stop offset="100%" stopColor={isThreat ? '#ef4444' : strokeEnd} stopOpacity={1} />
        </linearGradient>
      </defs>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        className={d.animated ? 'edge-animated' : undefined}
        style={{
          ...style,
          stroke: `url(#${gid})`,
          strokeWidth: isThreat ? 2.75 : 1.75,
          strokeLinecap: 'round',
          filter: isThreat ? 'drop-shadow(0 0 5px rgba(239,68,68,0.65))' : undefined,
        }}
      />
    </>
  );
}

export default memo(GradientEdge);
