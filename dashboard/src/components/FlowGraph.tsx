import { useCallback, useMemo } from 'react';
import { Background, Controls, ReactFlow, type Edge, type Node, type NodeTypes } from '@xyflow/react';
import type { MouseEvent as ReactMouseEvent } from 'react';
import '@xyflow/react/dist/style.css';
import dagre from '@dagrejs/dagre';
import type { CrossfireEvent } from '@shared/event_schema';
import SourceNode from './nodes/SourceNode';
import ProxyNode from './nodes/ProxyNode';
import ServerNode from './nodes/ServerNode';
import GradientEdge from './edges/GradientEdge';
import type { SourceNodeData } from './nodes/SourceNode';
import type { ServerNodeData } from './nodes/ServerNode';

const nodeTypes = {
  source: SourceNode,
  proxy: ProxyNode,
  server: ServerNode,
} satisfies NodeTypes;

const edgeTypes = {
  gradient: GradientEdge,
};

const SOURCE_LABELS: Record<string, string> = {
  ide: 'IDE (Cursor/Claude)',
  sdk: 'ADK / SDK Agent',
  'http-proxy': 'HTTP Client',
  scan: 'Scanner',
};

const SOURCE_COLORS: Record<string, string> = {
  ide: '#3b82f6',
  sdk: '#a855f7',
  'http-proxy': '#f59e0b',
  scan: '#06b6d4',
};

const DEFAULT_W = 220;
const DEFAULT_H = 76;
const PROXY_W = 268;
const PROXY_H = 132;
const SERVER_W = 228;
const SERVER_H = 96;

export type GraphFilter =
  | { kind: 'source'; source: string }
  | { kind: 'server'; server: string }
  | { kind: 'clear' };

function nodeSize(node: Node): { w: number; h: number } {
  if (node.type === 'proxy') return { w: PROXY_W, h: PROXY_H };
  if (node.type === 'server') return { w: SERVER_W, h: SERVER_H };
  return { w: DEFAULT_W, h: DEFAULT_H };
}

function layoutNodes(nodes: Node[], edges: Edge[]): Node[] {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: 'LR', nodesep: 48, ranksep: 180 });

  for (const node of nodes) {
    const { w, h } = nodeSize(node);
    g.setNode(node.id, { width: w, height: h });
  }
  for (const edge of edges) {
    g.setEdge(edge.source, edge.target);
  }

  dagre.layout(g);

  return nodes.map((node) => {
    const pos = g.node(node.id);
    const { w, h } = nodeSize(node);
    return { ...node, position: { x: pos.x - w / 2, y: pos.y - h / 2 } };
  });
}

function lastEventForSource(events: CrossfireEvent[], source: string): CrossfireEvent | undefined {
  for (const e of events) {
    const s = e.source ?? 'ide';
    if (s === source) return e;
  }
  return undefined;
}

function toolsForServer(events: CrossfireEvent[], server: string): string[] {
  const names = new Set<string>();
  for (const e of events) {
    if (e.server !== server || !e.tools_discovered) continue;
    for (const t of e.tools_discovered) names.add(t);
  }
  return [...names].slice(0, 12);
}

interface FlowGraphProps {
  events: CrossfireEvent[];
  guardianMode: 'monitor' | 'block';
  onGraphFilter?: (filter: GraphFilter) => void;
}

export default function FlowGraph({ events, guardianMode, onGraphFilter }: FlowGraphProps) {
  const topology = useMemo(() => {
    const servers = new Map<string, { threats: number; protocol: string; tools: number }>();
    const sources = new Set<string>();
    const sourceCounts = new Map<string, number>();
    let totalThreats = 0;

    for (const e of events) {
      const existing = servers.get(e.server) || { threats: 0, protocol: e.protocol, tools: 0 };
      if (e.threats.length > 0) existing.threats += e.threats.length;
      if (e.tools_discovered) existing.tools = e.tools_discovered.length;
      servers.set(e.server, existing);
      const k = e.source ?? 'ide';
      sources.add(k);
      sourceCounts.set(k, (sourceCounts.get(k) ?? 0) + 1);
      totalThreats += e.threats.length;
    }

    const serverKeys = [...servers.keys()].sort().join(',');
    const sourceKeys = [...sources].sort().join(',');

    return { servers, sources, sourceCounts, totalThreats, serverKeys, sourceKeys };
  }, [events]);

  const { nodes, edges } = useMemo(() => {
    const { servers, sources, sourceCounts, totalThreats } = topology;
    const hasThreats = totalThreats > 0;

    const rawNodes: Node[] = [];
    const edgeList: Edge[] = [];

    const activeSources = sources.size > 0 ? [...sources] : ['ide'];
    for (const src of activeSources) {
      const srcId = `source-${src}`;
      const last = lastEventForSource(events, src);
      const accent = SOURCE_COLORS[src] ?? '#3b82f6';
      const data: SourceNodeData = {
        label: SOURCE_LABELS[src] ?? src,
        sourceKey: src,
        accent,
        eventCount: sourceCounts.get(src) ?? 0,
        lastMethod: last?.method || undefined,
        lastTime: last ? new Date(last.timestamp).toLocaleTimeString() : undefined,
      };

      rawNodes.push({
        id: srcId,
        type: 'source',
        position: { x: 0, y: 0 },
        data,
      });

      edgeList.push({
        id: `${srcId}-proxy`,
        source: srcId,
        target: 'proxy',
        type: 'gradient',
        data: {
          strokeStart: accent,
          strokeEnd: '#6366f1',
          animated: (sourceCounts.get(src) ?? 0) > 0,
          threat: events.some((e) => (e.source ?? 'ide') === src && e.threats.length > 0),
        },
      });
    }

    rawNodes.push({
      id: 'proxy',
      type: 'proxy',
      position: { x: 0, y: 0 },
      data: {
        totalEvents: events.length,
        totalThreats,
        guardianMode,
        hasThreats,
      },
    });

    servers.forEach((info, name) => {
      const id = `server-${name}`;
      const toolNames = toolsForServer(events, name);
      const serverData: ServerNodeData = {
        serverName: name,
        toolCount: info.tools || toolNames.length,
        threatCount: info.threats,
        toolNames,
        healthy: info.threats === 0,
      };

      rawNodes.push({
        id,
        type: 'server',
        position: { x: 0, y: 0 },
        data: serverData,
      });

      edgeList.push({
        id: `proxy-${id}`,
        source: 'proxy',
        target: id,
        type: 'gradient',
        data: {
          strokeStart: '#6366f1',
          strokeEnd: info.threats > 0 ? '#ef4444' : '#22c55e',
          animated: true,
          threat: info.threats > 0,
        },
      });
    });

    return { nodes: layoutNodes(rawNodes, edgeList), edges: edgeList };
  }, [events, guardianMode, topology]);

  const onNodeClick = useCallback(
    (_event: ReactMouseEvent, node: Node) => {
      if (!onGraphFilter) return;
      if (node.type === 'source' && node.id.startsWith('source-')) {
        const source = node.id.slice('source-'.length);
        onGraphFilter({ kind: 'source', source });
        return;
      }
      if (node.type === 'server' && node.id.startsWith('server-')) {
        const server = node.id.slice('server-'.length);
        onGraphFilter({ kind: 'server', server });
        return;
      }
      if (node.type === 'proxy') {
        onGraphFilter({ kind: 'clear' });
      }
    },
    [onGraphFilter],
  );

  return (
    <div className="h-full min-h-0 [&_.react-flow]:h-full [&_.react-flow]:min-h-0">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
        fitViewOptions={{ padding: 0.2, maxZoom: 1.2 }}
        minZoom={0.25}
        maxZoom={1.75}
        proOptions={{ hideAttribution: true }}
        onNodeClick={onNodeClick}
        defaultEdgeOptions={{ type: 'gradient' }}
        className="bg-transparent"
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable
        zoomOnScroll
        zoomOnPinch
        panOnDrag
      >
        <Background color="#1a1a24" gap={22} size={1.2} className="opacity-40" />
        <Controls position="bottom-left" showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
