// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState } from 'react';
import { LateralTopStrip } from './LateralTopStrip';
import { LateralReasoningBand } from './LateralReasoningBand';
import { LateralGraph } from './LateralGraph';
import { LateralLegend } from './LateralLegend';
import { LateralNodeDrawer } from './LateralNodeDrawer';
import { LateralEdgeDrawer } from './LateralEdgeDrawer';
import { LateralEmpty } from './LateralEmpty';
import { quoteValue, rewriteLateralSeed, stripLateralCommand } from './helpers';
import type {
  LateralBand,
  LateralEdge,
  LateralEvidence,
  LateralGraphPayload,
  LateralMethodGroup,
  LateralNode,
  LateralRole,
  LateralSummary,
} from './types';

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

interface LateralViewProps {
  results: SearchResult[];
  /** Current query string — used for click-to-pivot rewrites */
  query?: string;
  /** Replace the entire query string and re-run */
  onSetQuery?: (query: string) => void;
  /** Append a base-search filter (used as fallback when onSetQuery isn't wired) */
  onAddToQuery?: (field: string, value: string, exclude: boolean) => void;
  fieldsCount?: number;
  onExpandFields?: () => void;
}

function asString(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function asNumber(v: unknown): number {
  return typeof v === 'number' ? v : 0;
}

function parseGraphPayload(raw: unknown): LateralGraphPayload | null {
  if (!raw || typeof raw !== 'object') return null;
  const obj = raw as Record<string, unknown>;
  const nodesRaw = Array.isArray(obj.nodes) ? obj.nodes : [];
  const edgesRaw = Array.isArray(obj.edges) ? obj.edges : [];
  const criticalPath = Array.isArray(obj.critical_path) ? (obj.critical_path as string[]) : [];
  const criticalEdgesRaw = Array.isArray(obj.critical_edges) ? obj.critical_edges : [];
  const evidenceRaw = obj.evidence && typeof obj.evidence === 'object' ? obj.evidence : {};
  const summaryRaw = obj.summary && typeof obj.summary === 'object' ? obj.summary : null;

  const nodes: LateralNode[] = nodesRaw.map((n) => {
    const nn = n as Record<string, unknown>;
    return {
      id: asString(nn.id),
      type: (asString(nn.type) || 'host') as LateralNode['type'],
      hop: asNumber(nn.hop),
      label: asString(nn.label),
      sub: asString(nn.sub),
      band: (asString(nn.band) || 'low') as LateralBand,
      role: (asString(nn.role) || 'edge') as LateralRole,
      firstSeen: asString(nn.firstSeen),
      events: asNumber(nn.events),
      flags: Array.isArray(nn.flags) ? (nn.flags as string[]) : undefined,
    };
  });

  const edges: LateralEdge[] = edgesRaw.map((e) => {
    const ee = e as Record<string, unknown>;
    return {
      from: asString(ee.from),
      to: asString(ee.to),
      method: asString(ee.method),
      detail: asString(ee.detail),
      count: asNumber(ee.count),
      firstSeen: asString(ee.firstSeen),
      band: (asString(ee.band) || 'low') as LateralBand,
    };
  });

  const criticalEdges: [string, string][] = criticalEdgesRaw
    .map((pair) => {
      if (!Array.isArray(pair) || pair.length < 2) return null;
      return [String(pair[0]), String(pair[1])] as [string, string];
    })
    .filter((p): p is [string, string] => p !== null);

  const evidence: Record<string, LateralEvidence> = {};
  for (const [k, v] of Object.entries(evidenceRaw)) {
    if (!v || typeof v !== 'object') continue;
    const e = v as Record<string, unknown>;
    evidence[k] = {
      auth: Array.isArray(e.auth) ? (e.auth as LateralEvidence['auth']) : [],
      network: Array.isArray(e.network) ? (e.network as LateralEvidence['network']) : [],
      process: Array.isArray(e.process) ? (e.process as LateralEvidence['process']) : [],
    };
  }

  const sObj = summaryRaw as Record<string, unknown> | null;
  const summary: LateralSummary = {
    seed: {
      kind:
        ((sObj?.seed as Record<string, unknown> | undefined)?.kind as 'host' | 'user') ?? 'host',
      id: asString((sObj?.seed as Record<string, unknown> | undefined)?.id),
    },
    method: asString(sObj?.method),
    maxHops: asNumber(sObj?.maxHops),
    windowLabel: asString(sObj?.windowLabel),
    windowStart: asString(sObj?.windowStart),
    windowEnd: asString(sObj?.windowEnd),
    hops: asNumber(sObj?.hops),
    nodes: asNumber(sObj?.nodes),
    edges: asNumber(sObj?.edges),
    reachCritical: asNumber(sObj?.reachCritical),
    reachCrown: asNumber(sObj?.reachCrown),
    deadEnds: asNumber(sObj?.deadEnds),
    truncated: sObj?.truncated === true,
    originalNodes: asNumber(sObj?.originalNodes),
  };

  return { nodes, edges, critical_path: criticalPath, critical_edges: criticalEdges, evidence, summary };
}

export function LateralView({
  results,
  query,
  onSetQuery,
  onAddToQuery,
  fieldsCount,
  onExpandFields,
}: LateralViewProps) {
  const meta = results.find((r) => r.fields?._display_type === 'lateral');
  const graph = useMemo(() => parseGraphPayload(meta?.fields?._lateral_graph), [meta]);

  const seedId = graph?.summary.seed.id ?? '';
  const initialMaxHops = Math.max(2, Math.min(4, graph?.summary.maxHops || 4));

  // ─── View-local state (NAN-395 invariant 1: never touches the query) ────────
  const [maxHops, setMaxHops] = useState(initialMaxHops);
  const [methods, setMethods] = useState<Set<LateralMethodGroup>>(
    () => new Set(['auth', 'network', 'process'])
  );
  const [criticalOnly, setCriticalOnly] = useState(false);
  const [edgeColor, setEdgeColor] = useState<'method' | 'severity'>('severity');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<LateralEdge | null>(null);

  const toggleMethod = (id: LateralMethodGroup) => {
    setMethods((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      if (next.size === 0) return s; // keep at least one active
      return next;
    });
  };

  // ─── Click-to-pivot helpers (NAN-395 invariants 2 + 3) ──────────────────────
  // Entity pivot: rewrite the `| lateral` arg so we hop seeds without leaving.
  // Used by the critical-path breadcrumb — just stays in the same surface.
  const handlePivotSeed = (id: string, kind: 'host' | 'user' | 'ip') => {
    if (!id || id === seedId) return;
    const field = kind === 'user' ? 'user' : kind === 'ip' ? 'src_ip' : 'src_host';
    if (query && onSetQuery) {
      onSetQuery(rewriteLateralSeed(query, field, id));
    } else if (onAddToQuery) {
      onAddToQuery(field, id, false);
    }
  };

  // Open asset view for a host/user node — drops `| lateral` and pipes to `| asset`.
  const handleOpenAsset = (node: LateralNode) => {
    if (!query || !onSetQuery) {
      onAddToQuery?.(
        node.type === 'user' ? 'user' : node.type === 'ip' ? 'src_ip' : 'src_host',
        node.label,
        false
      );
      return;
    }
    const field = node.type === 'user' ? 'user' : node.type === 'ip' ? 'src_ip' : 'src_host';
    const withoutLateral = stripLateralCommand(query);
    const filter = `${field}=${quoteValue(node.label)}`;
    const base = withoutLateral ? `${withoutLateral} ${filter}` : filter;
    onSetQuery(`${base} | asset`);
  };

  // "Pivot to events" for nodes / edges — drops `| lateral` and appends a base
  // filter so the user sees raw events. NAN-395 invariant 3.
  const handlePivotEventsForNode = (node: LateralNode) => {
    const field =
      node.type === 'user'
        ? 'user'
        : node.type === 'ip'
        ? 'src_ip'
        : node.type === 'process'
        ? 'process_name'
        : 'src_host';
    pivotToEvents(field, node.label);
  };

  const handlePivotEventsForEdge = (edge: LateralEdge) => {
    // Edge → use the destination as the filter (where the connection landed)
    const dest = graph?.nodes.find((n) => n.id === edge.to);
    if (!dest) return;
    const field =
      dest.type === 'user'
        ? 'user'
        : dest.type === 'ip'
        ? 'src_ip'
        : dest.type === 'process'
        ? 'process_name'
        : 'dest_host';
    pivotToEvents(field, dest.label);
  };

  function pivotToEvents(field: string, value: string) {
    if (!value) return;
    if (query && onSetQuery) {
      const withoutLateral = stripLateralCommand(query);
      const filter = `${field}=${quoteValue(value)}`;
      onSetQuery(withoutLateral ? `${withoutLateral} ${filter}` : filter);
    } else if (onAddToQuery) {
      onAddToQuery(field, value, false);
    }
  }

  const handleCopyQuery = (node: LateralNode) => {
    const field =
      node.type === 'user'
        ? 'user'
        : node.type === 'ip'
        ? 'src_ip'
        : node.type === 'process'
        ? 'process_name'
        : 'src_host';
    const q = `${field}=${quoteValue(node.label)}`;
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(q).catch(() => {});
    }
  };

  // ─── Empty states ───────────────────────────────────────────────────────────
  if (!graph || !seedId) {
    return (
      <div className="flex flex-col min-h-0 min-w-0 overflow-hidden">
        <LateralEmpty reason="no-seed" />
      </div>
    );
  }

  const selectedNode = selectedId ? graph.nodes.find((n) => n.id === selectedId) ?? null : null;
  const drawerOpen = !!(selectedNode || selectedEdge);

  const windowLabel = graph.summary.windowLabel
    ? graph.summary.windowLabel.split('·').pop()?.trim() ?? graph.summary.windowLabel
    : '—';

  // For the breadcrumb pivots, infer kind from the node lookup.
  const handlePivotByCriticalPathId = (id: string) => {
    const node = graph.nodes.find((n) => n.id === id);
    if (!node) return;
    if (node.type === 'host' || node.type === 'user' || node.type === 'ip') {
      handlePivotSeed(node.label, node.type);
    } else if (node.type === 'process') {
      pivotToEvents('process_name', node.label);
    }
  };

  return (
    // Bounded height so the SVG canvas scrolls internally instead of pushing
    // the page. Tall enough for a 4-hop graph plus an open method dropdown
    // without clipping; larger graphs get in-canvas scroll via `overflow-
    // auto` in LateralGraph.
    <div className="flex flex-col h-[680px] min-w-0 overflow-hidden">
      <LateralTopStrip
        summary={graph.summary}
        maxHops={maxHops}
        methods={methods}
        windowLabel={windowLabel}
        criticalOnly={criticalOnly}
        onSetMaxHops={setMaxHops}
        onToggleCritical={() => setCriticalOnly((v) => !v)}
        hasCriticalPath={
          graph.critical_path.length > 1 &&
          graph.critical_path
            .slice(1)
            .some((id) => graph.nodes.find((n) => n.id === id)?.band === 'critical')
        }
        edgeColor={edgeColor}
        onSetEdgeColor={setEdgeColor}
        fieldsCount={fieldsCount}
        onExpandFields={onExpandFields}
      />

      <LateralReasoningBand
        summary={graph.summary}
        criticalPath={graph.critical_path}
        onPivotNode={handlePivotByCriticalPathId}
      />

      {graph.nodes.length === 0 ? (
        <LateralEmpty reason="no-edges" />
      ) : (
        <div
          className="flex-1 min-h-0 min-w-0 grid"
          style={{
            gridTemplateColumns: drawerOpen ? '1fr 340px' : '1fr',
            // Force the row to `minmax(0, 1fr)` so the graph cell can clip
            // rather than grow to content height — lets `overflow-auto`
            // inside LateralGraph actually take effect.
            gridTemplateRows: 'minmax(0, 1fr)',
          }}
        >
          <LateralGraph
            nodes={graph.nodes}
            edges={graph.edges}
            seedId={seedId}
            selectedId={selectedId}
            selectedEdge={selectedEdge}
            onSelectNode={setSelectedId}
            onSelectEdge={setSelectedEdge}
            activeMethods={methods}
            maxHops={maxHops}
            criticalOnly={criticalOnly}
            criticalPath={graph.critical_path}
            criticalEdges={graph.critical_edges}
            edgeColor={edgeColor}
          />

          {selectedNode && (
            <LateralNodeDrawer
              node={selectedNode}
              evidence={graph.evidence[selectedNode.id] ?? null}
              onClose={() => setSelectedId(null)}
              onPivotEvents={handlePivotEventsForNode}
              onPivotAsset={handleOpenAsset}
              onCopyQuery={handleCopyQuery}
            />
          )}
          {!selectedNode && selectedEdge && (
            <LateralEdgeDrawer
              edge={selectedEdge}
              nodes={graph.nodes}
              onClose={() => setSelectedEdge(null)}
              onPivotEvents={handlePivotEventsForEdge}
            />
          )}
        </div>
      )}

      <LateralLegend
        methods={methods}
        edges={graph.edges}
        onToggleMethod={toggleMethod}
      />
    </div>
  );
}
