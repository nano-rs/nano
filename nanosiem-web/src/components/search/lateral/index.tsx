// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useMemo, useState } from 'react';
import { api } from '@/lib/api';
import { useReportPhase2Status } from '../footer-reporter';
import { LateralTopStrip } from './LateralTopStrip';
import { LateralReasoningBand } from './LateralReasoningBand';
import { LateralGraph } from './LateralGraph';
import { LateralLegend } from './LateralLegend';
import { LateralNodeDrawer } from './LateralNodeDrawer';
import { LateralEdgeDrawer } from './LateralEdgeDrawer';
import { LateralEmpty } from './LateralEmpty';
import { lateralFilter, lateralNodeKey, rewriteLateralSeed, stripLateralCommand } from './helpers';
import { useSchemaFieldMap } from '@/hooks/useSchemaFieldMap';
import type { SemanticField } from '@/lib/schema-fields';
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

interface LateralStreamState {
  key: string;
  graph: LateralGraphPayload | null;
  hops: number;
  complete: boolean;
  settled?: boolean;
  totalCount?: number;
  error?: string;
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
  // NAN-3077: a progressive answer is a pending marker; this view streams the
  // traversal itself and paints the cumulative graph after each hop.
  const pending = meta?.fields?._lateral_pending === true;
  const range = meta?.fields?._lateral_time_range as { start: string; end: string } | undefined;
  const pendingConfig = meta?.fields?._lateral_config as Record<string, unknown> | undefined;
  const plannedHops = asNumber(pendingConfig?.max_hops);
  const streamKey = JSON.stringify([query, range?.start, range?.end, pendingConfig, meta?.fields?._lateral_trace_id]);
  const [streamed, setStreamed] = useState<LateralStreamState | null>(null);
  useEffect(() => {
    if (!pending || !query || !range) return;
    let current = true;
    setStreamed({ key: streamKey, graph: null, hops: 0, complete: false });
    const accept = (rows: Record<string, unknown>[], hops: number, complete: boolean) => {
      if (!current) return;
      const marker = rows.find((row) => row._display_type === 'lateral');
      const next = parseGraphPayload(marker?._lateral_graph);
      if (!next) return;
      const totalEdges = (marker?._lateral_config as Record<string, unknown> | undefined)?.total_edges;
      setStreamed((previous) => ({
        ...previous,
        key: streamKey,
        graph: next,
        hops: Math.max(hops, previous?.key === streamKey ? previous.hops : 0),
        complete,
        totalCount: typeof totalEdges === 'number' ? totalEdges : previous?.totalCount,
      }));
    };
    const controller = api.searchStreamSSE(
      { query, time_range: range, skip_histogram: true, skip_field_stats: true },
      {
        onViewUpdate: (update) => {
          if (update.view === 'lateral') accept(update.rows, update.completed_hops, update.complete);
        },
        // Cached streams deliver the final graph in a row batch.
        onRows: (update) => accept(update.rows, 0, true),
        onCompleted: () => {
          if (current) setStreamed((previous) => previous?.key === streamKey
            ? { ...previous, settled: true, error: previous.complete ? previous.error : 'Traversal stopped; graph is incomplete' }
            : previous);
        },
        onError: (error) => {
          if (current) setStreamed((previous) => previous?.key === streamKey ? { ...previous, settled: true, error: error.message } : previous);
        },
      },
      { bypass: true, progressive: false },
    );
    // Dropping the SSE body aborts the server traversal (superseded pivot / unmount).
    return () => { current = false; controller.abort(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- streamKey covers query/range/config/trace id
  }, [pending, streamKey]);
  const activeStream = streamed?.key === streamKey ? streamed : null;
  const graph = useMemo(
    () => activeStream?.graph ?? parseGraphPayload(meta?.fields?._lateral_graph),
    [activeStream, meta],
  );
  useReportPhase2Status({
    loading: pending && !activeStream?.settled,
    settled: pending ? !!activeStream?.settled : true,
    error: activeStream?.error,
    totalCount: pending ? activeStream?.totalCount : asNumber((meta?.fields?._lateral_config as Record<string, unknown> | undefined)?.total_edges),
  });
  const progress = pending && !activeStream?.complete
    ? activeStream?.error
      ?? (activeStream?.hops
        ? `hop ${activeStream.hops}${plannedHops ? ` of ${plannedHops}` : ''} · ${activeStream.graph?.edges.length ?? 0} edges · enrichment pending`
        : 'Loading first hop…')
    : activeStream?.error ?? null;

  const seedId = graph?.summary.seed.id ?? '';
  const initialMaxHops = Math.max(2, Math.min(4, graph?.summary.maxHops || 4));

  // ─── View-local state (NAN-395 invariant 1: never touches the query) ────────
  const fieldMap = useSchemaFieldMap();
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
    // NAN-4903: no profile-shaped query until the schema profile is known.
    if (!fieldMap.ready) return fieldMap.guard(() => {})();
    if (query && onSetQuery) {
      onSetQuery(rewriteLateralSeed(query, kind, id, fieldMap));
    } else if (onAddToQuery) {
      onAddToQuery(fieldMap.field(lateralNodeKey(kind)), id, false);
    }
  };

  // Open asset view for a host/user node — drops `| lateral` and pipes to `| asset`.
  const handleOpenAsset = (node: LateralNode) => {
    // NAN-4903: no profile-shaped query until the schema profile is known.
    if (!fieldMap.ready) return fieldMap.guard(() => {})();
    const kind = node.type === 'process' ? 'host' : node.type;
    const key = lateralNodeKey(kind);
    if (!query || !onSetQuery) {
      onAddToQuery?.(fieldMap.field(key), node.label, false);
      return;
    }
    const withoutLateral = stripLateralCommand(query);
    const filter = lateralFilter(fieldMap, key, node.label);
    const base = withoutLateral ? `${withoutLateral} ${filter}` : filter;
    onSetQuery(`${base} | asset`);
  };

  // "Pivot to events" for nodes / edges — drops `| lateral` and appends a base
  // filter so the user sees raw events. NAN-395 invariant 3.
  const handlePivotEventsForNode = (node: LateralNode) => {
    pivotToEvents(lateralNodeKey(node.type), node.label);
  };

  const handlePivotEventsForEdge = (edge: LateralEdge) => {
    // Edge → use the destination as the filter (where the connection landed)
    const dest = graph?.nodes.find((n) => n.id === edge.to);
    if (!dest) return;
    pivotToEvents(lateralNodeKey(dest.type, 'destHost'), dest.label);
  };

  function pivotToEvents(key: SemanticField, value: string) {
    if (!value) return;
    // NAN-4903: no profile-shaped query until the schema profile is known.
    if (!fieldMap.ready) return fieldMap.guard(() => {})();
    if (query && onSetQuery) {
      const withoutLateral = stripLateralCommand(query);
      const filter = lateralFilter(fieldMap, key, value);
      onSetQuery(withoutLateral ? `${withoutLateral} ${filter}` : filter);
    } else if (onAddToQuery) {
      onAddToQuery(fieldMap.field(key), value, false);
    }
  }

  const handleCopyQuery = (node: LateralNode) => {
    // NAN-4903: no profile-shaped query until the schema profile is known.
    if (!fieldMap.ready) return fieldMap.guard(() => {})();
    const q = lateralFilter(fieldMap, lateralNodeKey(node.type), node.label);
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(q).catch(() => {});
    }
  };

  // ─── Empty states ───────────────────────────────────────────────────────────
  if (!graph || !seedId) {
    return (
      <div className="flex flex-col min-h-0 min-w-0 overflow-hidden">
        {pending ? (
          <div className="px-4 py-3 text-[10.5px] font-mono text-muted-foreground" role="status">{progress}</div>
        ) : (
          <LateralEmpty reason="no-seed" />
        )}
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
      pivotToEvents('processName', node.label);
    }
  };

  return (
    // Bounded height so the SVG canvas scrolls internally instead of pushing
    // the page. Tall enough for a 4-hop graph plus an open method dropdown
    // without clipping; larger graphs get in-canvas scroll via `overflow-
    // auto` in LateralGraph.
    <div className="flex flex-col h-[680px] min-w-0 overflow-hidden">
      {progress && (
        <div className="px-4 py-1 border-b border-border text-[10.5px] font-mono text-muted-foreground" role="status">{progress}</div>
      )}
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
