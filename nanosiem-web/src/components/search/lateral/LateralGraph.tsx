// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState } from 'react';
import { cn } from '@/lib/utils';
import {
  bandColor,
  fmtCount,
  LATERAL_METHOD_LABEL,
  methodColor,
  methodGroup,
  NodeIcon,
} from './helpers';
import type { LateralEdge, LateralMethodGroup, LateralNode } from './types';

// ─── Layout constants — match design-ref/shadcn/lateral-graph.jsx ─────────────
const COL_W = 220;
const COL_GAP = 96;
const NODE_W = 200;
const NODE_H = 56;
const ROW_GAP = 12;
const PAD_X = 28;
const PAD_Y = 32;

interface NodePos {
  x: number;
  y: number;
  w: number;
  h: number;
}

interface Layout {
  positions: Record<string, NodePos>;
  width: number;
  height: number;
  maxHop: number;
  hopBuckets: Record<number, LateralNode[]>;
}

function computeLayout(nodes: LateralNode[]): Layout {
  const hopBuckets: Record<number, LateralNode[]> = {};
  for (const n of nodes) {
    (hopBuckets[n.hop] ??= []).push(n);
  }
  const hops = Object.keys(hopBuckets).map(Number);
  const maxHop = hops.length > 0 ? Math.max(...hops) : 0;
  const maxColCount = Math.max(1, ...Object.values(hopBuckets).map((a) => a.length));
  const maxColHeight = maxColCount * (NODE_H + ROW_GAP);

  const positions: Record<string, NodePos> = {};
  for (let h = 0; h <= maxHop; h++) {
    const col = hopBuckets[h] ?? [];
    const totalH = col.length * (NODE_H + ROW_GAP) - ROW_GAP;
    const startY = PAD_Y + (maxColHeight - totalH) / 2;
    col.forEach((n, i) => {
      positions[n.id] = {
        x: PAD_X + h * (COL_W + COL_GAP),
        y: startY + i * (NODE_H + ROW_GAP),
        w: NODE_W,
        h: NODE_H,
      };
    });
  }
  const width = PAD_X * 2 + (maxHop + 1) * COL_W + maxHop * COL_GAP;
  // Extra bottom padding so same-hop curves (which arc ~28px below the
  // bottom-most node) don't get clipped by the scroll container. Without
  // this, edges like user → service-account in the same column trail off
  // the bottom and the container refuses to scroll further.
  // Same-hop curves arc ~28px below the bottom-most node. 32 is just enough
  // padding so the curve isn't clipped, without blowing out the canvas on
  // columns that don't have same-hop edges at all.
  const EDGE_PAD = 32;
  const height = PAD_Y * 2 + maxColHeight + EDGE_PAD;
  return { positions, width, height, maxHop, hopBuckets };
}

function edgePath(s: NodePos, t: NodePos): string {
  const x1 = s.x + s.w;
  const y1 = s.y + s.h / 2;
  const x2 = t.x;
  const y2 = t.y + t.h / 2;
  const dx = Math.max(40, (x2 - x1) * 0.55);
  return `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
}

function sameHopPath(s: NodePos, t: NodePos): string {
  // Route from the LEFT edge of both nodes and arc out to the left of the
  // column so the curve is visible and doesn't overlap other rows in the
  // same column. Without this, the curve collapses to a ~28px vertical nub
  // centered under the source node (all same-hop nodes share the same X),
  // which looks like a stray line going nowhere.
  const x1 = s.x;
  const y1 = s.y + s.h / 2;
  const x2 = t.x;
  const y2 = t.y + t.h / 2;
  const arcX = s.x - 36;
  return `M ${x1} ${y1} C ${arcX} ${y1}, ${arcX} ${y2}, ${x2} ${y2}`;
}

function edgeMarkerId(key: string): string {
  return `arrow-${key.replace(/[^a-zA-Z0-9_-]/g, '_')}`;
}

interface LateralGraphProps {
  nodes: LateralNode[];
  edges: LateralEdge[];
  seedId: string;
  selectedId: string | null;
  selectedEdge: LateralEdge | null;
  onSelectNode: (id: string | null) => void;
  onSelectEdge: (edge: LateralEdge | null) => void;
  activeMethods: Set<LateralMethodGroup>;
  maxHops: number;
  criticalOnly: boolean;
  criticalPath: string[];
  criticalEdges: [string, string][];
  /** How to color edges + method chips: by method family or by severity band. */
  edgeColor?: 'method' | 'severity';
}

export function LateralGraph({
  nodes,
  edges,
  seedId,
  selectedId,
  selectedEdge,
  onSelectNode,
  onSelectEdge,
  activeMethods,
  maxHops,
  criticalOnly,
  criticalPath,
  criticalEdges,
  edgeColor = 'method',
}: LateralGraphProps) {
  // Which chip dropdown is currently expanded (keyed by `${from}|${to}`).
  // Only chips with multiple methods show a dropdown — single-method chips
  // select their edge directly on click.
  const [openChipKey, setOpenChipKey] = useState<string | null>(null);

  // Resolve an edge's render color based on the current `edgeColor` mode.
  // Kept inline so it sees `edgeColor` without threading it through memos.
  const edgeColorFor = (e: LateralEdge): string =>
    edgeColor === 'severity' ? bandColor(e.band) : methodColor(e.method);
  const edgeColorKeyFor = (e: LateralEdge): string =>
    edgeColor === 'severity' ? `band-${e.band}` : `method-${e.method}`;
  // Which edge pair is hovered — drives on-demand visibility of single-
  // method chips so the graph stays uncluttered by default.
  const [hoveredPairKey, setHoveredPairKey] = useState<string | null>(null);

  const criticalNodeSet = useMemo(() => new Set(criticalPath), [criticalPath]);
  const criticalEdgeSet = useMemo(
    () => new Set(criticalEdges.map(([a, b]) => `${a}→${b}`)),
    [criticalEdges]
  );

  const filteredEdges = useMemo(() => {
    return edges.filter((e) => {
      const group = methodGroup(e.method);
      if (!activeMethods.has(group)) return false;
      if (criticalOnly && !criticalEdgeSet.has(`${e.from}→${e.to}`)) return false;
      return true;
    });
  }, [edges, activeMethods, criticalOnly, criticalEdgeSet]);

  const visibleNodes = useMemo(() => {
    const base = nodes.filter((n) => n.hop <= maxHops);
    if (!criticalOnly) return base;
    return base.filter(
      (n) =>
        criticalNodeSet.has(n.id) ||
        filteredEdges.some((e) => e.from === n.id || e.to === n.id)
    );
  }, [nodes, maxHops, criticalOnly, criticalNodeSet, filteredEdges]);

  const visibleIdSet = useMemo(() => new Set(visibleNodes.map((n) => n.id)), [visibleNodes]);
  const visibleEdges = useMemo(
    () => filteredEdges.filter((e) => visibleIdSet.has(e.from) && visibleIdSet.has(e.to)),
    [filteredEdges, visibleIdSet]
  );

  const layout = useMemo(() => computeLayout(visibleNodes), [visibleNodes]);
  const { positions, width, height, maxHop, hopBuckets } = layout;

  const selNeighbors = useMemo(() => {
    if (!selectedId) return null;
    const s = new Set<string>([selectedId]);
    visibleEdges.forEach((e) => {
      if (e.from === selectedId) s.add(e.to);
      if (e.to === selectedId) s.add(e.from);
    });
    return s;
  }, [selectedId, visibleEdges]);

  const hopByNode = useMemo(() => {
    const m: Record<string, number> = {};
    visibleNodes.forEach((n) => {
      m[n.id] = n.hop;
    });
    return m;
  }, [visibleNodes]);

  const hopCols = useMemo(() => {
    const cols: { h: number; x: number; count: number }[] = [];
    for (let h = 0; h <= maxHop; h++) {
      cols.push({
        h,
        x: PAD_X + h * (COL_W + COL_GAP),
        count: (hopBuckets[h] ?? []).length,
      });
    }
    return cols;
  }, [maxHop, hopBuckets]);

  // Build one arrow marker per distinct color key in use. When coloring by
  // severity we need four (critical/high/medium/low); by method we need one
  // per method id. Re-generated when the mode or edge set changes so unused
  // markers don't pile up in the <defs>.
  const usedMarkers = useMemo(() => {
    const byKey = new Map<string, string>();
    visibleEdges.forEach((e) => {
      const key = edgeColorKeyFor(e);
      if (!byKey.has(key)) byKey.set(key, edgeColorFor(e));
    });
    return [...byKey.entries()].map(([key, color]) => ({ key, color }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visibleEdges, edgeColor]);

  // Collapse edges sharing the same (from, to) into a single chip entry.
  // Picks the edge with the highest count as the primary method to show,
  // and stashes a `+N` count of other methods on the same pair. Position
  // is the visual apex of the curve (which differs for same-hop vs
  // cross-hop edges, but both collapse to roughly the midpoint).
  const edgeChips = useMemo(() => {
    const byPair = new Map<string, LateralEdge[]>();
    for (const e of visibleEdges) {
      const key = `${e.from}|${e.to}`;
      const bucket = byPair.get(key);
      if (bucket) bucket.push(e);
      else byPair.set(key, [e]);
    }
    // Assign each chip a T value along its curve so siblings from the same
    // source spread out horizontally instead of piling at the midpoint.
    // Order sibling edges by target Y, then distribute T across [0.3, 0.72].
    const siblings = new Map<string, string[]>();
    for (const key of byPair.keys()) {
      const [from] = key.split('|');
      const arr = siblings.get(from) ?? [];
      arr.push(key);
      siblings.set(from, arr);
    }
    const tForKey = new Map<string, number>();
    for (const [from, keys] of siblings.entries()) {
      keys.sort((a, b) => {
        const ta = byPair.get(a)?.[0];
        const tb = byPair.get(b)?.[0];
        const ya = ta ? positions[ta.to]?.y ?? 0 : 0;
        const yb = tb ? positions[tb.to]?.y ?? 0 : 0;
        return ya - yb;
      });
      const n = keys.length;
      if (n === 1) {
        tForKey.set(keys[0], 0.55);
      } else {
        keys.forEach((k, i) => {
          // Spread across the curve, biased slightly toward the target so
          // labels sit in the gap right before the next column.
          tForKey.set(k, 0.32 + (i / (n - 1)) * 0.4);
        });
      }
      void from;
    }
    const out: {
      key: string;
      primary: LateralEdge;
      edges: LateralEdge[];
      x: number;
      y: number;
      color: string;
      label: string;
      extraMethods: number;
    }[] = [];
    for (const [key, edges] of byPair.entries()) {
      const s = positions[edges[0].from];
      const t = positions[edges[0].to];
      if (!s || !t) continue;
      // Sort by count desc so dropdown lists most-used methods first.
      edges.sort((a, b) => b.count - a.count);
      const primary = edges[0];
      const label = LATERAL_METHOD_LABEL[primary.method];
      if (!label) continue;
      const sameHop = hopByNode[primary.from] === hopByNode[primary.to];
      // For cross-hop edges, place the chip near the TARGET (t=0.82 along
      // the curve) so chips spread vertically along the target column
      // instead of piling up in the mid-gap. Avoids overlapping hop-1 node
      // cards when an edge skips a hop (hop-0 → hop-2 direct).
      let mx: number;
      let my: number;
      if (sameHop) {
        mx = s.x - 36;
        my = (s.y + s.h / 2 + t.y + t.h / 2) / 2;
      } else {
        // Position the chip on the ACTUAL cubic bezier curve (not the
        // straight-line midpoint) so labels sit on top of the line they
        // describe. For steep diagonals the curve bows significantly away
        // from the chord, which used to leave labels floating in space.
        const x1 = s.x + s.w;
        const y1 = s.y + s.h / 2;
        const x2 = t.x;
        const y2 = t.y + t.h / 2;
        const dx = Math.max(40, (x2 - x1) * 0.55);
        const p0x = x1, p0y = y1;
        const p1x = x1 + dx, p1y = y1;
        const p2x = x2 - dx, p2y = y2;
        const p3x = x2, p3y = y2;
        const tVal = tForKey.get(key) ?? 0.5;
        const tv = tVal;
        const it = 1 - tv;
        const bx = it * it * it * p0x + 3 * it * it * tv * p1x + 3 * it * tv * tv * p2x + tv * tv * tv * p3x;
        const by = it * it * it * p0y + 3 * it * it * tv * p1y + 3 * it * tv * tv * p2y + tv * tv * tv * p3y;
        // Clamp X into the inter-column gap so the chip doesn't drift into
        // a node card even when the bezier point wanders close to one.
        mx = Math.max(x1 + 42, Math.min(x2 - 42, bx));
        my = by;
      }
      out.push({
        key,
        primary,
        edges,
        x: mx,
        y: my,
        color: edgeColorFor(primary),
        label,
        extraMethods: edges.length - 1,
      });
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visibleEdges, positions, hopByNode, edgeColor]);

  if (visibleNodes.length === 0) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center text-center px-6 py-10 gap-3 bg-background/40">
        <svg
          viewBox="0 0 64 64"
          className="w-10 h-10 text-muted-foreground/60"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
        >
          <circle cx="12" cy="12" r="4" />
          <circle cx="52" cy="52" r="4" />
          <circle cx="52" cy="12" r="4" />
          <circle cx="32" cy="32" r="4" />
          <path d="M16 12h32M52 16v32M16 16l32 32M36 32l12 16" />
        </svg>
        <div className="font-mono text-[12px] text-foreground">No edges in current view</div>
        <div className="font-mono text-[10.5px] text-muted-foreground/80 max-w-md leading-relaxed">
          Try increasing max hops, enabling more methods, or disabling the critical-path filter.
        </div>
      </div>
    );
  }

  return (
    <div
      className="relative h-full w-full min-h-0 min-w-0 overflow-auto bg-background/40"
      onClick={() => {
        onSelectNode(null);
        onSelectEdge(null);
        setOpenChipKey(null);
      }}
    >
      <div className="relative" style={{ width, height }}>
        {/* Column headers */}
        {hopCols.map((c) => (
          <div
            key={c.h}
            className="absolute top-2 font-mono text-[10px] tracking-[0.12em] uppercase text-muted-foreground/80 flex items-center gap-1.5"
            style={{ left: c.x, width: NODE_W }}
          >
            <span
              className="w-1 h-3 rounded-sm"
              style={{ background: c.h === 0 ? 'oklch(62% 0.18 28)' : 'oklch(70% 0.08 220)' }}
            />
            <span className="text-muted-foreground/80">{c.h === 0 ? 'SEED' : `HOP ${c.h}`}</span>
            <span className="text-muted-foreground/60">· {c.count}</span>
          </div>
        ))}

        {/* Column dividers + edges */}
        <svg className="absolute inset-0 pointer-events-none" width={width} height={height}>
          {hopCols.slice(1).map((c) => (
            <line
              key={c.h}
              x1={c.x - COL_GAP / 2}
              y1={PAD_Y - 4}
              x2={c.x - COL_GAP / 2}
              y2={height - 6}
              stroke="oklch(35% 0.01 240 / 0.35)"
              strokeDasharray="2 6"
              strokeWidth="1"
            />
          ))}

          <defs>
            {usedMarkers.map(({ key, color }) => (
              <marker
                key={key}
                id={edgeMarkerId(key)}
                viewBox="0 0 10 10"
                refX="9"
                refY="5"
                markerWidth="5"
                markerHeight="5"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill={color} />
              </marker>
            ))}
          </defs>

          {visibleEdges.map((e, i) => {
            const s = positions[e.from];
            const t = positions[e.to];
            if (!s || !t) return null;
            const sameHop = hopByNode[e.from] === hopByNode[e.to];
            const d = sameHop ? sameHopPath(s, t) : edgePath(s, t);
            const color = edgeColorFor(e);
            const thickness = 0.6 + Math.min(2.4, Math.log10(Math.max(1, e.count)) * 0.9);
            const isSel =
              selectedEdge && selectedEdge.from === e.from && selectedEdge.to === e.to;
            const related =
              selNeighbors && (selNeighbors.has(e.from) || selNeighbors.has(e.to));
            const dim = (selectedId && !related) || (selectedEdge && !isSel);
            const pairKey = `${e.from}|${e.to}`;
            return (
              <g key={`${e.from}|${e.to}|${e.method}|${i}`} style={{ opacity: dim ? 0.18 : 1, transition: 'opacity 120ms' }}
                 onMouseEnter={() => setHoveredPairKey(pairKey)}
                 onMouseLeave={() => setHoveredPairKey((cur) => (cur === pairKey ? null : cur))}>
                <path
                  d={d}
                  fill="none"
                  stroke={color}
                  strokeWidth={isSel ? thickness + 1.2 : thickness}
                  strokeOpacity={isSel ? 1 : 0.78}
                  strokeLinecap="round"
                  markerEnd={`url(#${edgeMarkerId(edgeColorKeyFor(e))})`}
                  className="pointer-events-auto cursor-pointer"
                  style={{ pointerEvents: 'visibleStroke' }}
                  onClick={(ev) => {
                    ev.stopPropagation();
                    onSelectEdge(e);
                    onSelectNode(null);
                  }}
                />
                {/* Hit target */}
                <path
                  d={d}
                  fill="none"
                  stroke="transparent"
                  strokeWidth="14"
                  className="pointer-events-auto cursor-pointer"
                  onClick={(ev) => {
                    ev.stopPropagation();
                    onSelectEdge(e);
                    onSelectNode(null);
                  }}
                />
              </g>
            );
          })}
        </svg>

        {/* Protocol chips — one per (src, dest) pair. Multiple methods
            between the same node pair collapse into one chip with a `+N`
            suffix; clicking the chip then opens a dropdown so analysts can
            pick which method to inspect. Single-method chips select their
            edge directly. */}
        {edgeChips.map((chip) => {
          const isOpen = openChipKey === chip.key;
          const selContainsPair = selectedEdge
            ? chip.edges.some(
                (e) => selectedEdge.from === e.from && selectedEdge.to === e.to
              )
            : false;
          const related =
            selNeighbors &&
            (selNeighbors.has(chip.primary.from) || selNeighbors.has(chip.primary.to));
          const dim =
            (selectedId && !related) ||
            (selectedEdge && !selContainsPair && !isOpen);
          const hasMany = chip.extraMethods > 0;
          const isHovered = hoveredPairKey === chip.key;
          // Keep the graph uncluttered: single-method chips only appear
          // when the edge is hovered, selected, or the dropdown is open.
          // Multi-method chips (+N) stay visible so the "interesting" pairs
          // always advertise their protocol diversity.
          const showChip =
            hasMany || isOpen || isHovered || selContainsPair || related;

          return (
            <div
              key={`chip-${chip.key}`}
              className="absolute -translate-x-1/2 -translate-y-1/2"
              style={{ left: chip.x, top: chip.y, zIndex: isOpen ? 10 : 1 }}
              onMouseEnter={() => setHoveredPairKey(chip.key)}
              onMouseLeave={() =>
                setHoveredPairKey((cur) => (cur === chip.key ? null : cur))
              }
            >
              <button
                onClick={(ev) => {
                  ev.stopPropagation();
                  if (hasMany) {
                    setOpenChipKey(isOpen ? null : chip.key);
                  } else {
                    onSelectEdge(chip.primary);
                    onSelectNode(null);
                  }
                }}
                className={cn(
                  'font-mono text-[9.5px] tracking-wide uppercase leading-none px-1.5 py-0.5 rounded-sm border cursor-pointer whitespace-nowrap flex items-center',
                  'transition-opacity duration-150',
                  !showChip && 'opacity-0 pointer-events-none',
                  showChip && (dim && !isOpen ? 'opacity-30' : 'opacity-90 hover:opacity-100'),
                  isOpen && 'opacity-100 ring-1 ring-offset-0'
                )}
                style={{
                  color: chip.color,
                  borderColor: `${chip.color}55`,
                  background: 'oklch(14% 0.01 240 / 0.92)',
                  boxShadow: isOpen ? `0 0 0 1px ${chip.color}55` : undefined,
                }}
                title={hasMany ? `${chip.edges.length} methods — click to choose` : chip.primary.detail}
              >
                {chip.label}
                {hasMany && (
                  <span className="ml-1 text-muted-foreground/80 normal-case tracking-normal">
                    +{chip.extraMethods}
                  </span>
                )}
              </button>
              {isOpen && hasMany && (
                <div
                  onClick={(ev) => ev.stopPropagation()}
                  className="absolute left-1/2 top-full mt-1 -translate-x-1/2 min-w-[180px] rounded-md border border-border bg-card shadow-lg overflow-hidden"
                  style={{ zIndex: 20 }}
                >
                  <div className="px-2 py-1 border-b border-border font-mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground/80">
                    {chip.edges.length} methods
                  </div>
                  {chip.edges.map((e, i) => {
                    const label = LATERAL_METHOD_LABEL[e.method] ?? e.method;
                    const itemColor = methodColor(e.method);
                    return (
                      <button
                        key={`${e.method}|${i}`}
                        onClick={(ev) => {
                          ev.stopPropagation();
                          onSelectEdge(e);
                          onSelectNode(null);
                          setOpenChipKey(null);
                        }}
                        className="w-full px-2 py-1.5 flex items-center gap-2 text-left hover:bg-foreground/[0.04] border-b border-border/60 last:border-b-0"
                      >
                        <span
                          className="w-1.5 h-1.5 rounded-full shrink-0"
                          style={{ background: itemColor }}
                        />
                        <span
                          className="font-mono text-[10px] uppercase tracking-wide shrink-0"
                          style={{ color: itemColor }}
                        >
                          {label}
                        </span>
                        <span className="flex-1 font-mono text-[10px] text-muted-foreground/80 truncate">
                          {e.detail}
                        </span>
                        <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums shrink-0">
                          {e.count}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}

        {/* Nodes */}
        {visibleNodes.map((n) => {
          const pos = positions[n.id];
          if (!pos) return null;
          const dim =
            (selectedId && !selNeighbors?.has(n.id)) ||
            (selectedEdge && selectedEdge.from !== n.id && selectedEdge.to !== n.id);
          const isOnCrit = criticalNodeSet.has(n.id);
          const isSeed = n.id === seedId;
          const color = bandColor(n.band);
          const selected = selectedId === n.id;
          return (
            <div
              key={n.id}
              onClick={(e) => {
                e.stopPropagation();
                onSelectNode(n.id);
                onSelectEdge(null);
              }}
              className={cn(
                'absolute rounded-md border bg-card transition-all duration-150 cursor-pointer group',
                selected
                  ? 'ring-2 ring-primary/60 border-primary/50'
                  : 'border-border hover:border-foreground/40',
                dim && 'opacity-25',
                isSeed && !selected && 'ring-1 ring-[oklch(68%_0.18_28/0.4)]'
              )}
              style={{
                left: pos.x,
                top: pos.y,
                width: pos.w,
                height: pos.h,
                boxShadow: selected
                  ? `0 0 0 1px ${color}55, 0 6px 22px -10px ${color}80`
                  : isOnCrit
                  ? `0 0 0 1px ${color}44`
                  : undefined,
              }}
            >
              <div className="flex items-center gap-2 h-full px-2.5">
                <div className="relative shrink-0">
                  <div
                    className="w-7 h-7 rounded flex items-center justify-center"
                    style={{
                      background: `${color}22`,
                      color,
                      border: `1px solid ${color}55`,
                    }}
                  >
                    <NodeIcon type={n.type} className="w-3.5 h-3.5" />
                  </div>
                  {isSeed && (
                    <span className="absolute -top-1 -right-1 text-[8px] font-mono px-1 rounded-sm bg-[oklch(62%_0.18_28)] text-white tracking-[0.08em]">
                      SEED
                    </span>
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-[12px] text-foreground truncate">
                      {n.label}
                    </span>
                    <span
                      className="w-1 h-1 rounded-full shrink-0"
                      style={{ background: color }}
                    />
                  </div>
                  <div className="font-mono text-[10px] text-muted-foreground/80 truncate">
                    {n.sub}
                  </div>
                </div>
                <div className="flex flex-col items-end shrink-0 font-mono">
                  <span className="text-[9px] text-muted-foreground/70 tabular-nums">
                    {n.firstSeen}
                  </span>
                  <span className="text-[9.5px] text-muted-foreground/80 tabular-nums">
                    {fmtCount(n.events)}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
