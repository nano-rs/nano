// SPDX-License-Identifier: AGPL-3.0-or-later

// TraceWaterfall + SpanDrawer (NAN-1536) — the Observability-console trace
// drill-in. Ported from the design handoff's obs-traces.jsx (TraceWaterfall /
// SpanDrawer), fed by REAL OTLP spans (api.observability.getTrace → OtelSpan[]).
//
// Adds a per-service color legend, a meta strip, and a right-side span drawer
// that shows the span's attributes + an "Explore in search" pivot keyed on
// trace_id. NAN-1547: this is now the single trace-waterfall surface — both the
// console's inline drill-in AND the standalone /trace/:id page (TracePage)
// render it, so the older TraceWaterfallView was retired.
//
// Dense conventions: mono for ids/durations/counts, 11–13px text, single 1px
// borders, no shadows. Colors flow through CSS custom props so they track theme.

import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowLeft,
  GitBranch,
  CornerDownRight,
  X,
  Search,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { parseUTCTimestamp } from '@/lib/date-utils';
import type { OtelSpan } from '@/lib/api/types';

// Span-kind → short tag tone (mirrors the design's SPAN_KIND_TONE).
const SPAN_KIND_TONE: Record<string, string> = {
  SERVER: 'text-brand',
  CLIENT: 'text-violet-400',
  INTERNAL: 'text-fg-3',
  PRODUCER: 'text-good',
  CONSUMER: 'text-warn',
};

// Deterministic per-service color for waterfall bars + the legend. Stable hash
// → oklch hue so the same service is the same color across traces.
function hashStr(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}
function svcColor(id: string): string {
  return `oklch(64% 0.13 ${hashStr(id) % 360})`;
}

function fmtMs(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '—';
  if (ms < 1) return `${(ms * 1000).toFixed(0)}µs`;
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`;
  return `${ms.toFixed(ms < 10 ? 2 : 1)}ms`;
}

// A span laid out for the waterfall: ms offsets relative to trace start + depth.
interface LayoutSpan {
  span: OtelSpan;
  depth: number;
  startMs: number; // offset from trace start
  durMs: number;
}

// Build a depth-ordered, parent/child-flattened layout from the flat span list.
// Spans whose parent isn't present become roots so nothing is dropped.
function layout(spans: OtelSpan[]): {
  rows: LayoutSpan[];
  traceStartMs: number;
  durMs: number;
} {
  type Node = { span: OtelSpan; startMs: number; durMs: number; children: Node[] };
  const byId = new Map<string, Node>();
  let traceStartMs = Infinity;
  let traceEndMs = -Infinity;

  for (const span of spans) {
    const startMs = parseUTCTimestamp(span.start_time).getTime();
    const durMs =
      span.duration_ns > 0
        ? span.duration_ns / 1e6
        : Math.max(0, parseUTCTimestamp(span.end_time).getTime() - startMs);
    if (Number.isFinite(startMs)) {
      traceStartMs = Math.min(traceStartMs, startMs);
      traceEndMs = Math.max(traceEndMs, startMs + durMs);
    }
    byId.set(span.span_id, { span, startMs, durMs, children: [] });
  }

  const roots: Node[] = [];
  for (const node of byId.values()) {
    const parent = node.span.parent_span_id ? byId.get(node.span.parent_span_id) : undefined;
    if (parent && parent !== node) parent.children.push(node);
    else roots.push(node);
  }

  if (!Number.isFinite(traceStartMs)) traceStartMs = 0;
  if (!Number.isFinite(traceEndMs)) traceEndMs = traceStartMs;

  const rows: LayoutSpan[] = [];
  const walk = (nodes: Node[], depth: number) => {
    nodes.sort((a, b) => a.startMs - b.startMs);
    for (const n of nodes) {
      rows.push({ span: n.span, depth, startMs: n.startMs - traceStartMs, durMs: n.durMs });
      walk(n.children, depth + 1);
    }
  };
  walk(roots, 0);

  return { rows, traceStartMs, durMs: Math.max(traceEndMs - traceStartMs, 0.001) };
}

// ---------------------------------------------------------------------------
// SpanDrawer — right rail showing the selected span's attributes + pivot.
// ---------------------------------------------------------------------------

function SpanDrawer({
  span,
  traceId,
  onClose,
}: {
  span: OtelSpan;
  traceId: string;
  onClose: () => void;
}) {
  const isError = span.status_code === 'ERROR';
  const durMs = span.duration_ns > 0 ? span.duration_ns / 1e6 : 0;

  // Core span facts first, then every key from the span's attribute maps. We
  // render the real attribute/resource maps rather than the mock's synthetic
  // keys so the drawer reflects what's actually on the span.
  const core: Array<[string, string]> = [
    ['span.id', span.span_id],
    ['trace.id', traceId],
    ['service.name', span.service_name || '—'],
    ['span.kind', span.span_kind || 'INTERNAL'],
    ['status', span.status_code || 'UNSET'],
    ['duration', fmtMs(durMs)],
  ];
  const attrEntries = Object.entries(span.attributes ?? {});
  const resEntries = Object.entries(span.resource_attributes ?? {});

  const searchQ = `trace_id="${traceId}"`;

  return (
    <div className="w-[320px] shrink-0 border-l border-border bg-card flex flex-col min-h-0">
      <div className="px-3.5 py-3 border-b border-border flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <div className="font-mono text-[12.5px] text-foreground truncate" title={span.span_name}>
            {span.span_name || '(unnamed)'}
          </div>
          <div className="flex items-center gap-2 mt-1">
            <span
              className={cn(
                'font-mono text-[10px] font-semibold',
                SPAN_KIND_TONE[span.span_kind] ?? 'text-fg-3'
              )}
            >
              {span.span_kind || 'INTERNAL'}
            </span>
            <span className="text-fg-4">·</span>
            <span className="font-mono text-[11px] text-fg-2 truncate">{span.service_name}</span>
            {isError && <span className="font-mono text-[10px] text-danger">ERROR</span>}
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close span detail"
          className="text-fg-4 hover:text-foreground w-5 h-5 flex items-center justify-center rounded hover:bg-foreground/5"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="p-3.5 flex flex-col gap-px overflow-y-auto scrollbar-thin min-h-0">
        <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-fg-4 mb-1.5">
          Span
        </div>
        {core.map(([k, v]) => (
          <div key={k} className="flex items-baseline gap-3 py-1 border-b border-border/40">
            <span className="font-mono text-[11px] text-fg-3 w-[120px] shrink-0">{k}</span>
            <span
              className={cn(
                'font-mono text-[11px] break-all',
                k === 'status' && isError ? 'text-danger' : 'text-foreground'
              )}
            >
              {v}
            </span>
          </div>
        ))}

        {attrEntries.length > 0 && (
          <>
            <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-fg-4 mt-3 mb-1.5">
              Attributes
            </div>
            {attrEntries.map(([k, v]) => (
              <div key={k} className="flex items-baseline gap-3 py-1 border-b border-border/40">
                <span className="font-mono text-[11px] text-fg-3 w-[120px] shrink-0 break-all">
                  {k}
                </span>
                <span className="font-mono text-[11px] text-foreground break-all">{String(v)}</span>
              </div>
            ))}
          </>
        )}

        {resEntries.length > 0 && (
          <>
            <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-fg-4 mt-3 mb-1.5">
              Resource
            </div>
            {resEntries.map(([k, v]) => (
              <div key={k} className="flex items-baseline gap-3 py-1 border-b border-border/40">
                <span className="font-mono text-[11px] text-fg-3 w-[120px] shrink-0 break-all">
                  {k}
                </span>
                <span className="font-mono text-[11px] text-fg-2 break-all">{String(v)}</span>
              </div>
            ))}
          </>
        )}

        {isError && span.status_message && (
          <div className="mt-3 rounded-md border border-danger/30 bg-danger/8 p-2.5">
            <div className="font-mono text-[10px] uppercase tracking-wider text-danger mb-1">
              status message
            </div>
            <div className="font-mono text-[11px] text-fg-2 leading-relaxed break-all">
              {span.status_message}
            </div>
          </div>
        )}
      </div>

      <div className="mt-auto p-3 border-t border-border">
        <Link
          to={`/search?q=${encodeURIComponent(searchQ)}`}
          className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md border border-border text-[11px] text-fg-2 hover:border-border-2 hover:text-foreground w-full justify-center"
        >
          <Search className="w-[12px] h-[12px] text-fg-3" />
          Explore in search
        </Link>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// TraceWaterfall — the inline drill-in (waterfall + meta strip + drawer).
// ---------------------------------------------------------------------------

export interface TraceWaterfallProps {
  traceId: string;
  spans: OtelSpan[];
  onBack: () => void;
  /**
   * Back-button label. Defaults to "Traces" for the in-console Traces tab; the
   * standalone /trace/:id page passes "Back" since it can be reached from
   * Services, a log→trace pivot, or a direct link — not just the Traces list.
   */
  backLabel?: string;
}

export function TraceWaterfall({ traceId, spans, onBack, backLabel = 'Traces' }: TraceWaterfallProps) {
  const [sel, setSel] = useState<OtelSpan | null>(null);
  const { rows, durMs } = useMemo(() => layout(spans), [spans]);

  const services = useMemo(
    () => [...new Set(spans.map((s) => s.service_name).filter(Boolean))],
    [spans]
  );
  const errors = useMemo(() => spans.filter((s) => s.status_code === 'ERROR').length, [spans]);

  const meta: Array<[string, string | number]> = [
    ['duration', fmtMs(durMs)],
    ['spans', spans.length],
    ['services', services.length],
    ['errors', errors],
  ];

  return (
    <div className="flex flex-col gap-3 min-h-0">
      {/* header */}
      <div className="flex items-center gap-3 flex-wrap">
        <button
          type="button"
          onClick={onBack}
          className="inline-flex items-center gap-1.5 h-7 px-2 rounded-md text-[11px] text-fg-3 hover:text-foreground hover:bg-foreground/5"
        >
          <ArrowLeft className="w-[13px] h-[13px]" /> {backLabel}
        </button>
        <GitBranch className="w-[15px] h-[15px] text-brand" />
        <h2 className="text-[15px] font-semibold text-foreground">Distributed trace</h2>
        <span className="font-mono text-[11.5px] text-fg-3 truncate">{traceId}</span>
        <span className="flex-1" aria-hidden />
        <Link
          to={`/search?q=${encodeURIComponent(`trace_id="${traceId}"`)}`}
          className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md border border-border text-[11px] text-fg-2 hover:border-border-2 hover:text-foreground"
        >
          <Search className="w-[12px] h-[12px] text-fg-3" />
          Logs for this trace
        </Link>
      </div>

      {/* meta strip */}
      <div className="rounded-lg border border-border bg-card px-3.5 py-2.5 flex items-center gap-6 font-mono text-[11.5px] flex-wrap">
        {meta.map(([k, v]) => (
          <div key={k} className="flex items-center gap-2">
            <span className="text-[9.5px] uppercase tracking-[0.12em] text-fg-4">{k}</span>
            <span
              className={cn(
                'tabular-nums',
                k === 'errors' && Number(v) > 0 ? 'text-danger' : 'text-foreground'
              )}
            >
              {v}
            </span>
          </div>
        ))}
        <span className="flex-1" aria-hidden />
        <div className="flex items-center gap-3 flex-wrap">
          {services.map((s) => (
            <span key={s} className="flex items-center gap-1.5 text-[10.5px] text-fg-3">
              <span className="w-2 h-2 rounded-sm" style={{ background: svcColor(s) }} />
              {s}
            </span>
          ))}
        </div>
      </div>

      {/* waterfall + drawer */}
      <div className="rounded-lg border border-border bg-card overflow-hidden flex min-h-0">
        <div className="flex-1 min-w-0 flex flex-col">
          <div className="grid grid-cols-[280px_1fr] gap-0 px-3.5 py-2 border-b border-border font-mono text-[9.5px] uppercase tracking-[0.1em] text-fg-4">
            <span>Span</span>
            <span>Timeline · {fmtMs(durMs)}</span>
          </div>
          {rows.length === 0 ? (
            <div className="text-center py-16 text-[12px] text-fg-3">
              No spans found for this trace.
            </div>
          ) : (
            rows.map(({ span, depth, startMs, durMs: spanDur }) => {
              const leftPct = (startMs / durMs) * 100;
              const widthPct = Math.max(1.5, (spanDur / durMs) * 100);
              const isError = span.status_code === 'ERROR';
              const active = sel?.span_id === span.span_id;
              const labelRight = leftPct + widthPct > 80;
              return (
                <button
                  type="button"
                  key={span.span_id}
                  onClick={() => setSel(span)}
                  className={cn(
                    'grid grid-cols-[280px_1fr] gap-0 px-3.5 py-1.5 border-b border-border/40 hover:bg-foreground/[0.03] text-left items-center',
                    active && 'bg-brand/8'
                  )}
                >
                  <div
                    className="flex items-center gap-1.5 min-w-0"
                    style={{ paddingLeft: depth * 16 }}
                  >
                    {depth > 0 && (
                      <CornerDownRight className="w-[11px] h-[11px] text-fg-4 shrink-0" />
                    )}
                    <span
                      className={cn('w-1.5 h-1.5 rounded-full shrink-0', isError && 'bg-danger')}
                      style={!isError ? { background: svcColor(span.service_name) } : undefined}
                    />
                    <span className="font-mono text-[11.5px] text-foreground truncate" title={span.span_name}>
                      {span.span_name || '(unnamed)'}
                    </span>
                    {span.span_kind && (
                      <span
                        className={cn(
                          'font-mono text-[8.5px] font-semibold shrink-0',
                          SPAN_KIND_TONE[span.span_kind] ?? 'text-fg-3'
                        )}
                      >
                        {span.span_kind}
                      </span>
                    )}
                  </div>
                  <div className="relative h-[18px] pr-1">
                    <div
                      className="absolute top-1/2 -translate-y-1/2 h-[11px] rounded-[2px]"
                      style={{
                        left: `${leftPct}%`,
                        width: `${widthPct}%`,
                        background: isError ? 'var(--color-danger)' : svcColor(span.service_name),
                        opacity: isError ? 0.9 : 0.55,
                      }}
                    />
                    {labelRight ? (
                      <span
                        className="absolute top-1/2 -translate-y-1/2 font-mono text-[10px] text-foreground tabular-nums"
                        style={{ right: 4 }}
                      >
                        {fmtMs(spanDur)}
                      </span>
                    ) : (
                      <span
                        className="absolute top-1/2 -translate-y-1/2 font-mono text-[10px] text-fg-2 tabular-nums whitespace-nowrap"
                        style={{ left: `calc(${leftPct}% + ${widthPct}% + 6px)` }}
                      >
                        {fmtMs(spanDur)}
                      </span>
                    )}
                  </div>
                </button>
              );
            })
          )}
        </div>
        {sel && <SpanDrawer span={sel} traceId={traceId} onClose={() => setSel(null)} />}
      </div>
    </div>
  );
}

export default TraceWaterfall;
