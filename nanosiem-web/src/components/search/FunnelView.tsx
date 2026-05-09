// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  ChevronRight,
  Filter as FilterIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';

// ─────────────────────────── types ───────────────────────────

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

interface FunnelViewProps {
  results: SearchResult[];
  query?: string;
  fieldsCollapsed?: boolean;
  fieldsCount?: number;
  onExpandFields?: () => void;
}

const NOTABLE_RED = 'oklch(62% 0.18 28)';

type SpanUnit = 's' | 'm' | 'h' | 'd';

interface ParsedFunnelCmd {
  byFields: string[];
  window?: { n: number; unit: SpanUnit };
  conditions: string[];
}

/**
 * Pull `by <fields>`, `window=Xm` (or `maxspan=Xm` alias), and `[cond]` brackets
 * out of `| funnel by ... [cond1] [cond2] ...`. Regex-based — we don't need the
 * full parser, just the command shape.
 */
function parseFunnelCmd(query: string | undefined): ParsedFunnelCmd {
  const empty: ParsedFunnelCmd = { byFields: [], conditions: [] };
  if (!query) return empty;
  const m = query.match(/\|\s*funnel\b([\s\S]*)$/i);
  if (!m) return empty;
  const body = m[1];

  const byM = body.match(/\bby\s+([a-zA-Z_][\w,\s]*?)(?=\s*(?:window\s*=|maxspan\s*=|\[|step\d+\s*=|$))/i);
  const byFields = byM
    ? byM[1]
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    : [];

  const windowM = body.match(/\b(?:window|maxspan)\s*=\s*(\d+)([smhd])\b/i);
  const windowSpan = windowM
    ? { n: parseInt(windowM[1], 10), unit: windowM[2].toLowerCase() as SpanUnit }
    : undefined;

  const conditions: string[] = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === '[') {
      if (depth === 0) start = i + 1;
      depth += 1;
    } else if (ch === ']') {
      depth -= 1;
      if (depth === 0 && start >= 0) {
        conditions.push(body.slice(start, i).trim());
        start = -1;
      }
    }
  }

  return { byFields, window: windowSpan, conditions };
}

// ─────────────────────────── adapter ───────────────────────────

interface DropperAttr {
  field: string;
  value: string;
  count: number;
  pct: number;
}

interface Stage {
  level: number;
  label: string;      // "event_id=N" or first 40 chars of condition
  sub: string;        // step_name or condition remainder
  count: number;
  dropperCount: number;
  dropperMedianIdleS: number | null;
  dropperTopAttrs: DropperAttr[];
}

function parseDropperAttrs(raw: unknown): DropperAttr[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((item) => {
      if (!item || typeof item !== 'object') return null;
      const o = item as Record<string, unknown>;
      const field = typeof o.field === 'string' ? o.field : null;
      const value = typeof o.value === 'string' ? o.value : null;
      const count = typeof o.count === 'number' ? o.count : Number(o.count ?? 0);
      const pct = typeof o.pct === 'number' ? o.pct : Number(o.pct ?? 0);
      if (!field || value == null) return null;
      return { field, value, count, pct };
    })
    .filter((x): x is DropperAttr => x !== null);
}

function adaptStages(results: SearchResult[], conditions: string[]): Stage[] {
  // Backend rows: { funnel_level, count, step_name? }.
  // Dedup by funnel_level (backend has been observed returning duplicate rows
  // per level in some cases) and cap to the number of parsed conditions so
  // phantom trailing stages don't leak into the UI.
  const byLevel = new Map<number, SearchResult>();
  for (const r of results) {
    const level = Number(r.fields.funnel_level ?? 0);
    if (!byLevel.has(level)) byLevel.set(level, r);
  }
  const maxLevel = conditions.length > 0 ? conditions.length : byLevel.size;
  const sorted = Array.from(byLevel.entries())
    .filter(([level]) => level >= 1 && level <= maxLevel)
    .sort(([a], [b]) => a - b)
    .map(([, r]) => r);

  return sorted.map((r, idx) => {
    const level = Number(r.fields.funnel_level ?? idx + 1);
    const count = Number(r.fields.count ?? 0);
    const stepName = r.fields.step_name;
    const condition = conditions[level - 1] ?? conditions[idx] ?? '';

    // Label: event_id=N if the condition has one, else the first 40 chars
    // (with an ellipsis when truncated so the user knows they're seeing a
    // slice, not the whole condition).
    const idMatch = condition.match(/event_id\s*=\s*(\d+)/i);
    const label = idMatch
      ? `event_id=${idMatch[1]}`
      : condition
        ? condition.length > 40 ? `${condition.slice(0, 39)}…` : condition
        : `Stage ${level}`;

    // Sub: prefer backend step_name when it's not the "none" placeholder,
    // else strip event_id from the condition for a cleaner read.
    let sub: string;
    if (stepName && stepName !== 'none' && String(stepName).length > 0) {
      sub = String(stepName);
    } else if (condition) {
      sub = condition.replace(/event_id\s*=\s*\d+\s*/i, '').trim() || `Stage ${level}`;
    } else {
      sub = `Stage ${level}`;
    }

    const dropperCountRaw = Number(r.fields.dropper_count ?? 0);
    const dropperCount = Number.isFinite(dropperCountRaw) ? Math.max(0, dropperCountRaw) : 0;

    const idleRaw = r.fields.dropper_median_idle_s;
    const idleNum = idleRaw == null ? NaN : Number(idleRaw);
    const dropperMedianIdleS = Number.isFinite(idleNum) && idleNum >= 0 ? idleNum : null;

    const dropperTopAttrs = parseDropperAttrs(r.fields.dropper_top_attrs);

    return { level, label, sub, count, dropperCount, dropperMedianIdleS, dropperTopAttrs };
  });
}

function formatIdle(seconds: number | null): string {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) return '—';
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  if (m < 60) return s ? `${m}m ${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

// ─────────────────────────── subcomponents ───────────────────────────

function HeaderChip({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-border text-[10px] normal-case tracking-normal font-semibold text-foreground">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-primary font-mono">{value}</span>
    </span>
  );
}

function FieldsBeaconPill({ count, onClick }: { count?: number; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-1.5 py-1 px-2 rounded-md border border-primary/25 bg-primary/8 text-primary text-[10px] font-medium cursor-pointer hover:bg-primary/14 transition-colors normal-case tracking-normal shrink-0"
      title="Show field index"
    >
      <span className="relative flex w-[7px] h-[7px] items-center justify-center">
        <span className="absolute inset-0 rounded-full bg-primary/50 animate-ping" />
        <span className="relative w-[4px] h-[4px] rounded-full bg-primary" />
      </span>
      <span className="font-mono uppercase tracking-[0.12em] text-[9.5px]">Fields</span>
      {count !== undefined && (
        <span className="text-primary/70 tabular-nums text-[10px]">{count}</span>
      )}
      <ArrowRight className="w-[10px] h-[10px]" />
    </button>
  );
}

function FunnelSummary({
  topCount,
  finalCount,
  overallConvert,
  byKey,
}: {
  topCount: number;
  finalCount: number;
  overallConvert: number;
  byKey: string;
}) {
  return (
    <div className="px-3 py-2 border-b border-border bg-muted/20 flex items-center gap-6 font-mono">
      <div className="flex flex-col gap-0.5">
        <span className="text-[10px] text-muted-foreground uppercase tracking-[0.12em]">Entered</span>
        <span className="text-[18px] text-foreground font-semibold tabular-nums leading-none">
          {topCount.toLocaleString()}
        </span>
        <span className="text-[9.5px] text-muted-foreground">{byKey}s</span>
      </div>
      <div className="flex flex-col gap-0.5">
        <span className="text-[10px] text-muted-foreground uppercase tracking-[0.12em]">Completed</span>
        <span className="text-[18px] text-foreground font-semibold tabular-nums leading-none">
          {finalCount.toLocaleString()}
        </span>
        <span className="text-[9.5px] text-muted-foreground">{overallConvert.toFixed(1)}% overall</span>
      </div>
    </div>
  );
}

interface FunnelGapProps {
  barWPrev: number;
  barWNext: number;
  retainPct: number;
  dropped: number;
  height: number;
  gapIdx: number;
  dropperMedianIdleS: number | null;
  dropperTopAttrs: DropperAttr[];
}

function FunnelGap({
  barWPrev,
  barWNext,
  retainPct,
  dropped,
  height,
  gapIdx,
  dropperMedianIdleS,
  dropperTopAttrs,
}: FunnelGapProps) {
  const [expanded, setExpanded] = useState(false);
  const width = Math.max(barWPrev, barWNext);
  const lostPct = 100 - retainPct;
  const hasAttrs = dropperTopAttrs.length > 0;

  return (
    <div className="relative flex flex-col items-center" style={{ width }}>
      <div className="relative" style={{ width, height }}>
        <svg
          width={width}
          height={height}
          viewBox={`0 0 ${width} ${height}`}
          className="block"
        >
          <defs>
            <linearGradient id={`fnlgrad-${gapIdx}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--primary)" stopOpacity="0.2" />
              <stop offset="100%" stopColor="var(--primary)" stopOpacity="0.06" />
            </linearGradient>
          </defs>
          <polygon
            points={`${(width - barWPrev) / 2},0 ${(width + barWPrev) / 2},0 ${(width + barWNext) / 2},${height} ${(width - barWNext) / 2},${height}`}
            fill={`url(#fnlgrad-${gapIdx})`}
            stroke="var(--border)"
          />
        </svg>

        {/* Drop callout on the LEFT */}
        <div
          className="absolute flex items-start gap-2 text-[11px] font-mono top-1/2 -translate-y-1/2"
          style={{ right: `calc(50% + ${barWPrev / 2 + 12}px)` }}
        >
          <div className="border border-border bg-card rounded-md px-2.5 py-1.5 shadow-sm flex flex-col min-w-[150px] items-end text-right">
            <span className="text-muted-foreground text-[9px] uppercase tracking-[0.12em] font-semibold">
              Dropped
            </span>
            <span className="tabular-nums text-foreground font-semibold text-[13px] leading-none mt-0.5">
              −{dropped.toLocaleString()}
            </span>
            <span className="text-muted-foreground text-[10px] mt-0.5 tabular-nums whitespace-nowrap">
              {lostPct.toFixed(1)}% lost
            </span>
            {hasAttrs && (
              <button
                type="button"
                onClick={() => setExpanded((v) => !v)}
                className="mt-1.5 inline-flex items-center gap-1 text-[9.5px] text-primary hover:text-foreground transition-colors uppercase tracking-[0.1em] whitespace-nowrap cursor-pointer"
              >
                <ChevronRight
                  className={cn(
                    'w-[10px] h-[10px] transition-transform',
                    expanded ? '-rotate-90' : 'rotate-180',
                  )}
                />
                {expanded ? 'Hide droppers' : 'Inspect droppers'}
              </button>
            )}
          </div>
        </div>

        {/* Retention % label centered on the wedge */}
        <div
          className="absolute top-0 left-1/2 -translate-x-1/2 pointer-events-none flex items-center justify-center"
          style={{ height }}
        >
          <span className="font-mono text-[12px] text-foreground/80 tabular-nums bg-card/80 px-1.5 py-0.5 rounded border border-border">
            {retainPct.toFixed(1)}%
          </span>
        </div>
      </div>

      {/* Expanded dropper attribution panel — rendered inline below the gap so
          it pushes the next stage down. Mockup used `mt-3` which collided with
          the callout; bump to `mt-6` for breathing room. */}
      {expanded && hasAttrs && (
        <div className="mt-6 mb-2 w-[620px] max-w-[92vw] border border-border bg-muted/40 rounded-md p-3 font-mono text-[11px] shadow-sm">
          <div className="flex items-center justify-between mb-2 gap-4">
            <span className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold whitespace-nowrap">
              Top shared attributes · {dropped.toLocaleString()} droppers
            </span>
            {dropperMedianIdleS != null && (
              <span className="text-[9.5px] text-muted-foreground tabular-nums whitespace-nowrap">
                Median idle before drop: {formatIdle(dropperMedianIdleS)}
              </span>
            )}
          </div>
          <div className="grid grid-cols-2 gap-x-6 gap-y-1.5">
            {dropperTopAttrs.map((a, i) => (
              <div key={`${a.field}:${a.value}:${i}`} className="flex items-center gap-2 min-w-0">
                <span className="text-muted-foreground shrink-0">{a.field}</span>
                <span className="text-foreground truncate" title={a.value}>{a.value}</span>
                <span className="flex-1 h-1 bg-foreground/10 rounded-full overflow-hidden min-w-[30px]">
                  <span
                    className="block h-full bg-primary"
                    style={{ width: `${Math.min(100, Math.max(0, a.pct))}%` }}
                  />
                </span>
                <span className="text-foreground/80 tabular-nums shrink-0">
                  {a.pct.toFixed(a.pct >= 10 ? 0 : 1)}%
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function FunnelTrapezoid({
  stages,
  topCount,
  selectedStage,
  setSelectedStage,
}: {
  stages: Stage[];
  topCount: number;
  selectedStage: number | null;
  setSelectedStage: (i: number | null) => void;
}) {
  const MAX_W = 720;
  const MIN_W = 140;
  const BAR_H = 64;
  const GAP_H = 58;

  const widthFor = (count: number) => {
    const r = topCount > 0 ? count / topCount : 0;
    return Math.max(MIN_W, MAX_W * r);
  };

  return (
    <div className="flex flex-col items-center">
      {stages.map((stg, i) => {
        const w = widthFor(stg.count);
        const prevCount = i > 0 ? stages[i - 1].count : topCount;
        const retainPct = prevCount > 0 ? (stg.count / prevCount) * 100 : 0;
        const overallPct = topCount > 0 ? (stg.count / topCount) * 100 : 0;
        const isSel = selectedStage === i;

        return (
          <div key={stg.level} className="flex flex-col items-center">
            {/* Stage bar */}
            <div
              onClick={() => setSelectedStage(isSel ? null : i)}
              className="relative"
              style={{ width: w, height: BAR_H }}
            >
              <div
                className={cn(
                  'absolute inset-0 rounded-md border transition-colors cursor-pointer overflow-hidden',
                  isSel
                    ? 'border-primary/50 bg-primary/12'
                    : 'border-primary/30 bg-primary/8 hover:bg-primary/10',
                )}
              />
              <div
                className="absolute inset-y-0 left-0 z-10 flex flex-col justify-center pl-3 min-w-0"
                style={{ maxWidth: w - 8 }}
              >
                <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold whitespace-nowrap truncate">
                  Stage {i + 1} · {stg.label}
                </span>
                <span className="font-mono text-[11px] text-foreground/80 truncate">{stg.sub}</span>
              </div>
              <div
                className="absolute top-0 bottom-0 flex flex-col justify-center whitespace-nowrap"
                style={{ left: w + 12 }}
              >
                <span className="font-mono text-[22px] text-foreground font-semibold tabular-nums leading-none">
                  {stg.count.toLocaleString()}
                </span>
                <span className="font-mono text-[9.5px] text-muted-foreground mt-1">
                  {i === 0
                    ? '100% base'
                    : `${retainPct.toFixed(1)}% from prev · ${overallPct.toFixed(1)}% overall`}
                </span>
              </div>
            </div>

            {/* Drop-off gap */}
            {i < stages.length - 1 && (() => {
              const nextCount = stages[i + 1].count;
              const dropped = Math.max(0, stg.count - nextCount);
              const rp = stg.count > 0 ? (nextCount / stg.count) * 100 : 0;
              // Backend's dropper_count is the truth for "entities that reached
              // this stage and no further"; fall back to the computed difference
              // when it's missing.
              const backendDropped = stg.dropperCount > 0 ? stg.dropperCount : dropped;
              return (
                <FunnelGap
                  barWPrev={w}
                  barWNext={widthFor(nextCount)}
                  retainPct={rp}
                  dropped={backendDropped}
                  height={GAP_H}
                  gapIdx={i}
                  dropperMedianIdleS={stg.dropperMedianIdleS}
                  dropperTopAttrs={stg.dropperTopAttrs}
                />
              );
            })()}
          </div>
        );
      })}
    </div>
  );
}

function FunnelEmpty({ conditions, byKey }: { conditions: string[]; byKey: string }) {
  return (
    <div className="flex-1 flex flex-col items-center justify-center p-10">
      <div className="w-12 h-12 rounded-full bg-primary/12 flex items-center justify-center mb-4">
        <FilterIcon className="w-[20px] h-[20px] text-primary" />
      </div>
      <div className="text-[13px] text-foreground/80 mb-2">
        No <span className="text-foreground font-medium">{byKey}</span> matched stage 1
      </div>
      <div className="text-[11px] text-muted-foreground max-w-[480px] text-center leading-relaxed">
        Funnel needs at least one {byKey} matching the first condition before it can measure drop-off.
        {conditions[0] && (
          <>
            {' '}Try broadening{' '}
            <span className="font-mono text-foreground/80">{conditions[0].slice(0, 60)}</span>.
          </>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────── main ───────────────────────────

export function FunnelView({
  results,
  query,
  fieldsCollapsed,
  fieldsCount,
  onExpandFields,
}: FunnelViewProps) {
  const parsed = useMemo(() => parseFunnelCmd(query), [query]);
  const byKey = parsed.byFields[0] ?? 'entity';

  const stages = useMemo(
    () => adaptStages(results, parsed.conditions),
    [results, parsed.conditions],
  );

  const [selectedStage, setSelectedStage] = useState<number | null>(null);

  const topCount = stages[0]?.count ?? 0;
  const finalCount = stages[stages.length - 1]?.count ?? 0;
  const overallConvert = topCount > 0 ? (finalCount / topCount) * 100 : 0;
  const hasAnyMatch = stages.length > 0 && topCount > 0;
  const anyConverted = finalCount > 0;

  return (
    <div className="flex flex-col min-h-0 min-w-0 overflow-hidden">
      {/* Header */}
      <div className="py-2 px-3 border-b border-border flex flex-wrap items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold whitespace-nowrap">
        <span className="flex items-center gap-1.5 shrink-0">
          <FilterIcon className="w-[12px] h-[12px] text-primary" />
          <span>Funnel</span>
          <span className="text-muted-foreground/60">·</span>
          <span className="normal-case tracking-normal text-foreground">
            by {parsed.byFields.join(', ') || '(fields)'}
          </span>
        </span>
        {parsed.window && (
          <HeaderChip label="window" value={`${parsed.window.n}${parsed.window.unit}`} />
        )}
        <HeaderChip label="stages" value={String(parsed.conditions.length || stages.length)} />
        {anyConverted && (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10px] normal-case tracking-normal font-semibold"
            style={{
              borderColor: 'oklch(62% 0.18 28 / 0.4)',
              color: NOTABLE_RED,
              background: 'oklch(62% 0.18 28 / 0.08)',
            }}
          >
            <AlertTriangle className="w-[10px] h-[10px]" />
            {finalCount} completed chain{finalCount === 1 ? '' : 's'}
          </span>
        )}
        {fieldsCollapsed && onExpandFields && (
          <FieldsBeaconPill count={fieldsCount} onClick={onExpandFields} />
        )}
        <span className="flex-1" aria-hidden />
        <span className="text-muted-foreground font-mono normal-case tracking-normal">
          {overallConvert.toFixed(1)}% overall conversion
        </span>
      </div>

      {/* Summary */}
      {hasAnyMatch && (
        <FunnelSummary
          topCount={topCount}
          finalCount={finalCount}
          overallConvert={overallConvert}
          byKey={byKey}
        />
      )}

      {/* Body */}
      <div className="flex-1 min-h-0 overflow-auto">
        <div className="px-6 py-6">
          {hasAnyMatch ? (
            <FunnelTrapezoid
              stages={stages}
              topCount={topCount}
              selectedStage={selectedStage}
              setSelectedStage={setSelectedStage}
            />
          ) : (
            <FunnelEmpty conditions={parsed.conditions} byKey={byKey} />
          )}
        </div>
      </div>

    </div>
  );
}
