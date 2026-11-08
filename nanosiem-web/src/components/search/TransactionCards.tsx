// SPDX-License-Identifier: AGPL-3.0-or-later

import React from 'react';
import {
  AlertTriangle,
  ArrowRight,
  ChevronRight,
  Download,
  Layers,
  Search as SearchIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useSchemaEntityMap } from '@/hooks/useSchemaEntityMap';
import { buildSecondaryPrefs, TRANSACTION_SECONDARY_BASE } from '@/lib/secondary-identity-prefs';

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

interface TransactionCardsProps {
  results: SearchResult[];
  query?: string;
  onDrilldown?: (filters: Record<string, unknown>) => void;
  fieldsCollapsed?: boolean;
  fieldsCount?: number;
  onExpandFields?: () => void;
}

// ───────────────────────── helpers ─────────────────────────

const NOTABLE_RED = 'oklch(62% 0.18 28)';

function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  const ms = Math.round(seconds * 1000);
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const m = Math.floor(ms / 60_000);
  const s = Math.floor((ms % 60_000) / 1000);
  if (m < 60) return s ? `${m}m ${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function toTs(value: unknown): number | null {
  if (value == null) return null;
  if (typeof value === 'number') return value;
  if (typeof value === 'string') {
    const d = new Date(value);
    if (!isNaN(d.getTime())) return d.getTime();
  }
  if (value instanceof Date) return value.getTime();
  return null;
}

function formatTime(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}
function formatDate(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getUTCMonth() + 1)}/${pad(d.getUTCDate())} ${formatTime(ms)}`;
}

type SpanUnit = 's' | 'm' | 'h' | 'd';
const SPAN_MS: Record<SpanUnit, number> = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };

interface ParsedTxCmd {
  fields: string[];
  maxspan?: { n: number; unit: SpanUnit };
  maxevents?: number;
  startswith?: string;
  endswith?: string;
}

/**
 * Pull grouping fields + `maxspan` / `maxevents` / `startswith` / `endswith`
 * out of `| transaction <fields> [opts]` so the header can surface them as chips.
 */
function parseTransactionCmd(query: string | undefined): ParsedTxCmd {
  const empty: ParsedTxCmd = { fields: [] };
  if (!query) return empty;
  const m = query.match(/\|\s*transaction\b([^|]*)/i);
  if (!m) return empty;
  const body = m[1];

  const maxspanM = body.match(/\bmaxspan\s*=\s*(\d+)([smhd])\b/i);
  const maxeventsM = body.match(/\bmaxevents\s*=\s*(\d+)\b/i);
  const startM = body.match(/\bstartswith\s*=\s*"([^"]*)"/i);
  const endM = body.match(/\bendswith\s*=\s*"([^"]*)"/i);

  // Remove option k=v pairs (quoted or unquoted) before extracting field list
  const stripped = body
    .replace(/\bmaxspan\s*=\s*\d+[smhd]\b/gi, '')
    .replace(/\bmaxevents\s*=\s*\d+\b/gi, '')
    .replace(/\bstartswith\s*=\s*"[^"]*"/gi, '')
    .replace(/\bendswith\s*=\s*"[^"]*"/gi, '')
    .trim();

  const fields = stripped
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);

  return {
    fields,
    maxspan: maxspanM ? { n: parseInt(maxspanM[1], 10), unit: maxspanM[2].toLowerCase() as SpanUnit } : undefined,
    maxevents: maxeventsM ? parseInt(maxeventsM[1], 10) : undefined,
    startswith: startM?.[1],
    endswith: endM?.[1],
  };
}

// ───────────────────────── data transform ─────────────────────────

interface Transaction {
  id: string;
  groupKey: string;         // primary grouping field (first)
  groupValue: string;
  secondary: string | null; // e.g. host shown under the primary identity
  eventCount: number;
  duration: number;         // seconds
  start: number | null;     // ms
  end: number | null;       // ms
  rawEvents: string[];
  fields: Record<string, unknown>;
  notable: boolean;
}

const RESERVED_KEYS = new Set([
  'eventcount', 'event_count',
  'duration',
  'transaction_start', 'transaction_end',
  '_raw_events',
  '_display_type',
]);

function toTransaction(
  r: SearchResult,
  parsedFields: string[],
  idx: number,
  secondaryPrefs: readonly string[],
): Transaction {
  const f = r.fields ?? {};
  const duration = Number(f.duration ?? 0);
  const eventCount = Number(f.eventcount ?? f.event_count ?? 0);
  const start = toTs(f.transaction_start);
  const end = toTs(f.transaction_end);
  const rawEvents = Array.isArray(f._raw_events)
    ? (f._raw_events as unknown[]).map((x) => String(x))
    : [];

  const groupingFields = parsedFields.length
    ? parsedFields.filter((k) => k in f)
    : Object.keys(f).filter((k) => !RESERVED_KEYS.has(k.toLowerCase()));

  const groupKey = groupingFields[0] ?? 'transaction';
  const groupValue = String(f[groupKey] ?? `#${idx + 1}`);

  let secondary: string | null = null;
  for (const k of secondaryPrefs) {
    if (k !== groupKey && f[k] != null && String(f[k]).trim() !== '') {
      secondary = String(f[k]);
      break;
    }
  }
  if (!secondary) {
    // Fall back to the next grouping field if one exists
    const extra = groupingFields.find((k) => k !== groupKey);
    if (extra) secondary = String(f[extra] ?? '');
    if (!secondary) secondary = null;
  }

  return {
    id: r.id || `tx_${idx}`,
    groupKey,
    groupValue,
    secondary,
    eventCount,
    duration,
    start,
    end,
    rawEvents,
    fields: f,
    notable: false, // computed later against maxspan or global thresholds
  };
}

// ───────────────────────────── card ───────────────────────────────

interface CardProps {
  tx: Transaction;
  maxDurationSec: number;
  maxSpanMs: number | null;
  isExpanded: boolean;
  onToggle: () => void;
}

function Sparkline({ buckets, notable }: { buckets: number[]; notable: boolean }) {
  const max = Math.max(1, ...buckets);
  const color = notable ? NOTABLE_RED : 'var(--primary)';
  return (
    <svg width="60" height="18" className="shrink-0">
      {buckets.map((v, i) => {
        const h = (v / max) * 14;
        return (
          <rect
            key={i}
            x={i * 2.5}
            y={16 - h}
            width={1.8}
            height={h}
            fill={color}
            opacity={0.85}
          />
        );
      })}
    </svg>
  );
}

/** Evenly-distribute events across the duration — we don't have per-event
 *  timestamps from the backend yet, so this is a visual approximation. */
function bucketEvents(count: number, n = 24): number[] {
  if (count <= 0) return new Array(n).fill(0);
  const buckets = new Array(n).fill(0);
  for (let i = 0; i < count; i++) {
    const b = Math.floor((i / Math.max(1, count)) * n);
    buckets[Math.min(n - 1, b)]++;
  }
  return buckets;
}

function TransactionCardRow({ tx, maxDurationSec, maxSpanMs, isExpanded, onToggle }: CardProps) {
  const durationPct = maxDurationSec > 0 ? Math.min(100, (tx.duration / maxDurationSec) * 100) : 0;
  const exceedsSpan = maxSpanMs != null && tx.duration * 1000 > maxSpanMs;
  const notable = tx.notable || exceedsSpan;
  const buckets = React.useMemo(() => bucketEvents(tx.eventCount, 24), [tx.eventCount]);

  return (
    <div
      className={cn(
        'border rounded-md transition-colors',
        notable
          ? 'border-[oklch(62%_0.18_28_/_0.35)] bg-[oklch(62%_0.18_28_/_0.04)]'
          : 'border-border bg-muted/20',
        isExpanded && 'bg-muted/40',
      )}
    >
      {/* summary row */}
      <div
        onClick={onToggle}
        className="grid items-center gap-3 px-3 py-2 cursor-pointer hover:bg-foreground/[0.03] rounded-md transition-colors"
        style={{ gridTemplateColumns: '16px 220px 1fr 120px 68px' }}
      >
        <ChevronRight
          className={cn('w-[13px] h-[13px] text-muted-foreground transition-transform', isExpanded && 'rotate-90')}
        />
        {/* actor */}
        <div className="flex items-center gap-2 min-w-0">
          <span
            className="w-1.5 h-1.5 rounded-full shrink-0"
            style={{ background: notable ? NOTABLE_RED : 'color-mix(in oklab, var(--primary) 60%, transparent)' }}
          />
          <div className="flex flex-col min-w-0">
            <span className="font-mono text-[12px] text-foreground truncate">{tx.groupValue}</span>
            {tx.secondary && (
              <span className="font-mono text-[10px] text-muted-foreground truncate">{tx.secondary}</span>
            )}
          </div>
        </div>
        {/* duration bar + sparkline */}
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex-1 min-w-0 flex flex-col gap-1">
            <div className="relative h-1 rounded-full bg-foreground/10 overflow-hidden">
              <div
                className="absolute inset-y-0 left-0 rounded-full"
                style={{
                  width: `${durationPct}%`,
                  background: notable ? NOTABLE_RED : 'var(--primary)',
                }}
              />
              {maxSpanMs != null && maxDurationSec > 0 && (
                <div
                  className="absolute inset-y-0 bg-muted-foreground/60"
                  style={{
                    left: `${Math.min(100, (maxSpanMs / 1000 / maxDurationSec) * 100)}%`,
                    width: '1px',
                    opacity: 0.6,
                  }}
                />
              )}
            </div>
            {/* event-count chip + notable tag */}
            <div className="flex items-center gap-1 overflow-hidden">
              <span className="inline-flex items-center gap-1 px-1.5 py-[1px] rounded text-[9.5px] font-mono whitespace-nowrap text-primary bg-primary/10 border border-primary/25">
                {tx.eventCount}
              </span>
              {exceedsSpan && (
                <span
                  className="inline-flex items-center gap-1 px-1.5 py-[1px] rounded text-[9.5px] font-mono whitespace-nowrap font-semibold"
                  style={{
                    color: NOTABLE_RED,
                    background: 'oklch(62% 0.18 28 / 0.12)',
                    border: '1px solid oklch(62% 0.18 28 / 0.3)',
                  }}
                >
                  maxspan exceeded
                </span>
              )}
            </div>
          </div>
          <Sparkline buckets={buckets} notable={notable} />
        </div>
        {/* duration text */}
        <div className="flex flex-col items-end">
          <span
            className={cn(
              'font-mono text-[12px] tabular-nums',
              exceedsSpan ? 'font-semibold' : 'text-foreground',
            )}
            style={exceedsSpan ? { color: NOTABLE_RED } : undefined}
          >
            {formatDuration(tx.duration)}
          </span>
          <span className="font-mono text-[9.5px] text-muted-foreground">
            {tx.start != null ? formatDate(tx.start) : '—'}
          </span>
        </div>
        {/* event count */}
        <div className="flex flex-col items-end">
          <span className="font-mono text-[12px] tabular-nums text-foreground font-semibold">
            {tx.eventCount}
          </span>
          <span className="font-mono text-[9.5px] text-muted-foreground uppercase tracking-wide">
            events
          </span>
        </div>
      </div>

      {isExpanded && <TransactionDetail tx={tx} />}
    </div>
  );
}

// ───────────────────────── expanded detail ─────────────────────────

function TransactionDetail({ tx }: { tx: Transaction }) {
  const [hoverIdx, setHoverIdx] = React.useState<number | null>(null);

  const W = 880, H = 56, PL = 14, PR = 14, PB = 18;
  const chartW = W - PL - PR;
  const n = tx.rawEvents.length;

  // Backend `_raw_events` doesn't include per-event timestamps — we evenly
  // distribute ticks across the duration for a visual sense of density.
  const xAt = (i: number) => {
    if (n <= 1) return PL + chartW / 2;
    return PL + (chartW * i) / (n - 1);
  };

  return (
    <div className="border-t border-border/60 bg-background/40">
      <div className="px-3 pt-2 pb-0">
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} className="block">
          <line x1={PL} y1={H - PB} x2={W - PR} y2={H - PB} stroke="var(--border)" />
          <text
            x={PL}
            y={H - 4}
            fontSize={9}
            fill="var(--muted-foreground)"
            fontFamily="ui-monospace, monospace"
          >
            {tx.start != null ? formatTime(tx.start) : '—'}
          </text>
          <text
            x={W / 2}
            y={H - 4}
            fontSize={9}
            fill="var(--muted-foreground)"
            textAnchor="middle"
            fontFamily="ui-monospace, monospace"
          >
            {formatDuration(tx.duration)}
          </text>
          <text
            x={W - PR}
            y={H - 4}
            fontSize={9}
            fill="var(--muted-foreground)"
            textAnchor="end"
            fontFamily="ui-monospace, monospace"
          >
            {tx.end != null ? formatTime(tx.end) : '—'}
          </text>
          {tx.rawEvents.map((_, i) => {
            const cx = xAt(i);
            const isBookend = i === 0 || i === n - 1;
            const isHover = hoverIdx === i;
            return (
              <g
                key={i}
                onMouseEnter={() => setHoverIdx(i)}
                onMouseLeave={() => setHoverIdx(null)}
                style={{ cursor: 'pointer' }}
              >
                <line
                  x1={cx}
                  y1={H - PB}
                  x2={cx}
                  y2={H - PB - (isBookend ? 18 : 12)}
                  stroke="var(--primary)"
                  strokeWidth={isBookend ? 1.4 : 1}
                  opacity={isHover ? 1 : 0.7}
                />
                <circle
                  cx={cx}
                  cy={H - PB - (isBookend ? 22 : 16)}
                  r={isBookend ? 5 : isHover ? 4 : 3}
                  fill={isBookend ? 'var(--primary)' : 'var(--background)'}
                  stroke="var(--primary)"
                  strokeWidth={1.5}
                />
              </g>
            );
          })}
        </svg>
      </div>

      <div className="px-3 pb-3 pt-1">
        <div className="relative">
          <div className="absolute left-[9px] top-[4px] bottom-[4px] w-px bg-border" />
          <div className="flex flex-col">
            {tx.rawEvents.map((msg, i) => {
              const isHover = hoverIdx === i;
              return (
                <div
                  key={i}
                  onMouseEnter={() => setHoverIdx(i)}
                  onMouseLeave={() => setHoverIdx(null)}
                  className={cn(
                    'relative grid gap-3 py-1.5 pl-7 pr-2 rounded-md transition-colors',
                    isHover ? 'bg-primary/8' : 'hover:bg-foreground/[0.03]',
                  )}
                  style={{ gridTemplateColumns: 'auto 44px 1fr' }}
                >
                  <span
                    className="absolute left-[4px] top-1/2 -translate-y-1/2 rounded-full flex items-center justify-center"
                    style={{
                      width: 10,
                      height: 10,
                      background: 'var(--background)',
                      border: '1.5px solid var(--primary)',
                    }}
                  />
                  <span className="font-mono text-[10px] text-muted-foreground tabular-nums">
                    #{String(i + 1).padStart(2, '0')}
                  </span>
                  <span />
                  <span
                    className="font-mono text-[11px] text-foreground truncate col-start-3"
                    title={msg}
                  >
                    {msg}
                  </span>
                </div>
              );
            })}
            {tx.rawEvents.length === 0 && (
              <div className="pl-7 py-3 font-mono text-[11px] text-muted-foreground">
                No sample events returned — backend truncated this transaction.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ───────────────────────────── root ─────────────────────────────────

type SortKey = 'duration' | 'events' | 'time';

export function TransactionCards({
  results,
  query,
  fieldsCollapsed,
  fieldsCount,
  onExpandFields,
}: TransactionCardsProps) {
  const parsed = React.useMemo(() => parseTransactionCmd(query), [query]);

  const maxSpanMs = parsed.maxspan ? parsed.maxspan.n * SPAN_MS[parsed.maxspan.unit] : null;

  // Secondary identity column prefs follow the active schema (NAN-1241): UDM base
  // list, unioned with OCSF host/user/ip promoted columns when OCSF is active.
  const { schemaFields } = useSchemaEntityMap();
  const secondaryPrefs = React.useMemo(
    () => buildSecondaryPrefs(TRANSACTION_SECONDARY_BASE, schemaFields),
    [schemaFields],
  );

  const txns = React.useMemo(
    () => results.map((r, i) => toTransaction(r, parsed.fields, i, secondaryPrefs)),
    [results, parsed.fields, secondaryPrefs],
  );

  // Mark transactions as notable (exceeds maxspan)
  const txnsMarked = React.useMemo(() => {
    if (maxSpanMs == null) return txns;
    return txns.map((t) => ({ ...t, notable: t.duration * 1000 > maxSpanMs }));
  }, [txns, maxSpanMs]);

  const [sort, setSort] = React.useState<SortKey>('duration');
  const [filter, setFilter] = React.useState('');
  const [notableOnly, setNotableOnly] = React.useState(false);
  const [expanded, setExpanded] = React.useState<Set<string>>(() => new Set());

  const filtered = React.useMemo(() => {
    let list = txnsMarked;
    if (notableOnly) list = list.filter((t) => t.notable);
    if (filter) {
      const f = filter.toLowerCase();
      list = list.filter(
        (t) =>
          t.groupValue.toLowerCase().includes(f) ||
          (t.secondary ?? '').toLowerCase().includes(f),
      );
    }
    const sorted = [...list];
    if (sort === 'duration') sorted.sort((a, b) => b.duration - a.duration);
    else if (sort === 'events') sorted.sort((a, b) => b.eventCount - a.eventCount);
    else if (sort === 'time') sorted.sort((a, b) => (b.start ?? 0) - (a.start ?? 0));
    return sorted;
  }, [txnsMarked, notableOnly, filter, sort]);

  const maxDurationSec = React.useMemo(
    () => txnsMarked.reduce((m, t) => Math.max(m, t.duration), 0),
    [txnsMarked],
  );

  const toggle = (id: string) =>
    setExpanded((prev) => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  if (!results.length) {
    return (
      <div className="flex flex-col min-h-0 min-w-0 overflow-hidden">
        <div className="py-2 px-3 border-b border-border flex items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold">
          <Layers className="w-[12px] h-[12px] text-primary" />
          <span>Transactions</span>
        </div>
        <div className="p-8 text-center text-muted-foreground text-sm">
          No transactions returned — relax the grouping window (maxspan), add another field, or broaden the base query.
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col min-h-0 overflow-hidden">
      {/* header */}
      <div className="py-2 px-3 border-b border-border flex flex-wrap items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold">
        <span className="flex items-center gap-1.5 shrink-0">
          <Layers className="w-[12px] h-[12px] text-primary" />
          <span>Transactions</span>
          <span className="text-muted-foreground/60">·</span>
          <span className="normal-case tracking-normal text-foreground">
            by {parsed.fields.join(', ') || '(fields)'}
          </span>
        </span>
        {parsed.maxspan && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-border text-[10px] normal-case tracking-normal font-semibold text-foreground">
            <span className="text-muted-foreground">maxspan</span>
            <span className="text-primary font-mono">{parsed.maxspan.n}{parsed.maxspan.unit}</span>
          </span>
        )}
        {parsed.maxevents && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-border text-[10px] normal-case tracking-normal font-semibold text-foreground">
            <span className="text-muted-foreground">maxevents</span>
            <span className="text-primary font-mono">{parsed.maxevents}</span>
          </span>
        )}
        {(parsed.startswith || parsed.endswith) && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-border text-[10px] normal-case tracking-normal">
            {parsed.startswith && (
              <>
                <span className="text-muted-foreground">start</span>
                <span className="font-mono text-foreground truncate max-w-[160px]">{parsed.startswith}</span>
              </>
            )}
            {parsed.startswith && parsed.endswith && (
              <span className="text-muted-foreground/70">→</span>
            )}
            {parsed.endswith && (
              <>
                <span className="text-muted-foreground">end</span>
                <span className="font-mono text-foreground truncate max-w-[160px]">{parsed.endswith}</span>
              </>
            )}
          </span>
        )}
        {fieldsCollapsed && onExpandFields && (
          <button
            type="button"
            onClick={onExpandFields}
            className="inline-flex items-center gap-1.5 py-1 px-2 rounded-md border border-primary/25 bg-primary/8 text-primary text-[10px] font-medium cursor-pointer hover:bg-primary/14 transition-colors normal-case tracking-normal shrink-0"
            title="Show field index"
          >
            <span className="relative flex w-[7px] h-[7px] items-center justify-center">
              <span className="absolute inset-0 rounded-full bg-primary/50 animate-ping" />
              <span className="relative w-[4px] h-[4px] rounded-full bg-primary" />
            </span>
            <span className="font-mono uppercase tracking-[0.12em] text-[9.5px]">Fields</span>
            {fieldsCount !== undefined && (
              <span className="text-primary/70 tabular-nums text-[10px]">{fieldsCount}</span>
            )}
            <ArrowRight className="w-[10px] h-[10px]" />
          </button>
        )}
        <span className="flex-1" aria-hidden />
        <span className="text-muted-foreground font-mono normal-case tracking-normal">
          {filtered.length} transactions
        </span>
        <button
          type="button"
          title="Export"
          className="text-muted-foreground hover:text-primary p-1 cursor-pointer"
        >
          <Download className="w-[12px] h-[12px]" />
        </button>
      </div>

      {/* toolbar */}
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-border bg-muted/30">
        <div className="relative">
          <SearchIcon className="w-[11px] h-[11px] absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by user or host"
            className="bg-transparent outline-none text-[11px] pl-7 pr-2 py-1 rounded border border-border focus:border-primary/60 placeholder:text-muted-foreground w-[220px]"
          />
        </div>
        <button
          type="button"
          onClick={() => setNotableOnly((v) => !v)}
          disabled={maxSpanMs == null}
          title={maxSpanMs == null ? 'Set maxspan= in the query to flag notable transactions' : undefined}
          className={cn(
            'inline-flex items-center gap-1 px-2 py-1 rounded-md border text-[10.5px] transition-colors',
            notableOnly
              ? 'border-primary/40 text-primary bg-primary/10'
              : maxSpanMs == null
                ? 'border-border text-muted-foreground/50 cursor-not-allowed'
                : 'border-border text-muted-foreground hover:text-foreground',
          )}
        >
          <AlertTriangle className="w-[11px] h-[11px]" />
          Notable only
        </button>
        <span className="flex-1" aria-hidden />
        <span className="text-muted-foreground font-mono text-[10px] uppercase tracking-[0.12em]">
          sort
        </span>
        {(
          [
            ['duration', 'Duration'],
            ['events', 'Events'],
            ['time', 'Recent'],
          ] as Array<[SortKey, string]>
        ).map(([k, lbl]) => (
          <button
            key={k}
            type="button"
            onClick={() => setSort(k)}
            className={cn(
              'inline-flex items-center px-2 py-1 rounded-md text-[10.5px] transition-colors',
              sort === k
                ? 'bg-primary/12 text-primary'
                : 'text-muted-foreground hover:text-foreground',
            )}
          >
            {lbl}
          </button>
        ))}
      </div>

      {/* list */}
      <div className="flex-1 min-h-0 overflow-auto">
        <div className="p-3 flex flex-col gap-1.5">
          {filtered.map((tx) => (
            <TransactionCardRow
              key={tx.id}
              tx={tx}
              maxDurationSec={maxDurationSec}
              maxSpanMs={maxSpanMs}
              isExpanded={expanded.has(tx.id)}
              onToggle={() => toggle(tx.id)}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
