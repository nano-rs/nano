// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState } from 'react';
import {
  ArrowRight,
  Search as SearchIcon,
  Zap,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useSchemaEntityMap } from '@/hooks/useSchemaEntityMap';
import { buildSecondaryPrefs, SEQUENCE_SECONDARY_BASE } from '@/lib/secondary-identity-prefs';

// ─────────────────────────── types ───────────────────────────

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

interface SequenceViewProps {
  results: SearchResult[];
  query?: string;
  fieldsCollapsed?: boolean;
  fieldsCount?: number;
  onExpandFields?: () => void;
}

// ─────────────────────────── helpers ───────────────────────────

type SpanUnit = 's' | 'm' | 'h' | 'd';
const SPAN_MS: Record<SpanUnit, number> = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };

interface ParsedSeqCmd {
  byFields: string[];
  maxspan?: { n: number; unit: SpanUnit };
  conditions: string[];
}

/**
 * Pull `by <fields>`, `maxspan=Xm`, and `[cond]` brackets out of
 * `| sequence by ... [cond1] [cond2] ...` so the header can surface them.
 * Regex-based — we don't need the full parser, just the command shape.
 */
function parseSequenceCmd(query: string | undefined): ParsedSeqCmd {
  const empty: ParsedSeqCmd = { byFields: [], conditions: [] };
  if (!query) return empty;
  const m = query.match(/\|\s*sequence\b([\s\S]*)$/i);
  if (!m) return empty;
  const body = m[1];

  const byM = body.match(/\bby\s+([a-zA-Z_][\w,\s]*?)(?=\s*(?:maxspan\s*=|maxgap\s*=|fields\s*\(|\[|$))/i);
  const byFields = byM
    ? byM[1]
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    : [];

  const spanM = body.match(/\bmaxspan\s*=\s*(\d+)([smhd])\b/i);
  const maxspan = spanM
    ? { n: parseInt(spanM[1], 10), unit: spanM[2].toLowerCase() as SpanUnit }
    : undefined;

  // Extract balanced [...] blocks; nested brackets inside a condition are rare
  // but supported by simply consuming until the matching ].
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

  return { byFields, maxspan, conditions };
}

function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '—';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const m = Math.floor(ms / 60_000);
  const s = Math.floor((ms % 60_000) / 1000);
  if (m < 60) return s ? `${m}m ${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function formatUtcHms(ms: number): string {
  if (!Number.isFinite(ms)) return '—';
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

function parseStepTime(raw: string): number {
  if (!raw) return NaN;
  // Backend hands us ISO-ish or "YYYY-MM-DD HH:MM:SS" — tolerate both.
  const iso = raw.includes('T') ? raw : raw.replace(' ', 'T');
  const withZ = /Z$/.test(iso) ? iso : `${iso}Z`;
  const t = new Date(withZ).getTime();
  return Number.isFinite(t) ? t : NaN;
}

// ─────────────────────────── adapter ───────────────────────────

interface EntityStage {
  stepNum: number;
  timeMs: number;
  eventId: string;
  summary: string;       // primary description — "proc › spawned" or "proc → dest"
  details: string | null; // secondary line
}

interface Entity {
  key: string;        // joined group-by field values (stable id)
  display: string;    // primary label (first group value)
  secondary: string;  // second group field (user, etc.)
  startMs: number;
  endMs: number;
  duration: number;   // ms
  stages: EntityStage[];
}

/** Backend sequence row shape (examples):
 *   { src_ip: "...", user: "...",
 *     step1_time: "2026-04-18T02:08:42Z", step1_event_id: "4648", step1_url_domain: "…",
 *     step2_time: "...", step2_event_id: "...",
 *     sequence_count: 1, sequence_duration_seconds: 12.4, maxspan_seconds: 300 } */
const META_KEYS = new Set([
  'sequence_count',
  'sequence_duration_seconds',
  'maxspan_seconds',
  'timestamp',
  '_display_type',
]);

function adaptResult(
  r: SearchResult,
  byFields: string[],
  idx: number,
  secondaryPrefs: readonly string[],
): Entity | null {
  const f = r.fields ?? {};
  const group: Record<string, string> = {};
  const stepData: Record<number, { time?: string; eventId?: string; fields: Record<string, string> }> = {};

  for (const [key, value] of Object.entries(f)) {
    if (META_KEYS.has(key)) continue;
    const strValue = value == null ? '' : String(value);

    const stepMatch = key.match(/^step(\d+)_(.+)$/);
    if (stepMatch) {
      const stepNum = parseInt(stepMatch[1], 10);
      const fieldName = stepMatch[2];
      const slot = stepData[stepNum] ??= { fields: {} };
      if (fieldName === 'time') slot.time = strValue;
      else if (fieldName === 'event_id') slot.eventId = strValue;
      else slot.fields[fieldName] = strValue;
    } else {
      group[key] = strValue;
    }
  }

  const stageNums = Object.keys(stepData).map(Number).sort((a, b) => a - b);
  if (stageNums.length === 0) return null;

  const stages: EntityStage[] = stageNums.map((n) => {
    const s = stepData[n];
    const captured = s.fields;
    // Best-effort summary: proc > spawned, proc → dest, or first captured
    const procKey = Object.keys(captured).find((k) => /^(process|proc|process_name|parent_process_name)$/.test(k));
    const spawnedKey = Object.keys(captured).find((k) => /^(child_process|child_process_name|spawned)$/.test(k));
    const destKey = Object.keys(captured).find((k) => /^(dest|dest_ip|dest_host|dest_domain|dest_url|url)$/.test(k));
    let summary = '';
    if (procKey && spawnedKey) summary = `${captured[procKey]} › ${captured[spawnedKey]}`;
    else if (procKey && destKey) summary = `${captured[procKey]} → ${captured[destKey]}`;
    else if (procKey) summary = captured[procKey];
    else if (destKey) summary = captured[destKey];
    else {
      // First non-meta captured field value
      const first = Object.values(captured)[0];
      summary = first ?? (s.eventId ? `event_id=${s.eventId}` : `step ${n}`);
    }

    // Details: the next most-useful captured string, preferring cmdline/details/http
    const detailKeyOrder = ['command_line', 'cmdline', 'details', 'http_url', 'http_referrer', 'file_path'];
    let details: string | null = null;
    for (const k of detailKeyOrder) {
      const v = captured[k];
      if (v) { details = v; break; }
    }
    if (!details) {
      const remaining = Object.entries(captured).filter(([k]) => k !== procKey && k !== spawnedKey && k !== destKey);
      if (remaining.length) details = remaining.map(([k, v]) => `${k}=${v}`).join(' · ');
    }

    return {
      stepNum: n,
      timeMs: parseStepTime(s.time ?? ''),
      eventId: s.eventId ?? '',
      summary,
      details,
    };
  });

  const validTimes = stages.map((s) => s.timeMs).filter((t) => Number.isFinite(t));
  const startMs = validTimes.length ? Math.min(...validTimes) : NaN;
  const endMs = validTimes.length ? Math.max(...validTimes) : NaN;
  const rawDur = f.sequence_duration_seconds;
  const durationSec = rawDur != null ? Number(rawDur) : NaN;
  // Fallback to stage-time spread; clamp to >= 0 in case the backend reports
  // negative duration when stage ordering is ambiguous.
  const duration = Math.max(
    0,
    Number.isFinite(durationSec)
      ? durationSec * 1000
      : Number.isFinite(startMs) && Number.isFinite(endMs) ? endMs - startMs : 0,
  );

  const primaryField = byFields[0] ?? Object.keys(group)[0];
  const display = primaryField ? (group[primaryField] ?? '') : '';
  const secondary = secondaryPrefs
    .map((k) => group[k])
    .find((v) => v && v.length > 0) ?? '';

  const key = byFields.length
    ? byFields.map((k) => group[k] ?? '').join('·') || `row_${idx}`
    : display || `row_${idx}`;

  return {
    key,
    display: display || `#${idx + 1}`,
    secondary,
    startMs,
    endMs,
    duration,
    stages,
  };
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

interface Histo {
  buckets: number[];
  min: number;
  max: number;
}

function buildHistogram(durations: number[]): Histo {
  if (!durations.length) return { buckets: [], min: 0, max: 0 };
  const min = Math.min(...durations);
  const max = Math.max(...durations);
  const BUCKETS = 18;
  const buckets = new Array(BUCKETS).fill(0);
  for (const d of durations) {
    const r = max === min ? 0 : (d - min) / (max - min);
    const b = Math.min(BUCKETS - 1, Math.floor(r * BUCKETS));
    buckets[b] += 1;
  }
  return { buckets, min, max };
}

function SequenceSummary({
  matched,
  median,
  histo,
}: {
  matched: number;
  median: number;
  histo: Histo;
}) {
  const bmax = Math.max(1, ...histo.buckets);
  return (
    <div className="grid grid-cols-[auto_1fr_auto] gap-4 items-center px-3 py-2 border-b border-border bg-muted/20">
      <div className="flex items-center gap-4 font-mono">
        <div className="flex flex-col">
          <span className="text-[10px] text-muted-foreground uppercase tracking-[0.12em]">Matches</span>
          <span className="text-[18px] text-foreground font-semibold tabular-nums leading-none mt-0.5">
            {matched}
          </span>
        </div>
        <div className="flex flex-col">
          <span className="text-[10px] text-muted-foreground uppercase tracking-[0.12em]">Median</span>
          <span className="text-[14px] text-foreground tabular-nums leading-none mt-1">
            {formatDuration(median)}
          </span>
        </div>
        <div className="flex flex-col">
          <span className="text-[10px] text-muted-foreground uppercase tracking-[0.12em]">Range</span>
          <span className="text-[11px] text-foreground/80 tabular-nums leading-none mt-1">
            {formatDuration(histo.min)} – {formatDuration(histo.max)}
          </span>
        </div>
      </div>
      <div className="flex flex-col gap-1">
        <div className="flex items-center justify-between font-mono text-[9.5px] text-muted-foreground uppercase tracking-[0.12em]">
          <span>Chain duration · faster = more suspicious</span>
          <span>{formatDuration(histo.min)} ——— {formatDuration(histo.max)}</span>
        </div>
        <svg viewBox={`0 0 ${Math.max(1, histo.buckets.length) * 8} 22`} className="w-full h-[22px]">
          {histo.buckets.map((v, i) => {
            const h = (v / bmax) * 18;
            const t = 1 - (i / Math.max(1, histo.buckets.length - 1));
            return (
              <rect
                key={i}
                x={i * 8 + 1}
                y={20 - h}
                width={6}
                height={h}
                rx={1}
                fill="var(--primary)"
                opacity={0.35 + t * 0.5}
              />
            );
          })}
        </svg>
      </div>
      <div />
    </div>
  );
}

function shortCondition(c: string): { id: string | null; rest: string } {
  const m = c.match(/event_id\s*=\s*(\d+)\s+(.+)/i);
  if (m) return { id: m[1], rest: m[2] };
  return { id: null, rest: c };
}

interface MatrixProps {
  entities: Entity[];
  conditions: string[];
  byKey: string;
  selected: { ri: number; si: number } | null;
  setSelected: (v: { ri: number; si: number } | null) => void;
  maxDuration: number;
}

function SequenceMatrix({ entities, conditions, byKey, selected, setSelected, maxDuration }: MatrixProps) {
  const gridCols = `220px repeat(${Math.max(1, conditions.length)}, 1fr) 120px`;
  return (
    <div className="flex-1 min-h-0 overflow-auto">
      <div className="min-w-[900px]">
        {/* Sticky header */}
        <div
          className="sticky top-0 z-10 bg-card border-b border-border grid"
          style={{ gridTemplateColumns: gridCols }}
        >
          <div className="py-2 px-3 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold border-r border-border/60">
            {byKey}
          </div>
          {conditions.map((c, i) => {
            const sc = shortCondition(c);
            return (
              <div
                key={i}
                className="py-2 px-3 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold border-r border-border/60 truncate"
                title={c}
              >
                <div className="flex items-center gap-1.5">
                  <span className="inline-flex items-center justify-center w-[16px] h-[16px] rounded-full bg-primary/15 text-primary text-[9px] font-bold tabular-nums">
                    {i + 1}
                  </span>
                  <span className="text-foreground truncate normal-case tracking-normal">
                    {sc.id ? `event_id=${sc.id}` : ''}
                  </span>
                </div>
                <div className="normal-case tracking-normal text-muted-foreground mt-0.5 truncate font-normal">
                  {sc.rest}
                </div>
              </div>
            );
          })}
          <div className="py-2 px-3 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold text-right">
            Chain Duration
          </div>
        </div>

        {/* Rows */}
        {entities.map((ent, ri) => {
          // Only tag FASTEST when (a) we're top of the list, (b) there's more
          // than one row to be faster than, and (c) the winning duration is
          // actually a positive number (0ms is a tie, not a win).
          const isFastest = ri === 0 && entities.length > 1 && ent.duration > 0;
          return (
            <div
              key={ent.key}
              className={cn(
                'grid items-stretch border-b border-border/40 transition-colors hover:bg-foreground/3',
                isFastest && 'bg-primary/[0.04]',
              )}
              style={{ gridTemplateColumns: gridCols }}
            >
              {/* Entity cell */}
              <div className="py-2.5 px-3 border-r border-border/60 flex flex-col gap-0.5 min-w-0">
                {isFastest && (
                  <span className="inline-flex items-center font-mono text-[8.5px] font-bold tracking-[0.14em] text-primary">
                    FASTEST
                  </span>
                )}
                <span className="font-mono text-[12px] text-foreground truncate">{ent.display}</span>
                {ent.secondary && (
                  <span className="font-mono text-[10px] text-muted-foreground truncate">{ent.secondary}</span>
                )}
                {Number.isFinite(ent.startMs) && (
                  <span className="font-mono text-[9.5px] text-muted-foreground/70 mt-0.5">
                    started {formatUtcHms(ent.startMs)}
                  </span>
                )}
              </div>

              {/* Stage cells */}
              {ent.stages.map((stg, si) => {
                const prev = si > 0 ? ent.stages[si - 1] : null;
                const hopMs = prev && Number.isFinite(stg.timeMs) && Number.isFinite(prev.timeMs)
                  ? stg.timeMs - prev.timeMs
                  : 0;
                const isSel = selected && selected.ri === ri && selected.si === si;
                return (
                  <div
                    key={si}
                    onClick={() => setSelected(isSel ? null : { ri, si })}
                    className={cn(
                      'relative py-2.5 pr-3 border-r border-border/60 cursor-pointer transition-colors min-w-0',
                      si > 0 ? 'pl-6' : 'pl-3',
                      isSel ? 'bg-primary/10' : 'hover:bg-foreground/3',
                    )}
                  >
                    {si > 0 && hopMs > 0 && (
                      <div className="absolute left-0 top-2 -translate-x-1/2 z-10 flex items-center gap-0.5 bg-card border border-border rounded-full px-1.5 py-[1px] font-mono text-[9.5px] text-muted-foreground shadow-sm">
                        <span className="tabular-nums">+{formatDuration(hopMs)}</span>
                      </div>
                    )}
                    <div className="flex items-center gap-2 mb-1">
                      {Number.isFinite(stg.timeMs) && (
                        <span className="font-mono text-[10px] tabular-nums text-foreground/80">
                          {formatUtcHms(stg.timeMs)}
                        </span>
                      )}
                    </div>
                    <div
                      className="font-mono text-[11.5px] text-foreground truncate"
                      title={stg.summary}
                    >
                      {stg.summary || '—'}
                    </div>
                    {stg.details && (
                      <div
                        className="font-mono text-[10px] text-muted-foreground truncate mt-0.5"
                        title={stg.details}
                      >
                        {stg.details}
                      </div>
                    )}
                  </div>
                );
              })}
              {/* Stage padding cells when fewer stages than conditions */}
              {Array.from({ length: Math.max(0, conditions.length - ent.stages.length) }).map((_, i) => (
                <div key={`pad_${i}`} className="py-2.5 px-3 border-r border-border/60" />
              ))}

              {/* Duration cell */}
              <div className="py-2.5 px-3 flex flex-col items-end justify-center gap-1">
                <span
                  className={cn(
                    'font-mono text-[14px] tabular-nums whitespace-nowrap',
                    isFastest ? 'text-primary font-semibold' : 'text-foreground',
                  )}
                >
                  {formatDuration(ent.duration)}
                </span>
                <div className="w-full h-1 rounded-full bg-foreground/10 overflow-hidden">
                  <div
                    className="h-full bg-primary rounded-full"
                    style={{
                      width: `${Math.min(100, 10 + (ent.duration / Math.max(1, maxDuration)) * 90)}%`,
                    }}
                  />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SequenceEmptyState({ conditions, byKey }: { conditions: string[]; byKey: string }) {
  return (
    <div className="flex-1 flex flex-col items-center justify-center p-10">
      <div className="max-w-[560px] w-full flex flex-col items-center gap-5">
        <div className="w-12 h-12 rounded-full bg-primary/12 flex items-center justify-center">
          <Zap className="w-[20px] h-[20px] text-primary" />
        </div>
        <div className="text-center flex flex-col gap-1.5">
          <div className="font-mono text-[11px] uppercase tracking-[0.14em] text-primary font-semibold">
            No matches
          </div>
          <div className="text-[13px] text-foreground/80 leading-relaxed">
            No <span className="text-foreground font-medium">{byKey}</span> completed all{' '}
            {conditions.length} stage{conditions.length === 1 ? '' : 's'} in order within the time window.
          </div>
        </div>
        {conditions.length > 0 && (
          <div
            className="w-full grid gap-2 mt-2"
            style={{ gridTemplateColumns: `repeat(${conditions.length}, 1fr)` }}
          >
            {conditions.map((c, i) => (
              <div
                key={i}
                className="relative border border-dashed border-border rounded-md p-3 bg-muted/30"
              >
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="inline-flex items-center justify-center w-[16px] h-[16px] rounded-full bg-primary/15 text-primary text-[9px] font-bold tabular-nums">
                    {i + 1}
                  </span>
                  <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
                    Stage {i + 1}
                  </span>
                </div>
                <div className="font-mono text-[10.5px] text-muted-foreground break-all">{c}</div>
                <div className="font-mono text-[9px] text-muted-foreground/70 mt-2 tabular-nums">0 events</div>
                {i < conditions.length - 1 && (
                  <div className="absolute -right-2.5 top-1/2 -translate-y-1/2 z-10 w-5 h-5 rounded-full border border-border bg-card flex items-center justify-center">
                    <ArrowRight className="w-[10px] h-[10px] text-muted-foreground/70" />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
        <div className="text-[11px] text-muted-foreground text-center max-w-[480px] leading-relaxed">
          <span className="text-foreground/80">Sequence</span> looks for events matching stage 1, then
          stage 2, then stage 3 — in that order — per {byKey}. Try loosening{' '}
          <span className="font-mono text-foreground/80">maxspan</span> or broadening a stage condition.
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────── main ───────────────────────────

type SortKey = 'fastest' | 'recent' | 'entity';

export function SequenceView({
  results,
  query,
  fieldsCollapsed,
  fieldsCount,
  onExpandFields,
}: SequenceViewProps) {
  const parsed = useMemo(() => parseSequenceCmd(query), [query]);
  const byKey = parsed.byFields[0] ?? 'entity';

  // Secondary identity line follows the active schema (NAN-1241): UDM base list,
  // unioned with OCSF host/user/ip promoted columns when OCSF is active.
  const { schemaFields } = useSchemaEntityMap();
  const secondaryPrefs = useMemo(
    () => buildSecondaryPrefs(SEQUENCE_SECONDARY_BASE, schemaFields),
    [schemaFields],
  );

  const entitiesRaw: Entity[] = useMemo(
    () =>
      results
        .map((r, i) => adaptResult(r, parsed.byFields, i, secondaryPrefs))
        .filter((e): e is Entity => e !== null),
    [results, parsed.byFields, secondaryPrefs],
  );

  const [filter, setFilter] = useState('');
  const [sort, setSort] = useState<SortKey>('fastest');
  const [selected, setSelected] = useState<{ ri: number; si: number } | null>(null);

  const entities = useMemo(() => {
    const list = entitiesRaw.slice();
    const f = filter.trim().toLowerCase();
    const filtered = f
      ? list.filter((e) => e.display.toLowerCase().includes(f) || e.secondary.toLowerCase().includes(f))
      : list;
    if (sort === 'fastest') filtered.sort((a, b) => a.duration - b.duration);
    else if (sort === 'recent') filtered.sort((a, b) => b.startMs - a.startMs);
    else filtered.sort((a, b) => a.display.localeCompare(b.display));
    return filtered;
  }, [entitiesRaw, filter, sort]);

  const validDurations = useMemo(
    () => entitiesRaw.map((e) => e.duration).filter((d) => Number.isFinite(d) && d >= 0),
    [entitiesRaw],
  );
  const histo = useMemo(() => buildHistogram(validDurations), [validDurations]);
  const median = useMemo(() => {
    if (!validDurations.length) return 0;
    const sorted = validDurations.slice().sort((a, b) => a - b);
    return sorted[Math.floor(sorted.length / 2)];
  }, [validDurations]);

  const maxDuration = useMemo(
    () => entitiesRaw.reduce((m, e) => Math.max(m, e.duration), 0),
    [entitiesRaw],
  );

  const maxSpanMs = parsed.maxspan ? parsed.maxspan.n * SPAN_MS[parsed.maxspan.unit] : null;
  // maxspan label is shown as chip text; ms is unused here but derived for parity with other views.
  void maxSpanMs;

  const headerRight = entitiesRaw.length
    ? `${entities.length}/${entitiesRaw.length} ${byKey}s matched`
    : `0 ${byKey}s matched`;

  return (
    <div className="flex flex-col min-h-0 min-w-0 overflow-hidden">
      {/* Header */}
      <div className="py-2 px-3 border-b border-border flex flex-wrap items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold whitespace-nowrap">
        <span className="flex items-center gap-1.5 shrink-0">
          <Zap className="w-[12px] h-[12px] text-primary" />
          <span>Sequence</span>
          <span className="text-muted-foreground/60">·</span>
          <span className="normal-case tracking-normal text-foreground">
            by {parsed.byFields.join(', ') || '(fields)'}
          </span>
        </span>
        {parsed.maxspan && (
          <HeaderChip label="maxspan" value={`${parsed.maxspan.n}${parsed.maxspan.unit}`} />
        )}
        <HeaderChip label="stages" value={String(parsed.conditions.length)} />
        {fieldsCollapsed && onExpandFields && (
          <FieldsBeaconPill count={fieldsCount} onClick={onExpandFields} />
        )}
        <span className="flex-1" aria-hidden />
        <span className="text-muted-foreground font-mono normal-case tracking-normal">
          {headerRight}
        </span>
      </div>

      {/* Summary (hide when no matches, so the empty state stands alone) */}
      {entitiesRaw.length > 0 && (
        <SequenceSummary matched={entities.length} median={median} histo={histo} />
      )}

      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-border bg-muted/30">
        <div className="relative">
          <SearchIcon className="w-[11px] h-[11px] absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder={`Filter by ${byKey}`}
            className="bg-transparent outline-none text-[11px] pl-7 pr-2 py-1 rounded border border-border focus:border-primary/60 placeholder:text-muted-foreground w-[220px]"
          />
        </div>
        <span className="flex-1" aria-hidden />
        <span className="text-muted-foreground font-mono text-[10px] uppercase tracking-[0.12em]">
          sort
        </span>
        {(
          [
            ['fastest', 'Fastest'],
            ['recent', 'Recent'],
            ['entity', byKey],
          ] as Array<[SortKey, string]>
        ).map(([k, lbl]) => (
          <button
            key={k}
            type="button"
            onClick={() => setSort(k)}
            className={cn(
              'inline-flex items-center px-2 py-1 rounded-md text-[10.5px] transition-colors cursor-pointer',
              sort === k
                ? 'bg-primary/12 text-primary'
                : 'text-muted-foreground hover:text-foreground',
            )}
          >
            {lbl}
          </button>
        ))}
      </div>

      {entities.length > 0 ? (
        <SequenceMatrix
          entities={entities}
          conditions={parsed.conditions}
          byKey={byKey}
          selected={selected}
          setSelected={setSelected}
          maxDuration={maxDuration}
        />
      ) : (
        <SequenceEmptyState conditions={parsed.conditions} byKey={byKey} />
      )}
    </div>
  );
}
