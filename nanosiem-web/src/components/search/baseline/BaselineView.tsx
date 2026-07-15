// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * BaselineView — renderer for the `| baseline` command (NAN-1873).
 *
 * `| baseline` surfaces what is NEW for a host/user/ip vs. its own recent
 * history. Unlike asset/retro it does NOT emit a marker + refetch — the backend
 * (`build_baseline_view`) returns the actual new-to-entity rows inline, so this
 * view is purely presentational over `results`.
 *
 * Row shape (FE-normalised onto `.fields`):
 *   { entity, entity_type, dimension, value, count, first_seen, coverage,
 *     baseline_unknown }  — plus, when nothing is new, a single summary row
 *   { entity, entity_type, coverage, count:0, note }.
 *
 * Populated layout: header → finding band (what/how many/how much to trust it)
 * → per-dimension sections. Every value row is a drill-down into the search.
 */

import { useMemo } from 'react';
import {
  Sparkles,
  TriangleAlert,
  ShieldQuestion,
  Terminal,
  Globe,
  Network,
  User,
  Server,
  Plug,
  Box,
  ArrowUpRight,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

interface BaselineViewProps {
  results: SearchResult[];
  query?: string;
  onAddToQuery?: (field: string, value: string, exclude: boolean) => void;
  fieldsCollapsed?: boolean;
  fieldsCount?: number;
  onExpandFields?: () => void;
}

// ─────────────────────────── helpers ───────────────────────────

const str = (v: unknown): string => (v == null ? '' : String(v));
const num = (v: unknown): number => {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
};

/**
 * Dimension label (as emitted by the backend) → drilldown field + framing.
 * `desc` gets the entity subject ("this host") so an analyst reads what the
 * section actually means, not just its raw label.
 */
const DIM_META: Record<
  string,
  { field: string; singular: string; icon: typeof Globe; desc: (subj: string) => string }
> = {
  processes: {
    field: 'process_name',
    singular: 'process',
    icon: Terminal,
    desc: (s) => `programs ${s} ran for the first time`,
  },
  'destination IPs': {
    field: 'dest_ip',
    singular: 'destination IP',
    icon: Globe,
    desc: (s) => `addresses ${s} reached out to for the first time`,
  },
  'source IPs': {
    field: 'src_ip',
    singular: 'source IP',
    icon: Network,
    desc: (s) => `addresses that connected to ${s} for the first time`,
  },
  users: {
    field: 'user',
    singular: 'user',
    icon: User,
    desc: (s) => `accounts active on ${s} for the first time`,
  },
  hosts: {
    field: 'src_host',
    singular: 'host',
    icon: Server,
    desc: (s) => `hosts ${s} appeared on for the first time`,
  },
  ports: {
    field: 'dest_port',
    singular: 'port',
    icon: Plug,
    desc: (s) => `destination ports ${s} used for the first time`,
  },
};

const COVERAGE: Record<
  string,
  { label: string; cls: string; dot: string; text: string; hint: string; body: string }
> = {
  sufficient: {
    label: 'sufficient',
    cls: 'text-emerald-600 dark:text-emerald-400 border-emerald-500/40 bg-emerald-500/10',
    dot: 'bg-emerald-500',
    text: 'text-emerald-600 dark:text-emerald-400',
    hint: 'Enough history to trust a "never seen before" call.',
    body: 'enough prior activity to trust these as genuine first sightings.',
  },
  thin: {
    label: 'thin',
    cls: 'text-amber-600 dark:text-amber-400 border-amber-500/40 bg-amber-500/10',
    dot: 'bg-amber-500',
    text: 'text-amber-600 dark:text-amber-400',
    hint: 'Limited history — treat new values as leads, not verdicts.',
    body: 'limited prior activity to judge against — treat these as leads to verify, not verdicts.',
  },
  no_history: {
    label: 'no history',
    cls: 'text-muted-foreground border-border bg-muted/40',
    dot: 'bg-muted-foreground',
    text: 'text-muted-foreground',
    hint: 'No prior activity — cannot judge what is new for this entity.',
    body: 'no prior activity — "new" cannot be judged for this entity.',
  },
};

const BAND_LABEL: Record<string, string> = {
  sufficient: 'sufficient history',
  thin: 'thin history',
  no_history: 'no prior history',
};

const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** "Jul 11 15:13". Tolerant of null/empty. */
function fmtSeen(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  return `${MON[d.getMonth()]} ${d.getDate()} ${hh}:${mm}`;
}

/** Relative age ("41m" / "3h" / "2d") for a first-seen timestamp; '' if unusable. */
function fmtAge(iso: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  const ms = Date.now() - d.getTime();
  if (ms < 0) return '';
  const m = Math.round(ms / 60000);
  if (m < 60) return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.round(h / 24)}d`;
}

/** Compact occurrence count (1204 → "1.2k"). */
function fmtCount(v: number): string {
  if (v >= 1e6) return (v / 1e6).toFixed(1) + 'M';
  if (v >= 1e3) return (v / 1e3).toFixed(1) + 'k';
  return String(v);
}

interface Row {
  dimension: string;
  value: string;
  count: number;
  firstSeen: string;
  baselineUnknown: boolean;
}

// ─────────────────────────── component ───────────────────────────

export function BaselineView({
  results,
  onAddToQuery,
  fieldsCollapsed,
  fieldsCount,
  onExpandFields,
}: BaselineViewProps) {
  const { entity, entityType, coverage, note, groups, anyUnknown, total } = useMemo(() => {
    const first = results[0]?.fields ?? {};
    const entity = str(first.entity);
    const entityType = str(first.entity_type);
    const coverage = str(first.coverage) || 'no_history';
    // Empty case: a single summary row with no dimension, carrying `note`.
    const note = results.length === 1 && !str(first.dimension) ? str(first.note) : '';

    const rows: Row[] = results
      .map((r) => r.fields)
      .filter((f) => str(f.dimension) !== '' && str(f.value) !== '')
      .map((f) => ({
        dimension: str(f.dimension),
        value: str(f.value),
        count: num(f.count),
        firstSeen: str(f.first_seen),
        baselineUnknown: f.baseline_unknown === true,
      }));

    // Group by dimension, preserving first-appearance order.
    const order: string[] = [];
    const byDim = new Map<string, Row[]>();
    for (const row of rows) {
      if (!byDim.has(row.dimension)) {
        byDim.set(row.dimension, []);
        order.push(row.dimension);
      }
      byDim.get(row.dimension)!.push(row);
    }
    const groups = order.map((dim) => ({ dim, rows: byDim.get(dim)! }));
    const anyUnknown = rows.some((r) => r.baselineUnknown);

    return { entity, entityType, coverage, note, groups, anyUnknown, total: rows.length };
  }, [results]);

  const cov = COVERAGE[coverage] ?? COVERAGE.no_history;
  const isEmpty = groups.length === 0;

  const subj =
    entityType === 'host'
      ? 'this host'
      : entityType === 'user'
        ? 'this user'
        : entityType === 'ip'
          ? 'this IP'
          : 'this entity';

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 h-8 border-b border-border text-[11px] uppercase tracking-wide text-muted-foreground shrink-0">
        <span className="flex items-center gap-1.5 shrink-0">
          <Sparkles className="w-[12px] h-[12px] text-primary" />
          <span>Baseline</span>
        </span>
        <span className="text-muted-foreground/60">·</span>
        <span className="normal-case tracking-normal font-mono text-foreground">{entity || '—'}</span>
        {entityType && (
          <span className="normal-case tracking-normal text-muted-foreground/70">{entityType}</span>
        )}
        <span
          className={cn('px-1.5 py-px rounded-sm border text-[10px] font-mono normal-case tracking-normal', cov.cls)}
          title={cov.hint}
        >
          {cov.label}
        </span>
        {anyUnknown && (
          <span
            className="flex items-center gap-1 text-amber-600 dark:text-amber-400 normal-case tracking-normal"
            title="The lookback filled entirely with new values, so a baseline could not be established — these are unconfirmed, not proven first-sightings."
          >
            <TriangleAlert className="w-[11px] h-[11px]" />
            <span className="text-[10px]">baseline unknown</span>
          </span>
        )}
        {fieldsCollapsed && onExpandFields && (
          <button
            type="button"
            onClick={onExpandFields}
            className="ml-1 px-1.5 py-px rounded-sm border border-border text-[10px] font-mono normal-case tracking-normal text-muted-foreground hover:text-foreground hover:bg-muted"
          >
            {fieldsCount != null ? `${fieldsCount} fields` : 'fields'}
          </button>
        )}
        <span className="flex-1" aria-hidden />
        <span className="normal-case tracking-normal text-muted-foreground/70">
          {isEmpty ? 'new to this entity' : 'search window vs recent history'}
        </span>
      </div>

      {/* Body */}
      {isEmpty ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-2 text-center px-6 py-12 text-muted-foreground">
          <ShieldQuestion className="w-6 h-6 opacity-50" />
          <div className="text-[13px] text-foreground">
            {coverage === 'no_history'
              ? 'No history to baseline against'
              : `Nothing new for ${entity || 'this entity'}`}
          </div>
          <div className="text-[11px] max-w-md">
            {note ||
              (coverage === 'no_history'
                ? 'This entity has no prior activity in the lookback window, so "new" cannot be judged.'
                : 'Every value in this window was already seen for this entity in the lookback window.')}
          </div>
        </div>
      ) : (
        <>
          {/* Finding band — what this is, how much, how much to trust it */}
          <div className="flex items-start gap-4 px-3 py-2.5 border-b border-border bg-muted/20 shrink-0">
            <div className="flex flex-col shrink-0">
              <span className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-muted-foreground font-semibold">
                first sightings
              </span>
              <span className="font-mono text-[22px] font-semibold tabular-nums leading-none text-foreground mt-1">
                {total}
              </span>
            </div>
            <div className="flex flex-col gap-1 min-w-0 flex-1">
              <div className="text-[12px] text-foreground leading-snug">
                Values that appeared for <span className="font-mono">{entity || 'this entity'}</span> in
                your search window but were <span className="font-medium">absent from its recent history</span>
                {' — '}
                <span className="font-mono text-[11px]">
                  {groups.map((g, i) => (
                    <span key={g.dim}>
                      {i > 0 && <span className="text-muted-foreground/60"> · </span>}
                      <span className="tabular-nums">{g.rows.length}</span>{' '}
                      <span className="text-muted-foreground">
                        new {g.rows.length === 1 ? (DIM_META[g.dim]?.singular ?? g.dim) : g.dim}
                      </span>
                    </span>
                  ))}
                </span>
              </div>
              <div className="flex items-center gap-1.5 text-[11px] leading-snug">
                <span className={cn('w-[6px] h-[6px] rounded-full shrink-0', cov.dot)} aria-hidden />
                <span>
                  <span className={cn('font-medium', cov.text)}>{BAND_LABEL[coverage] ?? cov.label}</span>
                  <span className="text-muted-foreground"> — {cov.body}</span>
                </span>
              </div>
              {anyUnknown && (
                <div className="flex items-center gap-1.5 text-[11px] leading-snug">
                  <TriangleAlert className="w-[11px] h-[11px] text-amber-500 shrink-0" />
                  <span className="text-muted-foreground">
                    <span className="font-medium text-amber-600 dark:text-amber-400">baseline incomplete</span>
                    {' — the comparison cap filled entirely with new values, so some items may not be true first sightings.'}
                  </span>
                </div>
              )}
            </div>
            {onAddToQuery && (
              <span className="hidden sm:flex items-center gap-1 shrink-0 font-mono text-[10px] text-muted-foreground/70 pt-px">
                <ArrowUpRight className="w-[11px] h-[11px]" />
                click a value to filter
              </span>
            )}
          </div>

          {/* Per-dimension sections */}
          <div className="flex-1 min-h-0 overflow-y-auto">
            {groups.map((g) => {
              const meta = DIM_META[g.dim];
              const Icon = meta?.icon ?? Box;
              const clickable = !!(meta && onAddToQuery);
              const maxCount = Math.max(1, ...g.rows.map((r) => r.count));
              const showBars = g.rows.length > 1 && maxCount > 1;
              return (
                <section key={g.dim} className="border-b border-border last:border-b-0">
                  <div className="flex items-center gap-2 px-3 h-7 sticky top-0 z-10 bg-[color-mix(in_oklab,var(--color-muted)_50%,var(--color-card))]">
                    <Icon className="w-[12px] h-[12px] text-muted-foreground shrink-0" strokeWidth={1.5} />
                    <span className="text-[11px] font-medium text-foreground">{g.dim}</span>
                    <span className="font-mono text-[10.5px] tabular-nums text-muted-foreground">
                      {g.rows.length}
                    </span>
                    <span className="text-[10.5px] text-muted-foreground/70 truncate">
                      — {meta ? meta.desc(subj) : `values new for ${subj}`}
                    </span>
                    <span className="flex-1" aria-hidden />
                    {meta && (
                      <span className="font-mono text-[10px] text-muted-foreground/60 shrink-0">
                        {meta.field}
                      </span>
                    )}
                  </div>
                  {g.rows.map((r, i) => (
                    <button
                      key={`${g.dim}:${r.value}:${i}`}
                      type="button"
                      disabled={!clickable}
                      onClick={() => clickable && onAddToQuery!(meta!.field, r.value, false)}
                      title={clickable ? `Filter search to ${meta!.field}="${r.value}"` : undefined}
                      className={cn(
                        'group flex w-full items-center gap-3 px-3 h-[26px] text-[12px] text-left border-t border-border/50 first:border-t-0',
                        clickable ? 'cursor-pointer hover:bg-muted/40' : 'cursor-default',
                      )}
                    >
                      <span
                        className={cn(
                          'font-mono text-foreground truncate min-w-0',
                          clickable && 'group-hover:text-primary',
                        )}
                        title={r.value}
                      >
                        {r.value}
                      </span>
                      {r.baselineUnknown && (
                        <TriangleAlert
                          className="w-[11px] h-[11px] text-amber-500 shrink-0"
                          aria-label="baseline unknown"
                        />
                      )}
                      <span className="flex-1" aria-hidden />
                      {showBars && (
                        <span className="w-10 h-[3px] rounded-full bg-foreground/10 overflow-hidden shrink-0">
                          <span
                            className="block h-full rounded-full bg-primary/70"
                            style={{ width: `${(r.count / maxCount) * 100}%` }}
                          />
                        </span>
                      )}
                      <span className="font-mono text-[11px] text-muted-foreground shrink-0 tabular-nums w-[44px] text-right">
                        {fmtCount(r.count)}×
                      </span>
                      <span
                        className="font-mono text-[11px] text-muted-foreground/70 shrink-0 w-[126px] text-right tabular-nums"
                        title={r.firstSeen || undefined}
                      >
                        {fmtSeen(r.firstSeen)}
                        {fmtAge(r.firstSeen) && (
                          <span className="text-muted-foreground/50"> · {fmtAge(r.firstSeen)}</span>
                        )}
                      </span>
                      <span
                        className={cn(
                          'flex items-center justify-end gap-1 font-mono text-[10px] shrink-0 w-[44px]',
                          clickable
                            ? 'text-primary opacity-0 group-hover:opacity-100'
                            : 'opacity-0',
                        )}
                        aria-hidden
                      >
                        filter <ArrowUpRight className="w-[10px] h-[10px]" />
                      </span>
                    </button>
                  ))}
                </section>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

export default BaselineView;
