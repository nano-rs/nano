// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-483 — list pane for the Matches tab.
// Ports design-ref/shadcn/matches-list.jsx. Each row is a detection card; the
// mockup renders grouped aggregates + sparkline — the real API doesn't expose
// aggregate values, so grouped-style match rows show event counts + duration
// instead, which the data backs.

import { useMemo } from 'react';
import { Filter } from 'lucide-react';
import { cn } from '@/lib/utils';
import { relTime, type MatchView } from './helpers';

// Event burst sparkline — bins events by time into 8 buckets.
function BurstSpark({ view, width = 72, height = 16 }: { view: MatchView; width?: number; height?: number }) {
  const bins = 8;
  const counts = Array(bins).fill(0) as number[];
  const first = view.firstSeen.getTime();
  const range = Math.max(view.lastSeen.getTime() - first, 1);
  for (const e of view.events) {
    const raw = (e as Record<string, unknown>)['timestamp']
      ?? (e as Record<string, unknown>)['eventTime']
      ?? (e as Record<string, unknown>)['ingest_time'];
    if (typeof raw !== 'string') continue;
    const t = new Date(raw.includes('Z') || raw.includes('+') ? raw : raw.replace(' ', 'T') + 'Z').getTime();
    if (!Number.isFinite(t)) continue;
    const idx = Math.min(bins - 1, Math.floor(((t - first) / range) * bins));
    counts[idx]++;
  }
  const max = Math.max(...counts, 1);
  const barW = width / bins - 1;
  return (
    <svg width={width} height={height} className="overflow-visible">
      {counts.map((c, i) => {
        const h = Math.max(1.5, (c / max) * height);
        return (
          <rect
            key={i}
            x={i * (barW + 1)}
            y={height - h}
            width={barW}
            height={h}
            rx={0.5}
            fill={i === bins - 1 ? 'var(--primary)' : 'color-mix(in srgb, var(--primary) 55%, transparent)'}
          />
        );
      })}
    </svg>
  );
}

function StatusDot({ status, alertGenerated }: { status: string; alertGenerated: boolean }) {
  if (alertGenerated) return <span className="w-[6px] h-[6px] rounded-full bg-warning shrink-0" />;
  if (status === 'closed') return <span className="w-[6px] h-[6px] rounded-full bg-muted-foreground shrink-0" />;
  return <span className="w-[6px] h-[6px] rounded-full bg-muted-foreground shrink-0" />;
}

function EntityGlyph({ type }: { type: MatchView['entity']['type'] }) {
  const color =
    type === 'role' ? 'var(--warning)'
    : type === 'service' ? 'var(--primary)'
    : 'color-mix(in srgb, var(--foreground) 60%, transparent)';
  const letter =
    type === 'role' ? 'R'
    : type === 'service' ? 'S'
    : type === 'host' ? 'H'
    : type === 'ip' ? 'I'
    : 'U';
  return (
    <div
      className="w-[18px] h-[18px] rounded-[3px] flex items-center justify-center font-mono text-[9.5px] font-bold shrink-0"
      style={{ background: `color-mix(in srgb, ${color} 14%, transparent)`, color }}
    >
      {letter}
    </div>
  );
}

interface MatchRowProps {
  view: MatchView;
  selected: boolean;
  onSelect: () => void;
  alertGenerated: boolean;
  now: Date;
}

function MatchRow({ view, selected, onSelect, alertGenerated, now }: MatchRowProps) {
  const hasMultipleEvents = view.events.length > 1;
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        'w-full text-left px-3 py-2.5 border-l-2 transition-colors',
        'border-b border-border/60',
        selected
          ? 'bg-primary/[0.06] border-l-primary'
          : 'border-l-transparent hover:bg-foreground/[0.025]',
      )}
    >
      <div className="flex items-center gap-2">
        <StatusDot status={view.status} alertGenerated={alertGenerated} />
        <EntityGlyph type={view.entity.type} />
        <span className="font-mono text-[11.5px] text-foreground truncate flex-1">{view.entity.label}</span>
        {alertGenerated && (
          <span
            className="text-[9px] font-mono font-semibold uppercase tracking-[0.08em] px-1 h-[14px] flex items-center rounded-sm"
            style={{
              background: 'color-mix(in srgb, var(--destructive) 14%, transparent)',
              color: 'var(--destructive)',
            }}
          >
            Alert
          </span>
        )}
        <span className="font-mono text-[10px] text-muted-foreground tabular-nums">
          {relTime(view.detectedAt, now)}
        </span>
      </div>

      {hasMultipleEvents ? (
        <div className="mt-1.5 flex items-center gap-2.5 pl-[26px]">
          <div className="flex items-baseline gap-0.5 font-mono text-[10.5px]">
            <span className="text-muted-foreground">events</span>
            <span
              className={cn(
                'tabular-nums font-medium',
                view.events.length > 100 ? 'text-destructive' : 'text-foreground',
              )}
            >
              {view.events.length}
            </span>
          </div>
          <span className="text-muted-foreground/60 text-[10px]">·</span>
          <span className="font-mono text-[10.5px] text-muted-foreground">
            {view.uniqueIps} IP{view.uniqueIps !== 1 ? 's' : ''}
          </span>
          {view.durationMs > 0 && (
            <>
              <span className="text-muted-foreground/60 text-[10px]">·</span>
              <span className="font-mono text-[10.5px] text-muted-foreground">
                {(view.durationMs / 60000).toFixed(1)}m
              </span>
            </>
          )}
          <div className="ml-auto">
            <BurstSpark view={view} />
          </div>
        </div>
      ) : (
        <div className="mt-1 flex items-center gap-2 pl-[26px]">
          <span className="font-mono text-[10.5px] text-foreground truncate">
            {view.topActionName || 'Matched event'}
          </span>
          {view.region && (
            <span className="font-mono text-[10px] text-muted-foreground ml-auto">{view.region}</span>
          )}
        </div>
      )}
    </button>
  );
}

interface MatchesListProps {
  views: MatchView[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  filter: 'all' | 'alerts';
  onFilterChange: (f: 'all' | 'alerts') => void;
  alertedMatchIds: Set<string>;
  loading: boolean;
  /** Fill a bounded desktop pane instead of using the web page's sticky rail. */
  contained?: boolean;
}

export function MatchesList({
  views,
  selectedId,
  onSelect,
  filter,
  onFilterChange,
  alertedMatchIds,
  loading,
  contained = false,
}: MatchesListProps) {
  const now = useMemo(() => new Date(), [views]);

  const filters = [
    { id: 'all' as const, label: 'All', count: views.length },
    { id: 'alerts' as const, label: 'Alerts', count: alertedMatchIds.size },
  ];

  const filtered = useMemo(() => {
    if (filter === 'alerts') return views.filter((v) => alertedMatchIds.has(v.id));
    return views;
  }, [views, filter, alertedMatchIds]);

  return (
    <div
      // Stays pinned below the sticky tab bar while the detail pane scrolls.
      // `max-h` clamps at 80vh so the list always has an internal scrollbar
      // rather than trying to match the detail pane's height on long matches.
      className={cn(
        'flex min-h-0 flex-col overflow-hidden border-r border-border bg-card',
        contained ? 'h-full w-full self-stretch' : 'sticky top-9 max-h-[80vh] self-start',
      )}
    >
      {/* Filter tabs */}
      <div className="flex items-center gap-0.5 p-2 border-b border-border">
        {filters.map((f) => (
          <button
            key={f.id}
            type="button"
            onClick={() => onFilterChange(f.id)}
            className={cn(
              'h-6 px-2 rounded-md font-mono text-[10.5px] flex items-center gap-1.5 transition-colors',
              filter === f.id
                ? 'bg-foreground/[0.07] text-foreground'
                : 'text-muted-foreground hover:bg-foreground/[0.04] hover:text-foreground',
            )}
          >
            {f.label}
            <span
              className={cn(
                'tabular-nums text-[9.5px]',
                filter === f.id ? 'text-muted-foreground' : 'text-muted-foreground/70',
              )}
            >
              {f.count}
            </span>
          </button>
        ))}
      </div>

      {/* Header metadata */}
      <div className="px-3 py-1.5 border-b border-border/60 flex items-center gap-2 font-mono text-[9.5px] uppercase tracking-[0.1em] text-muted-foreground">
        <span>{filtered.length} matches</span>
        <span className="text-muted-foreground/60">·</span>
        <span>newest first</span>
      </div>

      {/* Scrollable list */}
      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="p-6 text-center text-[11px] text-muted-foreground">Loading matches…</div>
        ) : filtered.length === 0 ? (
          <div className="p-6 text-center flex flex-col items-center gap-1.5">
            <Filter className="w-5 h-5 text-muted-foreground/60" strokeWidth={1.5} />
            <div className="text-[12px] text-foreground font-medium">
              {filter === 'all' ? 'No matches to show' : 'No alerts in this window'}
            </div>
            <div className="text-[10.5px] text-muted-foreground">
              {filter === 'all'
                ? "This rule hasn't fired in the current window. Widen the time range or test against history."
                : 'Try a different filter — or switch to All to see everything.'}
            </div>
            {filter !== 'all' && (
              <button
                type="button"
                onClick={() => onFilterChange('all')}
                className="mt-1 text-[11px] text-primary hover:underline"
              >
                Show all
              </button>
            )}
          </div>
        ) : (
          filtered.map((v) => (
            <MatchRow
              key={v.id}
              view={v}
              selected={v.id === selectedId}
              onSelect={() => onSelect(v.id)}
              alertGenerated={alertedMatchIds.has(v.id)}
              now={now}
            />
          ))
        )}
      </div>
    </div>
  );
}
