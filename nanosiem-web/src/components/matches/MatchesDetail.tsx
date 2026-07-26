// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-483 — detail pane for the Matches tab.
// Ports design-ref/shadcn/matches-detail.jsx. Sections that the mockup ties to
// synthetic data (predicate breakdown, entity MFA/dept metadata, "recent
// activity for this entity") render "STUB" chips so they surface in review.

import { useEffect, useMemo, useState } from 'react';
import { ArrowRight, Check, ListFilter, Search, FileText } from 'lucide-react';
import { cn } from '@/lib/utils';
import { absTime, extractAction, extractEventTime, eventEntityLabel, entityNoun, relTime, topActions, meanTimeToDetect, type MatchView } from './helpers';
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from '@/components/ui/tooltip';
import { LatencyPill } from './LatencyPill';
import { EventViewer } from './EventViewer';
import { useIdentityUserLookup, useRulePredicates } from '@/hooks/use-api';
import { useSchemaEntityMap } from '@/hooks/useSchemaEntityMap';
import { api } from '@/lib/api';
import type { MatchEntity } from './helpers';

// Build a nano-ql query that filters on a specific entity. We pick a UDM
// field by entity type so we hit the indexed columns (case-insensitive
// `_search` columns are already wired into the query path) rather than
// scanning the full message body.
function entitySearchQuery(entity: MatchEntity, schema: string | undefined): string | null {
  const raw = (entity.raw || entity.label || '').trim();
  if (!raw) return null;
  // Escape backslashes first, then double quotes — order matters.
  const escaped = raw.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  // NAN-1656: emit ONLY the ACTIVE schema profile's real columns. Previously we
  // OR'd the UDM names with their OCSF-dotted equivalents to work under either
  // profile (NAN-1287), but on the inactive profile those extra clauses resolve
  // to `lower(toString(ext.<name>))` JSON lookups with no index — they can never
  // match AND OR-ing them in defeats the bloom index on the real columns, so an
  // entity search full-scans 7 days (151M rows on Saturn). Branch on the profile
  // so the WHERE only carries indexed columns that actually exist.
  const isOcsf = schema === 'ocsf';
  switch (entity.type) {
    case 'user':
    case 'role':
    case 'service':
      // ARN-style identifiers (CloudTrail) round-trip through user_identity.arn.
      if (raw.startsWith('arn:')) return `user_identity.arn="${escaped}"`;
      // OCSF Sysmon users live under actor.user.name / user.name; UDM uses `user`.
      return isOcsf
        ? `user.name="${escaped}" OR actor.user.name="${escaped}"`
        : `user="${escaped}"`;
    case 'host':
      return isOcsf
        ? `device.hostname="${escaped}" OR src_endpoint.hostname="${escaped}" OR dst_endpoint.hostname="${escaped}"`
        : `src_host="${escaped}" OR dest_host="${escaped}"`;
    case 'ip':
      return isOcsf
        ? `src_endpoint.ip="${escaped}" OR dst_endpoint.ip="${escaped}"`
        : `src_ip="${escaped}" OR dest_ip="${escaped}"`;
    default:
      // Fall back to a free-text search on the raw value.
      return `"${escaped}"`;
  }
}

// Lightweight hook — fires one /api/search call per entity for the entity
// activity card. Returns `null` while loading so the cell can show a `—`
// placeholder. Cancels in-flight requests on entity change.
function useEntityActivity7d(entity: MatchEntity | null): {
  count: number | null;
  loading: boolean;
} {
  const [count, setCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const { schema } = useSchemaEntityMap();
  const queryStr = useMemo(() => (entity ? entitySearchQuery(entity, schema) : null), [entity, schema]);
  useEffect(() => {
    if (!queryStr) {
      setCount(null);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    const end = new Date();
    const start = new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000);
    api
      .search({
        query: queryStr,
        time_range: { start: start.toISOString(), end: end.toISOString() },
        limit: 1,
        skip_field_stats: true,
        // This card shows only a total count — no time-bucketed histogram — so
        // skip the histogram companion (its GROUP BY forces a full 7-day scan).
        skip_histogram: true,
        table_view: true,
      })
      .then((res) => {
        if (cancelled) return;
        setCount(typeof res.total_count === 'number' ? res.total_count : (res.results?.length ?? 0));
      })
      .catch(() => {
        if (!cancelled) setCount(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [queryStr]);
  return { count, loading };
}

// Recent activity hook — top 10 most-recent events matching the entity over
// the last 7 days. Backs the "Recent activity for this entity" card.
function useEntityRecentActivity(entity: MatchEntity | null): {
  events: Array<Record<string, unknown>>;
  loading: boolean;
} {
  const [events, setEvents] = useState<Array<Record<string, unknown>>>([]);
  const [loading, setLoading] = useState(false);
  const { schema } = useSchemaEntityMap();
  const queryStr = useMemo(() => (entity ? entitySearchQuery(entity, schema) : null), [entity, schema]);
  useEffect(() => {
    if (!queryStr) {
      setEvents([]);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    const end = new Date();
    const start = new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000);
    api
      .search({
        query: `${queryStr} | sort -timestamp | head 10`,
        time_range: { start: start.toISOString(), end: end.toISOString() },
        limit: 10,
        skip_field_stats: true,
        // Top-10 list only — no histogram rendered, so skip the histogram
        // companion (its GROUP BY forces a full 7-day scan).
        skip_histogram: true,
        table_view: true,
      })
      .then((res) => {
        if (cancelled) return;
        setEvents(Array.isArray(res.results) ? res.results : []);
      })
      .catch(() => {
        if (!cancelled) setEvents([]);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [queryStr]);
  return { events, loading };
}

// Severity dot — colors mirror SEV_META in helpers but compact (no label).
function SeverityDot({ severity }: { severity?: string }) {
  const s = (severity || '').toLowerCase();
  const color =
    s === 'critical' ? 'oklch(62% 0.22 18)'
      : s === 'high' ? 'oklch(72% 0.18 28)'
      : s === 'medium' ? 'oklch(78% 0.15 70)'
      : s === 'low' ? 'oklch(82% 0.10 220)'
      : 'oklch(72% 0.04 250)';
  return <span className="w-[5px] h-[5px] rounded-full shrink-0" style={{ background: color }} />;
}

// Recent activity card — top 10 most-recent /api/search hits matching the
// entity over the last 7 days. Each row is timestamp + action + severity dot,
// 24px tall to match the density cookbook.
function RecentActivityCard({ view }: { view: MatchView }) {
  const { events, loading } = useEntityRecentActivity(view.entity);
  return (
    <div className="rounded-md border border-border/70 overflow-hidden bg-card">
      <div className="px-2.5 py-1.5 border-b border-border/60 flex items-center gap-2">
        <span className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
          Recent activity for this entity
        </span>
        {events.length > 0 && (
          <span className="ml-auto font-mono text-[10px] text-muted-foreground">
            top {events.length} · 7d
          </span>
        )}
      </div>
      {loading && events.length === 0 ? (
        <div className="p-2 text-[10.5px] text-muted-foreground/70 leading-[1.5]">
          Loading recent activity…
        </div>
      ) : events.length === 0 ? (
        <div className="p-2 text-[10.5px] text-muted-foreground leading-[1.5]">
          No other matches for this entity in the last 7 days.
        </div>
      ) : (
        <ul className="p-1 flex flex-col">
          {events.map((e, i) => {
            const t = extractEventTime(e);
            const action = extractAction(e) || (typeof e['source_type'] === 'string' ? (e['source_type'] as string) : 'event');
            const sev = typeof e['severity'] === 'string' ? (e['severity'] as string) : undefined;
            const id = typeof e['id'] === 'string' ? (e['id'] as string) : `re_${i}`;
            return (
              <li
                key={id}
                className="h-6 flex items-center gap-2 px-1.5 rounded hover:bg-foreground/5"
                title={t ? `${t.toISOString().replace('T', ' ').slice(0, 19)} UTC` : undefined}
              >
                <SeverityDot severity={sev} />
                <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums shrink-0 w-[56px]">
                  {t ? relTime(t) : '—'}
                </span>
                <span className="font-mono text-[11px] text-foreground truncate">{action}</span>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function Chip({
  tone = 'neutral',
  children,
  icon,
}: {
  tone?: 'neutral' | 'warn' | 'bad' | 'good' | 'brand';
  children: React.ReactNode;
  icon?: React.ReactNode;
}) {
  const tones: Record<string, { bg: string; fg: string }> = {
    neutral: { bg: 'color-mix(in srgb, var(--foreground) 7%, transparent)', fg: 'var(--foreground)' },
    warn: { bg: 'color-mix(in srgb, var(--warning) 15%, transparent)', fg: 'var(--warning)' },
    bad: { bg: 'color-mix(in srgb, var(--destructive) 15%, transparent)', fg: 'var(--destructive)' },
    good: { bg: 'color-mix(in srgb, var(--success) 15%, transparent)', fg: 'var(--success)' },
    brand: { bg: 'color-mix(in srgb, var(--primary) 14%, transparent)', fg: 'var(--primary)' },
  };
  const t = tones[tone];
  return (
    <span
      className="inline-flex items-center gap-1 h-[18px] px-1.5 rounded-sm font-mono text-[10px] font-medium"
      style={{ background: t.bg, color: t.fg }}
    >
      {icon}
      {children}
    </span>
  );
}

// NAN-814 — above this many distinct source IPs we swap the swim-lane viz for
// a temporal histogram + top-N leaderboard. At one row per IP a 859-event
// match produced a ~12,000px scrolling wall of dots.
const SWIMLANE_MAX_IPS = 12;

function EventTimeline({
  view,
  onEventHover,
  hoveredEventId,
}: {
  view: MatchView;
  onEventHover: (id: string | null) => void;
  hoveredEventId: string | null;
}) {
  const first = view.firstSeen.getTime();
  const last = view.lastSeen.getTime();
  const range = Math.max(last - first, 1000);

  // Lanes track the rule's grouping entity (host / user / ip), not just a
  // source IP — so OCSF host/user-grouped matches render a meaningful lane
  // instead of a single `—`. UDM IP rules still resolve to the IP via the same
  // entity precedence (NAN-1287).
  const entityCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const e of view.events) {
      const label = eventEntityLabel(e) || '—';
      counts.set(label, (counts.get(label) || 0) + 1);
    }
    return counts;
  }, [view.events]);

  const noun = entityNoun(view.entity.type);
  const useSwimLanes = entityCounts.size <= SWIMLANE_MAX_IPS;

  return (
    <div
      className="rounded-md border border-border/70 overflow-hidden"
      style={{ background: 'color-mix(in srgb, var(--foreground) 2%, transparent)' }}
    >
      <div className="px-2.5 py-1.5 flex items-center gap-2 border-b border-border/60">
        <span className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
          Event timeline
        </span>
        <span className="font-mono text-[10px] text-muted-foreground">
          {view.events.length} events · {entityCounts.size} {noun}{entityCounts.size !== 1 ? 's' : ''}
        </span>
        <span className="ml-auto font-mono text-[10px] text-muted-foreground tabular-nums">
          {absTime(view.firstSeen)} → {absTime(view.lastSeen)}
          <span className="text-muted-foreground/60"> · </span>
          <span className="text-foreground">{(range / 60000).toFixed(1)}m</span>
        </span>
      </div>
      {useSwimLanes ? (
        <EventTimelineSwimLanes
          view={view}
          entities={Array.from(entityCounts.keys())}
          onEventHover={onEventHover}
          hoveredEventId={hoveredEventId}
        />
      ) : (
        <EventTimelineDensity view={view} entityCounts={entityCounts} noun={noun} />
      )}
    </div>
  );
}

function EventTimelineSwimLanes({
  view,
  entities,
  onEventHover,
  hoveredEventId,
}: {
  view: MatchView;
  entities: string[];
  onEventHover: (id: string | null) => void;
  hoveredEventId: string | null;
}) {
  const first = view.firstSeen.getTime();
  const last = view.lastSeen.getTime();
  const range = Math.max(last - first, 1000);
  const entityRow = (label: string | undefined) => Math.max(0, entities.indexOf(label || '—'));
  const rowH = 14;
  const chartH = entities.length * rowH + 12;

  return (
    <div className="px-3 py-2">
      <div className="relative" style={{ height: chartH + 20 }}>
        {/* Row labels — truncated to the label gutter; full value on hover. */}
        <TooltipProvider delayDuration={200}>
          <div className="absolute left-3 top-2 flex flex-col" style={{ gap: '2px' }}>
            {entities.map((label) => (
              <Tooltip key={label}>
                <TooltipTrigger asChild>
                  <div
                    className="font-mono text-[9px] text-muted-foreground/70 tabular-nums truncate cursor-default"
                    style={{ height: rowH, lineHeight: `${rowH}px`, width: 84 }}
                  >
                    {label}
                  </div>
                </TooltipTrigger>
                <TooltipContent side="right" className="font-mono text-[10px]">
                  {label}
                </TooltipContent>
              </Tooltip>
            ))}
          </div>
        </TooltipProvider>
        {/* Events */}
        <div className="absolute top-2 right-3" style={{ left: 100, height: chartH }}>
          <div
            className="absolute left-0 right-0 bottom-2 h-px"
            style={{ background: 'color-mix(in srgb, var(--foreground) 8%, transparent)' }}
          />
          {view.events.map((e, i) => {
            const t = extractEventTime(e);
            if (!t) return null;
            const x = ((t.getTime() - first) / range) * 100;
            const label = eventEntityLabel(e);
            const y = entityRow(label) * rowH + rowH / 2 - 3;
            const raw = e as Record<string, unknown>;
            const eventId = typeof raw.id === 'string' ? raw.id : `ev_${i}`;
            const hovered = hoveredEventId === eventId;
            return (
              <div
                key={eventId}
                onMouseEnter={() => onEventHover(eventId)}
                onMouseLeave={() => onEventHover(null)}
                className="absolute cursor-pointer"
                style={{
                  left: `calc(${x}% - 3px)`,
                  top: y,
                  width: 6,
                  height: 6,
                  borderRadius: 2,
                  background: hovered ? 'var(--destructive)' : 'var(--warning)',
                  outline: hovered ? '2px solid color-mix(in srgb, var(--destructive) 30%, transparent)' : 'none',
                  transition: 'outline 120ms',
                }}
                title={`${absTime(t)} · ${extractAction(e) || 'event'}`}
              />
            );
          })}
          <div className="absolute left-0 right-0 bottom-[-14px] flex justify-between font-mono text-[9px] text-muted-foreground/70 tabular-nums">
            <span>{absTime(view.firstSeen)}</span>
            <span>{absTime(new Date((first + last) / 2))}</span>
            <span>{absTime(view.lastSeen)}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function EventTimelineDensity({
  view,
  entityCounts,
  noun,
}: {
  view: MatchView;
  entityCounts: Map<string, number>;
  noun: string;
}) {
  const first = view.firstSeen.getTime();
  const last = view.lastSeen.getTime();
  const range = Math.max(last - first, 1000);

  const BIN_COUNT = 30;
  const TOP_N = 10;

  const bins = useMemo(() => {
    const buckets = new Array(BIN_COUNT).fill(0);
    const binWidth = range / BIN_COUNT;
    for (const e of view.events) {
      const t = extractEventTime(e);
      if (!t) continue;
      const idx = Math.min(BIN_COUNT - 1, Math.max(0, Math.floor((t.getTime() - first) / binWidth)));
      buckets[idx]++;
    }
    return buckets;
  }, [view.events, first, range]);

  const binMax = Math.max(...bins, 1);
  const binWidth = range / BIN_COUNT;

  const topIps = useMemo(
    () =>
      Array.from(entityCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, TOP_N),
    [entityCounts],
  );
  const tailCount = entityCounts.size - topIps.length;
  const topMax = topIps[0]?.[1] ?? 1;

  return (
    <div className="p-3 flex flex-col gap-3">
      <div>
        <div
          className="flex items-end gap-[2px]"
          style={{ height: 80, borderBottom: '1px solid color-mix(in srgb, var(--foreground) 8%, transparent)' }}
        >
          {bins.map((count, i) => {
            const h = count === 0 ? 0 : Math.max(2, (count / binMax) * 80);
            const binStart = new Date(first + i * binWidth);
            const binEnd = new Date(first + (i + 1) * binWidth);
            return (
              <div
                key={i}
                className="flex-1 min-w-0"
                style={{
                  height: h,
                  background: 'var(--warning)',
                  borderRadius: 1,
                }}
                title={`${absTime(binStart)} → ${absTime(binEnd)} · ${count} event${count !== 1 ? 's' : ''}`}
              />
            );
          })}
        </div>
        <div className="mt-1 flex justify-between font-mono text-[9px] text-muted-foreground/70 tabular-nums">
          <span>{absTime(view.firstSeen)}</span>
          <span>{absTime(new Date((first + last) / 2))}</span>
          <span>{absTime(view.lastSeen)}</span>
        </div>
      </div>

      <div className="border-t border-border/60 pt-2.5">
        <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1.5">
          Top {noun}s
        </div>
        <div className="flex flex-col gap-1">
          {topIps.map(([ip, count]) => (
            <div key={ip} className="flex items-center gap-2 text-[11px]">
              <span className="font-mono text-foreground flex-1 truncate tabular-nums">{ip}</span>
              <div
                className="w-[120px] h-[4px] rounded-full overflow-hidden"
                style={{ background: 'color-mix(in srgb, var(--foreground) 6%, transparent)' }}
              >
                <div
                  className="h-full rounded-full"
                  style={{ width: `${(count / topMax) * 100}%`, background: 'var(--warning)' }}
                />
              </div>
              <span className="font-mono text-[10.5px] text-foreground tabular-nums w-[40px] text-right">
                {count}
              </span>
            </div>
          ))}
        </div>
        {tailCount > 0 && (
          <div className="mt-1.5 font-mono text-[10px] text-muted-foreground">
            + {tailCount.toLocaleString()} more IP{tailCount !== 1 ? 's' : ''}
          </div>
        )}
      </div>
    </div>
  );
}

function ActionFrequency({ events }: { events: Record<string, unknown>[] }) {
  const counts = useMemo(() => topActions(events, 8), [events]);
  if (counts.length === 0) return null;
  const max = Math.max(...counts.map((c) => c[1]));

  return (
    <div
      className="rounded-md border border-border/70 overflow-hidden"
      style={{ background: 'color-mix(in srgb, var(--foreground) 2%, transparent)' }}
    >
      <div className="px-2.5 py-1.5 border-b border-border/60">
        <span className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
          Top attempted actions
        </span>
      </div>
      <div className="p-2.5 flex flex-col gap-1">
        {counts.map(([action, count]) => (
          <div key={action} className="flex items-center gap-2 text-[11px]">
            <span className="font-mono text-foreground flex-1 truncate">{action}</span>
            <div
              className="w-[80px] h-[4px] rounded-full overflow-hidden"
              style={{ background: 'color-mix(in srgb, var(--foreground) 6%, transparent)' }}
            >
              <div
                className="h-full rounded-full"
                style={{ width: `${(count / max) * 100}%`, background: 'var(--primary)' }}
              />
            </div>
            <span className="font-mono text-[10.5px] text-foreground tabular-nums w-[20px] text-right">
              {count}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

interface EntityContextProps {
  view: MatchView;
}

function EntityContext({ view }: EntityContextProps) {
  const { count, loading } = useEntityActivity7d(view.entity);
  // Identity lookup — only fires for user-type entities. Returns null when no
  // identity provider is linked or the username doesn't match a directory record.
  const isUser = view.entity.type === 'user';
  const identityQuery = isUser ? view.entity.raw || view.entity.label : null;
  const { data: identity, loading: identityLoading } = useIdentityUserLookup(identityQuery);

  const otherMatches = (() => {
    if (loading) return <span className="text-muted-foreground/50">—</span>;
    if (count === null) return <span className="text-muted-foreground/50">unavailable</span>;
    if (count === 0) return <span className="text-muted-foreground/70">none</span>;
    return (
      <span className="font-mono tabular-nums">
        <span className="text-foreground">{count.toLocaleString()}</span>
        <span className="text-muted-foreground"> events in last 7d</span>
      </span>
    );
  })();

  const renderIdentityField = (
    value: string | boolean | undefined,
    kind: 'text' | 'bool',
  ): React.ReactNode => {
    if (!isUser) return <span className="text-muted-foreground/50">n/a</span>;
    if (identityLoading) return <span className="text-muted-foreground/50">—</span>;
    if (!identity) return <span className="text-muted-foreground/60">no directory record</span>;
    if (kind === 'bool') {
      if (typeof value !== 'boolean') return <span className="text-muted-foreground/60">unknown</span>;
      return (
        <span className={cn('font-mono', value ? 'text-[var(--success)]' : 'text-[var(--warning)]')}>
          {value ? 'yes' : 'no'}
        </span>
      );
    }
    if (typeof value !== 'string' || !value.trim()) {
      return <span className="text-muted-foreground/60">—</span>;
    }
    return <span>{value}</span>;
  };

  const items: Array<{ label: string; value: React.ReactNode; mono?: boolean }> = [
    { label: 'Identifier', value: view.entity.raw || view.entity.label, mono: true },
    { label: 'Type', value: view.entity.type },
    { label: 'Department', value: renderIdentityField(identity?.department, 'text') },
    { label: 'Other matches (7d)', value: otherMatches },
    { label: 'MFA enabled', value: renderIdentityField(identity?.mfa_enabled, 'bool') },
    { label: 'Last activity', value: view.detectedAt.toISOString().slice(11, 19), mono: true },
  ];
  return (
    <div className="rounded-md border border-border/70 overflow-hidden bg-card">
      <div className="px-2.5 py-1.5 border-b border-border/60 flex items-center gap-2">
        <span className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
          Entity
        </span>
      </div>
      <div className="p-2 flex flex-col gap-[3px]">
        {items.map((it) => (
          <div key={it.label} className="flex items-baseline gap-2 px-1 py-[2px]">
            <span className="font-mono text-[10px] text-muted-foreground w-[130px] shrink-0">{it.label}</span>
            <span
              className={cn(
                'text-[11px] flex-1 truncate',
                it.mono ? 'font-mono text-foreground' : 'text-foreground',
              )}
            >
              {it.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// NAN-501 — Rule conditions card backed by GET /api/rules/{id}/predicates.
function RuleConditionsCard({ data }: { data: import('@/lib/api/types').RulePredicatesResponse | null }) {
  // Loading: show skeletal header with the spinner-equivalent dim text.
  if (!data) {
    return (
      <div className="rounded-lg border border-border overflow-hidden bg-card">
        <div className="px-3 py-2 flex items-center gap-2 border-b border-border">
          <Check className="w-3.5 h-3.5 text-success" strokeWidth={2} />
          <span className="font-mono text-[11px] text-foreground font-semibold">Rule conditions</span>
          <span className="ml-auto font-mono text-[10.5px] text-muted-foreground">parsing…</span>
        </div>
        <div className="p-3 text-[11px] text-muted-foreground/70">Loading predicates…</div>
      </div>
    );
  }

  // Parser failed — fall back to the raw query.
  if (!data.parsed) {
    return (
      <div className="rounded-lg border border-border overflow-hidden bg-card">
        <div className="px-3 py-2 flex items-center gap-2 border-b border-border">
          <Check className="w-3.5 h-3.5 text-success" strokeWidth={2} />
          <span className="font-mono text-[11px] text-foreground font-semibold">Rule conditions</span>
          <span className="ml-auto font-mono text-[10.5px] text-muted-foreground">parser unavailable</span>
        </div>
        <div className="p-3">
          <pre className="font-mono text-[11px] text-foreground whitespace-pre-wrap break-all">
            {data.raw_query}
          </pre>
          {data.parse_error && (
            <div className="mt-2 font-mono text-[10px] text-destructive/80">
              Parse error: {data.parse_error}
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border overflow-hidden bg-card">
      <div className="px-3 py-2 flex items-center gap-2 border-b border-border">
        <Check className="w-3.5 h-3.5 text-success" strokeWidth={2} />
        <span className="font-mono text-[11px] text-foreground font-semibold">Rule conditions</span>
        <span className="ml-auto font-mono text-[10.5px] text-muted-foreground">
          {data.predicates.length} predicate{data.predicates.length !== 1 ? 's' : ''}
          {data.pipe_stages.length > 0 && (
            <> · {data.pipe_stages.length} stage{data.pipe_stages.length !== 1 ? 's' : ''}</>
          )}
        </span>
      </div>
      {data.predicates.length === 0 ? (
        <div className="p-3 text-[11px] text-muted-foreground">
          No predicates parsed — rule may match everything before the first pipe.
        </div>
      ) : (
        <div className="px-3 py-2 flex flex-col gap-1">
          {data.predicates.map((p, i) => (
            <PredicateRow
              key={`pred-${i}-${p.field ?? ''}-${p.operator ?? ''}`}
              predicate={p}
              first={i === 0}
            />
          ))}
        </div>
      )}
      {data.pipe_stages.length > 0 && (
        <div className="px-3 py-2 border-t border-border flex items-start gap-1.5 flex-wrap">
          <span className="h-[18px] inline-flex items-center font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
            Pipeline
          </span>
          {data.pipe_stages.map((stage, i) => (
            <span
              key={`stage-${i}-${stage.command}`}
              className="inline-flex min-w-0 max-w-full items-start gap-1 min-h-[18px] px-1.5 py-[2px] rounded-sm font-mono text-[10px] leading-[14px] font-medium"
              style={{
                background: 'color-mix(in srgb, var(--primary) 12%, transparent)',
                color: 'var(--primary)',
              }}
              title={stage.args || stage.command}
            >
              <span className="shrink-0">{stage.command}</span>
              {stage.args && (
                <span className="min-w-0 whitespace-normal break-words text-foreground/70">
                  {stage.args}
                </span>
              )}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function PredicateRow({
  predicate,
  first,
}: {
  predicate: import('@/lib/api/types').Predicate;
  first: boolean;
}) {
  const { kind, field, operator, value, values, negated, connector } = predicate;
  return (
    <div className="flex items-center gap-2 text-[11px] py-[2px]">
      <span className="font-mono text-[9.5px] uppercase tracking-[0.1em] text-muted-foreground w-[36px] shrink-0 text-right">
        {first ? '' : connector || ''}
      </span>
      {negated && (
        <span className="font-mono text-[9.5px] uppercase tracking-[0.1em] text-destructive font-semibold">
          NOT
        </span>
      )}
      {field && (
        <span className="font-mono text-[11px] text-foreground">{field}</span>
      )}
      {operator && (
        <span
          className="font-mono text-[10px] font-semibold px-1.5 h-[18px] inline-flex items-center rounded-sm"
          style={{
            background: 'color-mix(in srgb, var(--foreground) 6%, transparent)',
            color: 'var(--foreground)',
          }}
        >
          {operator}
        </span>
      )}
      {value !== undefined && value !== null && (
        <span className="font-mono text-[11px] text-foreground/90 truncate" title={value}>
          {value}
        </span>
      )}
      {values && values.length > 0 && (
        <span className="font-mono text-[11px] text-foreground/90 truncate" title={values.join(', ')}>
          ({values.slice(0, 3).join(', ')}
          {values.length > 3 && <span className="text-muted-foreground"> +{values.length - 3} more</span>})
        </span>
      )}
      <span className="ml-auto font-mono text-[9.5px] uppercase tracking-[0.1em] text-muted-foreground/60">
        {kind.replace(/_/g, ' ')}
      </span>
    </div>
  );
}

export interface MatchesDetailProps {
  view: MatchView | null;
  alertGenerated: boolean;
  linkedAlertId?: string;
  linkedAlertTitle?: string;
  onOpenInSearch: (view: MatchView) => void;
  /** Detection rule id, used for parsed-predicate fetch (NAN-501). */
  ruleId?: string;
}

export function MatchesDetail({
  view,
  alertGenerated,
  linkedAlertId,
  linkedAlertTitle,
  onOpenInSearch,
  ruleId,
}: MatchesDetailProps) {
  const [hoveredEventId, setHoveredEventId] = useState<string | null>(null);
  const matchMttd = useMemo(() => (view ? meanTimeToDetect([view]) : null), [view]);
  // NAN-501 — parsed predicates for the Rule conditions card.
  const { data: predicatesData } = useRulePredicates(ruleId);
  const isReviewed = !!view?.raw.reviewed;

  if (!view) {
    return (
      <div className="py-16 px-6 flex flex-col items-center gap-2 text-center">
        <ListFilter className="w-6 h-6 text-muted-foreground/60" strokeWidth={1.5} />
        <div className="text-[12px] text-foreground font-medium">Select a match</div>
        <div className="text-[10.5px] text-muted-foreground max-w-[360px]">
          Pick a match from the list on the left to see its timeline, entity, and contributing events.
        </div>
      </div>
    );
  }

  const hasMultipleEvents = view.events.length > 1;

  return (
    <div className="bg-background">
      <div className="p-5 flex flex-col gap-3">
        {/* Detail header */}
        <div className="flex items-start gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              {alertGenerated && <Chip tone="bad">Alert generated</Chip>}
              {isReviewed && (
                <Chip tone="good" icon={<Check className="w-3 h-3" strokeWidth={2} />}>
                  Reviewed
                </Chip>
              )}
              <Chip tone="warn">{view.status || 'open'}</Chip>
              {view.region && <Chip tone="neutral">{view.region}</Chip>}
              {matchMttd && (
                <LatencyPill latency={matchMttd} label />
              )}
              <span className="font-mono text-[10.5px] text-muted-foreground">
                Detected {view.detectedAt.toISOString().replace('T', ' ').slice(0, 19)} UTC
              </span>
            </div>
            <h2 className="mt-2 text-[17px] font-semibold text-foreground tracking-[-0.01em] leading-[1.25]">
              {view.isAggregate ? (
                <>Aggregate match against <span className="font-mono text-primary">{view.entity.label}</span></>
              ) : hasMultipleEvents ? (
                <>Detection fired against <span className="font-mono text-primary">{view.entity.label}</span></>
              ) : (
                <>Single-event match: <span className="font-mono">{view.topActionName || 'Matched event'}</span></>
              )}
            </h2>
            <p className="mt-1 text-[12px] text-muted-foreground leading-[1.55]">
              {view.isAggregate ? (
                <>
                  A <span className="text-foreground font-medium">stats</span> aggregate
                  matched all rule filters
                  {view.topActionName && (
                    <> — <span className="font-mono text-foreground">{view.topActionName}</span></>
                  )}
                  .
                </>
              ) : hasMultipleEvents ? (
                <>
                  This entity generated{' '}
                  <span className="text-foreground font-medium">{view.events.length}</span> contributing
                  events across{' '}
                  <span className="text-foreground font-medium">{view.uniqueIps}</span> source IP
                  {view.uniqueIps !== 1 ? 's' : ''} over a{' '}
                  <span className="text-foreground font-medium">
                    {(view.durationMs / 60000).toFixed(1)}-minute
                  </span>{' '}
                  window.
                </>
              ) : (
                <>Single event matched all rule filters.</>
              )}
            </p>
          </div>
          <div className="flex items-center gap-1 shrink-0">
            <button
              type="button"
              onClick={() => onOpenInSearch(view)}
              className="h-7 px-2 rounded-md bg-primary text-[var(--brand-ink)] hover:bg-primary/90 text-[11px] font-medium flex items-center gap-1.5"
            >
              <Search className="w-3 h-3" strokeWidth={2} />
              Open in search
              <ArrowRight className="w-3 h-3" strokeWidth={2} />
            </button>
          </div>
        </div>

        {/* Rule conditions — parsed nPL predicates (NAN-501). */}
        <RuleConditionsCard data={predicatesData as import('@/lib/api/types').RulePredicatesResponse | null} />

        {/* Timeline */}
        {hasMultipleEvents && (
          <EventTimeline
            view={view}
            onEventHover={setHoveredEventId}
            hoveredEventId={hoveredEventId}
          />
        )}

        <div className="grid grid-cols-[1fr_320px] @max-[1100px]:grid-cols-1 gap-3">
          <div className="flex flex-col gap-3 min-w-0">
            {hasMultipleEvents && <ActionFrequency events={view.events} />}
            <EventViewer
              key={view.id}
              events={view.events}
              matchDetectedAt={view.detectedAt}
              hoveredId={hoveredEventId}
              onHover={setHoveredEventId}
            />
          </div>
          <div className="flex flex-col gap-3">
            <EntityContext view={view} />

            {/* Linked alerts / cases */}
            <div className="rounded-md border border-border/70 overflow-hidden bg-card">
              <div className="px-2.5 py-1.5 border-b border-border/60 flex items-center">
                <span className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                  Linked
                </span>
              </div>
              <div className="p-2 flex flex-col gap-1.5">
                {alertGenerated && linkedAlertId ? (
                  <div className="px-2 py-1.5 rounded border border-destructive/30 bg-destructive/[0.05]">
                    <div className="flex items-center gap-1.5 font-mono text-[10px] text-destructive font-medium">
                      <FileText className="w-3 h-3" strokeWidth={2} />
                      {linkedAlertId}
                    </div>
                    {linkedAlertTitle && (
                      <div className="text-[10.5px] text-foreground mt-0.5 truncate">{linkedAlertTitle}</div>
                    )}
                  </div>
                ) : (
                  <div className="px-2 py-2 text-[10.5px] text-muted-foreground leading-[1.5]">
                    No linked alerts or cases. This match didn't trip any alert thresholds.
                  </div>
                )}
              </div>
            </div>

            {/* Recent activity for this entity */}
            <RecentActivityCard view={view} />
          </div>
        </div>
      </div>
    </div>
  );
}
