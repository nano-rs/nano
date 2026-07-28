// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useMemo, useRef, useState } from 'react';
import { ChevronRight, Filter, Layers, Star } from 'lucide-react';
import { cn } from '@/lib/utils';
import { fieldEntry } from '@/lib/ocsf-field-fallbacks';
import { api } from '@/lib/api';
import type {
  AssetEventsRequest,
  AssetEventsResponse,
  TimeRange,
} from '@/lib/api/types';
import { parseAsUTC } from './helpers';
import { isPrevalenceSentinelField } from '@/lib/prevalence-sentinels';

const TYPE_COLORS: Record<string, { fg: string; bg: string }> = {
  NETWORK: { fg: 'oklch(72% 0.16 160)', bg: 'oklch(72% 0.16 160 / 0.12)' },
  PROCESS: { fg: 'oklch(72% 0.14 250)', bg: 'oklch(72% 0.14 250 / 0.12)' },
  AUTH_SUCCESS: { fg: 'oklch(72% 0.11 210)', bg: 'oklch(72% 0.11 210 / 0.12)' },
  AUTH_FAILURE: { fg: 'oklch(62% 0.18 28)', bg: 'oklch(62% 0.18 28 / 0.12)' },
  FILE: { fg: 'oklch(74% 0.12 55)', bg: 'oklch(74% 0.12 55 / 0.12)' },
  REGISTRY: { fg: 'oklch(68% 0.05 260)', bg: 'oklch(68% 0.05 260 / 0.12)' },
  DNS: { fg: 'oklch(72% 0.12 180)', bg: 'oklch(72% 0.12 180 / 0.12)' },
  IMAGE_LOAD: { fg: 'oklch(68% 0.14 295)', bg: 'oklch(68% 0.14 295 / 0.12)' },
  EVENT: { fg: 'var(--muted-foreground)', bg: 'oklch(70% 0.01 260 / 0.12)' },
};

interface AssetStreamProps {
  identifierField: string;
  identifierValue: string;
  identities: Record<string, unknown>[];
  timeRange: TimeRange | undefined;
}

interface StreamEvent {
  id: string;
  timestamp: string;
  source_type: string;
  event_kind: string;
  user?: string;
  summary: Record<string, unknown>;
  details: Record<string, unknown>;
}

const PAGE_SIZE = 50;

export function AssetStream({
  identifierField,
  identifierValue,
  identities,
  timeRange,
}: AssetStreamProps) {
  const [data, setData] = useState<AssetEventsResponse | null>(null);
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [activeTypes, setActiveTypes] = useState<Set<string>>(new Set());
  const [activeSources, setActiveSources] = useState<Set<string>>(new Set());
  const [activeUsers, setActiveUsers] = useState<Set<string>>(new Set());
  const [interestingOnly, setInterestingOnly] = useState(false);
  const [groupRepeats, setGroupRepeats] = useState(false);
  const [filter, setFilter] = useState('');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const reqRef = useRef(0);

  // Initial fetch. Deps are intentionally granular: keying on the full
  // `timeRange` object would re-fire on every parent render that allocates a
  // new {start, end} reference (see NAN-1054 — Search.tsx had this exact bug),
  // wiping the event list each pass. We also leave `events`/`data` in place
  // while a new request is in flight so the panel doesn't blink between
  // identifier switches — the reqRef guard discards stale responses.
  useEffect(() => {
    if (!timeRange) return;
    const myReq = ++reqRef.current;
    setLoading(true);

    const req: AssetEventsRequest = {
      identifier_field: identifierField,
      identifier_value: identifierValue,
      identities,
      time_range: timeRange,
      offset: 0,
      limit: PAGE_SIZE,
    };
    api
      .getAssetEvents(req)
      .then((resp) => {
        if (myReq !== reqRef.current) return;
        setData(resp);
        setEvents(resp.events.map(normalizeEvent));
      })
      .catch(() => {
        if (myReq !== reqRef.current) return;
      })
      .finally(() => {
        if (myReq !== reqRef.current) return;
        setLoading(false);
      });
  }, [identifierField, identifierValue, identities, timeRange?.start, timeRange?.end]);

  const loadMore = async () => {
    if (!data || !data.has_more || !timeRange || loadingMore) return;
    setLoadingMore(true);
    try {
      const req: AssetEventsRequest = {
        identifier_field: identifierField,
        identifier_value: identifierValue,
        identities,
        time_range: timeRange,
        offset: events.length,
        limit: PAGE_SIZE,
      };
      const resp = await api.getAssetEvents(req);
      setEvents((prev) => [...prev, ...resp.events.map(normalizeEvent)]);
      setData(resp);
    } finally {
      setLoadingMore(false);
    }
  };

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return events.filter((e) => {
      if (activeTypes.size > 0 && !activeTypes.has(e.event_kind)) return false;
      if (activeSources.size > 0 && !activeSources.has(e.source_type)) return false;
      if (activeUsers.size > 0 && e.user && !activeUsers.has(e.user)) return false;
      if (interestingOnly && e.event_kind !== 'AUTH_FAILURE' && e.event_kind !== 'PROCESS') {
        // crude proxy for "interesting" — backend doesn't flag them today
        return false;
      }
      if (q) {
        const haystack = JSON.stringify(e).toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [events, activeTypes, activeSources, activeUsers, interestingOnly, filter]);

  const typeCounts = useMemo(() => countBy(events, (e) => e.event_kind), [events]);
  const sourceCounts = useMemo(() => countBy(events, (e) => e.source_type), [events]);
  const userCounts = useMemo(
    () => countBy(events.filter((e) => e.user), (e) => e.user ?? ''),
    [events]
  );

  const toggle = (set: Set<string>, setSet: (s: Set<string>) => void, val: string) => {
    const next = new Set(set);
    if (next.has(val)) next.delete(val);
    else next.add(val);
    setSet(next);
  };

  const toggleExpanded = (id: string) => {
    const next = new Set(expanded);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setExpanded(next);
  };

  const totalAvailable = data?.total_count ?? events.length;

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="px-4 py-2.5 border-b border-border flex items-center gap-2 flex-wrap">
        <Layers className="w-[13px] h-[13px] text-muted-foreground/70" />
        <span className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-foreground font-semibold">
          Asset stream
        </span>
        <span className="text-[10.5px] font-mono text-muted-foreground/70">
          ({events.length} of {totalAvailable} loaded)
        </span>
        <span className="flex-1" />
        <button
          onClick={() => setInterestingOnly((v) => !v)}
          className={cn(
            'inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10px] font-mono transition-colors',
            interestingOnly
              ? 'border-primary/40 bg-primary/10 text-primary'
              : 'border-border text-muted-foreground hover:text-foreground hover:bg-foreground/5'
          )}
        >
          <Star className="w-[10px] h-[10px]" />
          Interesting
        </button>
        <button
          onClick={() => setGroupRepeats((v) => !v)}
          className={cn(
            'inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10px] font-mono transition-colors',
            groupRepeats
              ? 'border-primary/40 bg-primary/10 text-primary'
              : 'border-border text-muted-foreground hover:text-foreground hover:bg-foreground/5'
          )}
        >
          <Layers className="w-[10px] h-[10px]" />
          Group
        </button>
      </div>

      <div className="px-4 py-3 border-b border-border space-y-2">
        <ChipRow label="TYPE">
          {[...typeCounts.entries()].map(([t, c]) => (
            <TypeChip
              key={t}
              label={t}
              count={c}
              active={activeTypes.size === 0 || activeTypes.has(t)}
              onClick={() => toggle(activeTypes, setActiveTypes, t)}
            />
          ))}
        </ChipRow>
        {sourceCounts.size > 0 && (
          <ChipRow label="SOURCE">
            {[...sourceCounts.entries()].map(([s, c]) => (
              <SimpleChip
                key={s}
                label={s}
                count={c}
                active={activeSources.size === 0 || activeSources.has(s)}
                onClick={() => toggle(activeSources, setActiveSources, s)}
              />
            ))}
          </ChipRow>
        )}
        {userCounts.size > 0 && (
          <ChipRow label="USER">
            {[...userCounts.entries()].slice(0, 12).map(([u, c]) => (
              <SimpleChip
                key={u}
                label={u}
                count={c}
                active={activeUsers.size === 0 || activeUsers.has(u)}
                onClick={() => toggle(activeUsers, setActiveUsers, u)}
              />
            ))}
          </ChipRow>
        )}
        <div className="relative">
          <Filter className="w-3 h-3 absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground/70" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter loaded events…"
            className="w-full h-7 pl-7 pr-3 text-[11.5px] font-mono bg-muted/40 border border-border rounded-md placeholder:text-muted-foreground/60 focus:outline-none focus:border-primary/40 focus:bg-card"
          />
        </div>
      </div>

      {loading ? (
        <div className="px-4 py-8 text-center text-[11.5px] text-muted-foreground/70 font-mono">
          Loading events…
        </div>
      ) : filtered.length === 0 ? (
        <div className="px-4 py-8 text-center text-[11.5px] text-muted-foreground/70 font-mono">
          No events match current filters
        </div>
      ) : (
        <ul className="divide-y divide-border">
          {filtered.map((e) => (
            <li key={e.id} className="px-4 py-2">
              <button
                onClick={() => toggleExpanded(e.id)}
                className="flex items-start gap-2 w-full text-left hover:bg-foreground/3 rounded py-1 -mx-2 px-2"
              >
                <ChevronRight
                  className={cn(
                    'w-3 h-3 mt-1 text-muted-foreground/70 transition-transform shrink-0',
                    expanded.has(e.id) && 'rotate-90'
                  )}
                />
                <span className="text-[11px] font-mono tabular-nums text-muted-foreground/70 w-[70px] shrink-0 mt-0.5">
                  {formatTime(e.timestamp)}
                </span>
                <TypeBadge type={e.event_kind} />
                <span className="text-muted-foreground/70 text-[11px] font-mono shrink-0 mt-0.5">
                  |
                </span>
                <span className="text-[11.5px] font-mono text-foreground/90 truncate flex-1 mt-0.5">
                  {summarize(e)}
                </span>
              </button>
              {expanded.has(e.id) && (
                <EventDetail
                  id={e.id}
                  timestamp={e.timestamp}
                  details={e.details}
                />
              )}
            </li>
          ))}
        </ul>
      )}

      {data?.has_more && (
        <div className="px-4 py-3 border-t border-border">
          <button
            onClick={loadMore}
            disabled={loadingMore}
            className="text-[11.5px] font-mono text-primary hover:text-primary/80 disabled:opacity-50"
          >
            {loadingMore ? 'Loading…' : `Load ${PAGE_SIZE} more →`}
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ChipRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2">
      <span className="text-[10px] font-mono uppercase tracking-[0.08em] text-muted-foreground/70 w-[54px] pt-1 shrink-0">
        {label}
      </span>
      <div className="flex flex-wrap gap-1 flex-1">{children}</div>
    </div>
  );
}

function TypeBadge({ type }: { type: string }) {
  const tone = TYPE_COLORS[type] ?? TYPE_COLORS.EVENT;
  return (
    <span
      className="inline-flex items-center gap-1 rounded-sm px-1.5 h-[18px] text-[10.5px] font-mono font-semibold tracking-[0.04em] whitespace-nowrap shrink-0 mt-0.5"
      style={{ background: tone.bg, color: tone.fg }}
    >
      {type}
    </span>
  );
}

function TypeChip({
  label,
  count,
  active,
  onClick,
}: {
  label: string;
  count: number;
  active: boolean;
  onClick: () => void;
}) {
  const tone = TYPE_COLORS[label] ?? TYPE_COLORS.EVENT;
  return (
    <button
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-1 rounded-sm px-2 h-[22px] text-[11px] font-mono font-semibold transition-all whitespace-nowrap border',
        active
          ? 'border-transparent'
          : 'border-border bg-transparent text-muted-foreground hover:text-foreground hover:bg-foreground/5 line-through decoration-muted-foreground/50'
      )}
      style={
        active
          ? {
              background: tone.bg,
              color: tone.fg,
              borderColor: `${tone.fg}33`,
            }
          : undefined
      }
    >
      {label}
      <span className={cn('opacity-70 tabular-nums', active ? '' : 'opacity-50')}>({count})</span>
    </button>
  );
}

function SimpleChip({
  label,
  count,
  active,
  onClick,
}: {
  label: string;
  count: number;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-1 rounded-sm px-2 h-[22px] text-[11px] font-mono transition-all whitespace-nowrap border',
        active
          ? 'border-border bg-foreground/5 text-foreground'
          : 'border-border bg-transparent text-muted-foreground hover:text-foreground hover:bg-foreground/5 line-through decoration-muted-foreground/50'
      )}
    >
      {label}
      <span className="opacity-70 tabular-nums">({count})</span>
    </button>
  );
}

function EventDetail({
  id,
  timestamp,
  details,
}: {
  id: string;
  timestamp: string;
  details: Record<string, unknown>;
}) {
  // Asset stream lists carry a slim ~45-column subset for payload reasons.
  // On expand we fetch the full event (~130 cols incl. ext fields like
  // threat_score, tls_intercepted, etc.) so analysts see everything that
  // exists for that record. Fetch fires once per mount; collapsing then
  // re-expanding triggers a fresh fetch (cheap, narrow time window).
  const [fullLog, setFullLog] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    // 2-second window around the event timestamp keeps the lookup pinned
    // to a single ClickHouse partition. Falls back to no-window on miss.
    // NAN-1032: pass source_type so the (source_type, timestamp, ...) PK can do a
    // tight range read — without it, S3-backed historical lookups take 12–60s.
    const ts = parseAsUTC(timestamp);
    const narrow = ts && !Number.isNaN(ts.getTime())
      ? {
          start: new Date(ts.getTime() - 1000).toISOString(),
          end: new Date(ts.getTime() + 1000).toISOString(),
        }
      : undefined;
    const sourceType = details?.source_type as string | undefined;

    (async () => {
      try {
        let resp = await api.fetchLog(id, narrow, sourceType);
        if (!resp.event && narrow) {
          // Narrow window missed — retry without time bound.
          resp = await api.fetchLog(id, undefined, sourceType);
        }
        if (cancelled) return;
        if (resp.event) setFullLog(resp.event);
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : 'Failed to load full event');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [id, timestamp, details]);

  const source = fullLog ?? details;
  const entries = Object.entries(source).filter(([k, v]) => {
    if (v === '' || v === null || v === undefined || v === 0) return false;
    // Hide prevalence sentinel values (9999 = common, 65535 = N/A). Neither is
    // meaningful in the stream. See lib/prevalence-sentinels.
    if (isPrevalenceSentinelField(k, v)) return false;
    // Hide internal/marker fields the slim payload sometimes carries.
    if (k === 'event_kind' || k === 'summary') return false;
    // NAN-1324: the OCSF full log (SELECT *) carries the entire raw source as a
    // single `event` JSON blob plus the `time_dt` timestamp alias — both OCSF-only
    // and redundant with the promoted columns already shown (the blob dwarfs the
    // row). UDM carries neither, so this is OCSF-only (UDM detail unchanged).
    if (k === 'event' || k === 'time_dt') return false;
    return true;
  });

  return (
    <div className="mt-2 ml-[100px] pl-3 border-l border-border/70 space-y-0.5">
      {loading && !fullLog && (
        <div className="text-[10.5px] font-mono text-muted-foreground/70 italic">
          Loading full event…
        </div>
      )}
      {error && (
        <div className="text-[10.5px] font-mono text-destructive/80">
          Couldn't load full event ({error}). Showing cached fields only.
        </div>
      )}
      {entries.map(([k, v]) => {
        // Match regular search results' k/v color treatment: muted key,
        // teal `text-str` value, with IOC (red) / risk (orange) overrides
        // for the same fields SearchResults flags. Keeps visual language
        // consistent across the two surfaces.
        const valueClass = k.startsWith('ioc_')
          ? 'text-red-400'
          : k === 'risk_score' || k === 'risk_entity' || k === 'risk_factors'
            ? 'text-orange-400'
            : 'text-str';
        return (
          // NAN-1324: left-align the label with a min-width (not fixed `w-[170px]
          // text-right`). OCSF dotted names range from `id` to
          // `actor.process.file.hashes.sha256` — right-aligning that spread left a
          // ragged left gutter, and long names overran the fixed box into the value.
          // Left-align + min-width keeps short labels' values aligned while letting
          // long labels take the room they need before the value.
          <div key={k} className="text-[11px] font-mono flex gap-3">
            <span className="text-muted-foreground shrink-0 whitespace-nowrap min-w-[150px]">{k}:</span>
            <span className={`${valueClass} break-all min-w-0`}>
              {typeof v === 'string' ? v : JSON.stringify(v)}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function normalizeEvent(raw: Record<string, unknown>): StreamEvent {
  const details =
    typeof raw.details === 'object' && raw.details !== null
      ? (raw.details as Record<string, unknown>)
      : raw;
  const summary =
    typeof raw.summary === 'object' && raw.summary !== null
      ? (raw.summary as Record<string, unknown>)
      : {};
  // Prefer the server-computed event_kind (asset-events now attaches it via the
  // shared classifier). Older payloads and non-asset callers fall through to
  // the local heuristic as a safety net.
  const eventKind =
    (raw.event_kind as string) ||
    (details.event_kind as string) ||
    classifyEventType(details) ||
    'EVENT';
  return {
    id: (raw.id as string) ?? `event-${Math.random().toString(36).slice(2, 10)}`,
    timestamp: (raw.timestamp as string) ?? (details.timestamp as string) ?? '',
    source_type:
      (raw.source_type as string) ?? (details.source_type as string) ?? 'unknown',
    event_kind: eventKind,
    // The user that drives the USER facet/filter. UDM keys this `user`; OCSF
    // keys the row by its native column (`user.name`, or `actor.user.name` on
    // actor-class events), so check those too (NAN-1303 — asset stream is
    // native-OCSF under OCSF).
    user:
      ((details.user ??
        details['user.name'] ??
        details['actor.user.name']) as string) || undefined,
    summary,
    details,
  };
}

/**
 * Fallback event-type classifier.
 *
 * The server-side classifier in `search::classification::EVENT_KIND_SQL` is the
 * source of truth and is attached to asset-events responses as `event_kind`.
 * This function only runs when that column is absent — e.g. legacy payloads or
 * manual callers. Keep the predicate shape aligned with the server rules.
 */
function classifyEventType(fields: Record<string, unknown>): string {
  const sourceType = String(fields.source_type ?? '').toLowerCase();
  const eventType = String(fields.event_type ?? '').toLowerCase();
  const authResult = String(fields.auth_result ?? '').toLowerCase();
  const fileAction = String(fields.file_action ?? '').toLowerCase();
  const category = String(fields.category ?? '').toLowerCase();
  const processName = String(fields.process_name ?? '').toLowerCase();
  const query = String(fields.query ?? '');
  const srcPort = Number(fields.src_port ?? 0);
  const destPort = Number(fields.dest_port ?? 0);
  const destIp = String(fields.dest_ip ?? '');

  if (sourceType === 'signal' || sourceType.includes('alert')) return 'ALERT';

  if (
    sourceType.includes('dhcp') ||
    eventType.includes('dhcp') ||
    eventType === 'network_info' ||
    eventType === 'networkinfo' ||
    eventType.includes('network_adapter')
  ) {
    return 'DHCP';
  }

  if (
    (sourceType.includes('dns') || query || srcPort === 53 || destPort === 53) &&
    !sourceType.includes('dhcp')
  ) {
    return 'DNS';
  }

  const isAuthCategory =
    category === 'authentication' ||
    category === 'authorization' ||
    category === 'account_management' ||
    category === 'credential_access';
  if (
    authResult ||
    sourceType.includes('auth') ||
    eventType.includes('login') ||
    eventType.includes('logon') ||
    isAuthCategory
  ) {
    if (authResult.includes('fail') || eventType.includes('fail')) return 'AUTH_FAILURE';
    return 'AUTH_SUCCESS';
  }

  if (eventType === 'image_load' || eventType === 'imageload') return 'IMAGE_LOAD';
  if (eventType.includes('registry') || category === 'registry') return 'REGISTRY';
  if (eventType.includes('pipe') || category === 'pipe') return 'PIPE';

  if (
    eventType.includes('connection') ||
    sourceType.includes('firewall') ||
    sourceType.includes('proxy') ||
    category === 'network' ||
    category === 'firewall'
  ) {
    return 'NETWORK';
  }

  if (processName || eventType.includes('process') || eventType.includes('exec')) return 'PROCESS';
  if (fileAction || eventType.includes('file') || category === 'file_access' || category === 'object_access') return 'FILE';
  if (destIp) return 'NETWORK';
  return 'EVENT';
}

function summarize(e: StreamEvent): string {
  const s = e.summary;
  const parts: string[] = [];
  for (const [k, v] of Object.entries(s)) {
    if (v === '' || v === null || v === undefined) continue;
    parts.push(`${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`);
    if (parts.length >= 4) break;
  }
  if (parts.length) return parts.join(' ');
  // Fallback to a few key details fields. NAN-1324/1326: under OCSF the row is keyed
  // by native columns (`process.name`, `dst_endpoint.hostname`, …). `fieldEntry`
  // resolves each concept to the ACTUAL key it lives under + value, so the summary
  // shows the schema-NATIVE name (`process.name=…` under OCSF, `process_name=…` under
  // UDM — byte-identical) and stays consistent with the native-keyed detail. It also
  // treats `"-"` as empty, so a Sysmon `dst_endpoint.hostname = "-"` falls through to
  // the IP instead of rendering `dest_host=-`. The key list + order are unchanged.
  // `event_kind`/`message` are operational columns present verbatim in both schemas.
  const d = e.details;
  const keys = [
    'dest_host',
    'dest_ip',
    'process_name',
    'command_line',
    'file_path',
    'query',
    'event_kind',
    'message',
  ];
  for (const k of keys) {
    if (k === 'event_kind' || k === 'message') {
      const v = d[k];
      if (v !== null && v !== undefined && v !== '') {
        return `${k}=${String(v).slice(0, 120)}`;
      }
      continue;
    }
    const entry = fieldEntry(d, k);
    if (entry) {
      return `${entry.key}=${String(entry.value).slice(0, 120)}`;
    }
  }
  return '';
}

function countBy<T>(arr: T[], key: (t: T) => string): Map<string, number> {
  const out = new Map<string, number>();
  for (const item of arr) {
    const k = key(item);
    if (!k) continue;
    out.set(k, (out.get(k) ?? 0) + 1);
  }
  return new Map([...out.entries()].sort((a, b) => b[1] - a[1]));
}

function formatTime(iso: string): string {
  const d = parseAsUTC(iso);
  if (!d) return iso;
  return d.toISOString().slice(11, 19);
}
