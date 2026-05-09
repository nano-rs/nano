// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState } from 'react';
import { List, Search, Filter as FilterIcon, Copy, Check } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { CloudDossierStreamEvent } from '@/lib/api/types';

interface StreamProps {
  events: CloudDossierStreamEvent[];
  totalEvents?: number;
  /** Click a summary KV / expanded detail field → scope the base search by it.
   * Signature matches the `handleAddFilter` dossier helper (drops | cloud). */
  onPivotField?: (field: string, value: string) => void;
}

// UDM field that each stream-row or detail key should map to when the user
// clicks. Keys NOT in this map are shown as read-only.
const STREAM_FIELD_MAP: Record<string, string> = {
  user: 'user',
  account: 'cloud_account_id',
  region: 'cloud_region',
  source_ip: 'src_ip',
  sourceIP: 'src_ip',
  sourceIPAddress: 'src_ip',
  resource: 'resource_name',
  service: 'cloud_service',
  eventName: 'action',
  error_code: 'status',
  status: 'status',
  error: 'status',
  secret: 'resource_name',
  secretId: 'resource_name',
  target: 'resource_name',
  bucket: 'resource_name',
  policy: 'resource_name',
  awsRegion: 'cloud_region',
  role: 'user',
};

const CLOUD_ACCENT_KEYS = new Set([
  'user',
  'sourceIPAddress',
  'sourceIP',
  'source_ip',
  'secret',
  'secretId',
  'target',
  'bucket',
  'key',
  'resource',
  'policy',
  'role',
]);

function typeColor(t: string): string {
  switch (t) {
    case 'AUTH':
      return 'oklch(70% 0.15 50)';
    case 'READ':
      return 'oklch(66% 0.14 240)';
    case 'WRITE':
      return 'oklch(70% 0.13 170)';
    case 'PERM':
      return 'oklch(68% 0.18 28)';
    default:
      return 'oklch(65% 0.05 250)';
  }
}

function serviceAccent(service: string): string {
  switch (service) {
    case 'iam':
      return 'oklch(65% 0.19 30)';
    case 'sts':
      return 'oklch(68% 0.14 30)';
    case 'secretsmanager':
    case 'secrets':
      return 'oklch(62% 0.18 0)';
    case 's3':
      return 'oklch(66% 0.16 170)';
    case 'kms':
      return 'oklch(68% 0.13 290)';
    case 'ec2':
      return 'oklch(66% 0.13 240)';
    case 'lambda':
      return 'oklch(66% 0.15 30)';
    case 'cloudformation':
    case 'cfn':
      return 'oklch(62% 0.12 280)';
    default:
      return 'oklch(65% 0.05 250)';
  }
}

function truncateVal(v: unknown): string {
  const s = typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v ?? '');
  if (s.length > 52) return s.slice(0, 48) + '…';
  return s;
}

export function Stream({ events, totalEvents, onPivotField }: StreamProps) {
  const [selType, setSelType] = useState<string | null>(null);
  const [selService, setSelService] = useState<string | null>(null);
  const [selUser, setSelUser] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [showErrors, setShowErrors] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // Aggregate facets from the loaded events.
  const facets = useMemo(() => {
    const by = (key: keyof CloudDossierStreamEvent): [string, number][] => {
      const m = new Map<string, number>();
      for (const ev of events) {
        const v = String((ev[key] ?? '') as string);
        if (!v) continue;
        m.set(v, (m.get(v) ?? 0) + 1);
      }
      return [...m.entries()].sort((a, b) => b[1] - a[1]);
    };
    return {
      type: by('type'),
      service: by('service'),
      user: by('user'),
    };
  }, [events]);

  const filtered = useMemo(() => {
    const qq = q.trim().toLowerCase();
    return events.filter((ev) => {
      if (selType && ev.type !== selType) return false;
      if (selService && ev.service !== selService) return false;
      if (selUser && ev.user !== selUser) return false;
      if (showErrors && !ev.error_code) return false;
      if (qq) {
        const hay = JSON.stringify(ev).toLowerCase();
        if (!hay.includes(qq)) return false;
      }
      return true;
    });
  }, [events, selType, selService, selUser, q, showErrors]);

  const hasFilter = selType || selService || selUser || q || showErrors;
  const clearFilters = () => {
    setSelType(null);
    setSelService(null);
    setSelUser(null);
    setQ('');
    setShowErrors(false);
  };

  const toggleExpanded = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="bg-card border border-border rounded-lg flex flex-col">
      {/* Header */}
      <div className="px-3.5 py-2 border-b border-border flex items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold">
        <List className="w-[12px] h-[12px] text-primary" strokeWidth={1.5} />
        Cloud event stream ·{' '}
        <span className="normal-case tracking-normal text-foreground">
          {filtered.length} of {events.length} loaded
          {totalEvents && totalEvents > events.length
            ? ` · ${totalEvents.toLocaleString()} total events`
            : ''}
        </span>
        <span className="flex-1" />
        {hasFilter && (
          <button
            onClick={clearFilters}
            className="text-[10px] font-mono normal-case text-primary hover:underline"
          >
            clear filters
          </button>
        )}
      </div>

      {/* Facet row */}
      <div className="px-3 py-2 border-b border-border flex items-center gap-1.5 flex-wrap">
        <span className="text-[9.5px] font-mono uppercase tracking-[0.1em] text-muted-foreground/70 mr-1">
          facets
        </span>
        {facets.type.map(([v, c]) => (
          <FacetChip
            key={`t:${v}`}
            label="type"
            value={v.toLowerCase()}
            count={c}
            active={selType === v}
            onClick={() => setSelType(selType === v ? null : v)}
            accent={typeColor(v)}
          />
        ))}
        {facets.service.length > 0 && (
          <span className="text-muted-foreground/70 mx-1">·</span>
        )}
        {facets.service.slice(0, 6).map(([v, c]) => (
          <FacetChip
            key={`s:${v}`}
            label="svc"
            value={v}
            count={c}
            active={selService === v}
            onClick={() => setSelService(selService === v ? null : v)}
            accent={serviceAccent(v)}
          />
        ))}
        {facets.user.length > 0 && (
          <span className="text-muted-foreground/70 mx-1">·</span>
        )}
        {facets.user.slice(0, 4).map(([v, c]) => (
          <FacetChip
            key={`u:${v}`}
            label="user"
            value={v}
            count={c}
            active={selUser === v}
            onClick={() => setSelUser(selUser === v ? null : v)}
          />
        ))}
      </div>

      {/* Toolbar */}
      <div className="px-3 py-1.5 border-b border-border flex items-center gap-2">
        <div className="flex-1 flex items-center gap-2 h-7 px-2 rounded-md border border-border bg-background/50">
          <Search className="w-[13px] h-[13px] text-muted-foreground/70" strokeWidth={1.5} />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search events (user, IP, resource, action…)"
            className="flex-1 bg-transparent outline-none text-[12px] font-mono text-foreground placeholder:text-muted-foreground/70"
          />
        </div>
        <button
          onClick={() => setShowErrors((e) => !e)}
          className={cn(
            'h-7 px-2.5 rounded-md border text-[11px] font-mono transition-colors',
            showErrors
              ? 'border-[oklch(62%_0.18_28/0.4)] bg-[oklch(62%_0.18_28/0.1)] text-[oklch(72%_0.17_28)]'
              : 'border-border text-muted-foreground/90 hover:text-foreground hover:bg-foreground/[0.04]'
          )}
        >
          errors only
        </button>
      </div>

      {/* Column headers */}
      <div className="px-3 h-[22px] flex items-center gap-2 border-b border-border text-[9.5px] font-mono uppercase tracking-[0.08em] text-muted-foreground/70">
        <span className="w-[9px]" />
        <span className="w-[60px]">time</span>
        <span className="w-[68px]">type</span>
        <span className="w-[96px]">service</span>
        <span className="w-[160px]">action</span>
        <span>|</span>
        <span className="flex-1">summary</span>
      </div>

      {/* Rows */}
      <div className="max-h-[560px] overflow-auto">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 py-10">
            <FilterIcon className="w-5 h-5 text-muted-foreground/40" strokeWidth={1.5} />
            <div className="text-[12.5px] font-medium text-foreground">
              No events match your filters
            </div>
            <div className="text-[11px] font-mono text-muted-foreground/70">
              Try a broader time range or remove a filter.
            </div>
          </div>
        ) : (
          filtered.map((ev) => (
            <EventRow
              key={ev.id}
              ev={ev}
              expanded={expanded.has(ev.id)}
              onToggle={() => toggleExpanded(ev.id)}
              onPivotField={onPivotField}
            />
          ))
        )}
      </div>
    </div>
  );
}

function FacetChip({
  label,
  value,
  count,
  active,
  onClick,
  accent,
}: {
  label: string;
  value: string;
  count: number;
  active: boolean;
  onClick: () => void;
  accent?: string;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-1.5 h-6 px-2 rounded-md border text-[10.5px] font-mono transition-colors',
        active
          ? 'border-primary/40 bg-primary/10 text-primary'
          : 'border-border text-muted-foreground/90 hover:text-foreground hover:bg-foreground/[0.04]'
      )}
    >
      {accent && (
        <span className="w-1 h-2.5 rounded-sm" style={{ background: accent }} />
      )}
      <span className={active ? 'text-primary' : 'text-muted-foreground/70'}>{label}:</span>
      <span className="text-foreground truncate max-w-[140px]">{value}</span>
      <span className="tabular-nums text-muted-foreground/70">({count})</span>
    </button>
  );
}

function EventRow({
  ev,
  expanded,
  onToggle,
  onPivotField,
}: {
  ev: CloudDossierStreamEvent;
  expanded: boolean;
  onToggle: () => void;
  onPivotField?: (field: string, value: string) => void;
}) {
  const [copied, setCopied] = useState<string | null>(null);
  const rawJson = JSON.stringify(
    {
      ts: ev.ts,
      eventName: ev.event_name,
      service: ev.service,
      user: ev.user,
      account: ev.account,
      region: ev.region,
      sourceIP: ev.source_ip,
      resource: ev.resource,
      errorCode: ev.error_code,
      ...ev.detail,
    },
    null,
    2
  );
  const doCopy = (label: string, text: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    void navigator.clipboard?.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 1200);
  };
  const summaryEntries = Object.entries(ev.summary ?? {}) as [string, unknown][];

  return (
    <>
      <div
        onClick={onToggle}
        className={cn(
          'group flex items-center gap-2 px-3 h-[28px] text-[11.5px] font-mono cursor-pointer border-b border-border/40 hover:bg-foreground/[0.03]',
          expanded && 'bg-foreground/[0.04]',
          ev.error_code && 'bg-[oklch(62%_0.18_28/0.04)]'
        )}
      >
        <svg
          viewBox="0 0 10 10"
          className={cn(
            'w-[9px] h-[9px] text-muted-foreground/70 shrink-0 transition-transform',
            expanded && 'rotate-90'
          )}
          fill="currentColor"
        >
          <path d="M3 1.5l4 3.5-4 3.5z" />
        </svg>
        <span className="w-[60px] text-muted-foreground/80 tabular-nums shrink-0">
          {ev.ts}
        </span>
        <span className="w-[68px] shrink-0 inline-flex items-center gap-1 uppercase tracking-[0.06em] text-[10px]">
          <span
            className="w-1.5 h-1.5 rounded-sm"
            style={{ background: typeColor(ev.type) }}
          />
          <span className="text-muted-foreground/90">{ev.type.toLowerCase()}</span>
        </span>
        <span className="w-[96px] shrink-0 flex items-center gap-1.5 truncate">
          <span
            className="w-1 h-2.5 rounded-sm shrink-0"
            style={{ background: serviceAccent(ev.service) }}
          />
          <span className="text-muted-foreground/90 truncate">{ev.service}</span>
        </span>
        <span className="w-[160px] shrink-0 truncate text-primary">{ev.event_name}</span>
        <span className="text-muted-foreground/70 shrink-0">|</span>
        <div className="flex-1 min-w-0 flex items-center gap-x-3 overflow-hidden whitespace-nowrap">
          {summaryEntries.slice(0, 4).map(([k, v]) => {
            const udmField = STREAM_FIELD_MAP[k];
            const rawValue =
              typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v ?? '');
            const clickable = !!onPivotField && !!udmField && rawValue.length > 0;
            return (
              <span key={k} className="inline-flex items-baseline gap-1 whitespace-nowrap">
                <span className="text-muted-foreground/70">{k}=</span>
                {clickable ? (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onPivotField(udmField, rawValue);
                    }}
                    className={cn(
                      'hover:underline',
                      CLOUD_ACCENT_KEYS.has(k) ? 'text-primary' : 'text-muted-foreground/90 hover:text-primary'
                    )}
                    title={`Filter by ${udmField}=${rawValue}`}
                  >
                    {truncateVal(v)}
                  </button>
                ) : (
                  <span
                    className={cn(
                      CLOUD_ACCENT_KEYS.has(k) ? 'text-primary' : 'text-muted-foreground/90'
                    )}
                  >
                    {truncateVal(v)}
                  </span>
                )}
              </span>
            );
          })}
          {summaryEntries.length > 4 && (
            <span className="text-muted-foreground/70 text-[10.5px]">
              +{summaryEntries.length - 4} more
            </span>
          )}
        </div>
        {ev.error_code && (
          <span className="text-[10px] font-mono px-1 rounded-sm bg-[oklch(62%_0.18_28/0.15)] text-[oklch(72%_0.17_28)] shrink-0">
            {ev.error_code}
          </span>
        )}
        {ev.interesting && (
          <span className="text-[10px] font-mono px-1 rounded-sm bg-[oklch(72%_0.14_80/0.15)] text-[oklch(78%_0.14_80)] shrink-0">
            ★
          </span>
        )}
        <button
          onClick={(e) => doCopy('row', rawJson, e)}
          title="Copy event JSON"
          className={cn(
            'shrink-0 w-5 h-5 flex items-center justify-center rounded-sm transition-opacity',
            copied === 'row'
              ? 'opacity-100 text-primary'
              : 'opacity-0 group-hover:opacity-100 text-muted-foreground/70 hover:text-foreground hover:bg-foreground/[0.06]'
          )}
        >
          {copied === 'row' ? (
            <Check className="w-3 h-3" strokeWidth={1.8} />
          ) : (
            <Copy className="w-3 h-3" strokeWidth={1.4} />
          )}
        </button>
      </div>

      {expanded && (
        <div className="border-b border-border/60 bg-muted/20 px-3 py-3">
          <div className="pl-[100px] pr-4 grid grid-cols-[150px_1fr] gap-y-[3px] gap-x-4 font-mono text-[11.5px]">
            {Object.entries(ev.detail ?? {}).map(([k, v]) => {
              const isAccent = CLOUD_ACCENT_KEYS.has(k);
              const display = typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v ?? '');
              const udmField = STREAM_FIELD_MAP[k];
              const clickable = !!onPivotField && !!udmField && display.length > 0;
              return (
                <div key={k} className="contents">
                  <span className="text-muted-foreground/80 text-right">{k}:</span>
                  <span className="group/kv flex items-start gap-1.5 min-w-0">
                    {clickable ? (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onPivotField(udmField, display);
                        }}
                        className={cn(
                          'break-all flex-1 min-w-0 text-left hover:underline',
                          isAccent ? 'text-primary' : 'text-foreground hover:text-primary'
                        )}
                        title={`Filter by ${udmField}=${display}`}
                      >
                        {display}
                      </button>
                    ) : (
                      <span
                        className={cn(
                          'break-all flex-1 min-w-0',
                          isAccent ? 'text-primary' : 'text-foreground'
                        )}
                      >
                        {display}
                      </span>
                    )}
                    <button
                      onClick={(e) => doCopy(`kv:${k}`, display, e)}
                      title={`Copy ${k}`}
                      className={cn(
                        'shrink-0 w-4 h-4 flex items-center justify-center rounded-sm transition-opacity mt-[1px]',
                        copied === `kv:${k}`
                          ? 'opacity-100 text-primary'
                          : 'opacity-0 group-hover/kv:opacity-100 text-muted-foreground/70 hover:text-foreground'
                      )}
                    >
                      {copied === `kv:${k}` ? (
                        <Check className="w-[10px] h-[10px]" strokeWidth={1.8} />
                      ) : (
                        <Copy className="w-[10px] h-[10px]" strokeWidth={1.4} />
                      )}
                    </button>
                  </span>
                </div>
              );
            })}
          </div>
          <div className="pl-[100px] pt-2 mt-2 border-t border-border/40 flex gap-2 items-center">
            <button className="text-[10.5px] font-mono font-semibold text-primary hover:underline">
              Pivot to events
            </button>
            <span className="text-muted-foreground/70 text-[10px]">·</span>
            <button
              onClick={(e) => doCopy('raw', rawJson, e)}
              className="text-[10.5px] font-mono text-muted-foreground/80 hover:text-foreground"
            >
              {copied === 'raw' ? (
                <span className="text-primary">✓ JSON copied</span>
              ) : (
                'Copy JSON'
              )}
            </button>
            <span className="text-muted-foreground/70 text-[10px]">·</span>
            <button className="text-[10.5px] font-mono text-muted-foreground/80 hover:text-foreground">
              Open in | asset view
            </button>
            <span className="text-muted-foreground/70 text-[10px]">·</span>
            <button className="text-[10.5px] font-mono text-muted-foreground/80 hover:text-foreground">
              Create case
            </button>
          </div>
        </div>
      )}
    </>
  );
}
