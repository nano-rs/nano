// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-483 — expandable contributing-events viewer for the Matches detail pane.
// Ports the pagination + all-field inspection pattern from the pre-redesign
// DetectionMatches EventViewer into the new density. Field categorisation
// (metadata / prevalence / enriched / lookup / ext / UDM) matches Search.

import { useState } from 'react';
import { ChevronDown, ChevronRight, ChevronLeft } from 'lucide-react';
import { cn, isClickHouseDefault } from '@/lib/utils';
import { extractEventTime, eventLatency } from './helpers';
import { LatencyPill } from './LatencyPill';

// Preview key-fields — priority order, UDM first. Matches the set the pre-
// redesign DetectionMatches page showed in its collapsed summary row. A row
// picks the first N non-empty values from this list so it works across every
// log source without a per-source column map.
const PREVIEW_KEYS = [
  'user',
  'src_ip',
  'dest_ip',
  'src_host',
  'dest_host',
  'http_method',
  'http_status_code',
  'status_code',
  'url',
  'event_type',
  'event_id',
  'process_name',
  'file_hash',
  'file_path',
  // AWS/CloudTrail legacy — only surface if UDM fields above didn't fill up.
  'eventName',
  'sourceIPAddress',
  'source_type',
];
const PREVIEW_MAX = 5;

function flattenObject(obj: Record<string, unknown>, prefix = ''): Array<{ key: string; value: unknown }> {
  return Object.entries(obj).flatMap(([k, v]) => {
    const key = prefix ? `${prefix}.${k}` : k;
    if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
      return flattenObject(v as Record<string, unknown>, key);
    }
    return [{ key, value: v }];
  });
}

// Category numbers match the existing Search field ordering.
function fieldCategory(name: string): number {
  if (name.startsWith('metadata.') || name === 'metadata') return 0;
  if (
    name.startsWith('_prevalence.') || name === '_prevalence' ||
    name === 'host_count' || name === 'is_rare' ||
    name === 'prevalence_score' || name === 'prevalence_type' ||
    name === 'prevalence_artifact' || name === 'total_occurrences' ||
    name === 'first_seen' || name === 'last_seen'
  ) return 1;
  if (name.startsWith('enriched.') || name.startsWith('enriched_')) return 2;
  if (name.startsWith('lookup.') || name.startsWith('lookup_')) return 3;
  if (name.startsWith('ext.')) return 4;
  return 5;
}

function fieldKeyColor(name: string): string {
  const c = fieldCategory(name);
  if (c === 0) return 'text-amber-500/90 dark:text-amber-300/90';
  if (c === 1) return 'text-emerald-400/90';
  if (name === 'risk_score' || name === 'risk_entity' || name === 'risk_factors') return 'text-orange-400/90';
  if (c === 2) return 'text-purple-400/90';
  if (c === 3) return 'text-cyan-400/90';
  return 'text-muted-foreground';
}

function visibleFields(event: Record<string, unknown>): string[] {
  return flattenObject(event)
    .filter(({ key, value }) => {
      const isPrevalence = key.startsWith('_prevalence.') || key === '_prevalence' ||
        key === 'host_count' || key === 'is_rare' || key === 'prevalence_score' ||
        key === 'prevalence_type' || key === 'total_occurrences';
      return isPrevalence || !isClickHouseDefault(value, key);
    })
    .map(({ key }) => key)
    .sort((a, b) => {
      const ca = fieldCategory(a);
      const cb = fieldCategory(b);
      if (ca !== cb) return ca - cb;
      return a.localeCompare(b);
    });
}

// Inline preview values are single-line; cap serialised objects so a large
// `ext` blob can't blow out the row height. The full value is still visible
// in the Raw JSON toggle below.
const FIELD_PREVIEW_MAX = 500;

function getFieldValue(event: Record<string, unknown>, field: string): string {
  const parts = field.split('.');
  let v: unknown = event;
  for (const p of parts) {
    if (v === null || v === undefined || typeof v !== 'object') return '';
    v = (v as Record<string, unknown>)[p];
  }
  if (isClickHouseDefault(v, field)) return '';
  const s = typeof v === 'object' ? JSON.stringify(v) : String(v);
  return s.length > FIELD_PREVIEW_MAX ? `${s.slice(0, FIELD_PREVIEW_MAX)}… (${s.length} chars)` : s;
}

interface EventViewerProps {
  events: Record<string, unknown>[];
  matchDetectedAt: Date;
  hoveredId: string | null;
  onHover: (id: string | null) => void;
  pageSize?: number;
}

export function EventViewer({ events, matchDetectedAt, hoveredId, onHover, pageSize = 10 }: EventViewerProps) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [page, setPage] = useState(0);

  const totalPages = Math.max(1, Math.ceil(events.length / pageSize));
  const start = page * pageSize;
  const end = Math.min(start + pageSize, events.length);
  const slice = events.slice(start, end);

  const toggle = (localIdx: number) => {
    const actualIdx = start + localIdx;
    setExpanded((s) => {
      const n = new Set(s);
      if (n.has(actualIdx)) n.delete(actualIdx);
      else n.add(actualIdx);
      return n;
    });
  };

  return (
    <div className="rounded-md border border-border/70 overflow-hidden bg-card">
      <div className="px-2.5 py-1.5 flex items-center gap-2 border-b border-border/60">
        <span className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
          Contributing events
        </span>
        <span className="font-mono text-[10px] text-muted-foreground">
          {events.length === 0 ? '0' : `${start + 1}–${end} of ${events.length}`}
        </span>
        <div className="flex-1" />
        {totalPages > 1 && (
          <div className="flex items-center gap-1">
            <button
              type="button"
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              className="h-5 w-5 rounded border border-border text-muted-foreground hover:text-foreground hover:bg-foreground/5 flex items-center justify-center disabled:opacity-40"
            >
              <ChevronLeft className="w-3 h-3" strokeWidth={2} />
            </button>
            <span className="font-mono text-[10px] text-muted-foreground px-1 tabular-nums">
              {page + 1} / {totalPages}
            </span>
            <button
              type="button"
              disabled={page >= totalPages - 1}
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              className="h-5 w-5 rounded border border-border text-muted-foreground hover:text-foreground hover:bg-foreground/5 flex items-center justify-center disabled:opacity-40"
            >
              <ChevronRight className="w-3 h-3" strokeWidth={2} />
            </button>
          </div>
        )}
      </div>

      {events.length === 0 ? (
        <div className="px-3 py-4 text-center text-[10.5px] text-muted-foreground">No events to display.</div>
      ) : (
        <div className="divide-y divide-border/30">
          {slice.map((e, i) => {
            const actualIdx = start + i;
            const raw = e as Record<string, unknown>;
            const id = typeof raw.id === 'string' ? raw.id : `ev_${actualIdx}`;
            const t = extractEventTime(e);
            const lat = eventLatency(e, matchDetectedAt);
            const isExpanded = expanded.has(actualIdx);
            const fields = isExpanded ? visibleFields(e) : [];
            const messageField = getFieldValue(e, 'message');

            const previewPairs: Array<[string, string]> = [];
            for (const k of PREVIEW_KEYS) {
              if (previewPairs.length >= PREVIEW_MAX) break;
              const v = getFieldValue(e, k);
              if (v) previewPairs.push([k, v]);
            }

            return (
              <div key={id}>
                <button
                  type="button"
                  onMouseEnter={() => onHover(id)}
                  onMouseLeave={() => onHover(null)}
                  onClick={() => toggle(i)}
                  className={cn(
                    'w-full flex items-start gap-2 px-2.5 py-1.5 cursor-pointer transition-colors text-left',
                    hoveredId === id ? 'bg-destructive/[0.08]' : 'hover:bg-foreground/[0.03]',
                  )}
                >
                  {isExpanded
                    ? <ChevronDown className="w-3 h-3 text-muted-foreground mt-[3px] shrink-0" strokeWidth={2} />
                    : <ChevronRight className="w-3 h-3 text-muted-foreground mt-[3px] shrink-0" strokeWidth={2} />}
                  <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums w-[30px] shrink-0 pt-[2px]">
                    #{actualIdx + 1}
                  </span>
                  <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums w-[200px] shrink-0 pt-[1px]">
                    {t ? t.toISOString() : '—'}
                  </span>
                  <div className="shrink-0 pt-[1px]"><LatencyPill latency={lat} /></div>
                  <div className="flex-1 min-w-0 flex flex-col gap-0.5">
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 font-mono text-[10.5px] leading-[1.4]">
                      {previewPairs.length === 0 ? (
                        <span className="text-muted-foreground/60">no key fields</span>
                      ) : (
                        previewPairs.map(([k, v]) => (
                          <span key={k} className="inline-flex items-baseline gap-1 min-w-0">
                            <span className="text-muted-foreground/80 shrink-0">{k}:</span>
                            <span className="text-foreground truncate max-w-[260px]">{v}</span>
                          </span>
                        ))
                      )}
                    </div>
                    {messageField && (
                      <div className="font-mono text-[11px] text-foreground/90 leading-[1.45] line-clamp-2 break-all">
                        {messageField}
                      </div>
                    )}
                  </div>
                </button>

                {isExpanded && (
                  <div className="border-t border-border/40 bg-muted/[0.15] px-3 py-2.5">
                    {/* Event/detection time strip */}
                    <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[10px]">
                      <div>
                        <span className="uppercase tracking-[0.12em] text-muted-foreground">Event</span>
                        <span className="ml-1.5 text-foreground tabular-nums">
                          {t ? t.toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '—'}
                        </span>
                      </div>
                      <div>
                        <span className="uppercase tracking-[0.12em] text-muted-foreground">Detected</span>
                        <span className="ml-1.5 text-foreground tabular-nums">
                          {matchDetectedAt.toISOString().replace('T', ' ').slice(0, 19)} UTC
                        </span>
                      </div>
                      <LatencyPill latency={lat} label />
                    </div>

                    {/* Full field grid */}
                    <div className="grid grid-cols-1 @min-[720px]:grid-cols-2 gap-x-5 gap-y-1">
                      {fields.map((f) => {
                        const v = getFieldValue(e, f);
                        if (!v) return null;
                        return (
                          <div key={f} className="flex gap-2 border-b border-border/20 py-[3px]">
                            <span className={cn('min-w-[130px] shrink-0 text-[10.5px] font-mono', fieldKeyColor(f))}>
                              {f}:
                            </span>
                            <span className="text-[10.5px] font-mono text-foreground/90 break-all leading-[1.5]">
                              {v}
                            </span>
                          </div>
                        );
                      })}
                    </div>

                    {/* Raw JSON */}
                    <details className="mt-2.5">
                      <summary className="cursor-pointer text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground hover:text-foreground">
                        Raw JSON
                      </summary>
                      <pre className="mt-1.5 max-h-48 overflow-auto rounded border border-border/50 bg-foreground/[0.03] p-2 text-[10.5px] font-mono leading-[1.55] text-foreground whitespace-pre">
                        {JSON.stringify(e, null, 2)}
                      </pre>
                    </details>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
