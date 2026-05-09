// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect, useMemo } from 'react';
import { Badge } from '@/components/ui/badge';
import { ChevronDown, ChevronRight, Clock, AlertTriangle, Copy, Hash, Bell } from 'lucide-react';
import { PaginatedTable } from '@/components/search/PaginatedTable';
import { TimechartView } from '@/components/search/TimechartView';
import { RankedBarChart } from '@/components/search/RankedBarChart';
import { formatUTCShort, parseUTCTimestamp } from '@/lib/date-utils';
import { isClickHouseDefault, cn } from '@/lib/utils';
import { toast } from 'sonner';
import type { SearchResponse, DisplayType } from '@/lib/api/types';

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

interface DetectionTestResultsProps {
  response: SearchResponse | null;
  isSearching: boolean;
  hasSearched: boolean;
  alertMode?: 'grouped' | 'per_event';
  /** Lookback window in minutes — used to bucket grouped results into alert groups */
  lookbackMinutes?: number | null;
}

function normalizeResults(raw: Record<string, unknown>[]): SearchResult[] {
  return raw.map((r, i) => ({
    id: String(r.id || r._id || i),
    timestamp: r.timestamp ? new Date(String(r.timestamp)) : new Date(),
    source: String(r.source_type || r.source || ''),
    fields: r,
  }));
}

function flattenFields(fields: Record<string, unknown>, prefix = ''): [string, unknown][] {
  const result: [string, unknown][] = [];
  for (const [key, value] of Object.entries(fields)) {
    const fullKey = prefix ? `${prefix}_${key}` : key;
    if (key.startsWith('prevalence_') && (value === 255 || value === 65535 || value === 9999)) continue;
    if (key === 'risk_score' && (value === 0 || value === '0')) continue;
    if (isClickHouseDefault(value, fullKey)) continue;
    if (key === 'metadata' && typeof value === 'object' && value !== null && !Array.isArray(value)) {
      result.push(...flattenFields(value as Record<string, unknown>, 'metadata'));
    } else {
      result.push([fullKey, value]);
    }
  }
  return result;
}

// ============================================================================
// Time-bucketed grouping for grouped alert_mode
// ============================================================================

interface AlertBucket {
  /** Start of this bucket window */
  windowStart: Date;
  /** End of this bucket window */
  windowEnd: Date;
  /** Events that fall in this window */
  events: SearchResult[];
}

/**
 * Bucket results into time windows matching the rule's lookback period.
 * Each bucket represents one alert that would be generated in grouped mode.
 */
function bucketByLookback(results: SearchResult[], lookbackMinutes: number): AlertBucket[] {
  if (results.length === 0) return [];

  // Sort events by timestamp ascending
  const sorted = [...results].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

  const windowMs = lookbackMinutes * 60 * 1000;

  // Align to clock boundaries (e.g. 5m windows start at :00, :05, :10...)
  // This matches how the cron scheduler fires in production
  const bucketMap = new Map<number, AlertBucket>();

  for (const event of sorted) {
    const ts = event.timestamp.getTime();
    const windowStart = Math.floor(ts / windowMs) * windowMs;

    if (!bucketMap.has(windowStart)) {
      bucketMap.set(windowStart, {
        windowStart: new Date(windowStart),
        windowEnd: new Date(windowStart + windowMs),
        events: [],
      });
    }
    bucketMap.get(windowStart)!.events.push(event);
  }

  // Return sorted by window start descending (most recent first)
  return Array.from(bucketMap.values()).sort(
    (a, b) => b.windowStart.getTime() - a.windowStart.getTime()
  );
}

function formatWindowRange(start: Date, end: Date): string {
  const fmt = (d: Date) => formatUTCShort(d);
  return `${fmt(start)} — ${fmt(end)}`;
}

// Entity fields to scan for dominant entity surfacing (ordered by priority)
const ENTITY_FIELDS = [
  'src_ip', 'dest_ip', 'user', 'src_user', 'dest_user',
  'src_host', 'dest_host', 'host', 'hostname',
  'process_name', 'file_hash', 'process_hash',
];

interface DominantEntity {
  field: string;
  value: string;
  /** How many distinct other entity values exist in the bucket */
  othersCount: number;
}

function getDominantEntity(events: SearchResult[]): DominantEntity | null {
  // For each entity field, count occurrences of each value
  for (const field of ENTITY_FIELDS) {
    const valueCounts = new Map<string, number>();
    for (const event of events) {
      const val = event.fields[field];
      if (val && typeof val === 'string' && val.trim() !== '') {
        valueCounts.set(val, (valueCounts.get(val) || 0) + 1);
      }
    }
    if (valueCounts.size > 0) {
      // Pick the most frequent value
      let topValue = '';
      let topCount = 0;
      for (const [val, count] of valueCounts) {
        if (count > topCount) {
          topValue = val;
          topCount = count;
        }
      }
      return {
        field,
        value: topValue,
        othersCount: valueCounts.size - 1,
      };
    }
  }
  return null;
}

// ============================================================================
// Event row (shared between flat and grouped views)
// ============================================================================

function EventRow({ event, index }: { event: SearchResult; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const fields = flattenFields(event.fields);
  const timestamp = event.fields.timestamp
    ? formatUTCShort(parseUTCTimestamp(String(event.fields.timestamp)))
    : null;

  const inlineFields = fields
    .filter(([k]) => !['timestamp', 'id', '_id'].includes(k))
    .slice(0, 8);

  return (
    <div className="border-b border-border/50 last:border-b-0">
      <div
        className="flex items-start gap-1.5 px-3 py-1.5 text-xs font-mono hover:bg-muted/50 cursor-pointer transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        {expanded
          ? <ChevronDown className="w-3 h-3 mt-0.5 text-muted-foreground flex-shrink-0" />
          : <ChevronRight className="w-3 h-3 mt-0.5 text-muted-foreground flex-shrink-0" />
        }
        <span className="text-muted-foreground/60 w-6 text-right flex-shrink-0">{index + 1}</span>
        {timestamp && (
          <span className="text-muted-foreground flex-shrink-0">{timestamp}</span>
        )}
        <div className="flex flex-wrap gap-x-2 gap-y-0.5 min-w-0">
          {inlineFields.map(([key, value]) => {
            const displayValue = typeof value === 'string' ? value : String(value ?? '');
            return (
              <span key={key} className="inline-flex items-center">
                <span className="text-muted-foreground">{key}=</span>
                <span className="text-primary truncate max-w-[200px]">{displayValue}</span>
              </span>
            );
          })}
        </div>
      </div>

      {expanded && (
        <div className="pl-10 pr-3 pb-2 space-y-0.5">
          {fields.map(([key, value]) => {
            const displayValue = typeof value === 'string' ? value : JSON.stringify(value ?? '');
            const copyValue = `${key}=${displayValue}`;
            return (
              <div
                key={key}
                className="flex items-start gap-2 text-xs font-mono hover:bg-accent/50 rounded px-1 py-0.5 cursor-pointer transition-colors group"
                onClick={() => {
                  navigator.clipboard.writeText(copyValue);
                  toast.success('Copied', {
                    description: copyValue.length > 60 ? copyValue.slice(0, 60) + '...' : copyValue,
                    duration: 1500,
                  });
                }}
                title={`Click to copy: ${copyValue}`}
              >
                <span className="text-muted-foreground min-w-[140px] flex-shrink-0 text-right">{key}</span>
                <span className="text-foreground break-all">{displayValue}</span>
                <Copy className="w-3 h-3 text-muted-foreground/0 group-hover:text-muted-foreground flex-shrink-0 mt-0.5 transition-colors" />
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Alert bucket row (grouped mode)
// ============================================================================

function AlertBucketRow({ bucket }: { bucket: AlertBucket }) {
  const [expanded, setExpanded] = useState(false);
  const entity = getDominantEntity(bucket.events);

  return (
    <div className="border-b border-border/30">
      <div
        className={cn(
          'flex items-center gap-2 px-3 py-2 text-xs cursor-pointer transition-colors',
          expanded ? 'bg-accent/40' : 'hover:bg-muted/50'
        )}
        onClick={() => setExpanded(!expanded)}
      >
        {expanded
          ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
          : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
        }
        <span className="text-muted-foreground font-mono text-[11px] flex-shrink-0">
          {formatWindowRange(bucket.windowStart, bucket.windowEnd)}
        </span>
        {entity && (
          <span className="font-mono text-[11px] truncate min-w-0">
            <span className="text-muted-foreground">{entity.field}=</span>
            <span className="text-primary">{entity.value}</span>
            {entity.othersCount > 0 && (
              <span className="text-muted-foreground/60"> (+{entity.othersCount} other{entity.othersCount !== 1 ? 's' : ''})</span>
            )}
          </span>
        )}
        <Badge variant="outline" className="text-[10px] ml-auto border-border/50 tabular-nums flex-shrink-0">
          {bucket.events.length} event{bucket.events.length !== 1 ? 's' : ''}
        </Badge>
      </div>

      {expanded && (
        <div className="border-t border-border/30 bg-muted/10">
          {bucket.events.map((event, i) => (
            <EventRow key={event.id} event={event} index={i} />
          ))}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Main component
// ============================================================================

export function DetectionTestResults({ response, isSearching, hasSearched, alertMode, lookbackMinutes }: DetectionTestResultsProps) {
  const [currentPage, setCurrentPage] = useState(0);
  const pageSize = 50;

  useEffect(() => {
    setCurrentPage(0);
  }, [response]);

  const results = useMemo(() => {
    if (!response?.results) return [];
    return normalizeResults(response.results);
  }, [response]);

  // Bucket results into alert groups when grouped mode + lookback is available
  const alertBuckets = useMemo(() => {
    if (alertMode !== 'grouped' || !lookbackMinutes || results.length === 0) return null;
    return bucketByLookback(results, lookbackMinutes);
  }, [results, alertMode, lookbackMinutes]);

  if (isSearching) {
    return (
      <div className="flex-1 flex items-center justify-center text-muted-foreground text-sm gap-2">
        <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        Searching...
      </div>
    );
  }

  if (!hasSearched || !response) {
    return (
      <div className="flex-1 flex items-center justify-center text-muted-foreground text-sm">
        Run a test to see matching events
      </div>
    );
  }

  const displayType: DisplayType = response.display_type || 'events';

  return (
    <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
      {/* Stats bar */}
      <div className="flex items-center gap-3 px-3 py-2 border-b border-border/50 flex-shrink-0">
        <div className="flex items-center gap-1.5">
          <Hash className="w-3.5 h-3.5 text-muted-foreground" />
          <span className="text-sm font-medium">{response.total_count.toLocaleString()}</span>
          <span className="text-xs text-muted-foreground">matches</span>
        </div>
        {alertBuckets && (
          <div className="flex items-center gap-1.5">
            <Bell className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="text-sm font-medium">{alertBuckets.length}</span>
            <span className="text-xs text-muted-foreground">alert{alertBuckets.length !== 1 ? 's' : ''}</span>
          </div>
        )}
        <div className="flex items-center gap-1.5">
          <Clock className="w-3.5 h-3.5 text-muted-foreground" />
          <span className="text-xs text-muted-foreground">{response.execution_time_ms}ms</span>
        </div>
        {response.warnings && response.warnings.length > 0 && (
          <div className="flex items-center gap-1">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            {response.warnings.map((w, i) => (
              <Badge key={i} variant="outline" className="text-[10px] text-amber-400 border-amber-500/20">
                {w.message || String(w)}
              </Badge>
            ))}
          </div>
        )}
      </div>

      {/* Results */}
      <div className="flex-1 overflow-auto min-h-0">
        {results.length === 0 ? (
          <div className="flex items-center justify-center h-32 text-muted-foreground text-sm">
            <div className="text-center">
              <AlertTriangle className="w-5 h-5 mx-auto mb-2 text-amber-400" />
              No matches found. Try expanding the time range or adjusting your query.
            </div>
          </div>
        ) : displayType === 'table' ? (
          <PaginatedTable
            results={results}
            totalCount={response.total_count}
            currentPage={currentPage}
            pageSize={pageSize}
            onPageChange={setCurrentPage}
            columnOrder={response.column_order}
          />
        ) : displayType === 'timechart' ? (
          <div className="p-3">
            <TimechartView results={results} />
          </div>
        ) : displayType === 'ranked_bar' ? (
          <div className="p-3">
            <RankedBarChart results={results} />
          </div>
        ) : alertBuckets ? (
          /* Grouped alert view — results bucketed by lookback window */
          <div>
            {alertBuckets.map((bucket) => (
              <AlertBucketRow
                key={bucket.windowStart.getTime()}
                bucket={bucket}
              />
            ))}
            {results.length < response.total_count && (
              <div className="text-center py-3 text-xs text-muted-foreground">
                Showing {results.length} of {response.total_count.toLocaleString()} events across {alertBuckets.length} alerts
              </div>
            )}
          </div>
        ) : (
          /* Default: flat events list (per_event mode or no lookback info) */
          <div>
            {results.map((event, i) => (
              <EventRow key={event.id} event={event} index={i} />
            ))}
            {results.length < response.total_count && (
              <div className="text-center py-3 text-xs text-muted-foreground">
                Showing {results.length} of {response.total_count.toLocaleString()} events
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default DetectionTestResults;
