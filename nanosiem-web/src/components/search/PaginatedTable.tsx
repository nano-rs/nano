// SPDX-License-Identifier: AGPL-3.0-or-later

import React from 'react';
import { Table as UITable, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, BookOpen, ArrowUp, ArrowDown, ArrowUpDown, Info, Copy, Check, Table, Download } from 'lucide-react';
import { IpIdentityPopover } from './IpIdentityPopover';
import { useSchemaEntityMap } from '@/hooks/useSchemaEntityMap';
import { cn, isClickHouseDefault } from '@/lib/utils';
import { isPrevalenceSentinelField, prevalenceSentinelLabel } from '@/lib/prevalence-sentinels';

/** Try to coerce a value into a numeric array for sparkline rendering.
 *  Handles: native arrays, JSON-encoded strings like "[1,2,3]", and
 *  ClickHouse Array(UInt8) which may arrive as a string. */
function tryParseSparklineArray(value: unknown): number[] | null {
  // Already a native array
  if (Array.isArray(value)) {
    if (value.length === 0) return null;
    if (value.every(v => typeof v === 'number')) return value;
    // Array of numeric strings (ClickHouse sometimes serializes this way)
    if (value.every(v => typeof v === 'string' && !isNaN(Number(v)))) {
      return value.map(Number);
    }
    return null;
  }
  // String-encoded JSON array
  if (typeof value === 'string' && value.startsWith('[')) {
    try {
      const parsed = JSON.parse(value);
      if (Array.isArray(parsed) && parsed.length > 0 && parsed.every((v: unknown) => typeof v === 'number')) {
        return parsed;
      }
    } catch { /* not valid JSON */ }
  }
  return null;
}

/** Detect if a cell value is a sparkline (array of numbers) */
function isSparklineValue(value: unknown, columnName: string): number[] | null {
  const arr = tryParseSparklineArray(value);
  if (!arr) return null;
  // Column named "sparkline" is always treated as one
  if (columnName.toLowerCase().includes('sparkline')) return arr;
  // Otherwise, only render as sparkline if 3+ points
  return arr.length >= 3 ? arr : null;
}

/** Downsample a large array into `targetBins` buckets by summing adjacent values */
function downsample(values: number[], targetBins: number): number[] {
  if (values.length <= targetBins) return values;
  const binSize = values.length / targetBins;
  const bins: number[] = [];
  for (let i = 0; i < targetBins; i++) {
    const start = Math.floor(i * binSize);
    const end = Math.floor((i + 1) * binSize);
    let sum = 0;
    for (let j = start; j < end; j++) sum += values[j];
    bins.push(sum);
  }
  return bins;
}

const MAX_BARS = 40;

const SVG_W = 140;
const SVG_H = 18;
const SVG_PAD = 1; // vertical padding so the line doesn't clip at edges

function flattenForDisplay(obj: Record<string, unknown>, prefix = ''): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      Object.assign(result, flattenForDisplay(value as Record<string, unknown>, fullKey));
    } else {
      result[fullKey] = value;
    }
  }
  return result;
}

/** Inline sparkline rendered as SVG polyline. */
function SparklineCell({ values }: { values: number[] }) {
  const pts = downsample(values, MAX_BARS);
  const max = Math.max(...pts, 1);
  const usableH = SVG_H - SVG_PAD * 2;

  // Build polyline points: evenly spaced x, y mapped from value
  const points = pts.map((v, i) => {
    const x = pts.length === 1 ? SVG_W / 2 : (i / (pts.length - 1)) * SVG_W;
    const y = SVG_PAD + usableH - (v / max) * usableH;
    return `${x},${y}`;
  }).join(' ');

  // Closed path for the fill area (line + bottom edge)
  const fillPath = pts.length > 1
    ? `M0,${SVG_PAD + usableH} ` +
      pts.map((v, i) => {
        const x = (i / (pts.length - 1)) * SVG_W;
        const y = SVG_PAD + usableH - (v / max) * usableH;
        return `L${x},${y}`;
      }).join(' ') +
      ` L${SVG_W},${SVG_PAD + usableH} Z`
    : '';

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <svg
            width={SVG_W}
            height={SVG_H}
            viewBox={`0 0 ${SVG_W} ${SVG_H}`}
            className="inline-block align-middle"
          >
            {fillPath && (
              <path d={fillPath} fill="#38bdf8" opacity={0.15} />
            )}
            <polyline
              points={points}
              fill="none"
              stroke="#38bdf8"
              strokeWidth={1.5}
              strokeLinejoin="round"
              strokeLinecap="round"
            />
          </svg>
        </TooltipTrigger>
        <TooltipContent side="top" className="text-xs">
          {values.length} buckets, peak {max}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

function CopyRowButton({ data }: { data: Record<string, unknown> }) {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = React.useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  }, [data]);

  return (
    <button
      className="opacity-0 group-hover:opacity-60 hover:!opacity-100 transition-opacity p-0.5"
      onClick={handleCopy}
      title="Copy row as JSON"
    >
      {copied
        ? <Check className="h-3.5 w-3.5 text-green-500" />
        : <Copy className="h-3.5 w-3.5 text-muted-foreground" />
      }
    </button>
  );
}

type SortDirection = 'asc' | 'desc' | null;
const MIN_COLUMN_WIDTH = 120;

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

// Field to entity type mapping for notebook. UDM fallback for the schema-aware
// resolver (useSchemaEntityMap); host normalized to this surface's `hostname`
// vocabulary so UDM output stays byte-identical (NAN-1241).
const FIELD_TO_ENTITY_TYPE: Record<string, string> = {
  src_ip: 'ip', dest_ip: 'ip', dst_ip: 'ip', source_ip: 'ip', client_ip: 'ip', server_ip: 'ip', dvc_ip: 'ip',
  dest_host: 'domain', dst_host: 'domain', url_domain: 'domain', domain: 'domain',
  src_host: 'hostname', hostname: 'hostname', dvc: 'hostname',
  user: 'user', user_name: 'user', username: 'user', src_user: 'user', dest_user: 'user',
  file_hash: 'hash', process_hash: 'hash', hash: 'hash', md5: 'hash', sha1: 'hash', sha256: 'hash',
  url: 'url', http_referrer: 'url',
};

/** Map ai_verdict + ai_confidence to left-border severity styling */
function getAiVerdictRowClass(fields: Record<string, unknown>): string {
  const verdict = typeof fields.ai_verdict === 'string' ? fields.ai_verdict.toUpperCase() : null;
  if (!verdict) return '';

  const confidence = typeof fields.ai_confidence === 'number' ? fields.ai_confidence : 0;

  // Red: confirmed bad verdicts
  if (['TP', 'MALICIOUS', 'EXFILTRATION', 'CRITICAL', 'HIGH'].includes(verdict)) {
    return confidence >= 0.7
      ? 'border-l-2 border-l-red-500 bg-red-500/5 rounded-l-sm'
      : 'border-l-2 border-l-red-400/60 rounded-l-sm';
  }

  // Amber: suspicious / needs attention
  if (['SUSPICIOUS', 'ANOMALOUS', 'MEDIUM'].includes(verdict)) {
    return confidence >= 0.7
      ? 'border-l-2 border-l-amber-500 bg-amber-500/5 rounded-l-sm'
      : 'border-l-2 border-l-amber-400/60 rounded-l-sm';
  }

  // Error states: muted warning
  if (['ERROR', 'PARSE_ERROR', 'MISMATCH_ERROR', 'INSUFFICIENT_DATA'].includes(verdict)) {
    return 'border-l-2 border-l-muted-foreground/40 rounded-l-sm';
  }

  // Benign / FP / NORMAL / SKIPPED: no highlight
  return '';
}

/** Classify a field name into a color category. The mapping is by name (or
 *  suffix) rather than value type, so `event.action` colors the same as `action`
 *  and `dest_user` colors the same as `user`. One "hero" (verb) + muted time +
 *  entity tints (ip/hash/user) + mono default. Numbers get mono default too so
 *  raw counters like bytes_out don't pretend to be hero fields. */
function getFieldColorClass(columnKey: string): string {
  const k = columnKey.toLowerCase();
  // Strip common prefixes: "event.action", "metadata.file_hash" → "action", "file_hash"
  const tail = k.split('.').pop() || k;

  // Time — always muted; the eye shouldn't anchor here.
  if (/^(_?time|timestamp|_?received|first_seen|last_seen|event_time|occurred_at)$/.test(tail)) {
    return 'text-muted-foreground/70';
  }
  // Enum verbs — the single "hero" column that anchors the scan.
  if (/^(event_type|action|verb|method|method_detail|auth_result|result|outcome)$/.test(tail)) {
    return 'text-primary';
  }
  // Entity tints — recognizable at a glance, consistent with field-stats panel.
  if (/_ip$|^ip$|ipv4|ipv6/.test(tail)) return 'text-[var(--chart-2)]';
  if (/_hash$|^hash$|^md5$|^sha1$|^sha256$|^sha512$/.test(tail)) return 'text-[var(--chart-3)]';
  if (/^user(name|_id)?$|^dest_user$|^src_user$|^principal$|^actor$/.test(tail)) return 'text-[var(--chart-4)]';
  // Default for non-classified fields — keeps the mono rhythm, avoids rainbow.
  return 'text-str';
}

interface PaginatedTableProps {
  results: SearchResult[];
  totalCount: number;
  currentPage: number;
  pageSize: number;
  onPageChange?: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
  onDrilldown?: (filters: Record<string, unknown>) => void;
  expandAll?: boolean;
  notebookActive?: boolean;
  onAddToNotebook?: (entityType: string, value: string) => void;
  /** Column order from backend (preserves user-specified order from | table command) */
  columnOrder?: string[];
  /** Optional tooltips for column headers (e.g. explaining why a field may be empty) */
  columnTooltips?: Record<string, string>;
  /** Optional download handler — renders a download icon in the header when set. */
  onDownload?: () => void;
}

const PAGE_SIZE_OPTIONS = [10, 20, 50, 100, 250];

/** Four-button pager: « ‹ › » matching the mockup density (6x6, mono). */
function PageBtn({
  disabled,
  onClick,
  label,
  title,
}: {
  disabled?: boolean;
  onClick?: () => void;
  label: React.ReactNode;
  title?: string;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      title={title}
      className={cn(
        'w-6 h-6 rounded flex items-center justify-center font-mono text-[12px] transition-colors',
        disabled
          ? 'text-muted-foreground/40 cursor-not-allowed'
          : 'text-muted-foreground hover:text-primary hover:bg-primary/10 cursor-pointer'
      )}
    >
      {label}
    </button>
  );
}

export function PaginatedTable({
  results,
  totalCount,
  currentPage,
  pageSize,
  onPageChange,
  onPageSizeChange,
  onDrilldown,
  expandAll = false,
  notebookActive,
  onAddToNotebook,
  columnOrder,
  columnTooltips,
  onDownload,
}: PaginatedTableProps) {
  // Schema-aware entity resolution (OCSF dotted columns); falls back to the UDM
  // map, normalizing the backend `host` type to this surface's `hostname`.
  const { resolveEntityType } = useSchemaEntityMap({
    fallback: FIELD_TO_ENTITY_TYPE,
    normalize: { host: 'hostname' },
  });
  const [expandedCells, setExpandedCells] = React.useState<Set<string>>(new Set());
  const [sortColumn, setSortColumn] = React.useState<string | null>(null);
  const [sortDirection, setSortDirection] = React.useState<SortDirection>(null);
  const [columnWidths, setColumnWidths] = React.useState<Record<string, number>>({});
  const headerRefs = React.useRef<Record<string, HTMLTableCellElement | null>>({});
  const suppressSortRef = React.useRef(false);

  const handleSort = (column: string) => {
    if (sortColumn === column) {
      // Cycle: asc -> desc -> null
      if (sortDirection === 'asc') {
        setSortDirection('desc');
      } else if (sortDirection === 'desc') {
        setSortColumn(null);
        setSortDirection(null);
      }
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  const toggleCell = (cellKey: string) => {
    setExpandedCells(prev => {
      const next = new Set(prev);
      if (next.has(cellKey)) {
        next.delete(cellKey);
      } else {
        next.add(cellKey);
      }
      return next;
    });
  };

  // Flatten all results to handle nested objects like _prevalence
  const flattenedResultsUnsorted = React.useMemo(() => results.map(result => ({
    ...result,
    fields: result.fields ? flattenForDisplay(result.fields) : {}
  })), [results]);

  // Sort results client-side
  const flattenedResults = React.useMemo(() => {
    if (!sortColumn || !sortDirection) {
      return flattenedResultsUnsorted;
    }

    return [...flattenedResultsUnsorted].sort((a, b) => {
      const aVal = a.fields?.[sortColumn];
      const bVal = b.fields?.[sortColumn];

      // Handle nulls/undefined - push to end
      if (aVal == null && bVal == null) return 0;
      if (aVal == null) return 1;
      if (bVal == null) return -1;

      // Numeric comparison
      if (typeof aVal === 'number' && typeof bVal === 'number') {
        return sortDirection === 'asc' ? aVal - bVal : bVal - aVal;
      }

      // String comparison (case-insensitive)
      const aStr = String(aVal).toLowerCase();
      const bStr = String(bVal).toLowerCase();
      const cmp = aStr.localeCompare(bStr);
      return sortDirection === 'asc' ? cmp : -cmp;
    });
  }, [flattenedResultsUnsorted, sortColumn, sortDirection]);

  // Determine column order:
  // - If columnOrder is provided (from | table command), use that order
  // - Otherwise, extract from data and filter empty/default columns
  const columns = React.useMemo(() => {
    // Get all unique columns from flattened results
    const allColumnsSet = new Set<string>();
    flattenedResults.forEach(result => {
      if (result.fields) {
        Object.keys(result.fields).forEach(key => allColumnsSet.add(key));
      }
    });

    if (columnOrder && columnOrder.length > 0) {
      // Use backend-specified order, but only include columns that exist in data
      return columnOrder.filter(col => allColumnsSet.has(col));
    }

    // Fallback: extract from data, filter out empty columns
    return Array.from(allColumnsSet).filter(col => {
      // Check if this column has any non-default values across all results
      return flattenedResults.some(result => {
        const value = result.fields?.[col];
        return !isClickHouseDefault(value, col);
      });
    });
  }, [columnOrder, flattenedResults]);

  React.useEffect(() => {
    setColumnWidths((prev) => {
      const next = Object.fromEntries(
        Object.entries(prev).filter(([key]) => columns.includes(key))
      );

      return Object.keys(next).length === Object.keys(prev).length ? prev : next;
    });
  }, [columns]);

  // Identify which columns are aggregation results (count, sum, avg, etc.) vs grouping fields
  // These columns cannot be used to filter raw logs since they're computed values
  const aggregateColumns = new Set(
    columns.filter(col => {
      const lowerCol = col.toLowerCase();
      // Match common aggregate function patterns and their aliases
      if (lowerCol === 'count' ||
          lowerCol === 'attempts' ||  // common alias for count
          lowerCol === 'total' ||     // common alias
          lowerCol.startsWith('count(') ||
          lowerCol.startsWith('count_') ||
          lowerCol.startsWith('sum(') ||
          lowerCol.startsWith('sum_') ||
          lowerCol.startsWith('avg(') ||
          lowerCol.startsWith('avg_') ||
          lowerCol.startsWith('min(') ||
          lowerCol.startsWith('min_') ||
          lowerCol.startsWith('max(') ||
          lowerCol.startsWith('max_') ||
          // values() aggregation - returns array of distinct values
          lowerCol.startsWith('values(') ||
          lowerCol.startsWith('values_') ||
          // earliest/latest aggregation - returns first/last value by time
          lowerCol.startsWith('earliest(') ||
          lowerCol.startsWith('earliest_') ||
          lowerCol.startsWith('latest(') ||
          lowerCol.startsWith('latest_') ||
          // first/last aliases
          lowerCol.startsWith('first_') ||
          lowerCol.startsWith('last_') ||
          // unique/distinct count variations
          lowerCol.startsWith('unique_') ||
          lowerCol.startsWith('distinct_') ||
          lowerCol.startsWith('uniq_') ||
          lowerCol.startsWith('dc_')) {
        return true;
      }

      // Detect array-valued columns as aggregates (values() returns arrays even when aliased)
      const hasArrayValue = flattenedResults.some(result =>
        result.fields && Array.isArray(result.fields[col])
      );
      if (hasArrayValue) {
        return true;
      }

      return false;
    })
  );

  // Get grouping fields (non-aggregate columns)
  const groupingFields = columns.filter(col => !aggregateColumns.has(col));

  const handleCellClick = (columnKey: string, value: unknown) => {
    if (!onDrilldown) return;

    // Only filter on the specific column that was clicked
    const filters: Record<string, unknown> = {};
    if (value !== null && value !== undefined) {
      filters[columnKey] = value;
    }

    onDrilldown(filters);
  };

  // Format cell value for display
  const formatCellValue = (value: unknown, fieldName?: string): string => {
    if (value === null || value === undefined) return '';
    // Prevalence sentinels: render "common" (9999) as a label — it's real signal
    // — and hide N/A (65535). See lib/prevalence-sentinels (NAN-1689).
    if (fieldName && isPrevalenceSentinelField(fieldName, value)) {
      return prevalenceSentinelLabel(fieldName, value) ?? '-';
    }
    if (typeof value === 'object') {
      return JSON.stringify(value);
    }
    return String(value);
  };

  // Pagination — use local result count so client-side pagination works
  // when the backend streams all rows (aggregation queries).
  const effectiveTotal = Math.max(totalCount, flattenedResults.length);
  const totalPages = Math.ceil(effectiveTotal / pageSize);
  const startRow = currentPage * pageSize + 1;
  const endRow = Math.min((currentPage + 1) * pageSize, effectiveTotal);
  const canGoPrev = currentPage > 0;
  const canGoNext = currentPage < totalPages - 1;

  // Only render the current page's rows — avoids dumping thousands of DOM nodes
  const pageRows = flattenedResults.slice(currentPage * pageSize, (currentPage + 1) * pageSize);

  const handleResizeStart = (columnKey: string, event: React.PointerEvent<HTMLSpanElement>) => {
    event.preventDefault();
    event.stopPropagation();

    const header = headerRefs.current[columnKey];
    if (!header) return;

    const startX = event.clientX;
    const startWidth = Math.max(header.getBoundingClientRect().width, MIN_COLUMN_WIDTH);
    suppressSortRef.current = false;

    const handlePointerMove = (moveEvent: PointerEvent) => {
      const delta = moveEvent.clientX - startX;
      const nextWidth = Math.max(MIN_COLUMN_WIDTH, Math.round(startWidth + delta));
      suppressSortRef.current = true;
      setColumnWidths((prev) => {
        if (prev[columnKey] === nextWidth) return prev;
        return { ...prev, [columnKey]: nextWidth };
      });
    };

    const handlePointerUp = () => {
      window.removeEventListener('pointermove', handlePointerMove);
      window.removeEventListener('pointerup', handlePointerUp);
      window.setTimeout(() => {
        suppressSortRef.current = false;
      }, 0);
    };

    window.addEventListener('pointermove', handlePointerMove);
    window.addEventListener('pointerup', handlePointerUp, { once: true });
  };

  const totalColumnWidth = columns.reduce(
    (sum, column) => sum + (columnWidths[column] ?? MIN_COLUMN_WIDTH),
    0
  );

  if (!results[0]?.fields) return null;

  return (
    <TooltipProvider>
      <div className="w-full min-w-0">
        <div className="overflow-hidden rounded-lg border border-border bg-card flex flex-col">
          <div className="py-2 px-3 border-b border-border flex items-center gap-1.5 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold">
            <span className="mr-1 inline-flex items-center gap-1.5">
              <Table className="w-[12px] h-[12px] text-primary"/>
              Table
            </span>
            <span className="flex-1"/>
            <span className="text-foreground/70 text-[11px] font-medium tracking-wide normal-case">
              {startRow.toLocaleString()}–{endRow.toLocaleString()} of {effectiveTotal.toLocaleString()}
            </span>
            {onDownload && (
              <button
                type="button"
                onClick={onDownload}
                title="Download results"
                className="ml-1 p-1 rounded text-muted-foreground hover:text-primary hover:bg-primary/10 transition-colors"
              >
                <Download className="w-[12px] h-[12px]"/>
              </button>
            )}
          </div>
          <div className="overflow-x-auto">
          <UITable
            className="min-w-full"
            style={{ minWidth: `${totalColumnWidth}px` }}
          >
            <colgroup>
              <col style={{ width: '32px' }} />
              {columns.map((key) => (
                <col
                  key={key}
                  style={{ width: `${columnWidths[key] ?? MIN_COLUMN_WIDTH}px` }}
                />
              ))}
            </colgroup>
            <TableHeader className="bg-card sticky top-0 z-[1]">
              <TableRow className="border-b border-border hover:bg-transparent">
                <TableHead className="w-8 px-1" />
                {columns.map(key => {
                  const isSorted = sortColumn === key;
                  return (
                    <TableHead
                      key={key}
                      ref={(node) => {
                        headerRefs.current[key] = node;
                      }}
                      className="group relative px-3 py-2 text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/80 cursor-pointer hover:text-foreground select-none"
                      onClick={() => {
                        if (suppressSortRef.current) return;
                        handleSort(key);
                      }}
                    >
                      <div className="flex items-center gap-1.5 pr-3">
                        <span className="truncate">{key}</span>
                        {columnTooltips?.[key] && (
                          <Tooltip>
                            <TooltipTrigger asChild onClick={(e) => e.stopPropagation()}>
                              <Info className="w-3 h-3 text-muted-foreground/50 hover:text-muted-foreground flex-shrink-0" />
                            </TooltipTrigger>
                            <TooltipContent side="bottom" className="max-w-[280px] text-xs font-normal normal-case tracking-normal">
                              {columnTooltips[key]}
                            </TooltipContent>
                          </Tooltip>
                        )}
                        <span className="flex-shrink-0">
                          {isSorted ? (
                            sortDirection === 'asc' ? (
                              <ArrowUp className="w-3 h-3 text-primary" />
                            ) : (
                              <ArrowDown className="w-3 h-3 text-primary" />
                            )
                          ) : (
                            <ArrowUpDown className="w-3 h-3 opacity-0 group-hover:opacity-40" />
                          )}
                        </span>
                      </div>
                      <span
                        role="separator"
                        aria-orientation="vertical"
                        aria-label={`Resize ${key} column`}
                        onPointerDown={(event) => handleResizeStart(key, event)}
                        onClick={(event) => event.stopPropagation()}
                        className="absolute right-0 top-0 h-full w-3 cursor-col-resize touch-none select-none"
                      >
                        <span className="absolute inset-y-2 right-1 w-px bg-border/80 transition-colors group-hover:bg-primary/50" />
                      </span>
                    </TableHead>
                  );
                })}
              </TableRow>
            </TableHeader>
            <TableBody>
              {pageRows.map((result, idx) => (
                <TableRow key={result.id} className={`group border-b border-border/50 transition-colors hover:bg-foreground/[0.03] ${idx % 2 === 0 ? '' : ''} ${result.fields ? getAiVerdictRowClass(result.fields) : ''}`}>
                  <TableCell className="px-1 py-1.5 w-8 align-top">
                    {result.fields && <CopyRowButton data={result.fields} />}
                  </TableCell>
                  {result.fields && columns.map(key => {
                    const value = result.fields[key];
                    const isAggregate = aggregateColumns.has(key);
                    // Only make string grouping fields clickable
                    const isClickable = onDrilldown && groupingFields.includes(key) && typeof value === 'string';
                    const displayValue = formatCellValue(value, key);
                    const cellKey = `${result.id}-${key}`;
                    // Character-based truncation threshold
                    const truncateAt = 80;
                    const isLongValue = displayValue.length > truncateAt;
                    // Cell is expanded if: individually toggled OR (expandAll is on AND it's a long value)
                    const isExpanded = expandedCells.has(cellKey) || (expandAll && isLongValue);
                    // Truncate display value if not expanded
                    const shownValue = isExpanded || !isLongValue
                      ? displayValue
                      : displayValue.substring(0, truncateAt);

                    // Sparkline: render inline bar chart instead of raw array
                    const sparklineData = isSparklineValue(value, key);
                    if (sparklineData) {
                      return (
                        <TableCell key={key} className="px-3 py-1.5 align-top">
                          <SparklineCell values={sparklineData} />
                        </TableCell>
                      );
                    }

                    return (
                      <TableCell
                        key={key}
                        className={`px-3 py-1.5 align-top font-mono text-[11.5px] leading-snug ${isClickable ? 'cursor-pointer hover:bg-primary/15' : ''}`}
                        onClick={isClickable ? () => handleCellClick(key, value) : undefined}
                        title={isClickable ? 'Click to see matching events' : undefined}
                      >
                        {typeof value === 'number' ? (
                          // Aggregate columns (count, sum, etc.) are the hero of a
                          // stats query — cyan with a dotted underline signals
                          // "click to drill down". Raw numeric fields (bytes_out,
                          // dest_port, …) fall through to the field-type color
                          // map, which defaults them to mono neutral.
                          <span className={isAggregate ? 'text-primary underline decoration-dotted underline-offset-2' : getFieldColorClass(key)}>
                            {Number.isInteger(value) ? value : value.toFixed(2)}
                          </span>
                        ) : (
                          <div className="flex items-start gap-1">
                            <span
                              className={`${isExpanded ? 'whitespace-pre-wrap break-all cursor-pointer' : ''} ${isClickable ? `${getFieldColorClass(key)} hover:text-primary` : getFieldColorClass(key)}`}
                              onClick={isExpanded && isLongValue ? (e) => { e.stopPropagation(); toggleCell(cellKey); } : undefined}
                            >
                              {shownValue}
                            </span>
                            {isLongValue && !isExpanded && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  toggleCell(cellKey);
                                }}
                                className="text-foreground hover:text-primary text-xs shrink-0"
                              >
                                ...
                              </button>
                            )}
                            {/* IP identity popover for IP fields */}
                            {resolveEntityType(key) === 'ip' && typeof value === 'string' && value.trim() && (
                              <IpIdentityPopover ip={value} />
                            )}
                            {/* Add to notebook button for entity fields */}
                            {(() => {
                              const cellEntityType = resolveEntityType(key);
                              return notebookActive && onAddToNotebook && cellEntityType && typeof value === 'string' && value.trim() && (
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      onAddToNotebook(cellEntityType, value);
                                    }}
                                    className="ml-1 text-amber-500 hover:text-amber-400 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity"
                                    title={`Add ${cellEntityType} to notebook`}
                                  >
                                    <BookOpen className="w-3.5 h-3.5" />
                                  </button>
                                </TooltipTrigger>
                                <TooltipContent side="top" className="bg-card border-border text-xs">
                                  <p>Add {cellEntityType} to notebook</p>
                                </TooltipContent>
                              </Tooltip>
                              );
                            })()}
                          </div>
                        )}
                      </TableCell>
                    );
                  })}
                </TableRow>
              ))}
            </TableBody>
          </UITable>
          </div>

          {/* Pagination controls — mockup: Rows select left, Page X of Y + « ‹ › » right. */}
          <div className="border-t border-border px-3 py-2 flex items-center gap-3 font-mono text-[10.5px] text-muted-foreground tracking-wide">
            {onPageSizeChange && (
              <span className="flex items-center gap-2">
                <span className="uppercase tracking-[0.12em] text-[9.5px] font-semibold">Rows</span>
                <select
                  value={pageSize}
                  onChange={(e) => onPageSizeChange(Number(e.target.value))}
                  className="bg-background border border-border rounded px-1.5 py-0.5 text-foreground text-[11px] outline-none hover:border-border/80 cursor-pointer"
                >
                  {PAGE_SIZE_OPTIONS.map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
              </span>
            )}
            <span className="flex-1"/>
            <span className="text-foreground/90 text-[11px] normal-case tracking-normal font-medium">
              Page {currentPage + 1} of {totalPages}
            </span>
            <div className="flex items-center gap-0.5">
              <PageBtn
                disabled={!canGoPrev}
                onClick={() => onPageChange?.(0)}
                label={<ChevronsLeft className="w-3.5 h-3.5" />}
                title="First page"
              />
              <PageBtn
                disabled={!canGoPrev}
                onClick={() => onPageChange?.(currentPage - 1)}
                label={<ChevronLeft className="w-3.5 h-3.5" />}
                title="Previous page"
              />
              <PageBtn
                disabled={!canGoNext}
                onClick={() => onPageChange?.(currentPage + 1)}
                label={<ChevronRight className="w-3.5 h-3.5" />}
                title="Next page"
              />
              <PageBtn
                disabled={!canGoNext}
                onClick={() => onPageChange?.(totalPages - 1)}
                label={<ChevronsRight className="w-3.5 h-3.5" />}
                title="Last page"
              />
            </div>
          </div>
        </div>

        {onDrilldown && (
          <p className="text-[10px] font-mono text-muted-foreground mt-1 px-4">Click any cell to drill down into matching events</p>
        )}
      </div>
    </TooltipProvider>
  );
}
