// SPDX-License-Identifier: AGPL-3.0-or-later

import React from 'react';
import { ArrowUp, ArrowDown, ArrowUpDown, Check, ChevronRight, Copy, Download, Table as TableIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { FieldValueMenu } from './SearchResults';
import { completeColumnOrder } from './column-order';

interface SearchResultLike {
  fields?: Record<string, unknown>;
}

interface StatsViewProps {
  results: SearchResultLike[];
  query?: string;
  columnOrder?: string[];
  fieldsCollapsed?: boolean;
  fieldsCount?: number;
  onExpandFields?: () => void;
  onDownload?: () => void;
  // NAN-955 F-1: wire GROUP BY cells (`process_name`, `src_ip`, etc.) into
  // the shared FieldValueMenu so they expose the same Add to filter /
  // Exclude / Copy / Open entity page actions as raw-event chips.
  onAddToQuery?: (field: string, value: string, exclude: boolean) => void;
  onSetQuery?: (query: string) => void;
  notebookActive?: boolean;
  onAddToNotebook?: (entityType: string, value: string) => void;
  /**
   * NAN-5701: how many rows the query produced in total. The first page holds
   * only the results page size, so a larger total must be said, never hidden.
   */
  totalCount?: number;
  /** Fetch every row (up to STATS_LOAD_ALL_CAP) in one page. */
  onLoadAll?: (count: number) => void;
}

/** Most grouped rows the Stats view loads into the browser at once. */
export const STATS_LOAD_ALL_CAP = 10_000;

interface ParsedStats {
  agg: string;
  aggField: string | null;
  by: string[];
  headerLabel: string;
}

/**
 * Parse the first `| stats <agg>[(<field>)] [as <alias>] [, ...] by <field>[, ...]` command.
 *
 * Why: StatsView needs to distinguish by-columns (shown as text) from aggregation
 * columns (shown with a bar) and to render a human-readable header like
 * `count by user` or `avg(bytes) by src_ip, user`. The backend doesn't return
 * this metadata, so we re-derive it from the query string.
 */
export function parseStatsCommand(query: string): ParsedStats | null {
  const m = query.match(/\|\s*stats\s+(.+?)(?:\s+by\s+([^|]+?))?\s*(?:\||$)/i);
  if (!m) return null;
  const aggPart = m[1].trim();
  const byPart = (m[2] ?? '').trim();
  const firstAgg = aggPart.split(',')[0].trim();
  const aggMatch = firstAgg.match(/^(\w+)(?:\(\s*([^)]*)\s*\))?/);
  if (!aggMatch) return null;
  const agg = aggMatch[1].toLowerCase();
  const aggField = aggMatch[2]?.trim() || null;
  const by = byPart ? byPart.split(',').map((s) => s.trim()).filter(Boolean) : [];
  const aggLabel = aggField ? `${agg}(${aggField})` : agg;
  const headerLabel = by.length ? `${aggLabel} by ${by.join(', ')}` : aggLabel;
  return { agg, aggField, by, headerLabel };
}

type SortDir = 'asc' | 'desc';

function formatCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function asNumber(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value !== '' && !isNaN(Number(value))) return Number(value);
  return null;
}

function PageBtn({ disabled, onClick, label, title }: { disabled: boolean; onClick: () => void; label: string; title?: string }) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      title={title}
      className={cn(
        'w-6 h-6 inline-flex items-center justify-center rounded text-[12px] select-none',
        disabled
          ? 'text-muted-foreground/40 cursor-not-allowed'
          : 'text-muted-foreground hover:text-foreground hover:bg-foreground/5 cursor-pointer',
      )}
    >
      {label}
    </button>
  );
}

function SortIcon({ active, dir }: { active: boolean; dir: SortDir }) {
  if (!active) return <ArrowUpDown className="w-[10px] h-[10px] opacity-40" />;
  return dir === 'asc' ? <ArrowUp className="w-[10px] h-[10px]" /> : <ArrowDown className="w-[10px] h-[10px]" />;
}

export function StatsView({
  results,
  query = '',
  columnOrder,
  fieldsCollapsed,
  fieldsCount,
  onExpandFields,
  onDownload,
  onAddToQuery,
  onSetQuery,
  notebookActive,
  onAddToNotebook,
  totalCount,
  onLoadAll,
}: StatsViewProps) {
  const parsed = React.useMemo(() => parseStatsCommand(query), [query]);

  // Derive columns from results: by-fields first (preserving query order, then columnOrder),
  // then the remaining keys as aggregation columns.
  const { byCols, aggCols, numericCols } = React.useMemo(() => {
    const rowsFields = results.map((r) => r.fields as Record<string, unknown> | undefined);
    // NAN-5702: every output column, including ones added after `stats`
    // (a `join`'s fields, a `rename`), not only the ones `column_order` names.
    const ordered = completeColumnOrder(columnOrder, rowsFields);
    const present = new Set(ordered);
    // A column is numeric when every value it has is a number (sort + bars).
    const numericCols = new Set(
      ordered.filter((k) => {
        let seen = false;
        for (const f of rowsFields) {
          const v = f?.[k];
          if (v === null || v === undefined || v === '') continue;
          if (asNumber(v) === null) return false;
          seen = true;
        }
        return seen;
      }),
    );
    const declaredBy = (parsed?.by ?? []).filter((k) => present.has(k));
    // Review P2: when the declared `by` fields are gone (renamed after
    // `stats`), the text columns are the group keys; never guess by position,
    // which put `count` into the keys and the renamed key into the bars.
    const textCols = ordered.filter((k) => !numericCols.has(k));
    const byCols = declaredBy.length ? declaredBy : textCols.length ? textCols : ordered.slice(0, 1);
    const aggCols = ordered.filter((k) => !byCols.includes(k));
    return { byCols, aggCols, numericCols };
  }, [results, parsed, columnOrder]);

  const primaryAgg = aggCols.find((c) => numericCols.has(c)) ?? aggCols[0] ?? '__count';

  const [sortCol, setSortCol] = React.useState<string>(primaryAgg);
  const [sortDir, setSortDir] = React.useState<SortDir>('desc');
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(20);
  const [copiedKey, setCopiedKey] = React.useState<string | null>(null);

  // Reset sort column if results/columns change and current column disappears.
  React.useEffect(() => {
    if (!byCols.includes(sortCol) && !aggCols.includes(sortCol)) {
      setSortCol(primaryAgg);
      setSortDir('desc');
    }
  }, [byCols, aggCols, sortCol, primaryAgg]);

  const rows = React.useMemo(() => {
    const raw = results.map((r) => (r.fields ?? {}) as Record<string, unknown>);
    if (!sortCol) return raw;
    // Numeric order only for a numeric column: a text column surfaced after
    // `stats` (a join's `dept`) sorts as text instead of all-NaN (no-op).
    const isNumericSort = numericCols.has(sortCol);
    const out = [...raw];
    out.sort((a, b) => {
      const av = a[sortCol];
      const bv = b[sortCol];
      if (isNumericSort) {
        const an = asNumber(av) ?? -Infinity;
        const bn = asNumber(bv) ?? -Infinity;
        return sortDir === 'asc' ? an - bn : bn - an;
      }
      const as = formatCell(av).toLowerCase();
      const bs = formatCell(bv).toLowerCase();
      const r = as < bs ? -1 : as > bs ? 1 : 0;
      return sortDir === 'asc' ? r : -r;
    });
    return out;
  }, [results, sortCol, sortDir, numericCols]);

  const total = rows.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(page, totalPages);
  const start = (safePage - 1) * pageSize;
  const end = Math.min(start + pageSize, total);
  const slice = rows.slice(start, end);

  // Max per aggregation column for bar scaling
  const maxByAgg = React.useMemo(() => {
    const m: Record<string, number> = {};
    for (const col of aggCols) {
      let max = 0;
      for (const r of rows) {
        const n = asNumber(r[col]);
        if (n != null && n > max) max = n;
      }
      m[col] = max;
    }
    return m;
  }, [rows, aggCols]);

  const toggleSort = (col: string) => {
    if (sortCol === col) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortCol(col);
      setSortDir(numericCols.has(col) ? 'desc' : 'asc');
    }
  };

  const copyRow = async (key: string, row: Record<string, unknown>) => {
    const parts = [...byCols, ...aggCols].map((c) => formatCell(row[c]));
    try {
      await navigator.clipboard?.writeText(parts.join('\t'));
    } catch {
      /* clipboard unavailable */
    }
    setCopiedKey(key);
    setTimeout(() => setCopiedKey((k) => (k === key ? null : k)), 1200);
  };

  const headerLabel = parsed?.headerLabel ?? (byCols.length ? `${aggCols.join(', ')} by ${byCols.join(', ')}` : aggCols.join(', '));

  return (
    <div className="flex flex-col min-h-0 min-w-0 overflow-hidden">
      {/* Header row */}
      <div className="py-2 px-3 border-b border-border flex flex-wrap items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold">
        <span className="flex items-center gap-1.5 shrink-0">
          <TableIcon className="w-[12px] h-[12px] text-primary" />
          <span>Stats</span>
          <span className="text-muted-foreground/60">·</span>
          <span className="normal-case tracking-normal text-foreground">{headerLabel}</span>
        </span>
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
            <ChevronRight className="w-[10px] h-[10px]" />
          </button>
        )}
        <span className="flex-1" aria-hidden />
        <span className="text-foreground/70 text-[11px] font-medium tracking-wide">
          {total === 0 ? '0 of 0' : `${start + 1}\u2013${end} of ${total}`}
        </span>
        {onDownload && (
          <button
            type="button"
            onClick={onDownload}
            title="Export"
            className="text-muted-foreground hover:text-primary p-1 cursor-pointer"
          >
            <Download className="w-[12px] h-[12px]" />
          </button>
        )}
      </div>

      {totalCount !== undefined && totalCount > results.length && (
        <div
          role="status"
          data-testid="stats-partial-notice"
          className="px-3 py-1.5 border-b border-border flex items-center gap-2 text-[11.5px] text-foreground/80"
        >
          <span>
            Showing the first <span className="font-mono tabular-nums">{results.length.toLocaleString()}</span> of{' '}
            <span className="font-mono tabular-nums">{totalCount.toLocaleString()}</span> rows. Sorting and totals here cover only the loaded rows.
          </span>
          {onLoadAll && totalCount <= STATS_LOAD_ALL_CAP ? (
            <button
              type="button"
              onClick={() => onLoadAll(totalCount)}
              className="text-primary hover:underline cursor-pointer"
            >
              Load all {totalCount.toLocaleString()}
            </button>
          ) : (
            <span className="text-muted-foreground">
              Too many to load here; narrow the search or keep the top rows with <span className="font-mono">| sort -count | head N</span>.
            </span>
          )}
        </div>
      )}

      {/* Table */}
      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full font-mono text-[11.5px] border-collapse">
          <thead className="sticky top-0 z-10 bg-card">
            <tr className="border-b border-border">
              {byCols.map((col) => (
                <StatsHeaderCell
                  key={col}
                  col={col}
                  active={sortCol === col}
                  dir={sortDir}
                  onClick={() => toggleSort(col)}
                />
              ))}
              {aggCols.map((col) => (
                <StatsHeaderCell
                  key={col}
                  col={col}
                  numeric
                  active={sortCol === col}
                  dir={sortDir}
                  onClick={() => toggleSort(col)}
                />
              ))}
              <th className="w-[28px]" />
            </tr>
          </thead>
          <tbody>
            {slice.map((row, i) => {
              const gi = start + i;
              const rowKey = byCols.length
                ? byCols.map((c) => formatCell(row[c])).join('\u241F') + '|' + gi
                : String(gi);
              const isCopied = copiedKey === rowKey;
              return (
                <tr key={rowKey} className="group border-b border-border/50 transition-colors hover:bg-foreground/[0.03]">
                  {byCols.map((col, ci) => {
                    const cellValue = row[col];
                    const cellDisplay = formatCell(cellValue);
                    return (
                      <td
                        key={col}
                        className={cn(
                          'py-1.5 pr-3 align-top text-foreground break-all',
                          ci === 0 ? 'pl-3' : '',
                        )}
                      >
                        {onAddToQuery && cellValue != null && cellDisplay !== '' ? (
                          <FieldValueMenu
                            fieldName={col}
                            value={cellValue}
                            displayValue={cellDisplay}
                            onAddToQuery={onAddToQuery}
                            onSetQuery={onSetQuery}
                            query={query}
                            notebookActive={notebookActive}
                            onAddToNotebook={onAddToNotebook}
                          />
                        ) : (
                          cellDisplay
                        )}
                      </td>
                    );
                  })}
                  {aggCols.map((col) => {
                    const n = asNumber(row[col]);
                    const max = maxByAgg[col] ?? 0;
                    const pct = n != null && max > 0 ? (n / max) * 100 : 0;
                    const label = n != null ? n.toLocaleString() : formatCell(row[col]);
                    return (
                      <td key={col} className="py-1.5 pr-3 align-top w-[200px]">
                        <div className="relative">
                          <div
                            className="absolute inset-y-0 left-0 bg-primary/12 rounded-sm"
                            style={{ width: `${pct}%` }}
                          />
                          <div className="relative px-1.5 tabular-nums text-foreground">{label}</div>
                        </div>
                      </td>
                    );
                  })}
                  <td className="py-1.5 pr-2 align-top w-[28px] text-right">
                    <button
                      type="button"
                      onClick={() => copyRow(rowKey, row)}
                      title={isCopied ? 'Copied' : 'Copy row'}
                      className={cn(
                        'inline-flex items-center justify-center w-[22px] h-[22px] rounded hover:bg-foreground/6 transition-opacity',
                        isCopied
                          ? 'opacity-100 text-primary'
                          : 'opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-foreground',
                      )}
                    >
                      {isCopied ? (
                        <Check className="w-[12px] h-[12px]" />
                      ) : (
                        <Copy className="w-[12px] h-[12px]" />
                      )}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div className="border-t border-border px-3 py-2 flex items-center gap-3 font-mono text-[10.5px] text-muted-foreground tracking-wide">
        <span className="flex items-center gap-2">
          <span className="uppercase tracking-[0.12em] text-[9.5px] font-semibold">Rows</span>
          <select
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value));
              setPage(1);
            }}
            className="bg-background border border-border rounded px-1.5 py-0.5 text-foreground text-[11px] outline-none hover:border-foreground/20 cursor-pointer"
          >
            <option value={10}>10</option>
            <option value={20}>20</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
        </span>
        <span className="flex-1" aria-hidden />
        <span className="text-foreground text-[11px] normal-case tracking-normal font-medium">
          Page {safePage} of {totalPages}
        </span>
        <div className="flex items-center gap-0.5">
          <PageBtn disabled={safePage === 1} onClick={() => setPage(1)} label="«" title="First page" />
          <PageBtn disabled={safePage === 1} onClick={() => setPage((p) => Math.max(1, p - 1))} label="‹" title="Previous page" />
          <PageBtn disabled={safePage === totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))} label="›" title="Next page" />
          <PageBtn disabled={safePage === totalPages} onClick={() => setPage(totalPages)} label="»" title="Last page" />
        </div>
      </div>
    </div>
  );
}

function StatsHeaderCell({
  col,
  numeric,
  active,
  dir,
  onClick,
}: {
  col: string;
  numeric?: boolean;
  active: boolean;
  dir: SortDir;
  onClick: () => void;
}) {
  return (
    <th
      className={cn(
        'py-2 px-3 text-left select-none cursor-pointer',
        'font-mono text-[10px] tracking-[0.12em] uppercase font-semibold',
        active ? 'text-foreground' : 'text-muted-foreground hover:text-foreground',
      )}
      onClick={onClick}
    >
      <span className={cn('inline-flex items-center gap-1', numeric && 'pl-1.5')}>
        <span>{col}</span>
        <SortIcon active={active} dir={dir} />
      </span>
    </th>
  );
}

export default StatsView;
