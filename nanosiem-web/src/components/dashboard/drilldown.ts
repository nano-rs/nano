// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Drilldown Utilities
 *
 * Functions for generating drilldown filters and constructing search queries
 * from dashboard panel click events.
 *
 * Requirements: 6.1, 6.2, 6.4, 6.5
 */

import type { TimeRangeValue } from '@/hooks/use-api';
import { nplQuotedBody } from '@/lib/npl-quote';

// Drilldown filter interface - represents a single field filter
export interface DrilldownFilter {
  field: string;
  value: string;
  operator: '=' | '!=' | '>' | '<' | '>=' | '<=';
}

/**
 * Payload emitted by a visualization when the user clicks a data element
 * (CONTRACT 3). `filters` carries ALL group-by field/value pairs for the clicked
 * element (numeric group-bys included, never just the first). For time-bucketed
 * (timechart) clicks the emitter sets `anchorStart`/`anchorEnd` to the clicked
 * bucket's `[start, start+span]` ISO window instead of emitting a synthetic
 * `time_bucket` filter (which is not a real column — DSH27).
 */
export interface DrilldownPayload {
  filters: Array<{ field: string; value: string }>;
  anchorStart?: string;
  anchorEnd?: string;
}

/** Options for {@link buildSearchUrl} (CONTRACT 3). */
export interface BuildSearchUrlOptions {
  /** Panel's pre-aggregation search stages, prepended so panel scope is kept. */
  baseQuery?: string;
  /** Absolute ISO start of the anchored window (from the clicked bucket/event). */
  startTime?: string;
  /** Absolute ISO end of the anchored window. */
  endTime?: string;
  /** Custom drilldown template (`drilldownTemplate`); `$value`/`$field` substituted. */
  template?: string;
}

// Extended drilldown context with all data from clicked element
export interface DrilldownContext {
  // Primary filter (the main field clicked)
  primaryFilter: DrilldownFilter;
  // All filters extracted from the clicked element (for grouped visualizations)
  allFilters: DrilldownFilter[];
  // Raw data from the clicked element
  rawData: Record<string, unknown>;
}

/**
 * Extract all grouping fields (non-numeric fields) from a data entry.
 * This is used for drilldown to include all group-by field values.
 *
 * @param entry - The data entry from the clicked chart element
 * @returns Array of DrilldownFilter objects for all non-numeric fields
 */
export function extractGroupingFields(entry: Record<string, unknown>): DrilldownFilter[] {
  const filters: DrilldownFilter[] = [];

  for (const [key, value] of Object.entries(entry)) {
    // Skip numeric values (these are typically aggregation results like count, sum, etc.)
    if (typeof value === 'number') continue;
    // Skip null/undefined values
    if (value === null || value === undefined) continue;
    // Skip internal fields
    if (key.startsWith('_')) continue;

    // Include string and other non-numeric values as filters
    filters.push({
      field: key,
      value: String(value),
      operator: '=',
    });
  }

  return filters;
}

/**
 * Build a drilldown context from clicked element data.
 * Extracts all relevant filters for comprehensive drilldown.
 *
 * @param entry - The data entry from the clicked chart element
 * @param primaryField - Optional primary field to use (defaults to first non-numeric field)
 * @returns DrilldownContext with primary and all filters
 */
export function buildDrilldownContext(
  entry: Record<string, unknown>,
  primaryField?: string
): DrilldownContext | null {
  const allFilters = extractGroupingFields(entry);

  if (allFilters.length === 0) {
    return null;
  }

  // Find primary filter - use specified field or first filter
  let primaryFilter = allFilters[0];
  if (primaryField) {
    const found = allFilters.find(f => f.field === primaryField);
    if (found) {
      primaryFilter = found;
    }
  }

  return {
    primaryFilter,
    allFilters,
    rawData: entry,
  };
}

/**
 * Sanitize a value for inclusion in a double-quoted nPL string literal.
 *
 * Delegates to the shared {@link nplQuotedBody} (NAN-2184) so every nPL call
 * site in the app shares one implementation. The reasoning DSH28 recorded here
 * still holds: nPL has no `\"` mechanism (NAN-1157), so an embedded double
 * quote is stripped rather than backslash-escaped.
 *
 * The one behavioural change is that consecutive backslashes are now doubled
 * on emit, because the parser collapses `\\` → `\`. Windows paths still match
 * (`C:\Windows\cmd.exe` round-trips identically — a lone backslash is
 * unaffected); UNC paths like `\\fileserver\share` stop silently losing a
 * backslash.
 *
 * @param value - The value to sanitize
 * @returns Value safe to place inside `"..."` in an nPL query
 */
export function escapeFilterValue(value: string): string {
  return nplQuotedBody(value);
}

/**
 * Construct a filter query string from drilldown filters.
 * Generates a piped query format filter clause.
 *
 * @param filters - Array of field/value(/operator) filters
 * @returns Query string in piped format (e.g., 'field1="value1" field2="value2"')
 */
export function constructFilterQuery(
  filters: Array<{ field: string; value: string; operator?: DrilldownFilter['operator'] }>
): string {
  return filters
    .map(filter => {
      const escapedValue = escapeFilterValue(filter.value);
      return `${filter.field}${filter.operator ?? '='}"${escapedValue}"`;
    })
    .join(' ');
}

/**
 * Apply a custom drilldown template, substituting `$value`/`$field` with the
 * primary (first) clicked filter. `$value` is sanitized for an nPL string
 * literal; `$field` is used verbatim (it is a column name). Only whole
 * `$value`/`$field` tokens are replaced (a following identifier char blocks the
 * match, so `$value_x` is left alone).
 */
export function applyDrilldownTemplate(
  template: string,
  primary: { field: string; value: string } | undefined
): string {
  const field = primary?.field ?? '';
  const value = primary?.value ?? '';
  return template
    .replace(/\$value\b/g, escapeFilterValue(value))
    .replace(/\$field\b/g, field);
}

/**
 * Build URL search parameters for navigating to the search page with drilldown.
 * Includes the filter query and preserves the dashboard time range.
 *
 * @deprecated Prefer {@link buildSearchUrl} with {@link BuildSearchUrlOptions};
 *   retained for the module re-export surface.
 */
export function buildSearchUrlParams(
  filters: DrilldownFilter[],
  timeRange: TimeRangeValue,
  baseQuery?: string
): URLSearchParams {
  const params = new URLSearchParams();

  // Build the query
  const filterQuery = constructFilterQuery(filters);
  const fullQuery = baseQuery
    ? `${baseQuery} ${filterQuery}`.trim()
    : filterQuery;

  if (fullQuery) {
    params.set('q', fullQuery);
  }

  // Set query mode to piped (drilldown always uses piped queries)
  params.set('mode', 'piped');

  // Preserve time range
  if (timeRange.type === 'custom' && timeRange.start && timeRange.end) {
    const startDate = timeRange.start instanceof Date ? timeRange.start : new Date(timeRange.start);
    const endDate = timeRange.end instanceof Date ? timeRange.end : new Date(timeRange.end);
    params.set('start', startDate.toISOString());
    params.set('end', endDate.toISOString());
  } else if (timeRange.type === 'preset' && timeRange.preset) {
    params.set('time', timeRange.preset);
  }

  return params;
}

/**
 * Build the full search URL for drilldown navigation (CONTRACT 3).
 *
 * - `baseQuery` (the panel's pre-aggregation stages) is prepended so the panel
 *   scope is preserved.
 * - When a `template` is supplied it REPLACES the auto-generated filters, with
 *   `$value`/`$field` substituted from the primary clicked filter. The panel
 *   `baseQuery` scope is still prepended so the panel's own filters are kept.
 * - When `startTime`/`endTime` are given they are emitted as explicit absolute
 *   bounds (the clicked bucket window / dashboard window resolved to absolute),
 *   never re-anchored to "now" by Search (NAN-1450/1451).
 *
 * @param filters - Group-by field/value pairs from the clicked element
 * @param opts - {@link BuildSearchUrlOptions}
 * @returns Full URL path with query parameters
 */
export function buildSearchUrl(
  filters: Array<{ field: string; value: string; operator?: DrilldownFilter['operator'] }>,
  opts: BuildSearchUrlOptions = {}
): string {
  const params = new URLSearchParams();

  let query: string;
  if (opts.template && opts.template.trim()) {
    const templated = applyDrilldownTemplate(opts.template, filters[0]);
    query = opts.baseQuery ? `${opts.baseQuery} ${templated}`.trim() : templated;
  } else {
    const filterQuery = constructFilterQuery(filters);
    query = opts.baseQuery
      ? `${opts.baseQuery} ${filterQuery}`.trim()
      : filterQuery;
  }

  if (query) {
    params.set('q', query);
  }

  // Drilldown always navigates to the piped editor.
  params.set('mode', 'piped');

  // Anchored absolute window takes precedence over any preset — Search must not
  // re-anchor a clicked bucket to "now" (NAN-1450/1451).
  if (opts.startTime && opts.endTime) {
    params.set('start', opts.startTime);
    params.set('end', opts.endTime);
  }

  return `/search?${params.toString()}`;
}

export default {
  extractGroupingFields,
  buildDrilldownContext,
  escapeFilterValue,
  constructFilterQuery,
  applyDrilldownTemplate,
  buildSearchUrlParams,
  buildSearchUrl,
};
