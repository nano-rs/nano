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

// Drilldown filter interface - represents a single field filter
export interface DrilldownFilter {
  field: string;
  value: string;
  operator: '=' | '!=' | '>' | '<' | '>=' | '<=';
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
 * Escape a value for use in a piped query filter.
 * Handles special characters like backslashes and quotes.
 * 
 * @param value - The value to escape
 * @returns Escaped value safe for query inclusion
 */
export function escapeFilterValue(value: string): string {
  return value
    .replace(/\\/g, '\\\\')  // Escape backslashes first
    .replace(/"/g, '\\"');    // Escape quotes
}

/**
 * Construct a filter query string from drilldown filters.
 * Generates a piped query format filter clause.
 * 
 * @param filters - Array of DrilldownFilter objects
 * @returns Query string in piped format (e.g., 'field1="value1" field2="value2"')
 */
export function constructFilterQuery(filters: DrilldownFilter[]): string {
  return filters
    .map(filter => {
      const escapedValue = escapeFilterValue(filter.value);
      return `${filter.field}${filter.operator}"${escapedValue}"`;
    })
    .join(' ');
}

/**
 * Build URL search parameters for navigating to the search page with drilldown.
 * Includes the filter query and preserves the dashboard time range.
 * 
 * @param filters - Array of DrilldownFilter objects
 * @param timeRange - The dashboard's current time range
 * @param baseQuery - Optional base query to prepend
 * @returns URLSearchParams object for navigation
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
 * Build the full search URL for drilldown navigation.
 * 
 * @param filters - Array of DrilldownFilter objects
 * @param timeRange - The dashboard's current time range
 * @param baseQuery - Optional base query to prepend
 * @returns Full URL path with query parameters
 */
export function buildSearchUrl(
  filters: DrilldownFilter[],
  timeRange: TimeRangeValue,
  baseQuery?: string
): string {
  const params = buildSearchUrlParams(filters, timeRange, baseQuery);
  return `/search?${params.toString()}`;
}

export default {
  extractGroupingFields,
  buildDrilldownContext,
  escapeFilterValue,
  constructFilterQuery,
  buildSearchUrlParams,
  buildSearchUrl,
};
