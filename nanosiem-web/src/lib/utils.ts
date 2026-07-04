// SPDX-License-Identifier: AGPL-3.0-or-later

import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { isPrevalenceSentinelField } from './prevalence-sentinels';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Fields that should show 0 as a meaningful value (not a ClickHouse default).
 * These are fields where 0 is a valid, intentional value.
 */
const FIELDS_WHERE_ZERO_IS_MEANINGFUL = new Set([
  'count',
  'total',
  'attempts',
  'status', // HTTP status codes can be meaningful
  // Prevalence fields - 0 is meaningful (rare/never seen)
  'host_count',
  'total_occurrences',
  'prevalence_score',
  // Risk fields - 0 is meaningful (no risk)
  'risk_score',
]);

/**
 * Check if a value is a ClickHouse default (empty) value.
 * ClickHouse uses default values instead of NULL:
 * - Integers → 0
 * - Strings → '' (empty string)
 * - Dates → 1970-01-01
 *
 * Prevalence sentinel values (used to indicate "no data") — see
 * lib/prevalence-sentinels: 65535 = N/A, 9999 = common (>= 1000 hosts).
 *
 * @param value The value to check
 * @param fieldName Optional field name for context-aware checking
 * @returns true if the value is a ClickHouse default/empty value
 */
export function isClickHouseDefault(value: unknown, fieldName?: string): boolean {
  // Null/undefined are always empty
  if (value === null || value === undefined) return true;

  // Empty string
  if (value === '' || value === 'null') return true;

  // Prevalence sentinel values (N/A / common) indicate "no data" / "not tracked".
  // Scoped to prevalence_* fields so a legitimate 9999/65535 elsewhere isn't hidden.
  if (fieldName && isPrevalenceSentinelField(fieldName, value)) return true;

  // For numeric 0, check if the field is one where 0 is meaningful
  if (value === 0) {
    if (fieldName) {
      const lowerField = fieldName.toLowerCase();
      // Check if this field should show 0
      if (FIELDS_WHERE_ZERO_IS_MEANINGFUL.has(lowerField)) return false;
      // Aggregate function results should show 0
      if (lowerField.startsWith('count') || lowerField.startsWith('sum') ||
          lowerField.startsWith('avg') || lowerField.startsWith('min') ||
          lowerField.startsWith('max')) return false;
    }
    return true;
  }

  // Unix epoch date (1970-01-01) - ClickHouse default for dates
  if (value instanceof Date && value.getTime() === 0) return true;
  if (typeof value === 'string' && value.startsWith('1970-01-01')) return true;

  return false;
}

/**
 * Check if a value should be displayed (is not a ClickHouse default).
 * Convenience wrapper around isClickHouseDefault.
 */
export function hasValue(value: unknown, fieldName?: string): boolean {
  return !isClickHouseDefault(value, fieldName);
}

/**
 * Strip comments from a search query.
 * Supports:
 * - Single-line comments: // comment
 * - Multi-line comments: slash-star ... star-slash
 * 
 * Comments inside quoted strings or regex patterns are preserved.
 * 
 * @param query The search query to strip comments from
 * @returns The query with comments removed
 */
export function stripComments(query: string): string {
  let result = '';
  let i = 0;
  let inQuote = false;
  let inRegex = false;
  
  while (i < query.length) {
    const c = query[i];
    const next = query[i + 1];
    
    // Handle escape sequences
    if (c === '\\' && i + 1 < query.length) {
      result += c + next;
      i += 2;
      continue;
    }
    
    // Handle quotes (toggle quote state)
    if (c === '"' && !inRegex) {
      inQuote = !inQuote;
      result += c;
      i++;
      continue;
    }
    
    // Handle regex patterns (after = or !=)
    if (c === '/' && !inQuote) {
      if (!inRegex) {
        // Check if this is a regex delimiter (preceded by = or !=)
        const before = result.trimEnd();
        if (before.endsWith('=') || before.endsWith('!=')) {
          inRegex = true;
          result += c;
          i++;
          continue;
        }
      } else {
        // End of regex
        inRegex = false;
        result += c;
        i++;
        continue;
      }
    }
    
    // Skip single-line comments (// ...) when not in quote or regex
    if (!inQuote && !inRegex && c === '/' && next === '/') {
      // Skip until end of line
      while (i < query.length && query[i] !== '\n') {
        i++;
      }
      continue;
    }
    
    // Skip multi-line comments (/* ... */) when not in quote or regex
    if (!inQuote && !inRegex && c === '/' && next === '*') {
      i += 2; // Skip /*
      // Find closing */
      while (i < query.length - 1) {
        if (query[i] === '*' && query[i + 1] === '/') {
          i += 2; // Skip */
          break;
        }
        i++;
      }
      continue;
    }
    
    result += c;
    i++;
  }
  
  return result.trim();
}

/**
 * Find the index of the first pipe (`|`) in an nPL query that isn't inside a
 * quoted string or regex literal. Returns -1 if none found. Used to splice
 * synthesized pipeline commands (e.g. the UI rarity filter) in *before* the
 * user's own pipe stages, so pre-aggregation filters aren't referenced by
 * post-projection CTEs where their columns are out of scope.
 */
/**
 * Splice a synthesized pipeline command (must include its own leading `|`) into
 * an nPL query *before* the user's first pipe stage. If the query has no pipe,
 * the command is appended. Used so UI-injected filters (e.g. the Rarity slider)
 * run at the event level before any `stats`/`table`/`timechart` projects away
 * their referenced columns.
 */
export function injectBeforeFirstPipe(query: string, command: string): string {
  const firstPipe = findFirstUnquotedPipe(query);
  return firstPipe === -1
    ? query + command
    : query.slice(0, firstPipe) + command + ' ' + query.slice(firstPipe);
}

export function findFirstUnquotedPipe(query: string): number {
  let inQuote = false;
  let inRegex = false;
  for (let i = 0; i < query.length; i++) {
    const c = query[i];
    if (c === '\\' && i + 1 < query.length) { i++; continue; }
    if (c === '"' && !inRegex) { inQuote = !inQuote; continue; }
    if (c === '/' && !inQuote) {
      if (!inRegex) {
        const before = query.slice(0, i).trimEnd();
        if (before.endsWith('=') || before.endsWith('!=')) inRegex = true;
      } else {
        inRegex = false;
      }
      continue;
    }
    if (c === '|' && !inQuote && !inRegex) return i;
  }
  return -1;
}
