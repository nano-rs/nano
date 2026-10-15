// SPDX-License-Identifier: AGPL-3.0-or-later

// Explicit extension keeps this helper testable with Node's native TypeScript
// runner as well as through Vite's bundler resolution.
import { nplFieldEquals } from './npl-quote.ts';

function valueAtPath(fields: Record<string, unknown>, path: string): unknown {
  if (Object.prototype.hasOwnProperty.call(fields, path)) return fields[path];
  let current: unknown = fields;
  for (const component of path.split('.')) {
    if (current === null || typeof current !== 'object' || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[component];
  }
  return current;
}

/** Resolve a log's trace identity across canonical OCSF and legacy rows. */
export function resolveLogTraceId(fields: Record<string, unknown> | undefined): string | null {
  if (!fields) return null;
  for (const path of ['trace.uid', 'unmapped.trace_id', 'trace_id']) {
    const value = valueAtPath(fields, path);
    if (typeof value === 'string' && value.trim() !== '') return value.trim().toLowerCase();
  }
  return null;
}

/**
 * OCSF log correlation predicate. Trace-profile classes use trace.uid; generic
 * Base Events retain the OTLP identifier under unmapped.trace_id.
 */
export function ocsfTraceLogPredicate(traceId: string): string {
  return `(${nplFieldEquals('trace.uid', traceId)} OR ${nplFieldEquals('unmapped.trace_id', traceId)})`;
}
