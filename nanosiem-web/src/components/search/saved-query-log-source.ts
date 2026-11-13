// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Infer the log source a saved query targets, for grouping in the saved
 * queries palette. NAN-5326: OCSF is the data model, so `metadata.log_source`
 * is the primary key. The legacy `source_type` / `sourcetype` spellings are
 * still recognised so older saved queries keep their group. Falls back to
 * "other".
 */
export function extractLogSource(query: string): string {
  const m = query.match(
    /(?:^|[^\w.])(?:metadata\.log_source|source_type|sourcetype)\s*=\s*["']?([a-zA-Z0-9_.-]+)/i,
  );
  return m ? m[1] : 'other';
}
