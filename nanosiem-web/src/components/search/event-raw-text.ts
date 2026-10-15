// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The inspector's Raw tab text for one event (NAN-3245).
 *
 * The original log line lives in different fields per schema:
 * - OCSF (lean / lake): `raw_data` — `message` is null or a human summary;
 * - UDM (dedicated): `message`;
 * - legacy rows with a `_raw` field: `_raw`.
 * The first non-empty string among them wins, in that order.
 *
 * OTLP/structured records (spans/metrics) have no raw text: the structured
 * record IS the raw, so it is built from the row's REAL ingested fields
 * (internal `_*`/id/timestamp excluded, null/"" skipped) and flagged
 * `synthetic` (NAN-1568). Returns null when there is nothing to show.
 *
 * `raw_data` is not in the lean list-row projection; the Raw tab gets it from
 * the hover/inspector full-event fetch (`POST /api/search/log`).
 */
export const RAW_TEXT_FIELDS = ['raw_data', 'message', '_raw'] as const;

export interface RawView {
  text: string;
  synthetic: boolean;
}

export function resolveRawView(fields: Record<string, unknown> | undefined): RawView | null {
  if (!fields) return null;
  for (const key of RAW_TEXT_FIELDS) {
    const value = fields[key];
    if (typeof value === 'string' && value.trim() !== '') {
      return { text: value, synthetic: false };
    }
  }
  const obj: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (k.startsWith('_') || k === 'id' || k === 'timestamp') continue;
    if (v == null || v === '') continue;
    obj[k] = v;
  }
  if (Object.keys(obj).length === 0) return null;
  return { text: JSON.stringify(obj, null, 2), synthetic: true };
}
