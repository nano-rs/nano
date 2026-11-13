/**
 * The line shown for each event in the search results stream (RawView).
 *
 * Every source renders the same way: a compact JSON line of the row's REAL
 * ingested fields. A top-level `message` (e.g. windows_event's "An account
 * failed to log on.") is NOT promoted to the row line — it stays a normal key
 * inside the JSON, like every other field (NAN-3010). Before that fix, rows with
 * `message` rendered the bare text while sysmon/conduit/apache/cloudtrail rows
 * rendered JSON, so one result list mixed two formats.
 *
 * Internal `_*` markers, `id`, and `timestamp` (already shown above the line)
 * are excluded, as are null/empty values. Nothing is stored or fabricated.
 * Returns null if there is nothing to show. `pretty` produces the indented form.
 *
 * NAN-5326: ClickHouse column defaults that can never be real data
 * (`dst_endpoint.port: 0`, `*.autonomous_system.number: 0`, prevalence N/A
 * `65535`) and internal helper columns (`*_unified`, `event_bytes`) are
 * dropped. A zero on any other column (`traffic.bytes_out`, `logon_type_id`,
 * `severity_id`, `exit_code`, …) can be real and is kept: this is the raw row.
 * Under OCSF the legacy `source_type` key is shown as `metadata.log_source`.
 */
import { PREVALENCE_NA } from '@/lib/prevalence-sentinels';

/** OCSF Authentication class — the only class where `is_mfa` carries data. */
const OCSF_AUTHENTICATION_CLASS_UID = 3002;

/**
 * True for a column that is internal plumbing, not event data: query
 * accelerators (`*_unified`), sizing metrics (`event_bytes`).
 */
export function isInternalHelperColumn(key: string): boolean {
  return key.endsWith('_unified') || key === 'event_bytes';
}

/**
 * Columns where `0` is only ever the ClickHouse fill value: port 0 and AS 0
 * are reserved, HTTP has no status 0, IP protocol 0 is never logged.
 */
const ZERO_IS_DEFAULT = /(?:^|[._])(?:port|autonomous_system\.number|asn|http_response\.code|http_status_code|protocol_num)$/i;

/**
 * True when a raw-row value is absent rather than data: null / empty, the
 * epoch date, the prevalence N/A sentinel, or a zero on a {@link ZERO_IS_DEFAULT}
 * column. Deliberately narrower than `isClickHouseDefault` (which hides every
 * non-allowlisted zero) — the raw row must not hide a real `0`.
 */
export function isRawRowDefault(value: unknown, key: string): boolean {
  if (value === null || value === undefined || value === '' || value === 'null') return true;
  if (typeof value === 'string' && value.startsWith('1970-01-01')) return true;
  // 65535 = N/A (no artifact on the row). 9999 = "common" (>= 1000 hosts) is
  // real signal and stays (NAN-1689).
  if (value === PREVALENCE_NA && key.toLowerCase().startsWith('prevalence_')) return true;
  return value === 0 && ZERO_IS_DEFAULT.test(key);
}

/**
 * True when an OCSF row carries a typed default for a field that does not
 * apply to its class. `is_mfa` is a Bool column, so every non-Authentication
 * event stores `false` — rendering that as "is_mfa false" on a process event
 * reads as data.
 */
export function isOcsfInapplicableDefault(
  key: string,
  value: unknown,
  row: Record<string, unknown>,
): boolean {
  if (key === 'is_mfa' && (value === false || value === 0 || value === 'false')) {
    // Only hide when the class is KNOWN to be non-Authentication: a projected
    // row (`| table actor.user.name, is_mfa`) has no class_uid, and a no-MFA
    // login there is exactly what the analyst is looking for.
    if (row.class_uid == null || row.class_uid === '') return false;
    return Number(row.class_uid) !== OCSF_AUTHENTICATION_CLASS_UID;
  }
  return false;
}

/** Display key for a row column under the active schema. */
export function ocsfDisplayKey(key: string, isOcsf: boolean): string {
  return isOcsf && key === 'source_type' ? 'metadata.log_source' : key;
}

export function buildEventRowLine(
  fields: Record<string, unknown> | undefined,
  pretty = false,
  isOcsf = false,
): string | null {
  const obj = eventRowLineObject(fields, isOcsf);
  if (!obj) return null;
  return pretty ? JSON.stringify(obj, null, 2) : JSON.stringify(obj);
}

/**
 * The keys/values `buildEventRowLine` renders, in order; null when none.
 * Shared with the highlighter (NAN-5328) so both see the same line.
 */
export function eventRowLineObject(
  fields: Record<string, unknown> | undefined,
  isOcsf = false,
): Record<string, unknown> | null {
  if (!fields) return null;
  const obj: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (k.startsWith('_') || k === 'id' || k === 'timestamp') continue;
    if (isInternalHelperColumn(k)) continue;
    if (isRawRowDefault(v, k)) continue;
    if (isOcsf && isOcsfInapplicableDefault(k, v, fields)) continue;
    const key = ocsfDisplayKey(k, isOcsf);
    if (key !== k && key in fields) continue; // real column wins over the alias
    obj[key] = v;
  }
  return Object.keys(obj).length === 0 ? null : obj;
}

/**
 * Sorted `[key, value]` entries of a raw event for a field list (rule-test
 * EVENT DETAIL), with the same default / helper-column / alias rules as the
 * results row line. Nested objects are kept (callers render them as JSON).
 */
export function eventDetailEntries(
  event: Record<string, unknown>,
  isOcsf: boolean,
): [string, unknown][] {
  const out: [string, unknown][] = [];
  for (const [k, v] of Object.entries(event)) {
    if (isInternalHelperColumn(k)) continue;
    if ((v === null || typeof v !== 'object') && isRawRowDefault(v, k)) continue;
    if (isOcsf && isOcsfInapplicableDefault(k, v, event)) continue;
    const key = ocsfDisplayKey(k, isOcsf);
    if (key !== k && key in event) continue;
    out.push([key, v]);
  }
  return out.sort(([a], [b]) => a.localeCompare(b));
}
