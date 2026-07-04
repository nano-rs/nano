// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Canonical handling of the sentinel values stamped into the UInt16
 * `prevalence_*` columns, so every surface hides / renders them identically.
 *
 * The columns (`prevalence_min`, `prevalence_file_hash`, `prevalence_process_hash`,
 * `prevalence_dest_domain`, `prevalence_dest_ip`) are all UInt16
 * (see `clickhouse/init.sql`). Two values are sentinels, not host counts:
 *   - `65535` — field N/A (the entity is absent on the row, or it's a
 *     private/link-local IP the pipeline deliberately does not track);
 *   - `9999`  — "common" (the artifact is on >= 1000 hosts, capped).
 * Every other value `1..9998` is a real host count and must render as-is.
 *
 * NOTE on `255`: older call sites also filtered `255` as a "UInt8 N/A" sentinel.
 * No prevalence column is UInt8 — `255` is a legitimate count of 255 hosts — so
 * filtering it silently hid real 255-host artifacts. It is intentionally NOT a
 * sentinel here (NAN-1670, audit gap G5). `AssetStream` was already correct in
 * omitting it; the other surfaces are brought into line via this module.
 */

/** Field N/A — entity absent on the row, or an untracked private/link-local IP. */
export const PREVALENCE_NA = 65535;
/** "Common" — artifact seen on >= 1000 hosts (capped). */
export const PREVALENCE_COMMON = 9999;

/**
 * True when a numeric prevalence value is a sentinel (N/A or common) rather than
 * a real host count. Use when the field is already known to be a prevalence value
 * (e.g. reading `prevalence_min` directly).
 */
export function isPrevalenceSentinelValue(value: unknown): boolean {
  return value === PREVALENCE_NA || value === PREVALENCE_COMMON;
}

/**
 * True when `field` is a `prevalence_*` column carrying a sentinel value — the
 * signal to hide/skip it in a generic field renderer. Case-insensitive on the
 * field name.
 */
export function isPrevalenceSentinelField(field: string, value: unknown): boolean {
  return field.toLowerCase().startsWith('prevalence_') && isPrevalenceSentinelValue(value);
}

/**
 * Human label for a prevalence sentinel that should still be shown, or `null`
 * when the value carries no signal and should be hidden.
 *
 * NAN-1689: `9999` ("common") is real information — the artifact is on >= 1000
 * hosts — but blanking it out (as N/A) makes it indistinguishable from "no
 * artifact on this row" (65535). Render `9999` as `common` and keep `65535`
 * hidden. Returns `null` for N/A and for non-prevalence / non-sentinel values
 * (callers render those as the raw count / their existing empty).
 */
export function prevalenceSentinelLabel(field: string, value: unknown): string | null {
  if (!field.toLowerCase().startsWith('prevalence_')) return null;
  return value === PREVALENCE_COMMON ? 'common' : null;
}
