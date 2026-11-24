// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5839: the log source timezone setting.
 *
 * A source's timezone is applied ONLY to timestamps that carry no offset or
 * zone of their own (PAN-OS `receive_time`, RFC 3164 syslog, ...): the parser
 * reads such a clock in this zone and stores true UTC. An inline offset in the
 * log always wins. The value is an IANA zone name or a fixed offset `±HH:MM`;
 * `UTC` is the default.
 *
 * The fixed offsets are kept in step with `nanosiem_core::timezone`
 * (the server is the authority and normalizes what it stores).
 */

export const DEFAULT_SOURCE_TIMEZONE = 'UTC';

/**
 * Fractional offsets the setting accepts: every one a real zone uses (standard
 * or daylight time). Whole hours run -12:00..+14:00. Same list as
 * `nanosiem_core::timezone::FRACTIONAL_SOURCE_OFFSETS`.
 */
export const FRACTIONAL_SOURCE_OFFSETS = [
  '-09:30', '-03:30', '-02:30', '+03:30', '+04:30', '+05:30', '+05:45', '+06:30',
  '+08:45', '+09:30', '+10:30', '+12:45', '+13:45',
] as const;

function pad(n: number): string {
  return String(n).padStart(2, '0');
}

/** Every fixed offset the setting accepts, west to east. */
export function fixedSourceOffsets(): string[] {
  const out: string[] = [];
  for (let h = 12; h >= 1; h--) out.push(`-${pad(h)}:00`);
  for (let h = 1; h <= 14; h++) out.push(`+${pad(h)}:00`);
  out.push(...FRACTIONAL_SOURCE_OFFSETS);
  const minutes = (o: string) => (o[0] === '-' ? -1 : 1) * (Number(o.slice(1, 3)) * 60 + Number(o.slice(4, 6)));
  return Array.from(new Set(out)).sort((a, b) => minutes(a) - minutes(b));
}

/**
 * Zones always offered: the common ones for old engines that cannot list
 * their own, and the current IANA spellings that browsers list under a CLDR
 * legacy alias (Intl returns Asia/Calcutta, Asia/Katmandu, Asia/Saigon,
 * Europe/Kiev). The server (chrono-tz) accepts both spellings.
 */
const FALLBACK_ZONES = [
  'Asia/Ho_Chi_Minh', 'Asia/Yangon', 'Europe/Kyiv', 'America/Argentina/Buenos_Aires', 'Atlantic/Faroe',
  'Pacific/Chuuk', 'Pacific/Pohnpei', 'Pacific/Kanton', 'America/Nuuk', 'Asia/Kathmandu', 'Asia/Kolkata',
  'America/New_York', 'America/Chicago', 'America/Denver', 'America/Phoenix', 'America/Los_Angeles',
  'America/Anchorage', 'Pacific/Honolulu', 'America/Toronto', 'America/Mexico_City', 'America/Sao_Paulo',
  'America/Bogota', 'Europe/London', 'Europe/Dublin', 'Europe/Paris', 'Europe/Berlin', 'Europe/Madrid',
  'Europe/Rome', 'Europe/Amsterdam', 'Europe/Stockholm', 'Europe/Helsinki', 'Europe/Moscow', 'Africa/Johannesburg',
  'Africa/Lagos', 'Asia/Dubai', 'Asia/Tehran', 'Asia/Kolkata', 'Asia/Kathmandu', 'Asia/Bangkok', 'Asia/Singapore',
  'Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Tokyo', 'Asia/Seoul', 'Australia/Perth', 'Australia/Adelaide',
  'Australia/Brisbane', 'Australia/Sydney', 'Pacific/Auckland',
];

let zoneCache: string[] | null = null;

/** IANA zone names the browser knows (the same tz database the server uses). */
export function ianaZones(): string[] {
  if (zoneCache) return zoneCache;
  let zones: string[] = [];
  try {
    const supported = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf;
    zones = supported ? supported('timeZone') : [];
  } catch {
    zones = [];
  }
  zoneCache = Array.from(new Set([...zones, ...FALLBACK_ZONES]))
    .filter((z) => z !== 'UTC' && z.includes('/'))
    .sort();
  return zoneCache;
}

/** True for a value shaped like a fixed offset (`+05:30`, `-0500`). */
export function isOffsetShaped(value: string): boolean {
  return /^[+-]\d{2}:?\d{2}$/.test(value.trim());
}

/** The zone's current UTC offset as `±HH:MM` (`±00:00` for UTC). */
export function currentOffset(zone: string, at: Date = new Date()): string {
  if (zone === DEFAULT_SOURCE_TIMEZONE) return '±00:00';
  if (isOffsetShaped(zone)) return zone;
  try {
    const part = new Intl.DateTimeFormat('en-US', { timeZone: zone, timeZoneName: 'longOffset' })
      .formatToParts(at)
      .find((p) => p.type === 'timeZoneName')?.value;
    // "GMT-05:00", "GMT+05:30", or "GMT" for zero.
    if (!part || part === 'GMT') return '±00:00';
    const m = /GMT([+-])(\d{1,2})(?::?(\d{2}))?/.exec(part);
    if (!m) return '';
    return `${m[1]}${pad(Number(m[2]))}:${m[3] ?? '00'}`;
  } catch {
    return '';
  }
}

/** Region of an IANA name, for grouping (`America/New_York` → `America`). */
export function zoneRegion(zone: string): string {
  return zone.split('/')[0];
}

/** What a stored value reads as in the UI. */
export function timezoneDisplay(value: string | null | undefined): string {
  const v = value && value.trim() ? value : DEFAULT_SOURCE_TIMEZONE;
  return v === DEFAULT_SOURCE_TIMEZONE ? 'UTC (default)' : v;
}

/** The one-line explanation shown with the setting. */
export const SOURCE_TIMEZONE_HELP =
  "Used only for timestamps without an offset, such as PAN-OS receive_time or BSD syslog. A zone written in the log always wins.";

export type TimezoneOption = { id: string; label: string; hint: string };
export type TimezoneGroup = { region: string; items: TimezoneOption[] };

/** Every option, grouped. Exported for tests. */
export function timezoneGroups(at: Date = new Date()): TimezoneGroup[] {
  const byRegion = new Map<string, TimezoneOption[]>();
  for (const zone of ianaZones()) {
    const region = zoneRegion(zone);
    const list = byRegion.get(region) ?? [];
    list.push({ id: zone, label: zone, hint: currentOffset(zone, at) });
    byRegion.set(region, list);
  }
  return [
    { region: 'Default', items: [{ id: DEFAULT_SOURCE_TIMEZONE, label: 'UTC (default)', hint: '±00:00' }] },
    {
      region: 'Fixed offset',
      items: fixedSourceOffsets().map((o) => ({ id: o, label: `UTC${o}`, hint: 'no DST' })),
    },
    ...Array.from(byRegion.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([region, items]) => ({ region, items })),
  ];
}

/** Groups filtered by a search query (matches the id, label or offset). */
export function filterTimezoneGroups(groups: TimezoneGroup[], query: string): TimezoneGroup[] {
  let q = query.trim().toLowerCase();
  if (!q) return groups;
  // A zero offset is UTC (the setting stores `+00:00` as `UTC`).
  if (/^(utc)?[-±+]?00:?00$/.test(q)) q = 'utc';
  const bare = q.replace(/^utc/, '');
  return groups
    .map((g) => ({
      region: g.region,
      items: g.items.filter(
        (it) =>
          it.id.toLowerCase().includes(q) ||
          it.label.toLowerCase().includes(q) ||
          (bare !== '' && it.hint.toLowerCase().includes(bare)),
      ),
    }))
    .filter((g) => g.items.length > 0);
}
