// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-483 — shared helpers for the per-rule Matches redesign.
// Port of design-ref/shadcn/matches-*.jsx derivation logic against the real
// DetectionMatch API shape. The mockup synthesises rich objects (entity,
// aggregates, isLive); the real API returns only `{ id, detected_at, events }`,
// so the helpers here derive the same view model from raw events.

import type { DetectionMatch, DetectionRule, DailyStat } from '@/lib/api/types';
import { parseUTCTimestamp } from '@/lib/date-utils';

export type EntityType = 'user' | 'service' | 'role' | 'host' | 'ip' | 'other';

export interface MatchEntity {
  id: string;
  label: string;
  type: EntityType;
  raw?: string;
}

export interface MatchView {
  id: string;
  raw: DetectionMatch;
  detectedAt: Date;
  severity: string;
  status: string;
  entity: MatchEntity;
  firstSeen: Date;
  lastSeen: Date;
  uniqueIps: number;
  durationMs: number;
  topActionName?: string;
  region?: string;
  events: Record<string, unknown>[];
}

function stringField(e: Record<string, unknown>, key: string): string | undefined {
  const v = e[key];
  return typeof v === 'string' && v.trim() ? v : undefined;
}

function nestedField(e: Record<string, unknown>, path: string): string | undefined {
  const parts = path.split('.');
  let cur: unknown = e;
  for (const p of parts) {
    if (cur && typeof cur === 'object' && p in (cur as Record<string, unknown>)) {
      cur = (cur as Record<string, unknown>)[p];
    } else {
      return undefined;
    }
  }
  return typeof cur === 'string' && cur.trim() ? cur : undefined;
}

// Entity extraction — a match fires against a grouping key (user, IP, host).
// We don't know which one the rule grouped by without parsing the query, so we
// prefer identity-ish fields first, then fall back to network identifiers.
export function extractEntity(events: Record<string, unknown>[]): MatchEntity {
  if (!events || events.length === 0) {
    return { id: 'unknown', label: 'unknown', type: 'other' };
  }
  const e = events[0];

  const arn = nestedField(e, 'user_identity.arn');
  if (arn) {
    const label = arn.split('/').pop() || arn;
    const isRole = arn.includes(':role/');
    const isService = label.includes('-service') || label.includes('lambda-') || label.includes('ci-');
    return {
      id: arn,
      label,
      type: isRole ? 'role' : isService ? 'service' : 'user',
      raw: arn,
    };
  }

  const user = stringField(e, 'user');
  if (user) return { id: user, label: user, type: 'user', raw: user };

  const host = stringField(e, 'src_host') || stringField(e, 'hostname') || stringField(e, 'dest_host');
  if (host) return { id: host, label: host, type: 'host', raw: host };

  const ip = stringField(e, 'src_ip') || stringField(e, 'dest_ip');
  if (ip) return { id: ip, label: ip, type: 'ip', raw: ip };

  return { id: 'unknown', label: 'unknown', type: 'other' };
}

// `YYYY-MM-DD[T| ]HH:MM` — gate the aggregate-row scan in `extractEventTime`
// so plain numbers, year strings, and IPs/hostnames don't reach the looser
// `parseUTCTimestamp` and pretend to be timestamps.
const ISO_TIMESTAMP_SHAPE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/;

// Event time fields — try canonical raw-event names first, then fall back to
// scanning the row for any non-underscore string field that parses as a UTC
// timestamp and pick the latest. The fallback handles `stats … by …` aggregate
// rows (NAN-739) where users alias their own time columns (`last_seen`,
// `bucket_end`, etc.) — `_`-prefixed fields are skipped so system-injected
// times like `_nano_detected_at` don't masquerade as the event time.
export function extractEventTime(e: Record<string, unknown>): Date | undefined {
  const direct = stringField(e, 'timestamp')
    || stringField(e, 'eventTime')
    || stringField(e, 'ingest_time')
    || stringField(e, '_time');
  if (direct) return parseUTCTimestamp(direct);

  let best: Date | undefined;
  for (const [k, v] of Object.entries(e)) {
    if (k.startsWith('_')) continue;
    if (typeof v !== 'string' || !ISO_TIMESTAMP_SHAPE.test(v)) continue;
    const d = parseUTCTimestamp(v);
    if (!d || Number.isNaN(d.getTime())) continue;
    if (!best || d.getTime() > best.getTime()) best = d;
  }
  return best;
}

// IP accessor — matches the UDM convention (src_ip) first, then CloudTrail's
// sourceIPAddress so existing fixtures keep rendering.
export function extractIp(e: Record<string, unknown>): string | undefined {
  return stringField(e, 'src_ip')
    || stringField(e, 'sourceIPAddress')
    || stringField(e, 'dest_ip');
}

export function extractAction(e: Record<string, unknown>): string | undefined {
  return stringField(e, 'eventName')
    || stringField(e, 'event_type')
    || stringField(e, 'action')
    || stringField(e, 'event_id');
}

export function extractRegion(e: Record<string, unknown>): string | undefined {
  return stringField(e, 'awsRegion')
    || stringField(e, 'region')
    || stringField(e, 'enriched_src_country');
}

// Event ingest time — when the detection engine fired (as opposed to when the
// log itself was generated). Prefers `_nano_detected_at` (injected by the
// detection engine), falls back to ingest timestamps.
export function extractIngestTime(e: Record<string, unknown>): Date | undefined {
  const ts = stringField(e, '_nano_detected_at')
    || stringField(e, 'ingest_time')
    || stringField(e, 'ingestTime')
    || stringField(e, '_ingest_time');
  return ts ? parseUTCTimestamp(ts) : undefined;
}

export type LatencyLevel = 'fast' | 'moderate' | 'slow';
export interface Latency {
  ms: number;
  level: LatencyLevel;
  formatted: string;
}

export function formatLatency(ms: number): string {
  const mins = Math.abs(ms) / 60000;
  if (mins < 1) return `${Math.round(Math.abs(ms) / 1000)}s`;
  if (mins < 60) return `${Math.round(mins)}m`;
  if (mins < 1440) {
    const h = Math.floor(mins / 60);
    const m = Math.round(mins % 60);
    return m > 0 ? `${h}h ${m}m` : `${h}h`;
  }
  const d = Math.floor(mins / 1440);
  const h = Math.round((mins % 1440) / 60);
  return h > 0 ? `${d}d ${h}h` : `${d}d`;
}

// Latency thresholds — matches the old DetectionMatches page: fast <5m, moderate <15m, else slow.
export function classifyLatency(ms: number): LatencyLevel {
  const mins = Math.abs(ms) / 60000;
  if (mins <= 5) return 'fast';
  if (mins <= 15) return 'moderate';
  return 'slow';
}

// Compute per-event latency: event timestamp → detection/ingest timestamp.
// Falls back to the match's detectedAt when _nano_detected_at isn't present.
export function eventLatency(event: Record<string, unknown>, matchDetectedAt: Date): Latency | null {
  const eventTs = extractEventTime(event);
  if (!eventTs) return null;
  const detectionTs = extractIngestTime(event) || matchDetectedAt;
  const ms = detectionTs.getTime() - eventTs.getTime();
  return { ms, level: classifyLatency(ms), formatted: formatLatency(ms) };
}

// Mean time to detect — average of all available event-level latencies within
// the passed match views. Returns null when no event had parseable timestamps.
export function meanTimeToDetect(views: MatchView[]): Latency | null {
  const samples: number[] = [];
  for (const v of views) {
    for (const e of v.events) {
      const l = eventLatency(e, v.detectedAt);
      if (l && Number.isFinite(l.ms) && l.ms >= 0) samples.push(l.ms);
    }
  }
  if (samples.length === 0) return null;
  const avg = samples.reduce((a, b) => a + b, 0) / samples.length;
  return { ms: avg, level: classifyLatency(avg), formatted: formatLatency(avg) };
}

export function buildMatchView(m: DetectionMatch): MatchView {
  const detectedAt = parseUTCTimestamp(m.detected_at);
  const events = m.events || [];

  const times: Date[] = [];
  const ips = new Set<string>();
  const actionCounts = new Map<string, number>();
  let region: string | undefined;

  for (const e of events) {
    const t = extractEventTime(e);
    if (t) times.push(t);
    const ip = extractIp(e);
    if (ip) ips.add(ip);
    const action = extractAction(e);
    if (action) actionCounts.set(action, (actionCounts.get(action) || 0) + 1);
    if (!region) region = extractRegion(e);
  }

  const firstSeen = times.length ? new Date(Math.min(...times.map((d) => d.getTime()))) : detectedAt;
  const lastSeen = times.length ? new Date(Math.max(...times.map((d) => d.getTime()))) : detectedAt;

  let topActionName: string | undefined;
  let topCount = 0;
  for (const [a, c] of actionCounts) {
    if (c > topCount) { topCount = c; topActionName = a; }
  }

  return {
    id: m.id,
    raw: m,
    detectedAt,
    severity: m.severity,
    status: m.status,
    entity: extractEntity(events),
    firstSeen,
    lastSeen,
    uniqueIps: ips.size,
    durationMs: Math.max(0, lastSeen.getTime() - firstSeen.getTime()),
    topActionName,
    region,
    events,
  };
}

// Action frequency — sorted top N for the detail pane's "Top attempted actions".
export function topActions(events: Record<string, unknown>[], n = 8): Array<[string, number]> {
  const m = new Map<string, number>();
  for (const e of events) {
    const a = extractAction(e);
    if (!a) continue;
    m.set(a, (m.get(a) || 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
}

// 28-day heat strip — aligns per-rule daily stats onto the last N days.
export function buildActivity28(stats: DailyStat[] | undefined, todayCount: number, days = 28): number[] {
  const byDate = new Map(stats?.map((s) => [s.date, s.match_count]) || []);
  const today = new Date();
  const todayStr = today.toISOString().split('T')[0];
  const out: number[] = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const iso = d.toISOString().split('T')[0];
    out.push(iso === todayStr ? todayCount : byDate.get(iso) || 0);
  }
  return out;
}

// MITRE helpers — reuse the primaryTactic logic from rules/helpers.ts would
// create a circular-ish dep; duplicate the tiny slug → label conversion.
export function primaryTactic(rule: DetectionRule | null | undefined): string | undefined {
  const raw = rule?.mitre_tactics?.[0];
  if (!raw) return undefined;
  if (raw.includes('-') || raw === raw.toLowerCase()) {
    return raw
      .split(/[-_\s]+/)
      .map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w))
      .join(' ');
  }
  return raw;
}

export function primaryTechnique(rule: DetectionRule | null | undefined): string | undefined {
  return rule?.mitre_techniques?.[0];
}

export type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEV_META: Record<SeverityKey, { color: string; label: string }> = {
  critical: { color: 'oklch(62% 0.22 18)',  label: 'Critical' },
  high:     { color: 'oklch(72% 0.18 28)',  label: 'High' },
  medium:   { color: 'oklch(78% 0.15 70)',  label: 'Medium' },
  low:      { color: 'oklch(82% 0.10 220)', label: 'Low' },
  info:     { color: 'oklch(72% 0.04 250)', label: 'Info' },
};

export function normalizeSeverity(raw: string): SeverityKey {
  if (raw === 'informational') return 'info';
  if (raw === 'critical' || raw === 'high' || raw === 'medium' || raw === 'low' || raw === 'info') {
    return raw;
  }
  return 'info';
}

// Time formatters — absTime is HH:MM:SS UTC; relTime is "5m ago" style.
export function absTime(d: Date): string {
  const h = String(d.getUTCHours()).padStart(2, '0');
  const m = String(d.getUTCMinutes()).padStart(2, '0');
  const s = String(d.getUTCSeconds()).padStart(2, '0');
  return `${h}:${m}:${s}`;
}

export function relTime(d: Date, now: Date = new Date()): string {
  const sec = Math.floor((now.getTime() - d.getTime()) / 1000);
  if (sec < 0) return 'just now';
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}
