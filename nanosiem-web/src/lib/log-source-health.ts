// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-3207: pure helpers for the log source health chart (sorting, segment
 * keys, `?segment=` parsing, source/segment-scoped Search links).
 */
import type { HealthSeriesPoint, LogSourceHealthSeries, SegmentHealthSeries, SourceHealthState } from '@/lib/api';
import { nplFieldEquals } from '@/lib/npl-quote';

/** Sort rank: attention states first. */
export const HEALTH_STATE_RANK: Record<SourceHealthState, number> = {
  segment_drop: 0,
  stale: 1,
  degraded: 2,
  healthy: 3,
  learning: 4,
  unknown: 5,
  disabled: 6,
};

export function healthStateRank(state: SourceHealthState): number {
  return HEALTH_STATE_RANK[state] ?? HEALTH_STATE_RANK.unknown;
}

/** Attention states (segment_drop, stale, degraded) first, then by name. */
export function sortHealthSeries(series: LogSourceHealthSeries[]): LogSourceHealthSeries[] {
  return [...series].sort(
    (a, b) =>
      healthStateRank(a.state) - healthStateRank(b.state) ||
      a.log_source_name.localeCompare(b.log_source_name),
  );
}

/**
 * NAN-3246: baseline progress of a `learning` source or segment, e.g.
 * `{ short: '2/3d', long: 'Learning baseline: 2 of 3 days collected' }`;
 * null for every other state (or when the server sent no progress).
 */
export function learningProgress(
  s: Pick<LogSourceHealthSeries, 'state' | 'baseline_days' | 'baseline_days_required'>,
): { short: string; long: string } | null {
  if (s.state !== 'learning') return null;
  const required = s.baseline_days_required;
  if (typeof required !== 'number' || required <= 0) return { short: '', long: 'Learning baseline' };
  const days = Math.min(Math.max(0, s.baseline_days ?? 0), required);
  return {
    short: `${days}/${required}d`,
    long: `Learning baseline: ${days} of ${required} day${required === 1 ? '' : 's'} of history collected`,
  };
}

export function segmentKey(s: Pick<SegmentHealthSeries, 'dimension' | 'value'>): string {
  return `${s.dimension}:${s.value}`;
}

const HOUR_MS = 3_600_000;

/**
 * Search scoped to a source's slugs (`metadata.log_source`, the field Search
 * scopes by on the lake), optionally narrowed to one segment value and to a
 * time window.
 */
export function healthSearchHref(
  sourceSlugs: string[],
  opts: { field?: string; value?: string; start?: string; end?: string; sourceField?: string } = {},
): string {
  const sourceField = opts.sourceField ?? 'metadata.log_source';
  const scope =
    sourceSlugs.length === 1
      ? nplFieldEquals(sourceField, sourceSlugs[0])
      : sourceSlugs.length > 1
        ? `(${sourceSlugs.map((s) => nplFieldEquals(sourceField, s)).join(' OR ')})`
        : '';
  const segment = opts.field && opts.value != null ? nplFieldEquals(opts.field, opts.value) : '';
  const q = [scope, segment].filter(Boolean).join(' ');
  const params = new URLSearchParams();
  if (q) params.set('q', q);
  if (opts.start && opts.end) {
    params.set('start', opts.start);
    params.set('end', opts.end);
  }
  return `/search#${params.toString()}`;
}

export function hourWindow(points: HealthSeriesPoint[], idx?: number): { start?: string; end?: string } {
  if (!points.length) return {};
  const from = idx ?? 0;
  const to = idx ?? points.length - 1;
  const s = new Date(points[from].hour).getTime();
  const e = new Date(points[to].hour).getTime() + HOUR_MS;
  if (Number.isNaN(s) || Number.isNaN(e)) return {};
  return { start: new Date(s).toISOString(), end: new Date(e).toISOString() };
}


/** `?segment=<dimension>:<value>` → segment key (value may itself contain ':'). */
export function parseSegmentParam(raw: string | null): string | null {
  if (!raw) return null;
  const i = raw.indexOf(':');
  if (i <= 0 || i === raw.length - 1) return null;
  return `${raw.slice(0, i)}:${raw.slice(i + 1)}`;
}
