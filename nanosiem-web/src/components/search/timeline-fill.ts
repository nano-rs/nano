// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Plot raw histogram counts once per bucket. Bucket starts remain the identity
 * used by tooltips and zoom; x is the bucket midpoint (clipped for line/area).
 * Line/area endpoints sit on the query boundaries; partial connections use a
 * separate dashed series. Counts are never rescaled or extrapolated.
 */

export interface TimelineBucket {
  time: string;
  timestamp: number;
  events: number;
}

export interface TimelinePlotPoint extends TimelineBucket {
  /** X position on the numeric time axis (ms). */
  x: number;
  /** Bucket width (ms) — tooltips render `timestamp → timestamp + bucketMs`. */
  bucketMs: number;
  /** True when the query window covers only part of this bucket. */
  partial: boolean;
  /** Visible part of a partial bucket, in epoch ms. */
  partialSpan: [number, number] | null;
  /** Tooltip description of the bucket's coverage. */
  partialLabel: string | null;
  /** Full-bucket series and the connections touching a partial bucket. */
  solid: number | null;
  leadingPartial: number | null;
  trailingPartial: number | null;
}

export interface BuildTimelinePlotOptions {
  /** Bucket width in ms. */
  bucketMs: number;
  /** Rendered x-axis domain [start, end] (ms); null when unknown. */
  domain: [number, number] | null;
  /**
   * The query window [start, end] (ms) used to decide partiality; null when
   * unknown (then nothing is flagged partial).
   */
  window: [number, number] | null;
  /** Bars retain their midpoint; line/area place endpoints on query boundaries. */
  chartType: 'bar' | 'line' | 'area';
  /** Static (timechart) mode: no transform — points sit at their timestamps. */
  staticMode?: boolean;
}

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

/** Static / passthrough mapping: one point per bucket at its timestamp. */
function passthrough(data: TimelineBucket[], bucketMs: number): TimelinePlotPoint[] {
  return data.map((d) => ({
    ...d,
    x: d.timestamp,
    bucketMs,
    partial: false,
    partialSpan: null,
    partialLabel: null,
    solid: d.events,
    leadingPartial: null,
    trailingPartial: null,
  }));
}

export function buildTimelinePlotData(
  data: TimelineBucket[],
  { bucketMs, domain, window, chartType, staticMode = false }: BuildTimelinePlotOptions,
): TimelinePlotPoint[] {
  if (data.length === 0) return [];
  if (staticMode || !(bucketMs > 0)) return passthrough(data, bucketMs);

  const sorted = [...data].sort((a, b) => a.timestamp - b.timestamp);
  const lastIdx = sorted.length - 1;

  // A bucket is partial when the query window boundary falls strictly INSIDE
  // it. A boundary outside the bucket (e.g. an in-query `earliest=` widened
  // the search past the picker, NAN-1454) says nothing about this bucket.
  const isPartial = (b: TimelineBucket, i: number): boolean => {
    if (!window) return false;
    const start = b.timestamp;
    const end = b.timestamp + bucketMs;
    if (i === 0 && window[0] > start && window[0] < end) return true;
    if (i === lastIdx && window[1] > start && window[1] < end) return true;
    return false;
  };

  const points = sorted.map((b, i) => {
    const partial = isPartial(b, i);
    const partialSpan: [number, number] | null = partial && window
      ? [Math.max(b.timestamp, window[0]), Math.min(b.timestamp + bucketMs, window[1])]
      : null;
    const minutes = (ms: number) => Number((ms / 60_000).toFixed(2));
    const midpoint = b.timestamp + bucketMs / 2;
    // A tiny clipped bucket still needs an ordinary visible point. Bars keep
    // their true centre so clipping never shifts the span they represent.
    const visible = chartType === 'bar' ? partialSpan ?? domain : window ?? domain;
    return {
      ...b,
      x: chartType === 'bar' || !visible ? midpoint
        : i === 0 ? visible[0] : i === lastIdx ? visible[1] : clamp(midpoint, visible[0], visible[1]),
      bucketMs,
      partial,
      solid: partial && chartType !== 'bar' ? null : b.events,
      leadingPartial: null as number | null,
      trailingPartial: null as number | null,
      partialSpan,
      partialLabel: partialSpan
        ? `partial bucket · ${minutes(partialSpan[1] - partialSpan[0])} of ${minutes(bucketMs)} min in range`
        : null,
    };
  });
  if (chartType !== 'bar') {
    points.forEach((p, i) => {
      if (points[0].partial && i <= 1) p.leadingPartial = p.events;
      if (points[lastIdx].partial && i >= lastIdx - 1 && !(lastIdx <= 1 && points[0].partial)) p.trailingPartial = p.events;
    });
  }
  return points;
}

/** A single bucket needs two render vertices; accounting still uses plotData. */
export function timelineSeriesData(points: TimelinePlotPoint[], chartType: BuildTimelinePlotOptions['chartType'], domain: [number, number] | null): TimelinePlotPoint[] {
  if (chartType === 'bar' || points.length !== 1 || !domain) return points;
  return [{ ...points[0], x: domain[0] }, { ...points[0], x: domain[1] }];
}

/** Line/area use the executed query window; bars keep their existing extent. */
export function timelinePlotDomain(
  chartType: BuildTimelinePlotOptions['chartType'],
  window: [number, number] | null,
  extent: [number, number] | null,
): [number, number] | null {
  return chartType === 'bar' ? extent : window ?? extent;
}

/**
 * Map a recharts mouse event on the plotted data back to the bucket START it
 * belongs to, so click / drag-to-zoom keep their bucket-start contract.
 */
export function resolveBucketStart(
  points: TimelinePlotPoint[],
  e: { activeTooltipIndex?: unknown; activeIndex?: unknown; activeLabel?: unknown } | null | undefined,
): number | undefined {
  if (!e) return undefined;
  const rawIdx = e.activeTooltipIndex ?? e.activeIndex;
  if (rawIdx != null && rawIdx !== '') {
    const idx = Number(rawIdx);
    if (Number.isInteger(idx) && idx >= 0 && idx < points.length) return points[idx].timestamp;
  }
  if (e.activeLabel != null && e.activeLabel !== '') {
    const label = Number(e.activeLabel);
    if (Number.isFinite(label)) {
      const hit = points.find((p) => p.x === label);
      if (hit) return hit.timestamp;
    }
  }
  return undefined;
}
