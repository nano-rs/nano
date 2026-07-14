import type { PanelQueryResponse } from './types';

/**
 * Turning a panel's rows into something a chart can draw.
 *
 * This is the part of dashboard rendering that is easy to get subtly, silently
 * wrong. Rows arrive as objects whose keys are alphabetised by serde, so `typeof`
 * alone cannot tell a numeric GROUP-BY (`dest_port`, `status_code`) from a numeric
 * AGGREGATE (`count`). Guess wrong and `stats count by dest_port` renders with the
 * port number as the bar height — a chart that is confidently, plausibly false.
 *
 * `column_order` from the server is what resolves it: group-bys first, aggregates
 * last. Passing it through is load-bearing, not optional.
 */

/** The names an aggregate goes by. Mirrors the web renderer's MEASURE_PREFIX. */
const MEASURE =
  /^(count|sum|avg|mean|min|max|median|mode|range|stdev|var|dc|estdc|distinct_count|values|list|first|last|earliest|latest|percentile|p\d{1,3})(_.*)?$/i;

/** A column holding the x-axis of a time series. */
const TIME_KEY = /(^|_)(time|timestamp|bucket|ts)($|_)|time_bucket/i;

export interface PanelData {
  rows: Record<string, unknown>[];
  /**
   * The column that names each point — a time bucket, or a group-by value. EMPTY
   * when the result has no group-by at all (`| stats count`), which is the normal
   * shape of a single_value panel.
   */
  labelKey: string;
  /** The numeric columns to plot. */
  valueKeys: string[];
  /** Whether labelKey is a time axis (decides densification and label format). */
  isTime: boolean;
  /**
   * The aggregate the series were pivoted FROM (`count`, `avg_duration`, …).
   *
   * After a split-by pivot the value keys are group NAMES (`allow`, `deny`), and
   * nothing about them says whether a missing bucket means zero. Only the measure
   * knows: a missing COUNT is 0, a missing AVERAGE is undefined.
   */
  measure?: string;
}

function isTimeKey(key: string): boolean {
  return TIME_KEY.test(key);
}

function isNumeric(value: unknown): boolean {
  return typeof value === 'number' && Number.isFinite(value);
}

/**
 * Column order, honouring the server's when it gave one.
 *
 * Without `column_order` we fall back to key order, which serde has alphabetised —
 * so `{count, source_type}` arrives with the AGGREGATE first. Hence the explicit
 * measure test rather than "first key is the label".
 */
function orderedColumns(rows: Record<string, unknown>[], columnOrder?: string[]): string[] {
  const present = new Set<string>();
  for (const row of rows) for (const key of Object.keys(row)) present.add(key);

  if (columnOrder?.length) {
    const ordered = columnOrder.filter((key) => present.has(key));
    for (const key of present) if (!ordered.includes(key)) ordered.push(key);
    return ordered;
  }
  return [...present];
}

export function classify(response: PanelQueryResponse): PanelData {
  const rows = response.results ?? [];
  if (rows.length === 0) {
    return { rows, labelKey: '', valueKeys: [], isTime: false };
  }

  const columns = orderedColumns(rows, response.column_order);
  const numeric = columns.filter((key) => rows.some((row) => isNumeric(row[key])));

  // MEASURES FIRST. A column is a measure because of what it's CALLED (`count`,
  // `avg_bytes`), not because it holds a number — `dest_port` and `status_code`
  // are numbers and are emphatically not measures. Deciding the label first and
  // then "whatever numbers are left" gets this backwards, and consumes the only
  // measure of a `| stats count` panel as its label.
  const measures = columns.filter((key) => numeric.includes(key) && MEASURE.test(key));

  // Dimensions are everything that isn't a measure — INCLUDING numeric ones.
  const dimensions = columns.filter((key) => !measures.includes(key));

  // A time column always wins the x-axis, whatever the order says.
  const timeColumn = dimensions.find(isTimeKey);

  // With no dimension at all (`| stats count`) there is nothing to label a point
  // WITH, and that is fine — a single_value panel has one number and no axis.
  // Claiming a label here would eat the measure.
  const labelKey = timeColumn ?? dimensions[0] ?? '';

  // Fall back to any numeric non-label column when nothing is named like an
  // aggregate (a hand-written query with unusual `as` aliases).
  const fallback = numeric.filter((key) => key !== labelKey);
  const valueKeys = measures.length > 0 ? measures : fallback;

  return {
    rows,
    labelKey,
    valueKeys,
    isTime: Boolean(timeColumn),
    measure: valueKeys.length === 1 ? valueKeys[0] : undefined,
  };
}

/**
 * `| timechart count by action` comes back LONG — one row per (bucket, action).
 * A chart wants it WIDE: one row per bucket, one column per action. Without this
 * the series overwrite each other and the chart shows only the last group.
 */
export function pivotSplitBy(data: PanelData): PanelData {
  const { rows, labelKey, valueKeys, isTime } = data;
  if (!isTime || valueKeys.length !== 1 || !labelKey) return data;

  const value = valueKeys[0];

  // The split column is any DIMENSION besides the time bucket — and a dimension
  // can be numeric. `timechart count by status_code` splits on numbers; refusing
  // to pivot it left the rows in long form, where densify's bucket map then kept
  // only the LAST group per bucket and plotted the 5xx count as the total traffic.
  const splitKey = Object.keys(rows[0] ?? {}).find(
    (key) => key !== labelKey && key !== value && !MEASURE.test(key)
  );
  if (!splitKey) return data;

  const buckets = new Map<string, Record<string, unknown>>();
  const series = new Set<string>();

  for (const row of rows) {
    const at = String(row[labelKey]);
    const name = String(row[splitKey]);
    series.add(name);
    const bucket = buckets.get(at) ?? { [labelKey]: row[labelKey] };
    bucket[name] = row[value];
    buckets.set(at, bucket);
  }

  return {
    rows: [...buckets.values()],
    labelKey,
    valueKeys: [...series],
    isTime,
    // The series are now group NAMES. Remember what they were counts OF, or a
    // missing bucket can't be told apart from a missing average.
    measure: value,
  };
}

/**
 * Insert the buckets the query didn't return.
 *
 * A timechart only emits buckets that HAD events. Plotted as-is, an hour with 400
 * events and an hour with 3 — a day apart — become adjacent points, and the line
 * reads as a continuous rate that never dipped. Same bug class as a truncated
 * series: the chart states something the data doesn't.
 *
 * A missing bucket is 0 for a COUNT (nothing happened) but NULL for an average
 * (the average of no events is undefined, not zero — drawing it as zero invents a
 * dip to the floor).
 */
export function densify(data: PanelData): PanelData {
  const { rows, labelKey, valueKeys, isTime, measure } = data;
  if (!isTime || rows.length < 2 || !labelKey) return data;

  const times = rows.map((row) => new Date(String(row[labelKey])).getTime());
  if (times.some((time) => !Number.isFinite(time))) return data;

  // The span is the smallest gap between consecutive buckets.
  let span = Infinity;
  for (let index = 1; index < times.length; index += 1) {
    const gap = times[index] - times[index - 1];
    if (gap > 0 && gap < span) span = gap;
  }
  if (!Number.isFinite(span) || span <= 0) return data;

  const first = times[0];
  const last = times[times.length - 1];

  // A pathological span would fabricate a million points; leave it alone.
  const steps = Math.round((last - first) / span);
  if (steps + 1 > 2000) return data;

  // BUCKETS ARE NOT ALWAYS EVENLY SPACED. `span=1mon` gives gaps of 28, 30 and 31
  // days, so a grid built by repeatedly adding the SMALLEST gap misses every real
  // bucket after the first — and, walking that grid, each miss gets zero-filled.
  // Five monthly data points became one real value and four invented zeros.
  //
  // So: snap each row to its nearest slot, and if the rows don't fit the grid at
  // all, don't densify. Better an undrawn gap than a fabricated one.
  const slots = new Map<number, Record<string, unknown>>();
  for (let index = 0; index < rows.length; index += 1) {
    slots.set(Math.round((times[index] - first) / span), rows[index]);
  }
  if (steps < rows.length - 1 || slots.size !== rows.length) return data;

  const dense: Record<string, unknown>[] = [];
  for (let step = 0; step <= steps; step += 1) {
    const existing = slots.get(step);
    if (existing) {
      dense.push(existing);
      continue;
    }
    const filled: Record<string, unknown> = {
      [labelKey]: new Date(first + step * span).toISOString(),
    };
    // Zero-fill is decided by the MEASURE, not by the series name. After a
    // split-by pivot the series are called `allow`/`deny`, which say nothing about
    // whether an absent bucket is zero — testing those names always said "no" and
    // turned every quiet hour of a count series into a hole in the line.
    const zero = zeroFills(measure ?? valueKeys[0] ?? '');
    for (const key of valueKeys) {
      filled[key] = zero ? 0 : null;
    }
    dense.push(filled);
  }

  return { ...data, rows: dense };
}

/** A count of nothing is 0. An average of nothing is not. */
function zeroFills(key: string): boolean {
  return /^(count|sum|dc|estdc|distinct_count)(_.*)?$/i.test(key);
}

export function preparePanelData(response: PanelQueryResponse): PanelData {
  return densify(pivotSplitBy(classify(response)));
}

/** Recharts wants a plain string for the axis; a bucket wants a readable time. */
export function formatLabel(value: unknown, isTime: boolean): string {
  if (!isTime) return String(value ?? '');
  const parsed = new Date(String(value));
  if (Number.isNaN(parsed.getTime())) return String(value ?? '');
  return parsed.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/** The web app's series palette, so the two clients colour a panel the same. */
export const SERIES_COLORS = [
  '#3b82f6',
  '#22c55e',
  '#eab308',
  '#ef4444',
  '#a855f7',
  '#06b6d4',
  '#f97316',
  '#ec4899',
];
