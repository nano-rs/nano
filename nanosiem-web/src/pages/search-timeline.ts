// SPDX-License-Identifier: AGPL-3.0-or-later
import { formatTimelineLabel, parseUTCTimestamp } from '@/lib/date-utils';

export interface TimelinePoint {
  time: string;
  timestamp: number;
  events: number;
}

export interface SearchTimelineInput {
  /** The server's normalized histogram companion (base-search event counts). */
  histogramData: ReadonlyArray<{ time: string; count: number }>;
  /** Result rows; only a timechart's `time_bucket` rows carry a real time axis. */
  results: ReadonlyArray<{ fields?: Record<string, unknown> }>;
  isAggregateQuery: boolean;
  spansDays: boolean;
  showSeconds: boolean;
}

/**
 * The Search page timeline: the server histogram when present, otherwise the
 * `time_bucket` rows of a timechart-shaped aggregate, otherwise nothing.
 *
 * NAN-3062: this never invents a timeline from rows that lack a real time
 * axis. A `… | stats count by host` row has no event timestamp, so bucketing
 * those rows put every group into one "now" bucket, which showed up as a
 * single dot at the far right of the chart. Paginated event pages can't
 * produce a timeline either: they are one page, not the whole window.
 */
export function buildSearchTimeline({
  histogramData,
  results,
  isAggregateQuery,
  spansDays,
  showSeconds,
}: SearchTimelineInput): TimelinePoint[] {
  if (histogramData.length > 0) {
    // Buckets that format to the same label are merged, keeping the earliest timestamp.
    const labelMap = new Map<string, { timestamp: number; events: number }>();
    for (const bucket of histogramData) {
      const time = parseUTCTimestamp(bucket.time);
      const label = formatTimelineLabel(time, spansDays, showSeconds);
      const existing = labelMap.get(label);
      if (existing) {
        existing.events += bucket.count;
        existing.timestamp = Math.min(existing.timestamp, time.getTime());
      } else {
        labelMap.set(label, { timestamp: time.getTime(), events: bucket.count });
      }
    }
    return Array.from(labelMap.entries())
      .map(([time, data]) => ({ time, timestamp: data.timestamp, events: data.events }))
      .sort((a, b) => a.timestamp - b.timestamp);
  }

  if (!isAggregateQuery || !results[0]?.fields?.time_bucket) {
    return [];
  }

  return results
    .filter((r) => r.fields?.time_bucket)
    .map((result) => {
      const fields = result.fields as Record<string, unknown>;
      const timeBucket = parseUTCTimestamp(fields.time_bucket as string);
      const countField = Object.keys(fields).find(
        (k) => k.toLowerCase() === 'count' || k.toLowerCase().startsWith('count('),
      );
      const events = countField ? Number(fields[countField]) || 1 : 1;
      return {
        time: formatTimelineLabel(timeBucket, spansDays, showSeconds),
        timestamp: timeBucket.getTime(),
        events,
      };
    })
    .sort((a, b) => a.timestamp - b.timestamp);
}
