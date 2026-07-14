import type { Tab } from '../state/tabs';
import type { SchemaProfile } from './types';

/**
 * What the analyst can currently see. Handed to pivt on every ask, so it starts
 * from the same picture they have rather than re-fetching what's already on
 * their screen.
 *
 * Deliberately a snapshot of the VISIBLE state — not the whole result set. The
 * Rust side caps how many rows it forwards and says so in the prompt, so the
 * assistant can't imply it reviewed events it never saw.
 */
export interface ScreenContext {
  screen: string;
  query: string;
  time_range: string;
  schema: string;
  status: string;
  total_count: number | null;
  histogram: string | null;
  rows: Record<string, unknown>[];
  expanded_event: Record<string, unknown> | null;
}

export function buildScreenContext(
  tab: Tab,
  profile: SchemaProfile,
  expandedEvent: Record<string, unknown> | null
): ScreenContext {
  return {
    screen: 'Search',
    query: tab.ranQuery || tab.query,
    time_range: tab.ranRange ? `${tab.ranRange.start} → ${tab.ranRange.end}` : describeRange(tab),
    schema: profile.isOcsf ? 'ocsf' : 'udm',
    status: tab.status,
    total_count: tab.metadata?.total_count ?? null,
    histogram: describeHistogram(tab),
    rows: tab.rows,
    expanded_event: expandedEvent,
  };
}

function describeRange(tab: Tab): string {
  if (tab.range.type === 'preset') return tab.range.preset ?? '';
  if (tab.range.start && tab.range.end) {
    return `${tab.range.start.toISOString()} → ${tab.range.end.toISOString()}`;
  }
  return '';
}

/**
 * The shape of the histogram is often the whole question ("why did this spike?"),
 * and it's cheaper to describe than to ship 337 buckets of JSON.
 */
function describeHistogram(tab: Tab): string | null {
  const buckets = tab.metadata?.histogram;
  if (!buckets?.length) return null;

  let peak = buckets[0];
  let total = 0;
  for (const bucket of buckets) {
    total += bucket.count;
    if (bucket.count > peak.count) peak = bucket;
  }
  const mean = total / buckets.length;
  const spike = peak.count > mean * 3 && peak.count > 0;

  return [
    `${buckets.length} buckets from ${buckets[0].time} to ${buckets[buckets.length - 1].time}`,
    `peak ${peak.count} at ${peak.time}`,
    `mean ${mean.toFixed(1)} per bucket`,
    spike ? 'the peak is >3x the mean — a visible spike' : 'no pronounced spike',
  ].join('; ');
}
