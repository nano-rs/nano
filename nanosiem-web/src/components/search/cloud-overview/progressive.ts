// SPDX-License-Identifier: AGPL-3.0-or-later
import type { CloudOverviewRequest, CloudOverviewResponse } from '@/lib/api/types';

/**
 * NAN-3077: the `| cloud` overview loads as a cheap `page` (header + provider
 * breakdown) followed by four independent cards, each its own
 * `POST /api/search/cloud-overview` with `fetch: <section>`. A slow or failed
 * card never blocks or blanks the others.
 */
export const overviewSections = ['identities', 'services', 'changes', 'denied'] as const;
export type OverviewSection = typeof overviewSections[number];
/** 'loading' | 'ready' | the failure message. */
export type SectionStatus = 'loading' | 'ready' | string;
export type OverviewFetch = NonNullable<CloudOverviewRequest['fetch']>;

export const allSections = (status: SectionStatus): Record<OverviewSection, SectionStatus> =>
  ({ identities: status, services: status, changes: status, denied: status });

/** Merge one card's answer into the overview; order-independent. */
export function mergeOverviewSection(current: CloudOverviewResponse | null, part: CloudOverviewResponse): CloudOverviewResponse {
  const previous = current ?? part;
  switch (part.section) {
    case 'identities': return { ...previous, header: { ...part.header, events_denied: previous.header.events_denied }, accounts: part.accounts, risky_principals: part.risky_principals, timeline: { ...part.timeline, markers: previous.timeline.markers } };
    case 'services': return { ...previous, service_health: part.service_health };
    case 'changes': return { ...previous, anomalies: part.anomalies, changes: part.changes, timeline: { ...previous.timeline, markers: part.timeline.markers } };
    case 'denied': return { ...previous, header: { ...previous.header, events_denied: part.header.events_denied } };
    default: return part;
  }
}

/**
 * Paint the page, then the cards with bounded concurrency (two in flight) so
 * a slow card cannot hold the other lane. Only a request failure (network /
 * HTTP error, including 413 VIEW_TOO_LARGE) marks a card unavailable; the
 * caller's `fetch` owns admission / memory-busy retries. Resolves `full: true`
 * when the server answered the page with a complete (unsectioned) overview.
 * Throws when neither the page nor any card could load.
 */
export async function loadOverviewSections(
  fetch: (section: OverviewFetch) => Promise<CloudOverviewResponse>,
  signal: AbortSignal,
  onPart: (part: CloudOverviewResponse) => void,
  onStatus: (section: OverviewSection, status: SectionStatus) => void,
): Promise<{ full: boolean }> {
  let painted = false;
  try {
    const page = await fetch('page');
    if (signal.aborted) return { full: false };
    onPart(page);
    painted = true;
    // A server without sections answers the whole overview.
    if (!page.section) return { full: true };
  } catch {
    if (signal.aborted) return { full: false };
  }
  let next = 0;
  const worker = async () => {
    while (!signal.aborted && next < overviewSections.length) {
      const section = overviewSections[next++];
      try {
        const part = await fetch(section);
        if (signal.aborted) return;
        onPart(part);
        painted = true;
        onStatus(section, 'ready');
      } catch (error) {
        if (signal.aborted) return;
        onStatus(section, error instanceof Error ? error.message : String(error));
      }
    }
  };
  await Promise.all([worker(), worker()]);
  if (!painted && !signal.aborted) throw new Error('Cloud overview summaries are unavailable');
  return { full: false };
}
