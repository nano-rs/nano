// SPDX-License-Identifier: AGPL-3.0-or-later
import type { CloudOverviewRequest, CloudOverviewResponse } from '@/lib/api/types';
export const overviewSections = ['identities', 'services', 'changes', 'denied'] as const;
export type OverviewSection = typeof overviewSections[number];
export type SectionStatus = 'loading' | 'ready' | string;

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

/** Bounded concurrency: a slow card cannot block the other lane. */
export async function loadOverviewSections(
  fetch: (section: NonNullable<CloudOverviewRequest['fetch']>) => Promise<CloudOverviewResponse>,
  signal: AbortSignal,
  onPart: (part: CloudOverviewResponse) => void,
  onStatus: (section: OverviewSection, status: SectionStatus) => void,
): Promise<{ needsDurable: boolean; full: boolean }> {
  let needsDurable = false;
  let painted = false;
  try {
    const page = await fetch('page');
    if (signal.aborted) return { needsDurable: false, full: false };
    if (page.durable_job || page.requires_durable) needsDurable = true;
    else {
      onPart(page);
      painted = true;
      if (!page.section) return { needsDurable: false, full: true };
    }
  } catch { if (signal.aborted) return { needsDurable: false, full: false }; }
  let next = 0;
  const worker = async () => {
    while (!signal.aborted && next < overviewSections.length) {
      const section = overviewSections[next++];
      try {
        const part = await fetch(section);
        if (signal.aborted) return;
        if (part.requires_durable || part.durable_job) {
          needsDurable = true;
          onStatus(section, 'Exact summary requires a durable job');
        } else {
          onPart(part);
          painted = true;
          onStatus(section, 'ready');
        }
      } catch (error) {
        if (signal.aborted) return;
        onStatus(section, error instanceof Error ? error.message : String(error));
      }
    }
  };
  await Promise.all([worker(), worker()]);
  if (!painted && !needsDurable && !signal.aborted) throw new Error('Cloud overview summaries are unavailable');
  return { needsDurable, full: false };
}
