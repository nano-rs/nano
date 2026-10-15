// SPDX-License-Identifier: AGPL-3.0-or-later
import { expect, it, vi } from 'vitest';
import { loadOverviewSections, mergeOverviewSection } from './progressive';
import type { CloudOverviewResponse } from '@/lib/api/types';
function part(section: CloudOverviewResponse['section']): CloudOverviewResponse {
  return { section, header: { events_total: 42, events_denied: section === 'denied' ? 3 : 0 }, timeline: { markers: section === 'changes' ? ['change'] : [], lanes: section === 'identities' ? ['identity'] : [], points: [] }, accounts: [], risky_principals: [], service_health: [], anomalies: [], changes: [], preview_events: [] } as unknown as CloudOverviewResponse;
}
it('paints a bounded page and fast cards while identity remains pending, with at most two requests', async () => {
  let release!: (value: CloudOverviewResponse) => void;
  let active = 0; let maximum = 0;
  const painted: string[] = [];
  const fetch = vi.fn(async (section) => {
    active++; maximum = Math.max(maximum, active);
    const answer = section === 'identities' ? await new Promise<CloudOverviewResponse>(resolve => { release = resolve; }) : part(section);
    active--; return answer;
  });
  const loading = loadOverviewSections(fetch, new AbortController().signal, result => painted.push(result.section!), vi.fn());
  await vi.waitFor(() => expect(painted).toEqual(['page', 'services', 'changes', 'denied']));
  expect(maximum).toBe(2);
  release(part('identities'));
  await loading;
  expect(painted[4]).toBe('identities');
});
it('keeps independent cards after a failure and stops new work after cancellation', async () => {
  const statuses = vi.fn();
  const painted: string[] = [];
  await loadOverviewSections(async section => { if (section === 'identities') throw new Error('risk unavailable'); return part(section as CloudOverviewResponse['section']); }, new AbortController().signal, result => painted.push(result.section!), statuses);
  expect(statuses).toHaveBeenCalledWith('identities', 'risk unavailable');
  expect(painted).toContain('services');
  const controller = new AbortController();
  const fetch = vi.fn(async () => { controller.abort(); return part('page'); });
  const paint = vi.fn();
  await loadOverviewSections(fetch, controller.signal, paint, statuses);
  expect(fetch).toHaveBeenCalledTimes(1); expect(paint).not.toHaveBeenCalled();
});
it('merges card results identically regardless of completion order', () => {
  const orders = [['identities', 'services', 'changes', 'denied'], ['denied', 'changes', 'services', 'identities']] as const;
  const merged = orders.map(order => order.reduce<CloudOverviewResponse | null>((current, section) => mergeOverviewSection(current, part(section)), part('page'))!);
  expect(merged[0]).toEqual(merged[1]);
  expect(merged[0].header.events_total).toBe(42);
  expect(merged[0].header.events_denied).toBe(3);
  expect(merged[0].timeline.markers).toEqual(['change']);
  expect(merged[0].timeline.lanes).toEqual(['identity']);
});
it('coalesces oversized card results into a single durable fallback decision', async () => {
  const outcome = await loadOverviewSections(async section => ({ ...part(section as CloudOverviewResponse['section']), requires_durable: section === 'identities' || section === 'services' }), new AbortController().signal, vi.fn(), vi.fn());
  expect(outcome.needsDurable).toBe(true);
});

it('reports an error if neither the preview nor any card can load', async () => {
  await expect(loadOverviewSections(async () => { throw new Error('offline'); }, new AbortController().signal, vi.fn(), vi.fn())).rejects.toThrow('summaries are unavailable');
});
