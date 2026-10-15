// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { CloudOverviewView } from './index';
import type { CloudOverviewResponse } from '@/lib/api/types';
const mocks = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { getCloudOverview: mocks.fetch } }));
vi.mock('../cloud-dossier/Stream', () => ({ Stream: () => <div>Preview events</div> }));
vi.mock('./CloudOverviewHeader', () => ({ CloudOverviewHeader: () => <div>Exact identity summary</div> }));
vi.mock('./AccountsGrid', () => ({ AccountsGrid: () => null }));
vi.mock('./RiskyPrincipals', () => ({ RiskyPrincipals: () => null }));
vi.mock('./CrossAccountTimeline', () => ({ CrossAccountTimeline: () => null }));
vi.mock('./AnomalyFeed', () => ({ AnomalyFeed: () => null }));
vi.mock('./ServiceHealth', () => ({ ServiceHealth: () => <div>Exact service health</div> }));
vi.mock('./TopChanges', () => ({ TopChanges: () => null }));
const range = { start: '2026-09-30T00:00:00Z', end: '2026-09-30T01:00:00Z' };
function response(section: CloudOverviewResponse['section']) {
  return { section, header: { providers: [], events_total: 42, events_denied: 3 }, timeline: { markers: [], lanes: [], points: [] }, accounts: [], risky_principals: [], service_health: [], anomalies: [], changes: [], preview_events: section === 'page' ? [{}] : [] } as unknown as CloudOverviewResponse;
}
afterEach(() => { cleanup(); mocks.fetch.mockReset(); });
it('renders preview events and service health before the slow identity card', async () => {
  let release!: (value: CloudOverviewResponse) => void;
  mocks.fetch.mockImplementation(request => request.fetch === 'identities' ? new Promise(resolve => { release = resolve; }) : Promise.resolve(response(request.fetch)));
  const mounted = render(<CloudOverviewView timeRange={range} query="| cloud" />);
  await waitFor(() => expect(screen.getByText('Exact service health')).toBeTruthy());
  expect(screen.getByText('Preview events')).toBeTruthy();
  expect(screen.queryByText('Exact identity summary')).toBeNull();
  expect(screen.getByText(/Identity and risk: loading/)).toBeTruthy();
  await act(async () => release(response('identities')));
  expect(screen.getByText('Exact identity summary')).toBeTruthy();
  mounted.unmount();
});
it('reports failed identity work without removing successful cards and aborts ownership on unmount', async () => {
  const signals: AbortSignal[] = [];
  mocks.fetch.mockImplementation((request, options) => { signals.push(options.signal); return request.fetch === 'identities' ? Promise.reject(new Error('identity unavailable')) : Promise.resolve(response(request.fetch)); });
  const mounted = render(<CloudOverviewView timeRange={range} />);
  await waitFor(() => expect(screen.getByText(/Identity and risk: unavailable/)).toBeTruthy());
  expect(screen.getByText('Exact service health')).toBeTruthy();
  expect(screen.getByText('Preview events')).toBeTruthy();
  mounted.unmount();
  expect(signals.every(signal => signal.aborted)).toBe(true);
});
