// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { CloudPrincipalDossier } from './index';
import type { CloudDossierResponse } from '@/lib/api/types';
const mocks = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { getCloudDossier: mocks.fetch } }));
vi.mock('@/hooks/useSchemaEntityMap', () => ({ useSchemaEntityMap: () => ({ schema: 'ocsf' }) }));
vi.mock('../durable-product-job', () => ({ waitForDurableProductArtifact: () => new Promise(() => {}) }));
vi.mock('./Stream', () => ({ Stream: ({ events }: { events: { id: string }[] }) => <div data-testid="stream">{events.map(e => e.id).join(',')}</div> }));
vi.mock('./IdentityHeader', () => ({ IdentityHeader: () => <div>Full identity</div> }));
vi.mock('./FacetsBand', () => ({ FacetsBand: () => <div>Exact facets</div> }));
vi.mock('./AssumeRoleChain', () => ({ AssumeRoleChain: () => null }));
vi.mock('./TimelineLanes', () => ({ TimelineLanes: () => null }));
vi.mock('./RegionsStrip', () => ({ RegionsStrip: () => null }));
vi.mock('./AuthPosture', () => ({ AuthPosture: () => null }));
vi.mock('./TopActions', () => ({ TopActions: () => null }));
vi.mock('./TopResources', () => ({ TopResources: () => null }));
vi.mock('./ErrorRate', () => ({ ErrorRate: () => null }));
const range = { start: '2026-09-30T00:00:00Z', end: '2026-09-30T01:00:00Z' };
const page = { bounded_preview: true, identity: { id: 'alice' }, facets: { provider: [] }, error_rate: { events_total: 1 }, stream: [{ id: 'newest' }] } as unknown as CloudDossierResponse;
afterEach(() => { cleanup(); mocks.fetch.mockReset(); });
it('paints the event page while exact aggregates remain pending, then replaces the sample', async () => {
  let resolve!: (value: CloudDossierResponse) => void;
  mocks.fetch.mockImplementation((request) => request.fetch === 'page' ? Promise.resolve(page) : new Promise(r => { resolve = r; }));
  render(<CloudPrincipalDossier principal="alice" timeRange={range} />);
  await waitFor(() => expect(screen.getByTestId('stream').textContent).toBe('newest'));
  expect(screen.queryByText('Exact facets')).toBeNull();
  expect(screen.getByRole('status').textContent).toContain('summaries loading');
  await act(async () => resolve({ ...page, bounded_preview: false, error_rate: { events_total: 900 } } as CloudDossierResponse));
  expect(screen.getByText('Exact facets')).toBeTruthy();
  expect(screen.queryByRole('status')).toBeNull();
});
it('keeps the page visible when independent aggregate work fails', async () => {
  mocks.fetch.mockImplementation((request) => request.fetch === 'page' ? Promise.resolve(page) : Promise.reject(new Error('aggregate unavailable')));
  render(<CloudPrincipalDossier principal="alice" timeRange={range} />);
  await waitFor(() => expect(screen.getByText(/aggregate unavailable/)).toBeTruthy());
  expect(screen.getByTestId('stream').textContent).toBe('newest');
  expect(screen.getByRole('status').textContent).toContain('summaries unavailable');
  expect(screen.queryByText('Exact facets')).toBeNull();
});
it('aborts preview ownership on pivot and unmount', async () => {
  const signals: AbortSignal[] = [];
  mocks.fetch.mockImplementation((_request, options) => { signals.push(options.signal); return new Promise(() => {}); });
  const mounted = render(<CloudPrincipalDossier principal="alice" timeRange={range} />);
  await waitFor(() => expect(signals).toHaveLength(1));
  mounted.rerender(<CloudPrincipalDossier principal="bob" timeRange={range} />);
  await waitFor(() => expect(signals).toHaveLength(2));
  expect(signals[0].aborted).toBe(true);
  expect(signals[1].aborted).toBe(false);
  mounted.unmount();
  expect(signals[1].aborted).toBe(true);
});

it('keeps the preview visible while a durable exact dossier is queued', async () => {
  mocks.fetch.mockImplementation((request) => request.fetch === 'page' ? Promise.resolve(page) : Promise.resolve({ durable_job: { job_id: 'queued-dossier', status: 'queued' } }));
  render(<CloudPrincipalDossier principal="alice" timeRange={range} />);
  await waitFor(() => expect(screen.getByTestId('stream').textContent).toBe('newest'));
  expect(screen.queryByText('Exact facets')).toBeNull();
  expect(screen.getByRole('status').textContent).toContain('summaries loading');
});
