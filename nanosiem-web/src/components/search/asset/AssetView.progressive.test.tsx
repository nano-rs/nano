// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

// NAN-3252: the lean Asset page must paint every partial dossier / artifact
// answer while `progress.complete` is false, mark it as refining, and never
// leave Rarity on a bare spinner.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AssetView } from './index';

const mocks = vi.hoisted(() => ({
  dossier: vi.fn(),
  events: vi.fn(),
  artifacts: vi.fn(),
}));
vi.mock('@/lib/api', () => ({
  api: {
    getAssetDossier: mocks.dossier,
    getAssetEvents: mocks.events,
    getAssetArtifacts: mocks.artifacts,
    getEntityContext: () => Promise.reject(new Error('not in this test')),
    getSchemaFields: async () => ({ schema: 'ocsf', fields: [] }),
    fetchLog: async () => ({ event: null }),
  },
}));
vi.mock('@/enterprise/components/risk/watchlists/AddToWatchlistMenu', () => ({
  AddToWatchlistMenu: ({ children }: { children?: unknown }) => children ?? null,
}));

const timeRange = { start: '2026-10-07T22:00:00Z', end: '2026-10-07T23:00:00Z' };
const partialProgress = {
  complete: false,
  covered_start: timeRange.start,
  covered_end: timeRange.end,
  retry_after_ms: 5,
};

function dossier(complete: boolean) {
  return {
    identity: {
      hostname: 'ws-it-083.corp.local', ip: '10.1.3.7', mac: null, user: 'CORP\\alice',
      vendor_product: 'Sysmon', first_seen_in_range: '2026-10-07T22:00:04Z',
      last_seen_in_range: '2026-10-07T22:59:58Z',
      log_sources: [{ name: 'windows_sysmon', event_count: 4200, last_event: '2026-10-07T22:59:58Z' }],
      domain: 'corp.local',
    },
    timeline: { buckets: 28, lanes: ['auth', 'proc', 'net', 'file', 'alert'], points: [[1, 1, 2]] },
    processes: {
      unique: 12, rare: complete ? 1 : 0, unsigned: 0, from_office: 0,
      top: [{ name: 'svchost.exe', count: 900, prev: 0 }],
      rare_list: complete ? [{ name: 'evil.exe', hash: null, prev: 1, cmd: null, flags: [] }] : [],
    },
    network: { total_conns: 3, bytes_in: 0, bytes_out: 0, unique_dsts: 2, new_domains: 0, top_dsts: [], rare_countries: [] },
    auth: { success: 0, failure: 0, interactive: 0, network: 0, lateral: 0, recent: [] },
    files: { writes: 0, sensitive: 0, exec: 0, recent: [] },
    dns: { queries: 0, unique: 0, nx: 0, rare_tlds: 0, top: [] },
    progress: complete ? { complete: true } : partialProgress,
  };
}

function artifacts(complete: boolean) {
  const prevalence = {
    artifact: 'rare.example', host_count: 1, is_rare: true, prevalence_score: 1,
    total_occurrences: 0, first_seen: '2026-10-07T22:10:00Z', prevalence_source: 'in-window', in_window_hosts: 1,
  };
  return {
    hashes: [],
    domains: [{ artifact: 'rare.example', timestamp: '2026-10-07T22:10:00Z' }],
    hash_prevalence: [],
    domain_prevalence: [prevalence],
    rarity_threshold: 5,
    total_artifacts: 1,
    artifacts_truncated: false,
    progress: complete ? { complete: true } : partialProgress,
  };
}

const results = [{
  id: 'asset',
  timestamp: new Date('2026-10-07T23:00:00Z'),
  source: 'asset',
  fields: {
    _display_type: 'asset',
    _asset_profile: {
      primary_identifier: { field: 'src_endpoint.hostname', value: 'ws-it-083.corp.local' },
      identities: [],
      first_seen: null,
      last_seen: null,
    },
  },
}];

beforeEach(() => {
  globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as unknown as typeof ResizeObserver;
  mocks.events.mockReset().mockResolvedValue({
    events: [], total_count: 0, total_count_exact: true, facets: {}, has_more: false, offset: 0,
  });
  mocks.dossier.mockReset();
  mocks.artifacts.mockReset();
});
afterEach(cleanup);

it('paints a partial dossier and artifacts with a refining marker, then settles', async () => {
  let dossierComplete = false;
  let artifactsComplete = false;
  mocks.dossier.mockImplementation(async () => dossier(dossierComplete));
  mocks.artifacts.mockImplementation(async () => artifacts(artifactsComplete));
  render(<MemoryRouter><AssetView results={results} timeRange={timeRange} /></MemoryRouter>);

  // Partial dossier: identity, timeline and section cards paint at once.
  expect(await screen.findByText('svchost.exe')).toBeTruthy();
  expect(screen.getAllByText(/ws-it-083\.corp\.local/).length).toBeGreaterThan(0);
  // Coverage is already full: the marker says "refining", not "loading".
  expect(screen.getByTestId('asset-dossier-refining').textContent).toMatch(/refining/);
  // Rarity says what it is waiting on instead of a bare spinner.
  expect(await screen.findByTestId('asset-prevalence-refining')).toBeTruthy();
  expect(screen.queryByText(/Loading rarity index/)).toBeNull();
  // Partial dots are plotted.
  await waitFor(() => expect(document.querySelector('[data-artifact="rare.example"]')).toBeTruthy());

  dossierComplete = true;
  artifactsComplete = true;
  await waitFor(() => expect(screen.queryByTestId('asset-dossier-refining')).toBeNull());
  await waitFor(() => expect(screen.queryByTestId('asset-prevalence-refining')).toBeNull());
  expect(screen.getByText('svchost.exe')).toBeTruthy();
});

it('names the stage Rarity waits on before any coverage, never a bare spinner', async () => {
  // A poll that answers before the first chunk lands has no coverage yet.
  mocks.dossier.mockImplementation(async () => ({ ...dossier(false), progress: { complete: false, retry_after_ms: 5 } }));
  mocks.artifacts.mockImplementation(async () => ({
    ...artifacts(false), domains: [], domain_prevalence: [], total_artifacts: 0,
    progress: { complete: false, retry_after_ms: 5 },
  }));
  render(<MemoryRouter><AssetView results={results} timeRange={timeRange} /></MemoryRouter>);
  expect(await screen.findByText('svchost.exe')).toBeTruthy();
  // No coverage yet: Rarity names the stage it waits on.
  expect((await screen.findByTestId('asset-prevalence-refining')).textContent).toMatch(/reading events/);
  expect(screen.queryByText(/Loading rarity index/)).toBeNull();
});

it('keeps a painted partial dossier and says why refining stopped when a poll is refused (NAN-3282)', async () => {
  let polls = 0;
  mocks.dossier.mockImplementation(async () => {
    polls += 1;
    if (polls === 1) return dossier(false);
    // The search service refused the view for its memory budget (413 VIEW_TOO_LARGE).
    throw Object.assign(
      new Error('This asset-dossier view is too large to assemble (200 MiB needed, budget 136 MiB); narrow the time window and try again'),
      { code: 'VIEW_TOO_LARGE', status: 413 },
    );
  });
  mocks.artifacts.mockImplementation(async () => artifacts(true));
  render(<MemoryRouter><AssetView results={results} timeRange={timeRange} /></MemoryRouter>);

  expect(await screen.findByText('svchost.exe')).toBeTruthy();
  const error = await screen.findByTestId('asset-dossier-error');
  expect(error.textContent).toMatch(/Dossier incomplete: .*narrow the time window/);
  // The partial panels stay; the refining marker no longer claims progress.
  expect(screen.getByText('svchost.exe')).toBeTruthy();
  expect(screen.queryByTestId('asset-dossier-refining')).toBeNull();
});
