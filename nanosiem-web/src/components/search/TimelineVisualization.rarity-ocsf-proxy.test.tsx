// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-5662: on OCSF proxy data the Rarity view must not call every domain
// RARE. Two causes, both covered here through the real component:
//   1. the in-window fallback keyed OCSF hosts on device.hostname (the proxy
//      appliance) and never on src_endpoint.ip, so github.com on 1,108 client
//      IPs counted 1 host;
//   2. the scatter `window` is relative to now, so a historical search gets a
//      0-host miss (`is_rare: true, first_seen: now`) for everything, and a
//      miss was shown as RARE even when no fallback count existed.
// The mocked search evaluates the `eval __h=...` chain the component sends
// over the seeded rows, so a wrong host identity fails these tests.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

type Row = Record<string, string>;

// Every proxy row: client IP only, the appliance as device, no src hostname.
const PROXY_ROWS: Row[] = [
  ...Array.from({ length: 1108 }, (_, i) => ({
    'src_endpoint.ip': `10.0.${i >> 8}.${i & 255}`,
    'device.hostname': 'proxy-01',
    'dst_endpoint.hostname': 'github.com',
  })),
  ...Array.from({ length: 2 }, (_, i) => ({
    'src_endpoint.ip': `10.9.0.${i}`,
    'device.hostname': 'proxy-01',
    'dst_endpoint.hostname': 'rare.example.org',
  })),
];

/** Evaluate the observation nPL the component sends over PROXY_ROWS. */
function runObservation(npl: string): Array<Record<string, unknown>> {
  const [predicate, evalStage, statsStage] = npl.split(' | ');
  const path = statsStage.match(/ by ([\w.]+)$/)![1];
  const wanted = new Set([...predicate.matchAll(/="([^"]*)"/g)].map((m) => m[1]));
  const chain = [...evalStage.matchAll(/if\(([\w.]+)!=""/g)].map((m) => m[1]);
  const fallback = evalStage.match(/"(\w+)"\)+$/)![1];
  const host = (r: Row) => chain.map((f) => r[f] ?? '').find((v) => v !== '') ?? fallback;
  const groups = new Map<string, Set<string>>();
  for (const r of PROXY_ROWS) {
    const key = r[path];
    if (!key || !wanted.has(key)) continue;
    if (!groups.has(key)) groups.set(key, new Set());
    groups.get(key)!.add(host(r));
  }
  return [...groups].map(([k, hosts]) => ({
    [path]: k,
    hosts: hosts.size,
    events: 1,
    first_in_window: '2026-11-12 10:00:00.000000',
  }));
}

const mocks = vi.hoisted(() => ({
  scatter: vi.fn(),
  search: vi.fn(),
}));

vi.mock('@/hooks/use-api', () => ({ usePrevalenceScatterData: () => ({ mutate: mocks.scatter }) }));
vi.mock('@/hooks/use-internal-domains', () => ({ useInternalDomains: () => [] }));
vi.mock('@/hooks/useSchemaFieldMap', () => ({ useSchemaFieldMap: () => ({ isOcsf: true, ready: true }) }));
vi.mock('@/lib/api', () => ({ api: { search: mocks.search, getAssetArtifacts: vi.fn() } }));

import { TimelineVisualization } from './TimelineVisualization';

/** The backend's miss placeholder (PrevalenceData::empty) for every artifact. */
const missFor = (req: { artifacts: { hashes: string[]; domains: string[] } }) => ({
  hash_points: [],
  domain_points: req.artifacts.domains.map((d) => ({
    artifact: d,
    artifact_type: 'domain',
    host_count: 0,
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    total_occurrences: 0,
    is_rare: true,
    prevalence_score: 0,
  })),
  ip_points: [],
  rarity_threshold: 3,
});

const noop = () => {};
// A historical 1h window, six days back (the scatter's 24h window misses it).
const START = Date.parse('2026-11-12T10:00:00.000Z');
const results = [
  ...Array.from({ length: 20 }, (_, i) => ({
    id: `g${i}`,
    timestamp: new Date(START + i * 60_000),
    fields: PROXY_ROWS[i * 50],
  })),
  ...PROXY_ROWS.slice(1108).map((fields, i) => ({ id: `r${i}`, timestamp: new Date(START + i * 90_000), fields })),
];
const props = {
  timelineData: [], eventCount: results.length, collapsed: false, onToggleCollapsed: noop, chartType: 'bar' as const,
  onChartTypeChange: noop, onZoomIn: noop, onZoomOut: noop, onResetZoom: noop, onTimelineClick: noop,
  refAreaLeft: null, refAreaRight: null, onMouseDown: noop, onMouseMove: noop, onMouseUp: noop,
  results: results as never, hasSearched: true, timeWindow: '24h', query: 'dst_endpoint.hostname=*',
  timeRange: { start: '2026-11-12T10:00:00.000Z', end: '2026-11-12T11:00:00.000Z' },
  urlRarityView: true, onUrlRarityViewChange: noop,
};

// jsdom has no ResizeObserver; the scatter plot only needs it to size itself.
globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as unknown as typeof ResizeObserver;

beforeEach(() => {
  mocks.scatter.mockReset().mockImplementation(async (req) => missFor(req));
  mocks.search.mockReset();
});
afterEach(cleanup);

it('counts proxy clients by src_endpoint.ip: only the 2-client domain is rare', async () => {
  mocks.search.mockImplementation(async (req: { query: string }) => ({ results: runObservation(req.query) }));
  render(<MemoryRouter><TimelineVisualization {...props} /></MemoryRouter>);
  await waitFor(() => expect(screen.getByText('22 artifacts')).toBeTruthy());
  const sent = mocks.search.mock.calls.map(([r]) => r.query as string);
  expect(sent.some((q) => q.includes('if(src_endpoint.ip!="", src_endpoint.ip'))).toBe(true);
  // The 2 rare.example.org dots are rare; the 20 github.com dots (1,108 hosts) are not.
  expect(screen.getByText('2 rare')).toBeTruthy();
  expect(screen.queryByText(/22 rare|21 rare|20 rare/)).toBeNull();
});

it('a baseline miss with no fallback count is unbaselined, never rare', async () => {
  mocks.search.mockRejectedValue(new Error('429'));
  render(<MemoryRouter><TimelineVisualization {...props} /></MemoryRouter>);
  await waitFor(() => expect(screen.getByText('22 artifacts')).toBeTruthy());
  expect(screen.queryByText(/\d+ rare/)).toBeNull();
});
