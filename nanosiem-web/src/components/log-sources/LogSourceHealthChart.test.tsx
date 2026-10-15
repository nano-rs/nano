// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-3207: log source health — status sort, segment expand, `?segment=`
 * deep-link pre-expansion, segments-unavailable note, search links.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import type { HealthSeriesPoint, LogSourceHealthSeries } from '@/lib/api';

const mocks = vi.hoisted(() => ({
  getHealthSeries: vi.fn(),
  getLogSourceHealthSeries: vi.fn(),
}));
vi.mock('@/lib/api', () => ({ api: mocks }));

import { LogSourceHealthList, LogSourceHealthPanel, LogSourceHealthRows } from './LogSourceHealthChart';
import { healthSearchHref, learningProgress, parseSegmentParam, sortHealthSeries } from '@/lib/log-source-health';

function pts(events: number[], dropFrom = -1): HealthSeriesPoint[] {
  return events.map((e, i) => ({
    hour: new Date(Date.UTC(2026, 9, 7, i)).toISOString(),
    events: e,
    expected: 100,
    low: 60,
    high: 140,
    assessment: i === events.length - 1 ? null : dropFrom >= 0 && i >= dropFrom ? 'dropped' : 'normal',
  }));
}

function source(over: Partial<LogSourceHealthSeries>): LogSourceHealthSeries {
  return {
    log_source_id: 'lsrc_x',
    log_source_name: 'x',
    source_slugs: ['x'],
    state: 'healthy',
    window_hours: 24,
    last_event_at: '2026-10-07T03:59:00Z',
    baseline_days: 7,
    baseline_days_required: 3,
    points: pts([100, 110, 95, 40]),
    segments: [],
    segments_available: true,
    ...over,
  };
}

const CLOUDTRAIL = source({
  log_source_id: 'lsrc_cloudtrail',
  log_source_name: 'AWS CloudTrail',
  source_slugs: ['aws_cloudtrail'],
  state: 'segment_drop',
  segments: [
    {
      dimension: 'region',
      value: 'us-east-1',
      search_field: 'cloud.region',
      other: false,
      state: 'segment_drop',
      dropped_since: '2026-10-07T02:00:00Z',
      baseline_days: 7,
      baseline_days_required: 3,
      window_events: 220,
      points: pts([100, 120, 0, 0], 2),
    },
    {
      dimension: 'account',
      value: '123456789012',
      search_field: 'cloud.account.uid',
      other: false,
      state: 'healthy',
      dropped_since: null,
      baseline_days: 7,
      baseline_days_required: 3,
      window_events: 900,
      points: pts([300, 300, 300, 0]),
    },
    {
      dimension: 'region',
      value: '(other)',
      search_field: 'cloud.region',
      other: true,
      state: 'unknown',
      dropped_since: null,
      baseline_days: 7,
      baseline_days_required: 3,
      window_events: 12,
      points: pts([3, 3, 3, 3]),
    },
  ],
});

const FIXTURE: LogSourceHealthSeries[] = [
  source({ log_source_id: 'lsrc_a', log_source_name: 'Apache', source_slugs: ['apache'], state: 'healthy' }),
  source({ log_source_id: 'lsrc_off', log_source_name: 'Old feed', state: 'disabled' }),
  source({ log_source_id: 'lsrc_deg', log_source_name: 'Okta', state: 'degraded' }),
  CLOUDTRAIL,
  source({ log_source_id: 'lsrc_stale', log_source_name: 'Sysmon', state: 'stale' }),
  source({
    log_source_id: 'lsrc_nosegs',
    log_source_name: 'Zeek',
    state: 'healthy',
    segments_available: false,
  }),
];

function Loc() {
  const l = useLocation();
  return <div data-testid="loc">{l.pathname + l.search}</div>;
}

function wrap(ui: React.ReactNode, initial = '/') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initial]}>
        <Routes>
          <Route path="*" element={<>{ui}<Loc /></>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  mocks.getHealthSeries.mockReset();
  mocks.getLogSourceHealthSeries.mockReset();
});
afterEach(cleanup);

describe('sortHealthSeries', () => {
  it('puts segment_drop, stale, degraded first', () => {
    expect(sortHealthSeries(FIXTURE).map((s) => s.state)).toEqual([
      'segment_drop',
      'stale',
      'degraded',
      'healthy',
      'healthy',
      'disabled',
    ]);
  });
});

describe('LogSourceHealthRows', () => {
  it('renders rows in attention order with status pills', () => {
    wrap(<LogSourceHealthRows series={FIXTURE} />);
    const rows = screen.getAllByTestId('health-source-row');
    expect(rows.map((r) => r.getAttribute('data-source'))).toEqual([
      'lsrc_cloudtrail',
      'lsrc_stale',
      'lsrc_deg',
      'lsrc_a',
      'lsrc_nosegs',
      'lsrc_off',
    ]);
    expect(within(rows[0]).getByTestId('health-state-pill').textContent).toMatch(/segment drop/i);
    expect(within(rows[0]).getByText(/1 segment down/)).toBeTruthy();
  });

  it('expands a source into its segments on click', () => {
    wrap(<LogSourceHealthRows series={FIXTURE} />);
    expect(screen.queryByTestId('health-segment-list')).toBeNull();
    const row = screen.getAllByTestId('health-source-row')[0];
    fireEvent.click(within(row).getByRole('button', { expanded: false }));
    const segs = within(row).getAllByTestId('health-segment-row');
    expect(segs.map((s) => s.getAttribute('data-segment'))).toEqual([
      'region:us-east-1',
      'account:123456789012',
      'region:(other)',
    ]);
    // The other-bucket is never judged and has no single value to search.
    expect(within(segs[2]).queryByTestId('health-state-pill')).toBeNull();
    expect(within(segs[2]).queryByTestId('health-segment-search')).toBeNull();
    // Segment search link scopes to the source and the segment field.
    const href = within(segs[0]).getByTestId('health-segment-search').getAttribute('href') ?? '';
    const q = new URLSearchParams(href.split('?')[1]).get('q');
    expect(q).toBe('metadata.log_source="aws_cloudtrail" cloud.region="us-east-1"');
  });

  it('shows a muted note when segment counts are unavailable', () => {
    wrap(<LogSourceHealthRows series={FIXTURE} />);
    const row = screen.getAllByTestId('health-source-row').find((r) => r.getAttribute('data-source') === 'lsrc_nosegs')!;
    fireEvent.click(within(row).getByRole('button', { expanded: false }));
    expect(within(row).getByTestId('health-segments-unavailable')).toBeTruthy();
    // Totals still render.
    expect(within(row).getByTestId('health-band-chart')).toBeTruthy();
  });

  it('marks dropped hours on the chart', () => {
    wrap(<LogSourceHealthRows series={FIXTURE} />);
    const row = screen.getAllByTestId('health-source-row')[0];
    fireEvent.click(within(row).getByRole('button', { expanded: false }));
    const seg = within(row).getAllByTestId('health-segment-row')[0];
    expect(within(seg).getAllByTestId('health-chart-dropped').length).toBe(1);
  });
});

describe('LogSourceHealthList', () => {
  it('fetches all sources and counts those needing attention', async () => {
    mocks.getHealthSeries.mockResolvedValue(FIXTURE);
    wrap(<LogSourceHealthList />);
    await screen.findAllByTestId('health-source-row');
    expect(mocks.getHealthSeries).toHaveBeenCalledWith(24);
    expect(screen.getByTestId('log-source-health-section').textContent).toMatch(/3 need attention/);
  });
});

describe('LogSourceHealthPanel', () => {
  it('pre-expands and highlights the ?segment= segment', async () => {
    mocks.getLogSourceHealthSeries.mockResolvedValue([CLOUDTRAIL]);
    wrap(<LogSourceHealthPanel logSourceId="lsrc_cloudtrail" />, '/ingestion/log-sources/lsrc_cloudtrail?segment=account:123456789012');
    await screen.findByTestId('log-source-health-panel');
    expect(mocks.getLogSourceHealthSeries).toHaveBeenCalledWith('lsrc_cloudtrail', 24);
    const seg = screen.getAllByTestId('health-segment-row').find((r) => r.getAttribute('data-segment') === 'account:123456789012')!;
    expect(seg.getAttribute('data-highlighted')).toBe('true');
    expect(seg.getAttribute('data-expanded')).toBe('true');
    // Full chart (with axes) is rendered for the expanded segment.
    expect(within(seg).getAllByTestId('health-chart-axis-label').length).toBeGreaterThan(0);
    const other = screen.getAllByTestId('health-segment-row').find((r) => r.getAttribute('data-segment') === 'region:us-east-1')!;
    expect(other.getAttribute('data-expanded')).toBeNull();
  });

  it('navigates to an hour-scoped search when the chart is clicked', async () => {
    mocks.getLogSourceHealthSeries.mockResolvedValue([CLOUDTRAIL]);
    wrap(<LogSourceHealthPanel logSourceId="lsrc_cloudtrail" />);
    const panel = await screen.findByTestId('log-source-health-panel');
    const chart = within(panel).getAllByTestId('health-band-chart')[0];
    fireEvent.mouseMove(chart, { clientX: 44 });
    expect(within(chart).getByTestId('health-chart-tooltip')).toBeTruthy();
    fireEvent.click(chart);
    await waitFor(() => expect(screen.getByTestId('loc').textContent).toMatch(/^\/search\?/));
    const params = new URLSearchParams(screen.getByTestId('loc').textContent!.split('?')[1]);
    expect(params.get('q')).toBe('metadata.log_source="aws_cloudtrail"');
    expect(params.get('start')).toBe('2026-10-07T00:00:00.000Z');
    expect(params.get('end')).toBe('2026-10-07T01:00:00.000Z');
  });

  it('shows an unavailable note when the source is not visible', async () => {
    mocks.getLogSourceHealthSeries.mockRejectedValue(Object.assign(new Error('not found'), { status: 404 }));
    wrap(<LogSourceHealthPanel logSourceId="lsrc_nope" />);
    expect(await screen.findByTestId('log-source-health-unavailable')).toBeTruthy();
  });
});

describe('helpers', () => {
  it('parses ?segment= values containing colons', () => {
    expect(parseSegmentParam('class:Network Activity')).toBe('class:Network Activity');
    expect(parseSegmentParam('service:arn:aws:x')).toBe('service:arn:aws:x');
    expect(parseSegmentParam('nocolon')).toBeNull();
    expect(parseSegmentParam(null)).toBeNull();
  });

  it('ORs multiple slugs in parentheses', () => {
    const href = healthSearchHref(['a', 'b'], { field: 'class_name', value: 'Process Activity' });
    expect(new URLSearchParams(href.split('?')[1]).get('q')).toBe(
      '(metadata.log_source="a" OR metadata.log_source="b") class_name="Process Activity"',
    );
  });
});

// NAN-3246: no baseline yet (a new source) reads as learning, with progress,
// distinct from "unknown" and from the folded `other` bucket's "not judged".
describe('learning baseline', () => {
  const APACHE = source({
    log_source_id: 'lsrc_apache',
    log_source_name: 'apache_access',
    source_slugs: ['apache_access'],
    state: 'learning',
    baseline_days: 2,
    baseline_days_required: 3,
    segments: [
      {
        dimension: 'class',
        value: 'HTTP Activity',
        search_field: 'class_name',
        other: false,
        state: 'learning',
        dropped_since: null,
        baseline_days: 2,
        baseline_days_required: 3,
        window_events: 2_400_000,
        points: pts([100_000, 100_000, 100_000, 40_000]),
      },
      {
        dimension: 'class',
        value: 'Network Activity',
        search_field: 'class_name',
        other: false,
        state: 'unknown',
        dropped_since: null,
        baseline_days: 7,
        baseline_days_required: 3,
        window_events: 120,
        points: pts([5, 5, 5, 5]),
      },
      {
        dimension: 'class',
        value: '(other)',
        search_field: 'class_name',
        other: true,
        state: 'unknown',
        dropped_since: null,
        baseline_days: 2,
        baseline_days_required: 3,
        window_events: 12,
        points: pts([3, 3, 3, 3]),
      },
    ],
  });

  it('formats progress only for the learning state', () => {
    expect(learningProgress(APACHE)).toEqual({
      short: '2/3d',
      long: 'Learning baseline: 2 of 3 days of history collected',
    });
    expect(learningProgress({ ...APACHE, state: 'unknown' })).toBeNull();
    expect(learningProgress({ ...APACHE, baseline_days: 9 })?.short).toBe('3/3d');
  });

  it('shows the learning label with progress on the source and segment pills', () => {
    wrap(<LogSourceHealthRows series={[APACHE]} />);
    const row = screen.getByTestId('health-source-row');
    const pill = within(row).getAllByTestId('health-state-pill')[0];
    expect(pill.dataset.state).toBe('learning');
    expect(pill.textContent).toBe('Learning2/3d');
    expect(pill.getAttribute('title')).toBe('Learning baseline: 2 of 3 days of history collected');
    fireEvent.click(within(row).getByRole('button', { expanded: false }));
    const segs = screen.getAllByTestId('health-segment-row');
    const http = segs.find((r) => r.dataset.segment === 'class:HTTP Activity')!;
    const httpPill = within(http).getByTestId('health-state-pill');
    expect(httpPill.dataset.state).toBe('learning');
    expect(httpPill.getAttribute('aria-label')).toMatch(/^Learning baseline/);
    // A judged-but-unknown segment stays "Unknown", without progress.
    const net = segs.find((r) => r.dataset.segment === 'class:Network Activity')!;
    expect(within(net).getByTestId('health-state-pill').textContent).toBe('Unknown');
    // The out-of-top-K bucket stays "not judged", never learning.
    const other = segs.find((r) => r.dataset.segment === 'class:(other)')!;
    expect(within(other).queryByTestId('health-state-pill')).toBeNull();
    expect(within(other).getByText('not judged')).toBeTruthy();
  });

  it('sorts learning after healthy and before unknown', () => {
    const order = sortHealthSeries([
      source({ log_source_id: 'u', log_source_name: 'u', state: 'unknown' }),
      source({ log_source_id: 'l', log_source_name: 'l', state: 'learning' }),
      source({ log_source_id: 'h', log_source_name: 'h', state: 'healthy' }),
    ]).map((s) => s.state);
    expect(order).toEqual(['healthy', 'learning', 'unknown']);
  });
});
