// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-2599: LogSourceDetail hourly events with parse failures highlighted. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { hourlyBuckets } from '@/lib/ingest-activity';
import { IngestActivitySparkline } from './IngestActivitySparkline';

const HOUR = 3_600_000;
const now = Date.parse('2026-09-23T10:30:00Z');
const iso = (t: number) => new Date(t).toISOString();

const mocks = vi.hoisted(() => ({ getLogSourceStats: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { getLogSourceStats: mocks.getLogSourceStats } }));
afterEach(cleanup);

describe('hourlyBuckets', () => {
  it('zero-fills a contiguous window ending at the current hour', () => {
    const b = hourlyBuckets([
      { hour: '2026-09-23T10:00:00Z', events: 5, bytes: 0, parse_failures: 1 },
      { hour: '2026-09-23T08:00:00Z', events: 3, bytes: 0, parse_failures: 0 },
      { hour: '2026-09-23T08:00:00Z', events: 2, bytes: 0, parse_failures: 2 },
      { hour: '2026-09-22T01:00:00Z', events: 99, bytes: 0, parse_failures: 0 },
    ], 4, now);
    expect(b.map((x) => iso(x.hour))).toEqual(['2026-09-23T07:00:00.000Z', '2026-09-23T08:00:00.000Z', '2026-09-23T09:00:00.000Z', '2026-09-23T10:00:00.000Z']);
    expect(b.map((x) => x.events)).toEqual([0, 5, 0, 5]);
    expect(b.map((x) => x.parseFailures)).toEqual([0, 2, 0, 1]);
  });
});

describe('IngestActivitySparkline', () => {
  it('renders 24 hourly bars and marks hours with parse failures', async () => {
    const current = Math.floor(Date.now() / HOUR) * HOUR;
    mocks.getLogSourceStats.mockResolvedValue({
      log_source_id: 'ls', log_source_name: 'fw', window_hours: 24, source_slugs: ['fw'], observed: true,
      total_events: 30, total_bytes: 0, total_parse_failures: 4,
      points: [
        { hour: iso(current), events: 20, bytes: 0, parse_failures: 4 },
        { hour: iso(current - 2 * HOUR), events: 10, bytes: 0, parse_failures: 0 },
      ],
    });
    render(<QueryClientProvider client={new QueryClient()}><IngestActivitySparkline logSourceId="ls" /></QueryClientProvider>);
    await screen.findByTestId('ingest-sparkline-totals');
    expect(screen.getAllByTestId('ingest-sparkline-bar')).toHaveLength(24);
    expect(mocks.getLogSourceStats).toHaveBeenCalledWith('ls', 24);
    const failing = screen.getAllByTestId('ingest-sparkline-bar').filter((g) => g.getAttribute('data-failures') !== '0');
    expect(failing).toHaveLength(1);
    expect(screen.getByTestId('ingest-sparkline-totals').textContent).toMatch(/4 parse failures/);
  });

  it('embedded variant drops its own card chrome but keeps totals and axis labels (NAN-3297)', async () => {
    const current = Math.floor(Date.now() / HOUR) * HOUR;
    mocks.getLogSourceStats.mockResolvedValue({
      log_source_id: 'ls', log_source_name: 'fw', window_hours: 24, source_slugs: ['fw'], observed: true,
      total_events: 3_200_000, total_bytes: 0, total_parse_failures: 0,
      points: [{ hour: iso(current), events: 192_500, bytes: 0, parse_failures: 0 }],
    });
    render(<QueryClientProvider client={new QueryClient()}><IngestActivitySparkline logSourceId="ls" embedded /></QueryClientProvider>);
    const totals = await screen.findByTestId('ingest-sparkline-totals');
    expect(totals.textContent).toMatch(/events/);
    const root = screen.getByTestId('ingest-sparkline');
    expect(root.className).not.toMatch(/rounded-md/);
    expect(root.className).not.toMatch(/bg-card/);
    expect(root.className).toMatch(/border-t/);
    expect(screen.getAllByTestId('ingest-sparkline-bar')).toHaveLength(24);
    expect(root.textContent).toMatch(/peak .* \/ h/);
    expect(root.textContent).toMatch(/\d\d:00Z/);
  });

  it('shows refused rows next to the totals and the refused-only verdict (NAN-3680)', async () => {
    const current = Math.floor(Date.now() / HOUR) * HOUR;
    mocks.getLogSourceStats.mockResolvedValue({
      log_source_id: 'ls', log_source_name: 'entra', window_hours: 24, source_slugs: ['azure_monitor'], observed: false,
      total_events: 0, total_bytes: 0, total_parse_failures: 0,
      points: [{ hour: iso(current), events: 0, bytes: 0, parse_failures: 0, refused_events: 100 }],
      verdict: { managed_by_platform: true, reason: 'x', detail: 'strict OCSF validation refused every one' },
      total_refused_events: 100, last_refusal: { reason: 'ocsf_constraint_failed', field: 'device' },
    });
    render(<QueryClientProvider client={new QueryClient()}><IngestActivitySparkline logSourceId="ls" /></QueryClientProvider>);
    const refused = await screen.findByTestId('ingest-sparkline-refused');
    expect(refused.textContent).toMatch(/100 refused \(constraint_failed at device\)/);
    expect(refused.getAttribute('title')).toBe('100 events refused by OCSF validation (constraint_failed at device)');
    expect(screen.getByText(/refused every one/)).toBeTruthy();
  });

  it('says nothing about refusals the lake does not record', async () => {
    mocks.getLogSourceStats.mockResolvedValue({
      log_source_id: 'ls', log_source_name: 'fw', window_hours: 24, source_slugs: ['fw'], observed: true,
      total_events: 3, total_bytes: 0, total_parse_failures: 0,
      points: [{ hour: iso(Math.floor(Date.now() / HOUR) * HOUR), events: 3, bytes: 0, parse_failures: 0 }],
    });
    render(<QueryClientProvider client={new QueryClient()}><IngestActivitySparkline logSourceId="ls" /></QueryClientProvider>);
    await screen.findByTestId('ingest-sparkline-totals');
    expect(screen.queryByTestId('ingest-sparkline-refused')).toBeNull();
  });

  it('shows the no-data verdict', async () => {
    mocks.getLogSourceStats.mockResolvedValue({
      log_source_id: 'ls', log_source_name: 'fw', window_hours: 24, source_slugs: ['fw'], observed: false, total_events: 0,
      total_bytes: 0, total_parse_failures: 0, points: [], verdict: { managed_by_platform: true, reason: 'x', detail: 'Nothing admitted yet.' },
    });
    render(<QueryClientProvider client={new QueryClient()}><IngestActivitySparkline logSourceId="ls" /></QueryClientProvider>);
    expect(await screen.findByText('Nothing admitted yet.')).toBeTruthy();
  });
});
