// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ServicesTab } from './ServicesTab';
const listServices = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ api: { observability: { listServices } } }));
vi.mock('@/components/search/footer-reporter', () => ({ useReportPhase2Status: () => {} }));
vi.mock('@/components/search/live-run-context', () => ({ useIsLiveRun: () => false }));
vi.mock('@/components/search/CachedNotice', () => ({ CachedNotice: () => null }));
vi.mock('@/components/observability/charts', () => ({ Sparkline: () => null }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });
it('shows raw jobs percentiles neutrally in list and grid without suppressing errors', async () => {
  listServices.mockResolvedValue({ services: [{ service: 'lake-jobs', request_count: 30, rate_per_sec: 0.03,
    error_rate: 0, p50_ms: 386.8, p95_ms: 1160, p99_ms: 2320, health: 'bad', sparkline: [] }] });
  render(<ServicesTab onOpenService={vi.fn()} onOpenTrace={vi.fn()}
    timeRange={{ type: 'preset', preset: 'Last 1 hour' }}
    apiTimeRange={{ start: '2026-10-16T20:00:00Z', end: '2026-10-16T21:00:00Z' }} />);
  const p99 = await screen.findByText('2.32s');
  expect(p99.className).not.toContain('text-danger');
  expect(screen.getByText('386.8ms')).toBeTruthy();
  expect(screen.getByText(/background · no latency objective/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'grid view' }));
  expect(screen.getByText('No latency objective')).toBeTruthy();
  expect(screen.queryByText('Critical')).toBeTruthy(); // the existing filter remains available
});
