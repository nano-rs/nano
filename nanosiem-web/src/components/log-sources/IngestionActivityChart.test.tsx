// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-3194: Log Sources ingestion chart — unscaled axis text, hover tooltip,
 * legend toggles that restack and recompute the peak.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import {
  INGEST_CHART_HIDDEN_STORAGE_KEY,
  IngestionActivityChart,
  type IngestionPoint,
} from './IngestionActivityChart';

// 60s buckets → per-bucket counts equal evt/min.
const HISTORY: IngestionPoint[] = [
  { source_type: 'apache_access', timestamp: '2026-10-07 10:00:00', count: 100 },
  { source_type: 'windows_sysmon', timestamp: '2026-10-07 10:00:00', count: 27_000 },
  { source_type: 'apache_access', timestamp: '2026-10-07 10:01:00', count: 200 },
  { source_type: 'windows_sysmon', timestamp: '2026-10-07 10:01:00', count: 1_000 },
];

beforeEach(() => {
  try {
    window.localStorage.clear();
  } catch {
    /* ignore */
  }
});
afterEach(cleanup);

const legendButton = (name: string) => screen.getByRole('button', { name: new RegExp(name) });

describe('IngestionActivityChart', () => {
  it('never puts axis labels inside a non-uniformly scaled svg', () => {
    const { container } = render(<IngestionActivityChart history={HISTORY} />);
    const labels = screen.getAllByTestId('ingest-chart-axis-label');
    expect(labels.length).toBeGreaterThan(0);
    for (const label of labels) {
      expect(label.closest('svg[preserveAspectRatio="none"]')).toBeNull();
    }
    expect(container.querySelector('svg[preserveAspectRatio="none"]')).toBeNull();
  });

  it('toggling a legend item hides its series and recomputes the peak', () => {
    render(<IngestionActivityChart history={HISTORY} />);
    expect(screen.getByTestId('ingest-chart-peak').textContent).toContain('27.1K');
    expect(screen.getByTestId('ingest-chart-series-windows_sysmon')).toBeTruthy();

    const sysmon = legendButton('windows_sysmon');
    expect(sysmon.getAttribute('aria-pressed')).toBe('true');
    fireEvent.click(sysmon);

    expect(sysmon.getAttribute('aria-pressed')).toBe('false');
    expect(screen.queryByTestId('ingest-chart-series-windows_sysmon')).toBeNull();
    expect(screen.getByTestId('ingest-chart-peak').textContent).toContain('200');
    expect(JSON.parse(window.localStorage.getItem(INGEST_CHART_HIDDEN_STORAGE_KEY)!)).toEqual([
      'windows_sysmon',
    ]);

    fireEvent.click(sysmon);
    expect(screen.getByTestId('ingest-chart-series-windows_sysmon')).toBeTruthy();
  });

  it('refuses to hide the last visible series', () => {
    render(<IngestionActivityChart history={HISTORY} />);
    fireEvent.click(legendButton('windows_sysmon'));
    const apache = legendButton('apache_access');
    fireEvent.click(apache);
    expect(apache.getAttribute('aria-pressed')).toBe('true');
    expect(screen.getByTestId('ingest-chart-series-apache_access')).toBeTruthy();
  });

  it('restores the hidden set from storage', () => {
    window.localStorage.setItem(INGEST_CHART_HIDDEN_STORAGE_KEY, JSON.stringify(['apache_access']));
    render(<IngestionActivityChart history={HISTORY} />);
    expect(legendButton('apache_access').getAttribute('aria-pressed')).toBe('false');
    expect(screen.queryByTestId('ingest-chart-series-apache_access')).toBeNull();
  });

  it('hover shows a tooltip with per-source values and total', () => {
    render(<IngestionActivityChart history={HISTORY} />);
    const plot = screen.getByTestId('ingest-chart-plot');
    expect(screen.queryByTestId('ingest-chart-tooltip')).toBeNull();

    // jsdom rects are zero-sized, so clientX maps directly to chart x; 0 snaps to bucket 0.
    fireEvent.mouseMove(plot, { clientX: 0 });
    const tip = screen.getByTestId('ingest-chart-tooltip');
    expect(within(tip).getByText('apache_access')).toBeTruthy();
    expect(within(tip).getByText('windows_sysmon')).toBeTruthy();
    expect(within(tip).getByText('27.0K')).toBeTruthy();
    expect(within(tip).getByText('100')).toBeTruthy();
    expect(within(tip).getByText('27.1K')).toBeTruthy(); // total
    expect(within(tip).getByText('evt/min')).toBeTruthy();

    // Far right snaps to the last bucket.
    fireEvent.mouseMove(plot, { clientX: 100_000 });
    expect(within(screen.getByTestId('ingest-chart-tooltip')).getByText('1.2K')).toBeTruthy();

    fireEvent.mouseLeave(plot);
    expect(screen.queryByTestId('ingest-chart-tooltip')).toBeNull();
  });

  it('tooltip only lists visible series', () => {
    render(<IngestionActivityChart history={HISTORY} />);
    fireEvent.click(legendButton('windows_sysmon'));
    fireEvent.mouseMove(screen.getByTestId('ingest-chart-plot'), { clientX: 0 });
    const tip = screen.getByTestId('ingest-chart-tooltip');
    expect(within(tip).queryByText('windows_sysmon')).toBeNull();
    expect(within(tip).getByText('apache_access')).toBeTruthy();
  });
});
