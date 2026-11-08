// @vitest-environment jsdom

import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { pivotSplitByData } from '../dashboard/VisualizationRenderer';
import { TimechartView, transformResults } from './TimechartView';

vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  AreaChart: ({ data, children }: { data: unknown[]; children: React.ReactNode }) => (
    <div data-testid="chart" data-buckets={data.length}>{children}</div>
  ),
  Area: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
  XAxis: () => null,
  YAxis: () => null,
}));

const rows = Array.from({ length: 289 }, (_, i) => ({
  time_bucket: new Date(Date.UTC(2026, 9, 1, 11, 20) + i * 300000).toISOString(),
  ...Object.fromEntries(Array.from({ length: 12 }, (_, n) => [`ip-${n}`, i === n ? 2 : 0])),
  OTHER: i === 0 ? 40 : 0,
  _timechart: { span_seconds: 300 },
}));
const results = rows.map((fields, i) => ({
  id: String(i),
  timestamp: new Date(fields.time_bucket),
  source: '',
  fields,
}));

const nullableRows = [
  {
    time_bucket: '2026-10-01T00:00:00Z',
    alpha: null,
    beta: 4,
    _timechart: { span_seconds: 300 },
  },
  {
    time_bucket: '2026-10-01T00:05:00Z',
    alpha: 12.5,
    beta: null,
    _timechart: { span_seconds: 300 },
  },
];
const nullableResults = nullableRows.map((fields, i) => ({
  id: `nullable-${i}`,
  timestamp: new Date(fields.time_bucket),
  source: '',
  fields,
}));

describe('complete server timecharts', () => {
  it('preserves configured series, every bucket, and the real remainder', () => {
    const transformed = transformResults(results);
    expect(transformed.rows).toHaveLength(289);
    expect(transformed.seriesKeys).toHaveLength(13);
    expect(transformed.seriesTotals.OTHER).toBe(40);
    expect(Object.values(transformed.seriesTotals).reduce((a, b) => a + b, 0)).toBe(64);
    expect(transformed.otherKeys).toEqual([]);
  });

  it('renders the complete chart, effective span, table, and legend totals', () => {
    render(
      <TimechartView
        results={results}
        query="* | timechart span=1m count by ip limit=12"
        onSetQuery={() => {}}
      />
    );
    expect(screen.getByTestId('chart').getAttribute('data-buckets')).toBe('289');
    expect(screen.getByText('5m')).toBeTruthy();
    expect(screen.getAllByText('OTHER')).toHaveLength(2);
    expect(screen.getAllByText('40').length).toBeGreaterThan(0);
  });

  it('uses every numeric dashboard column without repivoting metadata', () => {
    const result = pivotSplitByData(rows);
    expect(result.valueKeys).toHaveLength(13);
    expect(result.valueKeys).toContain('OTHER');
    expect(result.data).toHaveLength(289);
    expect(result.spanMs).toBe(300000);
  });

  it.each([
    ['avg', '* | timechart span=5m avg(bytes) by host'],
    ['percentile', '* | timechart span=5m percentile(bytes, 95) by host'],
  ])('keeps first-bucket nulls as table and chart gaps for %s', (_aggregation, query) => {
    const transformed = transformResults(nullableResults);
    expect(transformed.seriesKeys).toEqual(['alpha', 'beta']);
    expect(transformed.rows[0].alpha).toBeNull();
    expect(transformed.rows[1].beta).toBeNull();

    const { container } = render(<TimechartView results={nullableResults} query={query} />);
    const tableRows = container.querySelectorAll('tbody tr');
    const firstCells = tableRows[0].querySelectorAll('td');
    const secondCells = tableRows[1].querySelectorAll('td');
    expect(firstCells[1].textContent).toBe('');
    expect(firstCells[2].textContent).toBe('4');
    expect(firstCells[3].textContent).toBe('4');
    expect(secondCells[1].textContent).toBe('12.5');
    expect(secondCells[2].textContent).toBe('');
    expect(secondCells[3].textContent).toBe('12.5');
  });

  it.each(['avg', 'percentile'])(
    'discovers later numeric dashboard series and retains null gaps for %s',
    () => {
      const result = pivotSplitByData(nullableRows);
      expect(result.valueKeys).toEqual(['alpha', 'beta']);
      expect(result.data[0].alpha).toBeNull();
      expect(result.data[1].beta).toBeNull();
      expect(result.spanMs).toBe(300000);
    }
  );
});
