// @vitest-environment jsdom
import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TimechartView, transformResults } from './TimechartView';
import { pivotSplitByData } from '../dashboard/VisualizationRenderer';

vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  AreaChart: ({ data, children }: { data: unknown[]; children: React.ReactNode }) => <div data-testid="chart" data-buckets={data.length}>{children}</div>,
  Area: () => null, CartesianGrid: () => null, Tooltip: () => null, XAxis: () => null, YAxis: () => null,
}));

const rows = Array.from({ length: 289 }, (_, i) => ({
  time_bucket: new Date(Date.UTC(2026, 9, 1, 11, 20) + i * 300000).toISOString(),
  ...Object.fromEntries(Array.from({ length: 12 }, (_, n) => [`ip-${n}`, i === n ? 2 : 0])),
  OTHER: i === 0 ? 40 : 0,
  _timechart: { span_seconds: 300 },
}));
const results = rows.map((fields, i) => ({ id: String(i), timestamp: new Date(fields.time_bucket), source: '', fields }));

describe('complete server timecharts', () => {
  it('preserves configured series, all buckets, and the real remainder', () => {
    const transformed = transformResults(results);
    expect(transformed.rows).toHaveLength(289);
    expect(transformed.seriesKeys).toHaveLength(13);
    expect(transformed.seriesTotals.OTHER).toBe(40);
    expect(Object.values(transformed.seriesTotals).reduce((a, b) => a + b, 0)).toBe(64);
    expect(transformed.otherKeys).toEqual([]);
  });
  it('renders the complete chart, effective span, table and legend totals', () => {
    render(<TimechartView results={results} query="* | timechart span=1m count by ip limit=12" onSetQuery={() => {}} />);
    expect(screen.getByTestId('chart').getAttribute('data-buckets')).toBe('289');
    expect(screen.getByText('5m')).toBeTruthy();
    expect(screen.getAllByText('OTHER')).toHaveLength(2);
    expect(screen.getAllByText('40').length).toBeGreaterThan(0);
  });
  it('uses every numeric pivot column in dashboards without repivoting metadata', () => {
    const result = pivotSplitByData(rows);
    expect(result.valueKeys).toHaveLength(13);
    expect(result.valueKeys).toContain('OTHER');
    expect(result.data).toHaveLength(289);
    expect(result.spanMs).toBe(300000);
  });
});
