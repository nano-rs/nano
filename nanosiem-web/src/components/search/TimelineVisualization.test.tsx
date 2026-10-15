// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, waitFor } from '@testing-library/react';
import { cloneElement, type ComponentProps, type ReactElement } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { TimelineVisualization } from './TimelineVisualization';

vi.mock('@/hooks/use-api', () => ({ usePrevalenceScatterData: () => ({ mutate: vi.fn() }) }));
vi.mock('@/hooks/use-internal-domains', () => ({ useInternalDomains: () => [] }));
vi.mock('recharts', async importOriginal => {
  const actual = await importOriginal<typeof import('recharts')>();
  return { ...actual,
    Line: (props: ComponentProps<typeof actual.Line>) => <actual.Line {...props} isAnimationActive={false} />,
    Area: (props: ComponentProps<typeof actual.Area>) => <actual.Area {...props} isAnimationActive={false} />,
    ResponsiveContainer: ({children}: {children: ReactElement}) => cloneElement(children, {width: 900, height: 180} as object) };
});
afterEach(cleanup);
const start = Date.UTC(2026, 9, 13, 11, 25);
const data = Array.from({length: 13}, (_, i) => ({time: String(i), timestamp: start+i*300000, events: i===0 ? 2700 : i===12 ? 11000 : 13500}));
const noop = () => {};

it.each(['bar', 'line', 'area'] as const)('%s renders the histogram edge contract', async chartType => {
  const {container} = render(<MemoryRouter><TimelineVisualization timelineData={data} eventCount={data.reduce((s,p)=>s+p.events,0)} collapsed={false} onToggleCollapsed={noop} chartType={chartType} onChartTypeChange={noop} onZoomIn={noop} onZoomOut={noop} onResetZoom={noop} onTimelineClick={noop} refAreaLeft={null} refAreaRight={null} onMouseDown={noop} onMouseMove={noop} onMouseUp={noop} results={[]} hasSearched={false} timeRange={{start: new Date(start+120000).toISOString(), end: new Date(start+3720000).toISOString()}} /></MemoryRouter>);
  await waitFor(() => expect(container.querySelector('.recharts-surface')).not.toBeNull());
  expect(container.querySelectorAll('.recharts-reference-area')).toHaveLength(chartType==='bar' ? 2 : 0);
  if (chartType==='bar') {
    expect(container.querySelectorAll('.recharts-bar-rectangle')).toHaveLength(13);
    expect(container.querySelectorAll('.recharts-line-curve,.recharts-area-curve')).toHaveLength(0);
  } else {
    const curves = Array.from(container.querySelectorAll(chartType==='line' ? '.recharts-line-curve' : '.recharts-area-curve'));
    expect(curves).toHaveLength(3);
    expect(curves.slice(1).every(p => p.getAttribute('stroke-opacity')==='0.5')).toBe(true);
    expect(curves.slice(1).every(p => p.getAttribute('stroke-dasharray')?.includes('3'))).toBe(true);
    expect(curves.every(p => !p.getAttribute('d')?.includes('C'))).toBe(true);
    // Plot starts at x=60 (the Y axis plus margin), ends at x=895, and spans the exact range.
    expect(curves[1].getAttribute('d')).toMatch(/^M60,/);
    expect(curves[2].getAttribute('d')).toMatch(/L895,/);
  }
});
