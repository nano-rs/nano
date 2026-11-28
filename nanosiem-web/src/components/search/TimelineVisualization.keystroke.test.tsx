// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-5950 (Sentry NANO-FRONTEND-3): the Search page threw "Maximum update
// depth exceeded" from recharts' animation frame while a fresh result was
// animating and the analyst typed in the query editor. Every keystroke
// re-rendered the timeline, and each render re-registered its ReferenceAreas
// in the chart store and restarted the series animation. The timeline is now
// memoized and Search passes it only stable props, so a parent re-render
// that changes none of its props (a keystroke) does no chart work at all.
import { afterEach, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { cloneElement, useState, type ComponentProps, type ReactElement } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { TimelineVisualization } from './TimelineVisualization';

vi.mock('@/hooks/use-api', () => ({ usePrevalenceScatterData: () => ({ mutate: vi.fn() }) }));
vi.mock('@/hooks/use-internal-domains', () => ({ useInternalDomains: () => [] }));
// The timeline calls this hook once per render: it counts the renders.
const renders = vi.hoisted(() => ({ count: 0 }));
vi.mock('@/hooks/useSchemaFieldMap', () => ({
  useSchemaFieldMap: () => {
    renders.count += 1;
    return { isOcsf: false };
  },
}));
// Only the container is faked (jsdom has no layout); Bar/Line/Area and
// ReferenceArea are real, animation included.
vi.mock('recharts', async importOriginal => {
  const actual = await importOriginal<typeof import('recharts')>();
  return {
    ...actual,
    ResponsiveContainer: ({ children }: { children: ReactElement }) =>
      cloneElement(children, { width: 900, height: 180 } as object),
  };
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const start = Date.UTC(2026, 9, 13, 11, 25);
// Edge buckets are partial (the window starts and ends mid-bucket), so the
// bar chart draws partial-span ReferenceAreas, as a normal search does.
const data = Array.from({ length: 13 }, (_, i) => ({ time: String(i), timestamp: start + i * 300000, events: 1000 + i * 100 }));
const noop = () => {};

function props(chartType: 'bar' | 'line' | 'area'): ComponentProps<typeof TimelineVisualization> {
  return {
    timelineData: data,
    eventCount: data.reduce((s, p) => s + p.events, 0),
    collapsed: false,
    onToggleCollapsed: noop,
    chartType,
    onChartTypeChange: noop,
    onZoomIn: noop,
    onZoomOut: noop,
    onResetZoom: noop,
    onTimelineClick: noop,
    refAreaLeft: null,
    refAreaRight: null,
    onMouseDown: noop,
    onMouseMove: noop,
    onMouseUp: noop,
    results: [],
    hasSearched: true,
    query: 'source_type="dns"',
    timeRange: { start: new Date(start + 120000).toISOString(), end: new Date(start + 3720000).toISOString() },
  };
}

it('is memoized', () => {
  expect((TimelineVisualization as unknown as { $$typeof: symbol }).$$typeof).toBe(Symbol.for('react.memo'));
});

it.each(['bar', 'line', 'area'] as const)(
  '%s: typing in the page re-renders nothing in the chart and touches no recharts store or animation',
  async chartType => {
    const frames: string[] = [];
    const realRaf = window.requestAnimationFrame.bind(window);
    let lastFrame = performance.now();
    // recharts schedules both its animation clock and its store notifications
    // (removeArea/addArea, axis settings) on requestAnimationFrame.
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation(cb => {
      lastFrame = performance.now();
      frames.push(new Error().stack ?? '');
      return realRaf(cb);
    });
    const stable = props(chartType);
    // Like Search: page state (the draft query) changes per key; the
    // timeline's props do not.
    function Page() {
      const [draft, setDraft] = useState('');
      return (
        <MemoryRouter>
          <button onClick={() => setDraft(d => d + 'x')}>type</button>
          <span>{draft}</span>
          <TimelineVisualization {...stable} />
        </MemoryRouter>
      );
    }
    const { container } = render(<Page />);
    if (chartType === 'bar') expect(container.querySelectorAll('.recharts-reference-area').length).toBeGreaterThan(0);
    // The bars grow in (animation stays on); let it finish.
    await act(async () => {
      const deadline = performance.now() + 5000;
      while (performance.now() - lastFrame < 200 && performance.now() < deadline) {
        await new Promise(r => setTimeout(r, 50));
      }
    });
    expect(frames.some(f => /recharts[\\/].*animation/i.test(f))).toBe(true);

    frames.length = 0;
    renders.count = 0;
    for (let i = 0; i < 8; i++) fireEvent.click(screen.getByRole('button', { name: 'type' }));
    await act(async () => { await new Promise(r => setTimeout(r, 100)); });
    expect(screen.getByText('xxxxxxxx')).toBeTruthy();
    expect(renders.count).toBe(0);
    expect(frames).toEqual([]);
  },
  15000,
);
