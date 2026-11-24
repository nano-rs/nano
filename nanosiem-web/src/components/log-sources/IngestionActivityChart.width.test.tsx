// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5780: the chart's SVG is sized to its card even when the history arrives
 * after the first render (the plot div mounts late). It used to keep the
 * 1360px fallback width, overflowing the card and clipping the "now" label.
 *
 * The ResizeObserver here is a controllable fake: tests fire its callback to
 * simulate a resize, and count observe/disconnect calls to prove the observer
 * follows the plot element through unmount and remount without leaking.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render, screen } from '@testing-library/react';
import { IngestionActivityChart, type IngestionPoint } from './IngestionActivityChart';

const HISTORY: IngestionPoint[] = [
  { source_type: 'apache_access', timestamp: '2026-10-07 10:00:00', count: 100 },
  { source_type: 'apache_access', timestamp: '2026-10-07 10:01:00', count: 200 },
];
const FALLBACK_W = 1360;

let rectW = 640;
type Fake = { cb: ResizeObserverCallback; els: Element[]; disconnected: boolean };
let observers: Fake[] = [];

beforeEach(() => {
  rectW = 640;
  observers = [];
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(
    () => ({ width: rectW, height: 150, top: 0, left: 0, right: rectW, bottom: 150, x: 0, y: 0, toJSON: () => ({}) }) as DOMRect,
  );
  vi.stubGlobal(
    'ResizeObserver',
    class {
      private f: Fake;
      constructor(cb: ResizeObserverCallback) {
        this.f = { cb, els: [], disconnected: false };
        observers.push(this.f);
      }
      observe(el: Element) {
        this.f.els.push(el);
      }
      unobserve() {}
      disconnect() {
        this.f.disconnected = true;
      }
    },
  );
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const svgWidth = () => screen.getByTestId('ingest-chart-plot').querySelector('svg')?.getAttribute('width');
const live = () => observers.filter((o) => !o.disconnected);

/** Fire every live observer as the browser would after a layout change. */
function resizeTo(width: number) {
  act(() => {
    for (const o of live()) {
      o.cb(o.els.map((target) => ({ target, contentRect: { width } }) as unknown as ResizeObserverEntry), {} as ResizeObserver);
    }
  });
}

describe('IngestionActivityChart width (NAN-5780)', () => {
  it('measures the plot when history loads after the first render', () => {
    const { rerender } = render(<IngestionActivityChart history={[]} />);
    expect(screen.queryByTestId('ingest-chart-plot')).toBeNull();
    expect(observers).toHaveLength(0);

    rerender(<IngestionActivityChart history={HISTORY} />);
    const plot = screen.getByTestId('ingest-chart-plot');
    expect(live()).toHaveLength(1);
    expect(live()[0].els).toEqual([plot]);
    expect(svgWidth()).toBe('640');
  });

  it('follows resizes reported by the ResizeObserver (pivt opening, window resize)', () => {
    render(<IngestionActivityChart history={HISTORY} />);
    expect(svgWidth()).toBe('640');
    resizeTo(412);
    expect(svgWidth()).toBe('412');
    resizeTo(1180);
    expect(svgWidth()).toBe('1180');
    // A 0 entry (card hidden mid-transition) keeps the last real width.
    resizeTo(0);
    expect(svgWidth()).toBe('1180');
  });

  it('a plot that mounts at 0px wide takes its width from the first resize entry', () => {
    rectW = 0;
    render(<IngestionActivityChart history={HISTORY} />);
    expect(svgWidth()).toBe(String(FALLBACK_W));
    resizeTo(700);
    expect(svgWidth()).toBe('700');
  });

  it('disconnects when the plot unmounts and observes the new plot when data returns', () => {
    const { rerender, unmount } = render(<IngestionActivityChart history={HISTORY} />);
    expect(live()).toHaveLength(1);

    rerender(<IngestionActivityChart history={[]} />);
    expect(screen.queryByTestId('ingest-chart-plot')).toBeNull();
    expect(live()).toHaveLength(0);
    expect(observers[0].disconnected).toBe(true);

    rectW = 520;
    rerender(<IngestionActivityChart history={HISTORY} />);
    // React may reuse the empty-state <div> for the plot; either way the ref
    // detached (disconnect above) and re-attached, so the plot is observed anew.
    const second = screen.getByTestId('ingest-chart-plot');
    expect(live()).toHaveLength(1);
    expect(live()[0].els).toEqual([second]);
    expect(svgWidth()).toBe('520');

    unmount();
    expect(live()).toHaveLength(0);
    expect(observers).toHaveLength(2);
  });
});
