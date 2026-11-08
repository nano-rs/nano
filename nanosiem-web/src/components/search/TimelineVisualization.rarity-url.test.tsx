// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-4927 review: Search owns the URL (fragment), so the timeline's Rarity
// tab must not write `?view=rarity` itself and fight the fragment hook.
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { TimelineVisualization } from './TimelineVisualization';

vi.mock('@/hooks/use-api', () => ({ usePrevalenceScatterData: () => ({ mutate: vi.fn() }) }));
vi.mock('@/hooks/use-internal-domains', () => ({ useInternalDomains: () => [] }));
vi.mock('@/hooks/useSchemaFieldMap', () => ({ useSchemaFieldMap: () => ({ isOcsf: false }) }));
afterEach(cleanup);
const noop = () => {};
let locations: string[] = [];
function LocationLog() {
  const l = useLocation();
  locations.push(`${l.search}${l.hash}`);
  return null;
}
const base = {
  timelineData: [], eventCount: 0, collapsed: false, onToggleCollapsed: noop, chartType: 'bar' as const,
  onChartTypeChange: noop, onZoomIn: noop, onZoomOut: noop, onResetZoom: noop, onTimelineClick: noop,
  refAreaLeft: null, refAreaRight: null, onMouseDown: noop, onMouseMove: noop, onMouseUp: noop,
  results: [], hasSearched: true,
  timeRange: { start: '2026-10-17T12:00:00.000Z', end: '2026-10-17T13:00:00.000Z' },
};

it('a shared #view=rarity URL opens in rarity mode with no route churn', () => {
  locations = [];
  const onChange = vi.fn();
  render(
    <MemoryRouter initialEntries={['/search#q=error&view=rarity']}>
      <TimelineVisualization {...base} urlRarityView onUrlRarityViewChange={onChange} />
      <LocationLog />
    </MemoryRouter>,
  );
  expect(screen.getByRole('tab', { name: /Rarity/ }).getAttribute('data-state')).toBe('active');
  expect(onChange).not.toHaveBeenCalled();
  // The component never navigated: one location, the one it was opened on.
  expect(new Set(locations)).toEqual(new Set(['#q=error&view=rarity']));
});

it('switching tabs asks the URL owner instead of writing the query string', () => {
  locations = [];
  const onChange = vi.fn();
  render(
    <MemoryRouter initialEntries={['/search#q=error']}>
      <TimelineVisualization {...base} urlRarityView={false} onUrlRarityViewChange={onChange} />
      <LocationLog />
    </MemoryRouter>,
  );
  expect(screen.getByRole('tab', { name: /Event Stream/ }).getAttribute('data-state')).toBe('active');
  expect(onChange).not.toHaveBeenCalled();
  fireEvent.mouseDown(screen.getByRole('tab', { name: /Rarity/ }), { button: 0 });
  expect(onChange).toHaveBeenCalledWith(true);
  expect(locations.every(l => !l.startsWith('?'))).toBe(true);
});
