// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5842: the Impact & baseline card. jsdom has no layout (recharts draws
 * nothing at 0x0); the e2e screenshots cover the drawing. These pin the data
 * and the states: zero-fill, totals per calendar window, baseline, quiet state.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { BottomTray } from './BottomTray';

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ capabilities: { aiTuning: false } }),
}));

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

function card(dailyStats: Parameters<typeof BottomTray>[0]['dailyStats'], matchCount = 0) {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date('2026-11-22T12:00:00Z'));
  render(<BottomTray validation={null} matchCount={matchCount} versions={[]} dailyStats={dailyStats} />);
  return screen.getByTestId('rule-impact-card');
}

const classes = (el: Element) => el.className.toString().split(/\s+/);
const day = (date: string, match_count: number) => ({ date, match_count, alert_count: 0 });

describe('Impact & baseline card (NAN-5842)', () => {
  it('a rule with no matches renders the chart area with a quiet state', () => {
    const c = card([]);
    expect(within(c).getByTestId('rule-impact-chart')).toBeTruthy();
    expect(within(c).getByTestId('rule-impact-quiet').textContent).toBe('no matches in the last 7d');
    expect(within(c).getByTestId('rule-impact-baseline').textContent).toBe('baseline 0 prev 7d');
    expect(within(c).getByText('none')).toBeTruthy();
  });

  it('one match today: 1 in the window, "new", chart fills the card', () => {
    const c = card([day('2026-11-22', 1)], 1);
    const chart = within(c).getByTestId('rule-impact-chart');
    expect(chart.className).toContain('flex-1');
    expect(c.className).toContain('flex-col');
    expect(within(c).getByText('new')).toBeTruthy();
    expect(within(c).queryByTestId('rule-impact-quiet')).toBeNull();
  });

  it('sparse days are compared by calendar window, not by the last 7 active rows', () => {
    const c = card([
      day('2026-11-08', 1), day('2026-11-10', 6), day('2026-11-12', 2),
      day('2026-11-16', 4), day('2026-11-18', 2), day('2026-11-20', 5), day('2026-11-21', 1), day('2026-11-22', 3),
    ], 24);
    // last 7 (11-16..11-22) = 15; baseline (11-09..11-15) = 8; 11-08 is outside.
    expect(within(c).getByText('15')).toBeTruthy();
    expect(within(c).getByTestId('rule-impact-baseline').textContent).toBe('baseline 8 prev 7d');
    expect(within(c).getByText('+88%')).toBeTruthy();
  });

  it('quiet window with a non-zero baseline: the note is outside the chart and names both numbers', () => {
    const c = card([day('2026-11-10', 6), day('2026-11-14', 2)], 8);
    const quiet = within(c).getByTestId('rule-impact-quiet');
    const chart = within(c).getByTestId('rule-impact-chart');
    expect(quiet.textContent).toBe('no matches in the last 7d · 0 vs 8 baseline');
    // Never overlaid on the chart (where the dashed baseline is drawn).
    expect(chart.contains(quiet)).toBe(false);
    expect(classes(quiet)).not.toContain('absolute');
    expect(quiet.compareDocumentPosition(chart) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(c).getByTestId('rule-impact-baseline').textContent).toBe('baseline 8 prev 7d');
    expect(within(c).getByText('-100%')).toBeTruthy();
  });

  it('no stats loaded (a new rule) says so instead of drawing', () => {
    const c = card(undefined);
    expect(within(c).queryByTestId('rule-impact-chart')).toBeNull();
    expect(within(c).getByText('no activity data yet')).toBeTruthy();
  });
});
