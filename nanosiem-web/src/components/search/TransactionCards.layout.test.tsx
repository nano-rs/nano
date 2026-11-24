// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5777: transaction rows fit narrow dashboard panels and Search panes
 * without hiding signal. jsdom has no container queries, so these pin the
 * contract the real-browser scenario (test_v2035_layout_batch_a) measures:
 * the maxspan badge is rendered for every width band, the narrow second line
 * wraps, the row is keyboard-operable and nothing relies on a native title.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { TransactionCards } from './TransactionCards';

vi.mock('@/hooks/useSchemaEntityMap', () => ({
  useSchemaEntityMap: () => ({ schemaFields: undefined }),
}));

afterEach(cleanup);

const T0 = Date.UTC(2026, 10, 20, 8, 0, 0);
const row = (host: string, durationSec: number, events: number) => ({
  id: host,
  timestamp: new Date(T0),
  source: 'search',
  fields: {
    'device.hostname': host,
    duration: durationSec,
    eventcount: events,
    transaction_start: new Date(T0).toISOString(),
    transaction_end: new Date(T0 + durationSec * 1000).toISOString(),
    _raw_events: ['4625 failed logon for judy.chen from 198.51.100.66', '4625 failed logon'],
  },
});

// 123h 45m: the longest duration string formatDuration produces in practice.
const LONG = 123 * 3600 + 45 * 60;
const RESULTS = [row('jump-01', LONG, 42), row('dc-01', 60, 3)];
const QUERY = 'source_type="auth" status="Failure" | transaction device.hostname maxspan=30m';

describe('TransactionCards layout (NAN-5777)', () => {
  it('renders the maxspan badge for the narrow AND the wide layout, never only one', () => {
    render(<TransactionCards results={RESULTS} query={QUERY} />);
    const [longRow] = screen.getAllByTestId('tx-row');
    const badges = within(longRow).getAllByTestId('tx-maxspan-exceeded');
    // One lives in the bar column (shown from 36rem), one in the duration
    // cell (hidden from 36rem): together they cover every container width.
    expect(badges).toHaveLength(2);
    const narrow = badges.filter((b) => b.className.includes('@[36rem]/tx:hidden'));
    expect(narrow).toHaveLength(1);
    expect(narrow[0].closest('[data-testid="tx-duration"]')).not.toBeNull();
    const wide = badges.find((b) => !b.className.includes('@[36rem]/tx:hidden'))!;
    expect(wide.closest('.\\@\\[36rem\\]\\/tx\\:flex')).not.toBeNull();
    // A transaction within maxspan has no badge.
    expect(within(screen.getAllByTestId('tx-row')[1]).queryAllByTestId('tx-maxspan-exceeded')).toHaveLength(0);
  });

  it('the narrow second line wraps, so a multi-hour duration cannot overflow', () => {
    render(<TransactionCards results={RESULTS} query={QUERY} />);
    const cell = within(screen.getAllByTestId('tx-row')[0]).getByTestId('tx-duration');
    expect(cell.textContent).toContain('123h 45m');
    const cls = cell.className.split(/\s+/);
    expect(cls).toContain('flex-wrap');
    expect(cls).not.toContain('whitespace-nowrap');
    expect(cls).toContain('@[24rem]/tx:flex-nowrap');
    // Each value stays on one line by itself; the line wraps between them.
    for (const child of Array.from(cell.children).filter((c) => !c.classList.contains('sr-only'))) {
      expect(child.className).toContain('whitespace-nowrap');
    }
  });

  it('rows size to their container: no fixed-width grid template', () => {
    render(<TransactionCards results={RESULTS} query={QUERY} />);
    const r = screen.getAllByTestId('tx-row')[0];
    expect(r.getAttribute('style') ?? '').not.toContain('grid-template-columns');
    expect(r.className).toContain('grid-cols-[16px_minmax(0,1fr)_auto]');
    expect(r.closest('.\\@container\\/tx')).not.toBeNull();
  });

  it('the row toggles from the keyboard and exposes its state', () => {
    render(<TransactionCards results={RESULTS} query={QUERY} />);
    const toggle = screen.getByRole('button', { name: 'Expand transaction jump-01' });
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(toggle);
    const open = screen.getByRole('button', { name: 'Collapse transaction jump-01' });
    expect(open.getAttribute('aria-expanded')).toBe('true');
    expect(screen.getByText('4625 failed logon for judy.chen from 198.51.100.66')).toBeTruthy();
  });

  it('the last event time is available to screen readers on the collapsed row', () => {
    render(<TransactionCards results={RESULTS} query={QUERY} />);
    const cell = within(screen.getAllByTestId('tx-row')[0]).getByTestId('tx-duration');
    const sr = cell.querySelector('.sr-only');
    expect(sr?.textContent).toMatch(/^to \d\d\/\d\d \d\d:\d\d:\d\d UTC$/);
  });

  it('uses no native title tooltips for values', () => {
    const { container } = render(<TransactionCards results={RESULTS} query={QUERY} />);
    fireEvent.click(screen.getByRole('button', { name: 'Expand transaction jump-01' }));
    for (const el of Array.from(container.querySelectorAll('[title]'))) {
      // Only icon buttons / disabled-control hints keep a title.
      expect(el.tagName).toBe('BUTTON');
    }
  });

  it('the toolbar wraps and the filter input shrinks instead of a fixed 220px', () => {
    render(<TransactionCards results={RESULTS} query={QUERY} />);
    const input = screen.getByPlaceholderText('Filter by user or host');
    expect(input.className).toContain('w-full');
    expect(input.className).not.toContain('w-[220px]');
    const toolbar = input.closest('.border-b')!;
    expect(toolbar.className).toContain('flex-wrap');
    for (const name of ['Duration', 'Events', 'Recent', 'Notable only']) {
      expect(within(toolbar as HTMLElement).getByRole('button', { name: new RegExp(name) })).toBeTruthy();
    }
  });
});
