// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeAll, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import type { TimeRangeValue } from '@/lib/time-range';
import { DateTimeRangePicker } from './date-time-range-picker';

beforeAll(() => {
  // jsdom has neither; the picker's mobile check and Radix's popper need them.
  window.matchMedia ??= ((query: string) => ({
    matches: false, media: query, onchange: null,
    addEventListener: () => {}, removeEventListener: () => {},
    addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
  globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as unknown as typeof ResizeObserver;
});
afterEach(cleanup);

const custom = (start: string, end: string): TimeRangeValue =>
  ({ type: 'custom', start: new Date(start), end: new Date(end) });

it('keeps an in-progress edit when the value changes under an open popover (NAN-2836)', () => {
  // A live-tail tick re-anchors the page's range every interval, so the
  // picker's `value` changes while the analyst is editing. The staged edit is
  // theirs; the tick must not overwrite it, or Apply sends the old range back.
  const onChange = vi.fn();
  const { rerender } = render(
    <DateTimeRangePicker value={custom('2026-09-25T09:00:00Z', '2026-09-25T10:00:00Z')} onChange={onChange} variant="search" />,
  );
  fireEvent.click(screen.getByRole('button', { name: /Sep 25, 09:00/ }));

  const [fromDate] = document.querySelectorAll<HTMLInputElement>('input[type="date"]');
  fireEvent.change(fromDate, { target: { value: '2026-09-20' } });

  // The tail ticks: same one-hour window, re-anchored 15 s later.
  rerender(
    <DateTimeRangePicker value={custom('2026-09-25T09:00:15Z', '2026-09-25T10:00:15Z')} onChange={onChange} variant="search" />,
  );
  expect(document.querySelector<HTMLInputElement>('input[type="date"]')!.value).toBe('2026-09-20');

  fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
  expect(onChange).toHaveBeenCalledOnce();
  const applied = onChange.mock.calls[0][0] as TimeRangeValue;
  expect(applied.type).toBe('custom');
  expect(applied.start!.toISOString().slice(0, 10)).toBe('2026-09-20');
});

it('still follows an external value change while closed', () => {
  const onChange = vi.fn();
  const { rerender } = render(
    <DateTimeRangePicker value={custom('2026-09-25T09:00:00Z', '2026-09-25T10:00:00Z')} onChange={onChange} variant="search" />,
  );
  rerender(
    <DateTimeRangePicker value={custom('2026-09-22T01:00:00Z', '2026-09-22T02:00:00Z')} onChange={onChange} variant="search" />,
  );
  fireEvent.click(screen.getByRole('button', { name: /Sep 22, 01:00/ }));
  expect(document.querySelector<HTMLInputElement>('input[type="date"]')!.value).toBe('2026-09-22');
});

it('shows the rolling-window label instead of the stale range while the tail rolls it (NAN-3263)', () => {
  const value = custom('2026-10-08T02:16:00Z', '2026-10-08T03:16:00Z');
  const { rerender } = render(
    <DateTimeRangePicker
      value={value}
      onChange={() => {}}
      variant="search"
      displayOverride="Last 1h · live"
      displayTitle="2026-10-08 02:46:00 – 2026-10-08 03:46:00 UTC (live, rolling)"
    />,
  );
  const trigger = screen.getByRole('button', { name: /Last 1h · live/ });
  expect(trigger.textContent).not.toMatch(/02:16/);
  expect(trigger.getAttribute('title')).toMatch(/03:46:00 UTC/);

  // The tail stops: the picker shows the range it holds again.
  rerender(<DateTimeRangePicker value={value} onChange={() => {}} variant="search" />);
  expect(screen.getByRole('button', { name: /Oct 8, 02:16 - Oct 8, 03:16 UTC/ })).toBeTruthy();
});

// NAN-3884: a relative pick shows its relative label; the window it resolves
// to is the hover text. Fixed ranges keep showing absolute times.
it('shows a relative pick as its label, with the resolved window as hover text', () => {
  vi.useFakeTimers({ now: new Date('2026-10-15T14:02:00Z') });
  try {
    render(<DateTimeRangePicker value={{ type: 'preset', preset: 'Last 7 days' }} onChange={() => {}} variant="search" />);
    const trigger = screen.getByRole('button');
    expect(trigger.textContent).toBe('Last 7 days');
    expect(trigger.textContent).not.toMatch(/Oct/);
    // `7d · <start> → <end> <tz>` in the viewer's timezone.
    expect(trigger.getAttribute('title')).toMatch(/^7d · Oct \d+ \d\d:\d\d → Oct \d+ \d\d:\d\d \S+$/);
  } finally {
    vi.useRealTimers();
  }
});

it('re-resolves the hover window when hovered later', () => {
  vi.useFakeTimers({ now: new Date('2026-10-15T14:02:00Z') });
  try {
    render(<DateTimeRangePicker value={{ type: 'preset', preset: 'Last hour' }} onChange={() => {}} variant="search" />);
    const trigger = screen.getByRole('button');
    const before = trigger.getAttribute('title');
    vi.setSystemTime(new Date('2026-10-15T15:30:00Z'));
    fireEvent.pointerEnter(trigger);
    expect(trigger.getAttribute('title')).not.toBe(before);
    expect(trigger.getAttribute('title')).toMatch(/^1h · Oct \d+ \d\d:\d\d → Oct \d+ \d\d:\d\d \S+$/);
  } finally {
    vi.useRealTimers();
  }
});

it('keeps showing absolute times for a fixed range', () => {
  render(<DateTimeRangePicker value={custom('2026-10-01T04:00:00Z', '2026-10-01T10:00:00Z')} onChange={() => {}} variant="search" />);
  const trigger = screen.getByRole('button');
  expect(trigger.textContent).toBe('Oct 1, 04:00 - Oct 1, 10:00 UTC');
  expect(trigger.getAttribute('title')).toMatch(/^(Sep 30|Oct 1) \d\d:\d\d → Oct 1 \d\d:\d\d \S+$/);
});
