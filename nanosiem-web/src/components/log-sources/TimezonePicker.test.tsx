// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-5839: the log source timezone picker. UTC is the default and reads as
 * "UTC (default)"; the list is every IANA zone plus the fixed offsets the
 * parsers convert, searchable by name or offset; picking a value reports it.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { TimezonePicker } from './TimezonePicker';
import {
  SOURCE_TIMEZONE_HELP,
  currentOffset,
  filterTimezoneGroups,
  timezoneGroups,
  fixedSourceOffsets,
  timezoneDisplay,
} from '@/lib/source-timezones';

// jsdom lacks what Radix Popover / cmdk measure with.
beforeAll(() => {
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
  Element.prototype.scrollIntoView ??= function () {};
});

afterEach(cleanup);

function open(value = 'UTC') {
  const onChange = vi.fn();
  render(<TimezonePicker value={value} onChange={onChange} />);
  fireEvent.click(screen.getByRole('combobox', { name: /^Timezone:/ }));
  return onChange;
}

describe('TimezonePicker', () => {
  it('shows the default as "UTC (default)"', () => {
    render(<TimezonePicker value="UTC" onChange={() => {}} />);
    expect(screen.getByRole('combobox', { name: 'Timezone: UTC (default)' })).toBeTruthy();
    cleanup();
    render(<TimezonePicker value="" onChange={() => {}} />);
    expect(screen.getByRole('combobox', { name: 'Timezone: UTC (default)' })).toBeTruthy();
  });

  it('shows a configured zone in mono with its current offset', () => {
    render(<TimezonePicker value="Asia/Tokyo" onChange={() => {}} />);
    const trigger = screen.getByRole('combobox', { name: 'Timezone: Asia/Tokyo' });
    expect(trigger.textContent).toContain('Asia/Tokyo');
    expect(trigger.textContent).toContain('+09:00');
    expect(trigger.querySelector('.font-mono')?.textContent).toBe('Asia/Tokyo');
  });

  it('searches IANA zones and picks one', () => {
    const onChange = open();
    fireEvent.change(screen.getByLabelText('Search timezones'), { target: { value: 'new_york' } });
    const list = screen.getByRole('listbox', { name: 'Timezones' });
    const option = within(list).getByRole('option', { name: /America\/New_York/ });
    fireEvent.click(option);
    expect(onChange).toHaveBeenCalledWith('America/New_York');
    expect(screen.queryByRole('listbox')).toBeNull();
  });

  it('searches by offset and offers fixed offsets', () => {
    const onChange = open();
    fireEvent.change(screen.getByLabelText('Search timezones'), { target: { value: '+05:30' } });
    const list = screen.getByRole('listbox', { name: 'Timezones' });
    fireEvent.click(within(list).getByRole('option', { name: /UTC\+05:30/ }));
    expect(onChange).toHaveBeenCalledWith('+05:30');
  });

  it('explains that it applies only to timestamps without an offset', () => {
    open();
    expect(screen.getByText(SOURCE_TIMEZONE_HELP)).toBeTruthy();
    expect(SOURCE_TIMEZONE_HELP).toMatch(/only for timestamps without an offset/);
  });

  it('marks the selected option', () => {
    open('Europe/Berlin');
    fireEvent.change(screen.getByLabelText('Search timezones'), { target: { value: 'berlin' } });
    const option = screen.getByRole('option', { name: /Europe\/Berlin/ });
    expect(option.getAttribute('data-current')).toBe('true');
  });
});

describe('TimezonePicker keyboard and ARIA', () => {
  it('arrow keys move through options and Enter picks one', () => {
    const onChange = open();
    const input = screen.getByLabelText('Search timezones');
    fireEvent.change(input, { target: { value: 'america/new_york' } });
    fireEvent.keyDown(input, { key: 'ArrowDown' });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onChange).toHaveBeenCalledWith('America/New_York');
  });

  it('Escape closes and returns focus to the trigger', async () => {
    open();
    const input = screen.getByLabelText('Search timezones');
    fireEvent.keyDown(input, { key: 'Escape' });
    expect(screen.queryByRole('listbox')).toBeNull();
    const trigger = screen.getByRole('combobox', { name: /^Timezone:/ });
    await vi.waitFor(() => expect(document.activeElement).toBe(trigger));
  });

  it('the listbox owns only groups and options; the search input sits outside it', () => {
    open();
    const list = screen.getByRole('listbox');
    expect(list.contains(screen.getByLabelText('Search timezones'))).toBe(false);
    expect(within(list).queryByRole('textbox')).toBeNull();
    expect(within(list).getAllByRole('group').length).toBeGreaterThan(2);
    expect(list.textContent).not.toContain('Applies only to timestamps');
  });

  it('a zero offset search finds UTC (default)', () => {
    open('Asia/Tokyo');
    fireEvent.change(screen.getByLabelText('Search timezones'), { target: { value: '+00:00' } });
    expect(screen.getByRole('option', { name: /UTC \(default\)/ })).toBeTruthy();
  });
});

describe('timezone options', () => {
  it('lead with the default and the fixed offsets, then regions', () => {
    const groups = timezoneGroups(new Date('2026-01-15T12:00:00Z'));
    expect(groups[0]).toEqual({
      region: 'Default',
      items: [{ id: 'UTC', label: 'UTC (default)', hint: '±00:00' }],
    });
    expect(groups[1].region).toBe('Fixed offset');
    expect(groups.some((g) => g.region === 'America')).toBe(true);
    const ny = groups.flatMap((g) => g.items).find((i) => i.id === 'America/New_York');
    expect(ny?.hint).toBe('-05:00');
  });

  it('filtering keeps only matches', () => {
    const groups = filterTimezoneGroups(timezoneGroups(), 'kolkata');
    expect(groups.flatMap((g) => g.items).map((i) => i.id)).toEqual(['Asia/Kolkata']);
    expect(filterTimezoneGroups(timezoneGroups(), 'zzzz-nothing')).toEqual([]);
  });

  it('fixed offsets match what the server accepts', () => {
    const offsets = fixedSourceOffsets();
    expect(offsets[0]).toBe('-12:00');
    expect(offsets[offsets.length - 1]).toBe('+14:00');
    expect(offsets).toContain('+05:45');
    expect(offsets).toContain('+03:30');
    expect(offsets).not.toContain('+01:30');
    expect(offsets).not.toContain('-13:00');
  });

  it('offsets and display labels', () => {
    expect(currentOffset('America/New_York', new Date('2026-07-15T12:00:00Z'))).toBe('-04:00');
    expect(timezoneDisplay('UTC')).toBe('UTC (default)');
    expect(timezoneDisplay('-05:00')).toBe('-05:00');
  });
});
