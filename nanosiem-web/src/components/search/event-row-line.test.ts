// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { buildEventRowLine } from './event-row-line';

// NAN-3010: every source renders the JSON line in the search results stream,
// whether or not the row carries a top-level `message`.
describe('buildEventRowLine', () => {
  const windowsEventRow = {
    id: 'evt-win-1',
    timestamp: '2026-09-28T12:00:00Z',
    _source_table: 'logs',
    source_type: 'windows_event',
    message: 'An account failed to log on.',
    activity_name: 'Logon',
    class_uid: 3002,
    src_ip: '10.0.0.5',
    user: 'alice',
    status: 'Failure',
  };

  const sysmonRow = {
    id: 'evt-sysmon-1',
    timestamp: '2026-09-28T12:00:01Z',
    source_type: 'sysmon',
    activity_name: 'Launch',
    class_uid: 1007,
    process_name: 'powershell.exe',
  };

  it('renders a windows_event row (has message) as the JSON line, message kept as a field', () => {
    const line = buildEventRowLine(windowsEventRow);
    expect(line).not.toBe('An account failed to log on.');
    expect(line?.startsWith('{')).toBe(true);
    const parsed = JSON.parse(line!);
    expect(parsed.message).toBe('An account failed to log on.');
    expect(parsed.activity_name).toBe('Logon');
    expect(parsed.class_uid).toBe(3002);
    expect(parsed).not.toHaveProperty('id');
    expect(parsed).not.toHaveProperty('timestamp');
    expect(parsed).not.toHaveProperty('_source_table');
  });

  it('renders a sysmon row (no message) as the JSON line', () => {
    const line = buildEventRowLine(sysmonRow);
    expect(line).toBe(
      '{"source_type":"sysmon","activity_name":"Launch","class_uid":1007,"process_name":"powershell.exe"}',
    );
  });

  it('renders both sources in the same format', () => {
    for (const row of [windowsEventRow, sysmonRow]) {
      const line = buildEventRowLine(row)!;
      expect(() => JSON.parse(line)).not.toThrow();
      expect(line.includes('\n')).toBe(false);
    }
  });

  it('returns null when there is nothing to show', () => {
    expect(buildEventRowLine(undefined)).toBeNull();
    expect(buildEventRowLine({ id: 'x', timestamp: 't', message: '' })).toBeNull();
  });
});
