import { describe, expect, it } from 'vitest';
import { buildEventRowLine, eventDetailEntries } from './event-row-line';
import { flattenEventFields } from './event-flatten';

// NAN-5326: a process event carries ClickHouse defaults for columns its class
// doesn't use; neither the row line nor the inspector may present them as data.
const processRow = {
  id: 'e1',
  timestamp: '2026-11-12T03:16:43Z',
  activity: 'Launch',
  class_uid: 1007,
  'actor.user.name': 'mallory',
  'connection_info.protocol_num': 0,
  'dst_endpoint.port': 0,
  'src_endpoint.port': 0,
  'dst_endpoint.autonomous_system.number': 0,
  prevalence_min: 9999,
  prevalence_file_hash: 65535,
  source_type: 'defender_edr',
  is_mfa: false,
  user_unified: 'mallory',
  status: 'Success',
};

describe('buildEventRowLine (OCSF)', () => {
  it('drops zero defaults, prevalence sentinels, helper columns and inapplicable is_mfa', () => {
    const parsed = JSON.parse(buildEventRowLine(processRow, false, true)!);
    for (const k of [
      'connection_info.protocol_num',
      'dst_endpoint.port',
      'src_endpoint.port',
      'dst_endpoint.autonomous_system.number',
      'prevalence_file_hash',
      'is_mfa',
      'user_unified',
      'source_type',
    ]) {
      expect(parsed).not.toHaveProperty(k);
    }
    expect(parsed['metadata.log_source']).toBe('defender_edr');
    expect(parsed['actor.user.name']).toBe('mallory');
    expect(parsed.class_uid).toBe(1007);
    // 9999 = "common" (>= 1000 hosts) is real signal, not N/A (NAN-1689).
    expect(parsed.prevalence_min).toBe(9999);
  });

  it('keeps zeros that can be real data on the raw row', () => {
    const parsed = JSON.parse(
      buildEventRowLine(
        { class_uid: 3002, logon_type_id: 0, 'traffic.bytes_out': 0, severity_id: 0, exit_code: 0, 'dst_endpoint.port': 0 },
        false,
        true,
      )!,
    );
    expect(parsed.logon_type_id).toBe(0);
    expect(parsed['traffic.bytes_out']).toBe(0);
    expect(parsed.severity_id).toBe(0);
    expect(parsed.exit_code).toBe(0);
    expect(parsed).not.toHaveProperty('dst_endpoint.port');
  });

  it('keeps is_mfa=false when the row has no class_uid (projected row)', () => {
    const parsed = JSON.parse(buildEventRowLine({ 'actor.user.name': 'bob', is_mfa: false }, false, true)!);
    expect(parsed.is_mfa).toBe(false);
  });

  it('keeps is_mfa on an Authentication event', () => {
    const parsed = JSON.parse(buildEventRowLine({ class_uid: 3002, is_mfa: false }, false, true)!);
    expect(parsed.is_mfa).toBe(false);
  });
});

describe('Event Inspector flatten (OCSF)', () => {
  it('agrees with the row line on is_mfa and source_type', () => {
    const keys = flattenEventFields(processRow, true).map(([k]) => k);
    expect(keys).not.toContain('is_mfa');
    expect(keys).not.toContain('source_type');
    expect(keys).toContain('metadata.log_source');
    expect(keys).not.toContain('dst_endpoint.port');
  });
});

describe('eventDetailEntries (rule-test EVENT DETAIL)', () => {
  it('lists real fields only', () => {
    const keys = eventDetailEntries(processRow, true).map(([k]) => k);
    expect(keys).not.toContain('user_unified');
    expect(keys).not.toContain('prevalence_file_hash');
    expect(keys).not.toContain('dst_endpoint.port');
    expect(keys).not.toContain('source_type');
    expect(keys).toContain('metadata.log_source');
    expect(keys).toContain('actor.user.name');
  });
});
