// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { resultRowKeyFields, resultRowSource } from './result-row-source';

describe('resultRowSource (NAN-5271)', () => {
  it('reads the OCSF host, then the source IP', () => {
    expect(resultRowSource({ class_uid: 1007, 'device.hostname': 'ws-01', 'src_endpoint.ip': '' })).toBe('ws-01');
    expect(resultRowSource({ class_uid: 4002, 'src_endpoint.hostname': 'proxy-1' })).toBe('proxy-1');
    expect(resultRowSource({ class_uid: 3002, 'src_endpoint.ip': '10.1.4.106' })).toBe('10.1.4.106');
  });
  it('keeps the UDM keys for a UDM row', () => {
    expect(resultRowSource({ src_host: 'h1', src_ip: '1.2.3.4' })).toBe('h1');
    expect(resultRowSource({ src_ip: '1.2.3.4' })).toBe('1.2.3.4');
    expect(resultRowSource({})).toBe('unknown');
  });
  it('labels a finding with its risk entity under either profile', () => {
    expect(resultRowSource({ source_type: 'findings', metadata: { risk_entity: 'alice' } })).toBe('alice');
    expect(resultRowSource({ source_type: 'findings', 'unmapped.risk_entity': 'bob' })).toBe('bob');
    expect(resultRowSource({ source_type: 'findings' })).toBe('finding');
  });
});

describe('resultRowKeyFields (NAN-5271)', () => {
  it('names the OCSF columns on an OCSF row', () => {
    expect(
      resultRowKeyFields({ 'src_endpoint.ip': '10.0.0.1', 'actor.user.name': 'alice', 'device.hostname': 'ws-01' }),
    ).toBe('src_endpoint.ip: 10.0.0.1, actor.user.name: alice, device.hostname: ws-01');
  });
  it('is empty when the row has no entities', () => {
    expect(resultRowKeyFields({ class_uid: 4001 })).toBe('');
    expect(resultRowKeyFields(undefined)).toBe('');
  });
});
