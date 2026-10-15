// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { DEFAULT_RISK_NOTABLE_RULE_ID, inferRiskEntityType, riskNotableEntity } from './risk-notable';

describe('riskNotableEntity (NAN-3225)', () => {
  it('recognises the retired risk_notable kind', () => {
    expect(
      riskNotableEntity({ kind: 'risk_notable', rule_id: undefined, matched_events: [{ entity: 'alice' }] }),
    ).toEqual({ entity: 'alice', entity_type: 'user' });
  });
  it('recognises the default notable rule and dataset=risk rows', () => {
    expect(
      riskNotableEntity({
        kind: 'detection',
        rule_id: DEFAULT_RISK_NOTABLE_RULE_ID,
        matched_events: [{ entity: '10.0.0.5', entity_type: 'ip' }],
      }),
    ).toEqual({ entity: '10.0.0.5', entity_type: 'ip' });
    expect(
      riskNotableEntity({
        kind: 'detection',
        rule_id: 'custom-risk-rule',
        matched_events: [{ entity: 'ws-01.corp', score_7d: 120 }],
      }),
    ).toEqual({ entity: 'ws-01.corp', entity_type: 'hostname' });
  });
  it('ignores ordinary detection alerts and empty entities', () => {
    expect(riskNotableEntity({ kind: 'detection', rule_id: 'r', matched_events: [{ entity: 'x', src_ip: '1' }] })).toBeNull();
    expect(riskNotableEntity({ kind: 'risk_notable', rule_id: undefined, matched_events: [{ entity: '  ' }] })).toBeNull();
    expect(riskNotableEntity({ kind: 'risk_notable', rule_id: undefined, matched_events: [] })).toBeNull();
    expect(riskNotableEntity(null)).toBeNull();
  });
  it('types values like the risk reader', () => {
    expect(inferRiskEntityType('192.168.1.1')).toBe('ip');
    expect(inferRiskEntityType('a@b.c')).toBe('email');
    expect(inferRiskEntityType('host.corp')).toBe('hostname');
    expect(inferRiskEntityType('bob')).toBe('user');
  });
});
