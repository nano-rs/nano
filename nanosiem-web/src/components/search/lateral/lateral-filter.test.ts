// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-4903: lateral pivots + rule-editor risk_entity follow the schema profile. */
import { describe, expect, it } from 'vitest';
import { schemaFieldMap } from '@/lib/schema-fields';
import { lateralFilter, lateralNodeKey, rewriteLateralSeed } from './helpers';
import { riskEntityOptions } from '@/components/editor/detection-autocomplete';

describe('lateral pivots', () => {
  it('UDM output is unchanged (bare tokens unquoted)', () => {
    const udm = schemaFieldMap('udm');
    expect(rewriteLateralSeed('', 'host', 'WIN-HR11', udm)).toBe('src_host=WIN-HR11 | lateral seed=host');
    expect(lateralFilter(udm, lateralNodeKey('ip'), '10.0.0.1')).toBe('src_ip=10.0.0.1');
  });

  it('OCSF uses endpoint columns and ORs class-dependent users', () => {
    const ocsf = schemaFieldMap('ocsf');
    expect(lateralFilter(ocsf, lateralNodeKey('ip'), '10.0.0.1')).toBe('src_endpoint.ip=10.0.0.1');
    expect(rewriteLateralSeed('', 'user', 'bob smith', ocsf)).toBe(
      '(actor.user.name="bob smith" OR user.name="bob smith") | lateral seed=user',
    );
    expect(lateralFilter(ocsf, lateralNodeKey('host', 'destHost'), 'dc01')).toBe('dst_endpoint.hostname=dc01');
  });
});

describe('risk_entity options', () => {
  it('follow the profile', () => {
    expect(riskEntityOptions('udm').map((o) => o.value)).toEqual([
      'auto-detect', 'src_ip', 'user', 'hostname', 'dest_ip', 'process_name',
    ]);
    expect(riskEntityOptions('ocsf').map((o) => o.value)).toEqual([
      'auto-detect', 'src_endpoint.ip', 'actor.user.name', 'device.hostname', 'dst_endpoint.ip', 'process.name',
    ]);
  });
});
