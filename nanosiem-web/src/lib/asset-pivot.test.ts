// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5312: asset-view pivots on OCSF. "Open sequence" searched
// source_type="signal" (no rows), the "Open asset view" / Investigate pivots
// rewrote OCSF fields to UDM `src_host`, a `device.uid` value was opened as a
// hostname, and the identity clause dropped the FQDN the asset was opened on.
import { describe, expect, it } from 'vitest';
import { assetPivotField, primaryIdentityKind, profileEntityFilter } from './asset-pivot';
import { assetConceptDrill } from './schema-fields';
import { withAssetIdentity } from '@/components/search/asset/helpers';

describe('assetConceptDrill alerts (Open sequence / ALERT lane)', () => {
  it('OCSF selects the Findings category, never source_type=signal', () => {
    const drill = assetConceptDrill('ocsf', 'alerts');
    expect(drill).toEqual({ _tableCommand: '| where category_uid=2' });
    expect(JSON.stringify(drill)).not.toContain('signal');
  });

  it('UDM selects findings rows (and legacy signal rows)', () => {
    const drill = assetConceptDrill('udm', 'alerts');
    expect(drill._tableCommand).toContain('source_type="findings"');
    expect(drill).not.toHaveProperty('source_type');
  });
});

describe('assetPivotField', () => {
  it('keeps the clicked OCSF path under OCSF', () => {
    expect(assetPivotField('device.hostname', 'host', 'ocsf')).toBe('device.hostname');
    expect(assetPivotField('src_endpoint.ip', 'ip', 'ocsf')).toBe('src_endpoint.ip');
    expect(assetPivotField('actor.user.name', 'user', 'ocsf')).toBe('actor.user.name');
  });

  it('offers no asset view for device.uid (not a hostname)', () => {
    expect(assetPivotField('device.uid', 'host', 'ocsf')).toBeNull();
  });

  it('keeps the legacy UDM canonical mapping', () => {
    expect(assetPivotField('hostname', 'host', 'udm')).toBe('src_host');
    expect(assetPivotField('dest_ip', 'ip', 'udm')).toBe('src_ip');
    expect(assetPivotField('user', 'user', 'udm')).toBe('user');
  });
});

describe('profileEntityFilter (Investigate)', () => {
  it('translates a canonical src_host to OCSF host columns', () => {
    const out = profileEntityFilter({ src_host: 'ir-wks-01.corp.local' }, 'ocsf');
    expect(out).not.toHaveProperty('src_host');
    expect(out._rawClause).toBe(
      '(device.hostname="ir-wks-01.corp.local" OR src_endpoint.hostname="ir-wks-01.corp.local")',
    );
  });

  it('passes OCSF paths and UDM filters through unchanged', () => {
    expect(profileEntityFilter({ 'device.hostname': 'h' }, 'ocsf')).toEqual({ 'device.hostname': 'h' });
    expect(profileEntityFilter({ src_host: 'h' }, 'udm')).toEqual({ src_host: 'h' });
  });
});

describe('withAssetIdentity', () => {
  it('includes the primary FQDN even when identities only carry the short name', () => {
    const out = withAssetIdentity(
      {},
      [{ hostname: 'ir-wks-01', user: 'mallory' }],
      { field: 'src_host', value: 'ir-wks-01.corp.local' },
      'ocsf',
    );
    const clause = String(out._identityClause);
    expect(clause).toContain('device.hostname="ir-wks-01.corp.local"');
    expect(clause).toContain('device.hostname="ir-wks-01"');
    expect(clause).not.toContain('src_host=');
  });

  it('classifies primary identifier fields', () => {
    expect(primaryIdentityKind('device.hostname')).toBe('hostname');
    expect(primaryIdentityKind('src_ip')).toBe('ip');
    expect(primaryIdentityKind('user.name')).toBe('user');
    expect(primaryIdentityKind('device.uid')).toBeNull();
  });
});
