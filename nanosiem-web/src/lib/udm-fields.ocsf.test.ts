import { describe, expect, it } from 'vitest';
import { filterFieldsWithSchema, filterUdmFields } from './udm-fields';

// NAN-5292: the playbook builder's Where autocomplete must not teach UDM short
// names on an OCSF deployment.
const OCSF_FIELDS = [
  'src_endpoint.ip',
  'dst_endpoint.ip',
  'device.hostname',
  'dst_endpoint.hostname',
  'process.name',
  'actor.user.name',
  'source_type',
];

describe('filterFieldsWithSchema (NAN-5292)', () => {
  it('suggests only schema fields when OCSF fields are supplied', () => {
    const all = filterFieldsWithSchema('', OCSF_FIELDS, 100);
    expect(all).toEqual([...OCSF_FIELDS].sort((a, b) => a.localeCompare(b)));
    for (const udm of ['src_ip', 'dest_host', 'process_name', 'user']) {
      expect(all).not.toContain(udm);
    }
  });

  it('matches OCSF paths by prefix and by dotted leaf', () => {
    expect(filterFieldsWithSchema('src', OCSF_FIELDS)).toEqual(['src_endpoint.ip']);
    expect(filterFieldsWithSchema('hostname', OCSF_FIELDS)).toEqual([
      'device.hostname',
      'dst_endpoint.hostname',
    ]);
  });

  it('keeps the UDM list unchanged on a UDM deployment', () => {
    expect(filterFieldsWithSchema('src', undefined)).toEqual(filterUdmFields('src'));
    expect(filterFieldsWithSchema('src', [])).toContain('src_ip');
  });
});
