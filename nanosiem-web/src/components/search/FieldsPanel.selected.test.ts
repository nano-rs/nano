import { describe, expect, it } from 'vitest';
import {
  FIELD_STATS_PINNED_COLUMNS,
  SELECTED_FIELDS_OCSF,
  SELECTED_FIELDS_UDM,
} from './FieldsPanel';

// NAN-3251: the OCSF "Selected" set must carry the same host identity the UDM
// set does (src_host/dest_host), plus device.hostname for endpoint-class
// events, so OCSF tenants land on hostnames without digging through Available.
describe('FieldsPanel Selected field sets', () => {
  const ocsfHostFields = [
    'src_endpoint.hostname',
    'dst_endpoint.hostname',
    'device.hostname',
  ];

  it('OCSF Selected set includes the host-identity fields', () => {
    for (const field of ocsfHostFields) {
      expect(SELECTED_FIELDS_OCSF.has(field), field).toBe(true);
    }
  });

  it('OCSF Selected set includes the protocol name (UDM `protocol` analog)', () => {
    expect(SELECTED_FIELDS_OCSF.has('connection_info.protocol_name')).toBe(true);
  });

  it('UDM Selected set keeps its host fields', () => {
    expect(SELECTED_FIELDS_UDM.has('src_host')).toBe(true);
    expect(SELECTED_FIELDS_UDM.has('dest_host')).toBe(true);
  });

  it('pinned field-stats columns cover both Selected sets', () => {
    for (const field of [...SELECTED_FIELDS_UDM, ...SELECTED_FIELDS_OCSF]) {
      expect(FIELD_STATS_PINNED_COLUMNS).toContain(field);
    }
    for (const field of ocsfHostFields) {
      expect(FIELD_STATS_PINNED_COLUMNS).toContain(field);
    }
  });
});
