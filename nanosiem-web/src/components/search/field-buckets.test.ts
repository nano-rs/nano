// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import {
  FIELD_BUCKET_TOOLTIPS,
  buildOnDemandFields,
  extendedTooltip,
  spillBucket,
  spillFieldName,
  spillPrefix,
} from './field-buckets';
import { buildFieldCategories } from './event-flatten';

// NAN-5265: the API returns bare spill keys; the namespace is added once.
describe('spillFieldName', () => {
  it('prefixes a bare UDM ext key with ext.', () => {
    expect(spillPrefix(false)).toBe('ext.');
    expect(spillFieldName('error_code', false)).toBe('ext.error_code');
  });

  it('prefixes a bare OCSF spill key with unmapped. exactly once', () => {
    expect(spillPrefix(true)).toBe('unmapped.');
    expect(spillFieldName('client_ip', true)).toBe('unmapped.client_ip');
    expect(spillFieldName('event_data.utc_time', true)).toBe('unmapped.event_data.utc_time');
  });

  it('never emits a doubled namespace', () => {
    // A spill object literally named `unmapped` goes through the ext. alias,
    // which the OCSF profile resolves to the same spill path.
    expect(spillFieldName('unmapped.task', true)).toBe('ext.unmapped.task');
    expect(spillFieldName('ext.code', false)).toBe('ext.code');
    for (const [key, ocsf] of [['task', true], ['unmapped.task', true], ['code', false], ['ext.code', false]] as const) {
      expect(spillFieldName(key, ocsf)).not.toMatch(/^(unmapped\.unmapped\.|ext\.ext\.)/);
    }
  });
});

describe('buildOnDemandFields', () => {
  it('UDM: the ext spill is the Extended bucket; an extended inventory is ignored', () => {
    expect(spillBucket(false)).toBe('extended');
    expect(buildOnDemandFields(['custom_key', 'src_ip_raw'], ['module.file.name'], false, new Set(['src_ip']))).toEqual([
      { field: 'ext.custom_key', bucket: 'extended' },
      { field: 'ext.src_ip_raw', bucket: 'extended' },
    ]);
  });

  it('OCSF: valid non-promoted attributes are Extended, the spill is Unmapped', () => {
    expect(spillBucket(true)).toBe('unmapped');
    expect(
      buildOnDemandFields(
        ['client_ip', 'event_data.utc_time'],
        ['module.file.company_name', 'actor.process.file.name'],
        true,
        new Set(),
      ),
    ).toEqual([
      { field: 'module.file.company_name', bucket: 'extended' },
      { field: 'actor.process.file.name', bucket: 'extended' },
      { field: 'unmapped.client_ip', bucket: 'unmapped' },
      { field: 'unmapped.event_data.utc_time', bucket: 'unmapped' },
    ]);
  });

  it('skips real columns, empty names and duplicates', () => {
    expect(
      buildOnDemandFields(['task', 'task', ''], ['process.name', 'module.file.name', 'module.file.name'], true, new Set(['process.name', 'unmapped.task'])),
    ).toEqual([{ field: 'module.file.name', bucket: 'extended' }]);
    expect(buildOnDemandFields(undefined, undefined, true, new Set())).toEqual([]);
  });
});

describe('labels shared with the event inspector', () => {
  it('inspector buckets use the same labels and tooltips', () => {
    const ocsf = buildFieldCategories(
      [['src_endpoint.ip', '10.0.0.1'], ['module.file.company_name', 'MS'], ['unmapped.task', 7]],
      new Set(['src_endpoint.ip']),
      true,
    );
    expect(ocsf.map(c => [c.label, c.tooltip])).toEqual([
      ['Core', FIELD_BUCKET_TOOLTIPS.core],
      ['Extended', 'Valid OCSF fields stored in the event JSON'],
      ['Unmapped', "Source fields the parser didn't map to OCSF"],
    ]);
    expect(FIELD_BUCKET_TOOLTIPS.core).toBe('Indexed columns');

    const udm = buildFieldCategories([['src_ip', '10.0.0.1'], ['custom_key', 'x']], new Set(), false);
    expect(udm.map(c => [c.label, c.tooltip])).toEqual([
      ['Core', 'Indexed columns'],
      ['Extended', extendedTooltip(false)],
    ]);
  });
});
