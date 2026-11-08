// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  getQueryAutocompleteSuggestions,
  setAutocompleteDataSource,
  type AutocompleteDataSource,
} from './query-autocomplete';

// The real OCSF field universe, as `GET /api/schema/fields` serves it under
// NANO_SCHEMA_PROFILE=ocsf (OcsfProfile::fields() is built from this artifact).
const promoted = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('../../../nanosiem-core/docs/ocsf/events/promoted.json', import.meta.url)),
    'utf8',
  ),
) as { ocsf_path: string; ch_type: string; category: string }[];

const OCSF_FIELDS = promoted.map((e) => ({ name: e.ocsf_path, type: e.ch_type, category: e.category }));

function install(schema: 'ocsf' | 'udm') {
  const source: AutocompleteDataSource = {
    getSourceTypes: async () => [['windows_sysmon', 10]],
    getSchemaFields: async () => ({ schema, fields: schema === 'ocsf' ? OCSF_FIELDS : [] }),
    getLegacyUdmFields: async () =>
      ['src_ip', 'dest_ip', 'user', 'process_name'].map((name) => ({
        name,
        column_name: name,
        data_type: 'String',
        category: 'System',
        description: '',
      })),
    getFieldUsage: async () => null,
  };
  setAutocompleteDataSource(source);
}

const suggest = (q: string, explicit = false) => getQueryAutocompleteSuggestions(q, q.length, [], { explicit });

describe('autocomplete under the OCSF profile (NAN-4903)', () => {
  beforeEach(() => install('ocsf'));

  it('"metadata." lists the metadata.* children, log source first', async () => {
    const r = await suggest('metadata.');
    expect(r.context).toBe('field');
    const names = r.options.map((o) => o.value);
    expect(names[0]).toBe('metadata.log_source');
    expect(names).toEqual(expect.arrayContaining(['metadata.product.name', 'metadata.uid', 'metadata.event_code']));
    expect(names.every((n) => n.startsWith('metadata.'))).toBe(true);
  });

  it('nested paths complete (src_endpoint.)', async () => {
    const names = (await suggest('src_endpoint.')).options.map((o) => o.value);
    expect(names).toEqual(expect.arrayContaining(['src_endpoint.ip', 'src_endpoint.hostname', 'src_endpoint.port']));
  });

  it('cold-start list is the OCSF one, not the UDM common fields', async () => {
    const names = (await suggest('', true)).options.map((o) => o.value);
    expect(names[0]).toBe('metadata.log_source');
    expect(names).not.toContain('src_ip');
    expect(names).not.toContain('process_name');
    expect(names).toContain('src_endpoint.ip');
  });

  it('metadata.log_source= completes source values', async () => {
    const r = await suggest('metadata.log_source=win');
    expect(r.context).toBe('source_type');
    expect(r.options.map((o) => o.value)).toContain('windows_sysmon');
  });

  it('pipe field contexts complete OCSF paths', async () => {
    const names = (await suggest('* | stats count by process.')).options.map((o) => o.value);
    expect(names).toEqual(expect.arrayContaining(['process.name', 'process.cmd_line']));
  });
});

describe('autocomplete under the UDM profile', () => {
  beforeEach(() => install('udm'));

  it('keeps UDM names and no metadata.* paths', async () => {
    const names = (await suggest('', true)).options.map((o) => o.value);
    expect(names).toContain('src_ip');
    expect(names).not.toContain('metadata.log_source');
  });
});
