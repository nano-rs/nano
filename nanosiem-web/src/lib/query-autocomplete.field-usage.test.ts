// SPDX-License-Identifier: AGPL-3.0-or-later
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  getQueryAutocompleteSuggestions,
  invalidateFieldUsageCache,
  setAutocompleteDataSource,
  type AutocompleteDataSource,
  type FieldUsage,
  type UdmFieldInfo,
} from './query-autocomplete';

const UDM_FIELDS: UdmFieldInfo[] = ['src_ip', 'dest_ip', 'user', 'hostname', 'process_name', 'auth_result', 'mac'].map(
  (name) => ({ name, column_name: name, data_type: 'String', category: 'System', description: '' }),
);

let usage: FieldUsage | null = null;
const getFieldUsage = vi.fn(async () => usage);

function install() {
  const source: AutocompleteDataSource = {
    getSourceTypes: async () => [],
    getSchemaFields: async () => ({ schema: 'udm', fields: [] }),
    getLegacyUdmFields: async () => UDM_FIELDS,
    getFieldUsage,
  };
  setAutocompleteDataSource(source);
}

const suggest = (q: string, explicit = false) => getQueryAutocompleteSuggestions(q, q.length, [], { explicit });

describe('field suggestions use recent + popular + common order (NAN-3812)', () => {
  beforeEach(() => {
    usage = null;
    getFieldUsage.mockClear();
    install();
  });

  it('empty explicit prompt with no history offers the common list first', async () => {
    const r = await suggest('', true);
    expect(r.context).toBe('field');
    expect(r.options[0]).toMatchObject({ value: 'sourcetype', section: 'common' });
  });

  it('empty prompt does not pop without an explicit request, nor inside a pipe', async () => {
    expect((await suggest('')).options).toHaveLength(0);
    expect((await suggest('source_type="aws" | stats count ', true)).context).not.toBe('field');
  });

  it('after a prior term, explicit prompt offers fields again', async () => {
    const r = await suggest('source_type="aws" ', true);
    expect(r.context).toBe('field');
    expect(r.options.length).toBeGreaterThan(0);
  });

  it('a field searched recently appears under Recent, then Popular, then Common', async () => {
    usage = { recent: ['auth_result'], popular: ['mac'] };
    const r = await suggest('', true);
    expect(r.options.slice(0, 3).map((o) => [o.value, o.section])).toEqual([
      ['auth_result', 'recent'],
      ['mac', 'popular'],
      ['sourcetype', 'common'],
    ]);
    const names = r.options.map((o) => o.value);
    expect(new Set(names).size).toBe(names.length);
  });

  it('prefix filters inside groups while typing', async () => {
    usage = { recent: ['auth_result'], popular: ['src_ip'] };
    const r = await suggest('s');
    expect(r.options.map((o) => [o.value, o.section])).toEqual([
      ['src_ip', 'popular'],
      ['sourcetype', 'common'],
      ['source_type', 'common'],
      ['source', 'common'],
    ]);
  });

  it('caches usage for a short time and refetches after invalidation', async () => {
    usage = { recent: [], popular: [] };
    await suggest('s');
    await suggest('sr');
    expect(getFieldUsage).toHaveBeenCalledTimes(1);
    invalidateFieldUsageCache();
    await suggest('src');
    expect(getFieldUsage).toHaveBeenCalledTimes(2);
  });

  it('a failing usage endpoint falls back to the common order', async () => {
    getFieldUsage.mockRejectedValueOnce(new Error('503'));
    const r = await suggest('', true);
    expect(r.options[0].value).toBe('sourcetype');
  });
});
