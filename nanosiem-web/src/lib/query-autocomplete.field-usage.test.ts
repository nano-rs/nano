// SPDX-License-Identifier: AGPL-3.0-or-later
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  getQueryAutocompleteSuggestions,
  invalidateFieldUsageCache,
  setAutocompleteDataSource,
  type AutocompleteDataSource,
  type FieldUsage,
} from './query-autocomplete';

const OCSF_FIELDS = [
  'metadata.event_code',
  'metadata.log_source',
  'src_endpoint.ip',
  'dst_endpoint.ip',
  'actor.user.name',
  'process.name',
  'class_uid',
].map((name) => ({ name, type: 'String', category: 'System' }));

let usage: FieldUsage | null = null;
const getFieldUsage = vi.fn(async () => usage);

function install() {
  const source: AutocompleteDataSource = {
    getSourceTypes: async () => [],
    getSchemaFields: async () => ({ schema: 'ocsf', fields: OCSF_FIELDS }),
    getLegacyUdmFields: async () => [],
    getFieldUsage,
  };
  setAutocompleteDataSource(source);
}

const suggest = (q: string, explicit = false) => getQueryAutocompleteSuggestions(q, q.length, [], { explicit });

describe('field suggestions use recent + popular + curated order (NAN-3812)', () => {
  beforeEach(() => {
    usage = null;
    getFieldUsage.mockClear();
    install();
  });

  it('empty explicit prompt with no history offers metadata.log_source first', async () => {
    const r = await suggest('', true);
    expect(r.context).toBe('field');
    expect(r.options[0]).toMatchObject({ value: 'metadata.log_source', section: 'common' });
  });

  it('empty prompt does not pop without an explicit request, nor inside a pipe', async () => {
    expect((await suggest('')).options).toHaveLength(0);
    expect((await suggest('metadata.log_source="aws" | stats count ', true)).context).not.toBe('field');
  });

  it('after a prior term, explicit prompt offers fields again', async () => {
    const r = await suggest('metadata.log_source="aws" ', true);
    expect(r.context).toBe('field');
    expect(r.options.length).toBeGreaterThan(0);
  });

  it('a field searched recently appears under Recent', async () => {
    usage = { recent: ['src_endpoint.ip'], popular: ['class_uid'] };
    const r = await suggest('', true);
    expect(r.options.slice(0, 3).map((o) => [o.value, o.section])).toEqual([
      ['src_endpoint.ip', 'recent'],
      ['class_uid', 'popular'],
      ['metadata.log_source', 'common'],
    ]);
  });

  it('prefix filters inside groups while typing', async () => {
    usage = { recent: ['src_endpoint.ip'], popular: ['metadata.event_code'] };
    const r = await suggest('me');
    expect(r.options.map((o) => [o.value, o.section])).toEqual([
      ['metadata.event_code', 'popular'],
      ['metadata.log_source', 'common'],
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

  it('a failing usage endpoint falls back to the curated order', async () => {
    getFieldUsage.mockRejectedValueOnce(new Error('503'));
    const r = await suggest('', true);
    expect(r.options[0].value).toBe('metadata.log_source');
  });
});
