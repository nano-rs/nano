// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { filterRepositoryItems, ruleSourceTypes, sourceTypeCounts } from './repository-filters';

type Item = { id: string; name: string; category: string; sources: string[]; raw: { is_imported: boolean } };

const items: Item[] = [
  { id: 'a', name: 'Windows sign-in', category: 'available', sources: ['windows', 'identity'], raw: { is_imported: false } },
  { id: 'b', name: 'Windows process', category: 'updated', sources: ['windows'], raw: { is_imported: true } },
  { id: 'c', name: 'Linux sign-in', category: 'imported', sources: ['linux', 'identity'], raw: { is_imported: true } },
];

const filter = (overrides: Partial<Parameters<typeof filterRepositoryItems<Item>>[1]> = {}) =>
  filterRepositoryItems(items, {
    query: '',
    importStatus: 'all',
    selectedSourceTypes: new Set(),
    sourceTypes: (item) => item.sources,
    searchText: (item) => item.name,
    inCategory: () => true,
    ...overrides,
  }).map((item) => item.id);

describe('repository filters', () => {
  it('uses the import flag so updated items still count as imported', () => {
    expect(filter({ importStatus: 'imported' })).toEqual(['b', 'c']);
    expect(filter({ importStatus: 'not-imported' })).toEqual(['a']);
  });

  it('composes category, search, import status, and multiple source types', () => {
    expect(filter({
      query: 'WINDOWS',
      importStatus: 'imported',
      selectedSourceTypes: new Set(['linux', 'windows']),
      inCategory: (item) => item.category === 'updated',
    })).toEqual(['b']);
    expect(filter({ selectedSourceTypes: new Set(['identity']) })).toEqual(['a', 'c']);
  });

  it('counts each source type once per item and includes all rule targets', () => {
    expect([...sourceTypeCounts(items, (item) => [...item.sources, item.sources[0]])]).toEqual([
      ['windows', 2], ['identity', 2], ['linux', 1],
    ]);
    expect(ruleSourceTypes({ requires_source_types: ['windows', 'linux'], suggested_source_types: ['windows'] })).toEqual(['windows', 'linux']);
  });

  it('limits bulk selection to rows still visible after filtering', () => {
    const selected = new Set(['a', 'b']);
    const visible = filterRepositoryItems(items, {
      query: '', importStatus: 'imported', selectedSourceTypes: new Set(['windows']),
      sourceTypes: (item) => item.sources,
      searchText: (item) => item.name,
      inCategory: () => true,
    });
    expect(visible.filter((item) => selected.has(item.id)).map((item) => item.id)).toEqual(['b']);
  });
});
