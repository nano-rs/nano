// SPDX-License-Identifier: AGPL-3.0-or-later
import { beforeEach, describe, expect, it } from 'vitest';
import {
  getQueryAutocompleteSuggestions,
  setAutocompleteDataSource,
  type AutocompleteDataSource,
} from './query-autocomplete';

// NAN-5326: `unmapped.` completes the OCSF spill keys; categories use one case.
beforeEach(() => {
  const source: AutocompleteDataSource = {
    getSourceTypes: async () => [],
    getSchemaFields: async () => ({
      schema: 'ocsf',
      fields: [
        { name: 'src_endpoint.ip', type: 'String', category: 'network' },
        { name: 'src_endpoint.port', type: 'UInt16', category: 'network' },
      ],
    }),
    getLegacyUdmFields: async () => [],
    getFieldUsage: async () => null,
    getSpillFieldNames: async () => ['vendor_sev', 'unmapped.raw_tag'],
  };
  setAutocompleteDataSource(source);
});

describe('OCSF autocomplete', () => {
  it('"unmapped." lists the spill keys (merged without blocking suggestions)', async () => {
    const q = 'unmapped.';
    await getQueryAutocompleteSuggestions(q, q.length, []);
    await new Promise((r) => setTimeout(r, 0));
    const names = (await getQueryAutocompleteSuggestions(q, q.length, [])).options.map((o) => o.value);
    expect(names).toEqual(expect.arrayContaining(['unmapped.vendor_sev', 'unmapped.raw_tag']));
  });

  it('category labels are capitalised consistently', async () => {
    const q = 'src_endpoint.';
    const opts = (await getQueryAutocompleteSuggestions(q, q.length, [])).options;
    const cats = opts.map((o) => o.category).filter(Boolean);
    expect(cats.length).toBeGreaterThan(0);
    expect(cats.every((c) => c === 'Network')).toBe(true);
  });
});
