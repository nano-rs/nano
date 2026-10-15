// SPDX-License-Identifier: AGPL-3.0-or-later
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CompletionContext, type CompletionResult } from '@codemirror/autocomplete';
import { EditorState } from '@codemirror/state';

const suggestions = vi.hoisted(() => ({
  next: { options: [] as { value: string; section?: string }[], context: null as string | null },
}));

vi.mock('@/lib/query-autocomplete', () => ({
  getQueryAutocompleteSuggestions: vi.fn(async () => suggestions.next),
}));
vi.mock('./detection-language', () => ({ isInYamlSection: () => false }));

import { searchQueryAutocomplete } from './search-autocomplete';
import { queryAutocomplete } from './detection-autocomplete';

type Source = (ctx: CompletionContext) => Promise<CompletionResult | null>;

/** Run a completion source at end of `doc`, accept `label`, return the new doc. */
async function accept(source: Source, doc: string, label: string, context: string | null = 'field') {
  suggestions.next = { options: [{ value: label }], context };
  const state = EditorState.create({ doc });
  const pos = doc.length;
  const result = await source(new CompletionContext(state, pos, true));
  expect(result).not.toBeNull();
  const typed = doc.slice(result!.from, pos);
  // CodeMirror keeps the result alive (and filters by) the typed span.
  expect(result!.validFor instanceof RegExp && result!.validFor.test(typed)).toBe(true);
  const option = result!.options.find((o) => o.label === label)!;
  // CodeMirror's fuzzy filter matches the label against the typed span.
  expect(label.startsWith(typed)).toBe(true);
  // Insert exactly what CodeMirror would: the string `apply` if set, else the label.
  const insert = typeof option.apply === 'string' ? option.apply : option.label;
  return state.update({ changes: { from: result!.from, to: result!.to ?? pos, insert } }).state.doc.toString();
}

describe.each([
  ['search bar', searchQueryAutocomplete as Source],
  ['rule editor query', queryAutocomplete as Source],
])('%s autocomplete replaces the whole dotted token (NAN-3192)', (_name, source) => {
  beforeEach(() => {
    suggestions.next = { options: [], context: null };
  });

  it('dst_endpoint. + dst_endpoint.ip -> dst_endpoint.ip', async () => {
    expect(await accept(source, 'dst_endpoint.', 'dst_endpoint.ip')).toBe('dst_endpoint.ip');
  });

  it('actor.process.na + actor.process.name -> actor.process.name', async () => {
    expect(await accept(source, 'actor.process.na', 'actor.process.name')).toBe('actor.process.name');
  });

  it('src + src_ip -> src_ip', async () => {
    expect(await accept(source, 'src', 'src_ip')).toBe('src_ip');
  });

  it('dotted field after a prior condition keeps the prefix', async () => {
    expect(await accept(source, 'src_ip=1.2.3.4 AND dst_endpoint.', 'dst_endpoint.ip')).toBe(
      'src_ip=1.2.3.4 AND dst_endpoint.ip',
    );
  });

  it('argument value after param= inserts the bare value (NAN-3193)', async () => {
    expect(await accept(source, '* | timechart span=', '1h', 'argument_value')).toBe('* | timechart span=1h');
    expect(await accept(source, '* | timechart span=1', '1h', 'argument_value')).toBe('* | timechart span=1h');
    expect(await accept(source, '* | anomaly method=', 'zscore', 'argument_value')).toBe(
      '* | anomaly method=zscore',
    );
  });

  it('parameter name inserts the bare name (NAN-3193)', async () => {
    expect(await accept(source, '* | timechart sp', 'span', 'parameter')).toBe('* | timechart span');
  });
});

describe('rule editor function completion (NAN-3193)', () => {
  it('eval function still appends ()', async () => {
    expect(await accept(queryAutocomplete as Source, '* | eval x=low', 'lower', 'function')).toBe(
      '* | eval x=lower()',
    );
  });
});

describe('getQueryAutocompleteSuggestions contexts (NAN-3193)', () => {
  it('classifies param values, param names and eval functions distinctly', async () => {
    const actual = await vi.importActual<typeof import('@/lib/query-autocomplete')>('@/lib/query-autocomplete');
    const get = (q: string) => actual.getQueryAutocompleteSuggestions(q, q.length, []);

    for (const q of ['* | timechart span=', '* | bin span=1', '* | transaction maxspan=', '* | join type=']) {
      const r = await get(q);
      expect(r.context, q).toBe('argument_value');
      expect(r.options.length, q).toBeGreaterThan(0);
    }
    const span = await get('* | timechart span=');
    expect(span.options.map((o) => o.value)).toContain('1h');

    expect((await get('* | bin spa')).context).toBe('parameter');
    expect((await get('* | eval x=low')).context).toBe('function');
    expect((await get('* | stats co')).context).toBe('function');
  });
});

describe('search bar field groups (NAN-3812)', () => {
  it('maps field sections to ranked CodeMirror sections and passes explicit', async () => {
    const mocked = await import('@/lib/query-autocomplete');
    suggestions.next = {
      options: [
        { value: 'src_endpoint.ip', section: 'recent' },
        { value: 'class_uid', section: 'popular' },
        { value: 'metadata.log_source', section: 'common' },
        { value: 'zeta', section: 'other' },
      ],
      context: 'field',
    };
    const state = EditorState.create({ doc: '' });
    const result = await searchQueryAutocomplete(new CompletionContext(state, 0, true));
    expect(vi.mocked(mocked.getQueryAutocompleteSuggestions)).toHaveBeenLastCalledWith('', 0, [], { explicit: true });
    const sections = result!.options.map((o) => (typeof o.section === 'object' ? o.section : null));
    expect(sections.map((s) => s?.name)).toEqual(['Recent (you)', 'Popular in this workspace', 'Common', 'All fields']);
    expect(sections.map((s) => s?.rank)).toEqual([0, 1, 2, 3]);
  });
});
