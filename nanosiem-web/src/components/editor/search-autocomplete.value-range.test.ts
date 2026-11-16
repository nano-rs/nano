// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5500: accepting a value completion must replace the WHOLE nPL value
// token. `metadata.log_source=web-app-json` + Enter used to become
// `metadata.log_source=web-app-"web-app-json"` (0 events) because the token
// regex stopped at `-`.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CompletionContext, type CompletionResult } from '@codemirror/autocomplete';
import { EditorState } from '@codemirror/state';

const suggestions = vi.hoisted(() => ({
  next: { options: [] as { value: string }[], context: null as string | null },
}));

vi.mock('@/lib/query-autocomplete', () => ({
  getQueryAutocompleteSuggestions: vi.fn(async () => suggestions.next),
}));
vi.mock('./detection-language', () => ({ isInYamlSection: () => false }));

import { completionRange, searchQueryAutocomplete } from './search-autocomplete';
import { queryAutocomplete } from './detection-autocomplete';

type Source = (ctx: CompletionContext) => Promise<CompletionResult | null>;

/** `‸` in `marked` is the cursor (defaults to end of doc). */
function split(marked: string): { doc: string; pos: number } {
  const i = marked.indexOf('‸');
  return i === -1 ? { doc: marked, pos: marked.length } : { doc: marked.slice(0, i) + marked.slice(i + 1), pos: i };
}

async function run(source: Source, marked: string, labels: string[], context: string | null, explicit = true) {
  suggestions.next = { options: labels.map((value) => ({ value })), context };
  const { doc, pos } = split(marked);
  const state = EditorState.create({ doc });
  return { state, pos, result: await source(new CompletionContext(state, pos, explicit)) };
}

function validFor(result: CompletionResult, text: string): boolean {
  const v = result.validFor;
  if (v instanceof RegExp) return v.test(text);
  if (typeof v === 'function') return Boolean(v(text, result.from, result.to ?? result.from, EditorState.create()));
  return false;
}

/** Accept `label` the way CodeMirror does on Enter / Tab / click (same apply + range). */
async function accept(source: Source, marked: string, label: string, context = 'source_type', others: string[] = []) {
  const { state, pos, result } = await run(source, marked, [label, ...others], context);
  expect(result).not.toBeNull();
  const typed = state.doc.sliceString(result!.from, pos);
  expect(validFor(result!, typed)).toBe(true);
  const option = result!.options.find((o) => o.label === label)!;
  expect(option).toBeDefined();
  const insert = typeof option.apply === 'string' ? option.apply : option.label;
  return state.update({ changes: { from: result!.from, to: result!.to ?? pos, insert } }).state.doc.toString();
}

describe.each([
  ['search bar', searchQueryAutocomplete as Source],
  ['rule editor query', queryAutocomplete as Source],
])('%s value completion replaces the whole nPL value (NAN-5500)', (_name, source) => {
  beforeEach(() => {
    suggestions.next = { options: [], context: null };
  });

  it('exact failing case: partial hyphenated log_source', async () => {
    expect(await accept(source, 'metadata.log_source=web-app-js', 'web-app-json')).toBe(
      'metadata.log_source=web-app-json',
    );
  });

  it('exact typed value closes the popup so Enter runs the search', async () => {
    const { result } = await run(source, 'metadata.log_source=web-app-json', ['web-app-json'], 'source_type', false);
    expect(result).toBeNull();
  });

  it('exact typed value with a longer sibling still closes the popup (Enter must not swap it)', async () => {
    const { result } = await run(
      source,
      'metadata.log_source=web-app-json',
      ['web-app-json', 'web-app-json-v2'],
      'source_type',
      false,
    );
    expect(result).toBeNull();
  });

  it('exact match is case-insensitive, like the option filter', async () => {
    const { result } = await run(source, 'metadata.log_source=Web-App-Json', ['web-app-json'], 'source_type', false);
    expect(result).toBeNull();
    const { result: partial } = await run(source, 'metadata.log_source=web-', ['web-app-json'], 'source_type');
    expect(validFor(partial!, 'WEB-APP-JSON')).toBe(false);
  });

  it('explicit (Ctrl-Space) on an exact value lists the siblings, whole-token range', async () => {
    expect(
      await accept(source, 'metadata.log_source=web-app-json', 'web-app-json-v2', 'source_type', ['web-app-json']),
    ).toBe('metadata.log_source=web-app-json-v2');
  });

  it('validFor stays valid across hyphens and re-queries once the token is an exact option', async () => {
    const { result } = await run(source, 'metadata.log_source=web-', ['web-app-json'], 'source_type');
    expect(validFor(result!, 'web-app-j')).toBe(true);
    expect(validFor(result!, 'web-app-json')).toBe(false);
    expect(validFor(result!, 'web app')).toBe(false);
  });

  it('dotted value', async () => {
    expect(await accept(source, 'source_type=aws.cloud', 'aws.cloudtrail')).toBe('source_type=aws.cloudtrail');
  });

  it('IPv4 and IPv6 values', async () => {
    expect(await accept(source, 'source_type=10.0.', '10.0.0.1')).toBe('source_type=10.0.0.1');
    expect(await accept(source, 'source_type=2605:d580:', '2605:d580::1')).toBe('source_type=2605:d580::1');
  });

  it('path / email / plus characters stay inside the token', async () => {
    expect(await accept(source, 'source_type=syslog/fw-', 'syslog/fw-01')).toBe('source_type=syslog/fw-01');
    expect(await accept(source, 'source_type=dan@na', 'dan@nano.rs')).toBe('source_type=dan@nano.rs');
  });

  it('field=value pair after another condition keeps the prefix', async () => {
    expect(await accept(source, 'src_ip=1.2.3.4 AND metadata.log_source=web-a', 'web-app-json')).toBe(
      'src_ip=1.2.3.4 AND metadata.log_source=web-app-json',
    );
  });

  it('cursor mid-token replaces the whole token, not just the prefix', async () => {
    expect(await accept(source, 'metadata.log_source=web-‸app-json | stats count', 'web-app-json-v2')).toBe(
      'metadata.log_source=web-app-json-v2 | stats count',
    );
  });

  it('inside an open quoted string: bare value, existing closing quote kept', async () => {
    expect(await accept(source, 'metadata.log_source="web-app‸"', 'web-app-json')).toBe(
      'metadata.log_source="web-app-json"',
    );
  });

  it('inside an unclosed quoted string: closes the literal', async () => {
    expect(await accept(source, 'metadata.log_source="web-app', 'web-app-json')).toBe(
      'metadata.log_source="web-app-json"',
    );
  });

  it('unclosed quote does not swallow the pipeline after the value', async () => {
    expect(await accept(source, 'metadata.log_source="web‸|stats count', 'web-app-json')).toBe(
      'metadata.log_source="web-app-json"|stats count',
    );
  });

  it('values carrying wildcard characters are quoted so they stay literal', async () => {
    expect(await accept(source, 'source_type=we', 'web*')).toBe('source_type="web*"');
  });

  it('value that nPL cannot take bare is quoted', async () => {
    expect(await accept(source, 'source_type=my', 'my source')).toBe('source_type="my source"');
  });

  it('field-name completion is unchanged: `-` stays a boundary (sort -field)', async () => {
    expect(await accept(source, '* | sort -cou', 'count', 'field')).toBe('* | sort -count');
  });
});

describe('completionRange', () => {
  it('value contexts span the parser unquoted-value charset', () => {
    const doc = 'metadata.log_source=web-app-json';
    expect(completionRange(doc, doc.length, 'source_type')).toMatchObject({ from: 20, to: doc.length, quoted: false });
  });

  it('field contexts keep the dotted-name token', () => {
    const doc = 'x=1 AND dst_endpoint.i';
    expect(completionRange(doc, doc.length, 'field')).toMatchObject({ from: 8, to: doc.length });
  });
});
