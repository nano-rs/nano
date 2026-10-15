// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-3383: dotted field paths (`metadata.log_source`) highlight as ONE field
 * token in every nPL highlighter — the search-bar / query editor StreamLanguage,
 * the detection-rule StreamLanguage, and the static code-block tokenizer —
 * while dotted values (IPs, domains) stay non-fields.
 */
import { describe, expect, it } from 'vitest';
import { StringStream } from '@codemirror/language';
import { queryLanguageDefinition } from './query-language';
import { detectionLanguageDefinition } from './detection-language';
import { tokenizeQuery } from '@/lib/syntax-highlight';

type Pair = [string, string | null];
type StreamDef<S> = { startState: () => S; token: (stream: StringStream, state: S) => string | null };

function tokenizeStream<S>(def: StreamDef<S>, line: string): Pair[] {
  const state = def.startState();
  const out: Pair[] = [];
  const stream = new StringStream(line, 2, 2);
  while (!stream.eol()) {
    const style = def.token(stream, state);
    const text = stream.current();
    if (text.trim()) out.push([text, style]);
    stream.start = stream.pos;
  }
  return out;
}

function tokenizeStatic(line: string): Pair[] {
  return tokenizeQuery(line)
    .filter((t) => t.value.trim())
    .map((t) => [t.value, t.type]);
}

const highlighters: Array<{ name: string; field: string; tokenize: (line: string) => Pair[] }> = [
  { name: 'search bar (query-language)', field: 'special(propertyName)', tokenize: (l) => tokenizeStream(queryLanguageDefinition, l) },
  { name: 'rule editor (detection-language)', field: 'special(propertyName)', tokenize: (l) => tokenizeStream(detectionLanguageDefinition, l) },
  { name: 'static code blocks (syntax-highlight)', field: 'udm-field', tokenize: tokenizeStatic },
];

describe('rule editor (detection-language) multi-line', () => {
  it('leaves YAML frontmatter alone and highlights dotted paths in the query body', () => {
    const def = detectionLanguageDefinition;
    const state = def.startState();
    const out: Pair[] = [];
    for (const line of ['---', 'title: evil.example.com', '---', 'metadata.log_source="x"', '| stats count by actor.user.name']) {
      const stream = new StringStream(line, 2, 2);
      while (!stream.eol()) {
        const style = def.token(stream, state);
        if (stream.current().trim()) out.push([stream.current(), style]);
        stream.start = stream.pos;
      }
    }
    expect(out.filter(([, s]) => s === 'special(propertyName)').map(([t]) => t)).toEqual([
      'metadata.log_source',
      'actor.user.name',
    ]);
  });
});

describe.each(highlighters)('$name', ({ field, tokenize }) => {
  const fieldTokens = (line: string) => tokenize(line).filter(([, s]) => s === field).map(([t]) => t);

  it('tokenizes metadata.log_source="x" as one field token', () => {
    expect(tokenize('metadata.log_source="x"')[0]).toEqual(['metadata.log_source', field]);
    expect(fieldTokens('metadata.log_source="conduit_proxy"')).toEqual(['metadata.log_source']);
  });

  it('covers multi-segment paths and != comparisons', () => {
    expect(fieldTokens('a.b.c="x"')).toEqual(['a.b.c']);
    expect(fieldTokens('a.b!=1')).toEqual(['a.b']);
    expect(fieldTokens('a.b != 1')).toEqual(['a.b']);
  });

  it('covers dotted paths inside pipe commands', () => {
    expect(fieldTokens('* | where a.b > 1')).toEqual(['a.b']);
    expect(fieldTokens('* | stats count by a.b')).toEqual(['a.b']);
    expect(fieldTokens('* | table a.b, c')).toContain('a.b');
    expect(fieldTokens('* | eval x=a.b')).toContain('a.b');
  });

  it('does not classify dotted values as fields', () => {
    // IP after = — first token is the (plain) field, the IP is never a field
    expect(fieldTokens('src_ip=10.0.0.1')).toEqual(['src_ip']);
    // quoted domain
    expect(fieldTokens('dest_host="evil.example.com"')).toEqual(['dest_host']);
    // bare domain after =
    expect(fieldTokens('dest_host=evil.example.com')).toEqual(['dest_host']);
    expect(tokenize('dest_host=evil.example.com').map(([t]) => t)).toContain('evil.example.com');
    // bare free-text domain keyword
    expect(fieldTokens('evil.example.com')).toEqual([]);
  });
});
