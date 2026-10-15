// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
/** NAN-3195: VRL tokenizer + highlighted read-only views. */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { StringStream } from '@codemirror/language';
import { highlightVrl, vrlLanguageDefinition, type VrlState } from './vrl-language';
import { VrlEditor } from './VrlEditor';
import { VrlLine } from './VrlHighlight';

afterEach(cleanup);

/** Tokenize lines with the stream definition; returns [text, style] pairs (whitespace dropped). */
function tokenize(...lines: string[]): Array<[string, string | null]> {
  const state: VrlState = vrlLanguageDefinition.startState();
  const out: Array<[string, string | null]> = [];
  for (const line of lines) {
    const stream = new StringStream(line, 2, 2);
    while (!stream.eol()) {
      const style = vrlLanguageDefinition.token(stream, state);
      const text = stream.current();
      if (text.trim()) out.push([text, style]);
      stream.start = stream.pos;
    }
  }
  return out;
}

describe('vrl tokenizer', () => {
  it('tags a # line comment, including -> inside it', () => {
    expect(tokenize('# ---- method -> activity_id ----')).toEqual([
      ['# ---- method -> activity_id ----', 'lineComment'],
    ]);
  });

  it('tags a trailing comment after code', () => {
    expect(tokenize('x = 1 # note').at(-1)).toEqual(['# note', 'lineComment']);
  });

  it('tags a raw regex literal as one regexp token', () => {
    expect(tokenize("ip_re = r'^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$|^[0-9A-Fa-f:]{3,}$'")).toEqual([
      ['ip_re', 'variableName'],
      ['=', 'operator'],
      ["r'^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$|^[0-9A-Fa-f:]{3,}$'", 'regexp'],
    ]);
  });

  it("tags s'…' as string and t'…' as special string", () => {
    expect(tokenize("a = s'raw \\' quote'")[2]).toEqual(["s'raw \\' quote'", 'string']);
    expect(tokenize("b = t'2021-02-11T10:32:50Z'")[2]).toEqual(["t'2021-02-11T10:32:50Z'", 'special(string)']);
  });

  it('splits escapes out of double-quoted strings', () => {
    expect(tokenize('"a\\nb"')).toEqual([
      ['"a', 'string'],
      ['\\n', 'escape'],
      ['b"', 'string'],
    ]);
  });

  it('tags fallible and infallible calls, ??, and object braces', () => {
    expect(tokenize('__source_kv = object(parse_json!(encode_json(parsed))) ?? {}')).toEqual([
      ['__source_kv', 'variableName'],
      ['=', 'operator'],
      ['object', 'function(variableName)'],
      ['(', 'punctuation'],
      ['parse_json!', 'function(variableName)'],
      ['(', 'punctuation'],
      ['encode_json', 'function(variableName)'],
      ['(', 'punctuation'],
      ['parsed', 'variableName'],
      [')', 'punctuation'],
      [')', 'punctuation'],
      [')', 'punctuation'],
      ['??', 'logicOperator'],
      ['{', 'punctuation'],
      ['}', 'punctuation'],
    ]);
  });

  it('tags event paths, metadata paths and property access', () => {
    expect(tokenize('.http.request = string!(.message) ?? %custom.tag ?? parsed.method')).toEqual([
      ['.http', 'propertyName'],
      ['.request', 'propertyName'],
      ['=', 'operator'],
      ['string!', 'function(variableName)'],
      ['(', 'punctuation'],
      ['.message', 'propertyName'],
      [')', 'punctuation'],
      ['??', 'logicOperator'],
      ['%custom', 'special(propertyName)'],
      ['.tag', 'propertyName'],
      ['??', 'logicOperator'],
      ['parsed', 'variableName'],
      ['.method', 'propertyName'],
    ]);
  });

  it('tags if / == / null / numbers / bools / abort', () => {
    expect(tokenize('if err == null { x = 4002; ok = true } else { abort }')).toEqual([
      ['if', 'keyword'],
      ['err', 'variableName'],
      ['==', 'compareOperator'],
      ['null', 'null'],
      ['{', 'punctuation'],
      ['x', 'variableName'],
      ['=', 'operator'],
      ['4002', 'number'],
      [';', 'punctuation'],
      ['ok', 'variableName'],
      ['=', 'operator'],
      ['true', 'bool'],
      ['}', 'punctuation'],
      ['else', 'keyword'],
      ['{', 'punctuation'],
      ['abort', 'keyword'],
      ['}', 'punctuation'],
    ]);
  });

  it('tags named arguments and comparison chains', () => {
    expect(tokenize('if code >= 200 && code < 400 { t = to_unix_timestamp(ts, unit: "milliseconds") }')).toEqual([
      ['if', 'keyword'],
      ['code', 'variableName'],
      ['>=', 'compareOperator'],
      ['200', 'number'],
      ['&&', 'logicOperator'],
      ['code', 'variableName'],
      ['<', 'compareOperator'],
      ['400', 'number'],
      ['{', 'punctuation'],
      ['t', 'variableName'],
      ['=', 'operator'],
      ['to_unix_timestamp', 'function(variableName)'],
      ['(', 'punctuation'],
      ['ts', 'variableName'],
      [',', 'punctuation'],
      ['unit', 'labelName'],
      [':', 'punctuation'],
      ['"milliseconds"', 'string'],
      [')', 'punctuation'],
      ['}', 'punctuation'],
    ]);
  });

  it('carries an unterminated string to the next line', () => {
    expect(tokenize('x = "abc', 'def"', 'y')).toEqual([
      ['x', 'variableName'],
      ['=', 'operator'],
      ['"abc', 'string'],
      ['def"', 'string'],
      ['y', 'variableName'],
    ]);
  });
});

describe('highlightVrl', () => {
  const src = '# header\nraw = string!(.message)\n\nif raw == null { abort }';

  it('returns one segment list per line that spells the source exactly', () => {
    const lines = highlightVrl(src);
    expect(lines).toHaveLength(4);
    expect(lines.map((l) => l.map((s) => s.text).join(''))).toEqual(src.split('\n'));
  });

  it('resolves theme styles to CSS variables', () => {
    const [comment, line2] = highlightVrl(src);
    expect(comment[0].style?.color).toBe('var(--syntax-comment)');
    const fn = line2.find((s) => s.text === 'string!');
    expect(fn?.style?.color).toBe('var(--syntax-function)');
    const field = line2.find((s) => s.text === '.message');
    expect(field?.style?.color).toBe('var(--syntax-field)');
  });

  it('VrlLine renders styled spans, and falls back to plain text on mismatch', () => {
    const [, line2] = highlightVrl(src);
    const { container, rerender } = render(<VrlLine segments={line2} text="raw = string!(.message)" />);
    expect(container.querySelectorAll('span[data-vrl-token]').length).toBeGreaterThan(3);
    rerender(<VrlLine segments={line2} text="something else" />);
    expect(container.querySelectorAll('span').length).toBe(0);
    expect(container.textContent).toBe('something else');
  });
});

describe('VrlEditor read-only view', () => {
  it('renders highlighted token spans (cm highlight classes)', () => {
    const { container } = render(
      <div style={{ height: 400 }}>
        <VrlEditor value={'# c\nx = parse_json!(.message) ?? null'} onChange={() => undefined} readOnly />
      </div>,
    );
    const lines = container.querySelectorAll('.cm-line');
    expect(lines.length).toBe(2);
    // CodeMirror wraps each tagged token in a span carrying a generated
    // HighlightStyle class; untagged (Rust-misparsed) text has none.
    const comment = lines[0].querySelector('span');
    expect(comment?.textContent).toBe('# c');
    expect(comment?.className).toMatch(/\S/);
    const spans = Array.from(lines[1].querySelectorAll('span')).map((s) => s.textContent);
    expect(spans).toEqual(expect.arrayContaining(['parse_json!', '.message', '??', 'null']));
  });
});
