// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * CodeMirror 6 language mode for VRL (Vector Remap Language) — NAN-3195.
 *
 * VRL used to borrow `@codemirror/lang-rust`, but VRL is not Rust: `#` starts
 * a comment (Rust reads an attribute), `r'…'` / `s'…'` / `t'…'` are literals
 * (Rust has no single-quoted strings, so error recovery swallowed whole
 * regions untagged), `fn!(…)` is a fallible call (Rust reads a macro), `.a.b`
 * is an event path and `%meta` a metadata path. This stream tokenizer tags
 * those natively; colours come from the shared `syntaxTheme`.
 *
 * `highlightVrl` runs the same tokenizer without an editor so read-only
 * listings (version diffs, repo preview, upstream diff) highlight identically.
 */
import type { CSSProperties } from 'react';
import { StreamLanguage, type StringStream } from '@codemirror/language';
import { highlightTree, tagHighlighter, tags, type Tag } from '@lezer/highlight';
import { syntaxTheme } from './codemirror-theme';

/** Open multi-line literal carried across lines, or null. */
type StringKind = '"' | "r'" | "s'" | "t'";

export interface VrlState {
  inString: StringKind | null;
}

const KEYWORDS = new Set(['if', 'else', 'abort', 'return']);
const BOOLS = new Set(['true', 'false']);

/** Body of a literal up to (and consuming) its closing quote. */
function readString(stream: StringStream, state: VrlState, kind: StringKind): string {
  const quote = kind === '"' ? '"' : "'";
  const style = kind === "r'" ? 'regexp' : kind === "t'" ? 'special(string)' : 'string';
  // `"…"` strings: escapes get their own token so `\n` / `\"` stand out.
  if (kind === '"' && stream.pos === stream.start && stream.peek() === '\\') {
    stream.next();
    stream.next();
    return 'escape';
  }
  while (!stream.eol()) {
    const ch = stream.peek();
    if (ch === '\\') {
      if (kind === '"') {
        state.inString = kind;
        return style; // stop before the escape; the next call tags it
      }
      stream.next(); // raw literals: `\'` is the only escape, keep it in the body
      stream.next();
      continue;
    }
    stream.next();
    if (ch === quote) {
      state.inString = null;
      return style;
    }
  }
  state.inString = kind;
  return style;
}

export const vrlLanguageDefinition = {
  name: 'vrl',

  startState(): VrlState {
    return { inString: null };
  },

  copyState(state: VrlState): VrlState {
    return { ...state };
  },

  token(stream: StringStream, state: VrlState): string | null {
    if (state.inString) return readString(stream, state, state.inString);

    if (stream.eatSpace()) return null;

    if (stream.match('#')) {
      stream.skipToEnd();
      return 'lineComment';
    }

    // Prefixed literals: r'regex', s'raw string', t'timestamp'.
    const prefixed = stream.match(/^[rst]'/) as RegExpMatchArray | null;
    if (prefixed) {
      const kind = prefixed[0] as StringKind;
      state.inString = kind;
      return readString(stream, state, kind);
    }
    if (stream.match('"')) {
      state.inString = '"';
      return readString(stream, state, '"');
    }

    // Numbers (ints, floats, exponents, `_` separators).
    if (stream.match(/^\d[\d_]*(\.\d[\d_]*)?([eE][+-]?\d+)?/)) return 'number';

    // Metadata path: `%meta`, `%custom.field`, bare `%`. Modulo needs spaces
    // around it in practice, so `%` glued to an identifier is metadata.
    if (stream.match(/^%[A-Za-z_][\w]*/)) return 'special(propertyName)';

    // Event / object paths: `.field`, `.a.b`, `parsed.method`, `."quoted key"`.
    if (stream.match(/^\.[A-Za-z_@][\w@]*/)) return 'propertyName';
    if (stream.match(/^\."(?:[^"\\]|\\.)*"/)) return 'propertyName';

    // Identifiers: keyword, bool, null, function call (incl. fallible `!`),
    // named argument (`unit:`), or plain variable.
    const ident = stream.match(/^[A-Za-z_][\w]*/) as RegExpMatchArray | null;
    if (ident) {
      const word = ident[0];
      if (KEYWORDS.has(word)) return 'keyword';
      if (BOOLS.has(word)) return 'bool';
      if (word === 'null') return 'null';
      if (stream.match(/^!?(?=\s*\()/, false)) {
        stream.eat('!');
        return 'function(variableName)';
      }
      if (stream.match(/^\s*:(?!:)/, false)) return 'labelName';
      return 'variableName';
    }

    // Operators, longest first.
    if (stream.match(/^(\?\?|&&|\|\|)/)) return 'logicOperator';
    if (stream.match(/^(==|!=|>=|<=|>|<)/)) return 'compareOperator';
    if (stream.match(/^(\|=|=)/)) return 'operator';
    if (stream.match(/^[+\-*/%]/)) return 'arithmeticOperator';
    if (stream.match(/^[!|]/)) return 'operator';
    // Root path `.` (whole event) or a stray dot.
    if (stream.match('.')) return 'propertyName';

    if (stream.match(/^[{}()[\],;:]/)) return 'punctuation';

    stream.next();
    return null;
  },
};

const tokenTable: Record<string, Tag> = {
  lineComment: tags.lineComment,
  string: tags.string,
  'special(string)': tags.special(tags.string),
  regexp: tags.regexp,
  escape: tags.escape,
  number: tags.number,
  keyword: tags.keyword,
  bool: tags.bool,
  null: tags.null,
  'function(variableName)': tags.function(tags.variableName),
  labelName: tags.labelName,
  variableName: tags.variableName,
  propertyName: tags.propertyName,
  'special(propertyName)': tags.special(tags.propertyName),
  logicOperator: tags.logicOperator,
  compareOperator: tags.compareOperator,
  arithmeticOperator: tags.arithmeticOperator,
  operator: tags.operator,
  punctuation: tags.punctuation,
};

export const vrlLanguage = StreamLanguage.define<VrlState>({
  ...vrlLanguageDefinition,
  languageData: { commentTokens: { line: '#' } },
  tokenTable,
});

// ---------------------------------------------------------------------------
// Editor-free highlighting (read-only listings and diffs)
// ---------------------------------------------------------------------------

export interface VrlSegment {
  text: string;
  /** Inline style resolved from `syntaxTheme`; undefined for untagged text. */
  style?: CSSProperties;
}

// Map each `syntaxTheme` spec to an index "class", then resolve back to the
// spec's inline style. One source of truth for colours — no CSS to mount.
const SPECS = syntaxTheme.specs;
const indexHighlighter = tagHighlighter(
  SPECS.map((spec, i) => ({ tag: spec.tag as Tag | readonly Tag[], class: String(i) })),
);

function styleFor(classes: string): CSSProperties {
  const out: Record<string, unknown> = {};
  for (const c of classes.split(' ')) {
    const spec = SPECS[Number(c)];
    if (!spec) continue;
    for (const [k, v] of Object.entries(spec)) if (k !== 'tag') out[k] = v;
  }
  return out as CSSProperties;
}

/**
 * Tokenize a whole VRL document and return one segment list per line. Parsing
 * the whole document (not line by line) keeps multi-line literals correct.
 */
export function highlightVrl(src: string): VrlSegment[][] {
  const lineStarts = [0];
  for (let i = 0; i < src.length; i++) if (src[i] === '\n') lineStarts.push(i + 1);
  const lines: VrlSegment[][] = lineStarts.map(() => []);

  let line = 0;
  const push = (from: number, to: number, classes: string) => {
    while (from < to) {
      while (line + 1 < lineStarts.length && lineStarts[line + 1] <= from) line++;
      const lineEnd = line + 1 < lineStarts.length ? lineStarts[line + 1] - 1 : src.length;
      const end = Math.min(to, lineEnd);
      if (end > from) {
        lines[line].push(
          classes ? { text: src.slice(from, end), style: styleFor(classes) } : { text: src.slice(from, end) },
        );
      }
      from = end === lineEnd ? end + 1 : end;
    }
  };

  const tree = vrlLanguage.parser.parse(src);
  let pos = 0;
  highlightTree(tree, indexHighlighter, (from, to, classes) => {
    if (from > pos) push(pos, from, '');
    push(from, to, classes);
    pos = to;
  });
  if (pos < src.length) push(pos, src.length, '');
  return lines;
}

export default vrlLanguage;
