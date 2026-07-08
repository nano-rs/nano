// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Dashboard variable substitution — NAN-1719, CONTRACT 5
 * (DSH3 / DSH4 / DSH20 / DSH21 / DSH51).
 *
 * ONE shared implementation used by the dashboard VIEW, the EDITOR preview, and
 * the panel Test modal so all three produce byte-identical queries. The old code
 * duplicated three subtly-different regex passes that disagreed on empty values,
 * quoting, and quoted-literal handling — silently corrupting panel filters.
 *
 * Semantics (documented so view/editor/test stay identical):
 *  - Only `$name` tokens whose `name` is in `definedNames` are substituted.
 *    Unknown `$tokens` are left literal, matching the server substitutor which
 *    leaves unknown names intact.
 *  - `$tokens` inside quoted string literals ("…" or '…') are NEVER touched, so
 *    hunting literals like "$RECYCLE.BIN", "$PSHome", "*$env*" survive intact
 *    (DSH3).
 *  - Values are quoted/escaped for nPL, which has NO backslash escaping: a value
 *    containing the active quote char has that char STRIPPED (not backslashed).
 *    This neutralises spaces (implicit AND), pipes (stage injection) and quotes
 *    (parse breakage) — the DSH4 class.
 *  - Empty-value semantics (a variable that is DEFINED but has no value/default),
 *    identical across view/editor/test (DSH21):
 *      * `field <op> $var`  -> the whole clause is removed (field left unfiltered)
 *      * bare `$var`        -> replaced with `*` (explicit match-all term)
 *  - Whitespace is collapsed ONLY outside quoted regions (DSH20); quoted literals
 *    keep their exact spacing (load-bearing in command-line hunts).
 */

interface Segment {
  text: string;
  quoted: boolean;
}

// Split a query into alternating unquoted / quoted segments. nPL has no
// backslash escaping, so a quoted region simply runs to the next matching quote
// char (or end-of-string if unterminated).
function tokenize(query: string): Segment[] {
  const segments: Segment[] = [];
  let buf = '';
  let i = 0;
  while (i < query.length) {
    const ch = query[i];
    if (ch === '"' || ch === "'") {
      if (buf) {
        segments.push({ text: buf, quoted: false });
        buf = '';
      }
      const quote = ch;
      let region = ch;
      i++;
      while (i < query.length && query[i] !== quote) {
        region += query[i];
        i++;
      }
      if (i < query.length) {
        region += query[i]; // closing quote
        i++;
      }
      segments.push({ text: region, quoted: true });
    } else {
      buf += ch;
      i++;
    }
  }
  if (buf) segments.push({ text: buf, quoted: false });
  return segments;
}

// Wrap an equality/keyword value in double quotes, stripping any embedded
// double-quote (nPL has no backslash escaping, so we cannot escape it).
function quoteEqualityValue(value: string): string {
  return `"${value.replace(/"/g, '')}"`;
}

// Relational comparisons (`>`, `<`, `>=`, `<=`) are numeric — drop anything that
// could break parsing or inject a stage. A well-formed numeric value is
// unaffected.
function sanitizeRelationalValue(value: string): string {
  return value.replace(/["'|]/g, '').replace(/\s+/g, '');
}

// `field <op> $var`  |  bare `$var`
const CLAUSE_OR_BARE =
  /([A-Za-z_][\w.]*)(\s*(?:!=|>=|<=|=|>|<)\s*)\$([A-Za-z_]\w*)|\$([A-Za-z_]\w*)/g;

function substituteSegment(
  text: string,
  values: Record<string, string>,
  defined: Set<string>,
): string {
  // Group 1/2/3 = field / op / var for the clause form; group 4 = var for the
  // bare form. Params are contextually `any` (the lib types the replacer args as
  // `...args: any[]`) since alternation leaves the other branch's groups
  // undefined.
  const substituted = text.replace(
    CLAUSE_OR_BARE,
    (match, field, op, clauseVar, bareVar) => {
      if (clauseVar !== undefined) {
        const name: string = clauseVar;
        if (!defined.has(name)) return match; // unknown -> leave literal
        const value = values[name] ?? '';
        if (value === '') return ''; // empty -> remove the whole clause
        const opStr: string = op ?? '';
        const fieldStr: string = field ?? '';
        const trimmedOp = opStr.trim();
        if (trimmedOp === '=' || trimmedOp === '!=') {
          return `${fieldStr}${opStr}${quoteEqualityValue(value)}`;
        }
        return `${fieldStr}${opStr}${sanitizeRelationalValue(value)}`;
      }
      // bare $var
      const bareName: string = bareVar;
      if (!defined.has(bareName)) return match; // unknown -> leave literal
      const value = values[bareName] ?? '';
      if (value === '') return '*'; // empty -> explicit match-all term
      return quoteEqualityValue(value);
    },
  );
  // Collapse whitespace only outside quoted regions (DSH20).
  return substituted.replace(/\s+/g, ' ');
}

/**
 * Substitute dashboard variables in an nPL query. Only names present in
 * `definedNames` are touched; see the module docblock for the full semantics.
 */
export function substituteVariables(
  query: string,
  values: Record<string, string>,
  definedNames: string[],
): string {
  if (!query) return query;
  const defined = new Set(definedNames);
  const out = tokenize(query)
    .map(seg => (seg.quoted ? seg.text : substituteSegment(seg.text, values, defined)))
    .join('');
  return out.trim();
}

export default { substituteVariables };
