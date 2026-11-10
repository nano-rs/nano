// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Canonical quoting for values interpolated into nPL double-quoted string
 * literals (NAN-2184).
 *
 * ## Why `\"` does not work
 *
 * nPL's `double_quoted_string` is `take_while(|c| c != '"')` — the FIRST `"`
 * always terminates the literal and a backslash NEVER escapes it. That is
 * deliberate (NAN-1157) so Windows paths like `"C:\Windows\System32\"` parse
 * instead of the trailing `\"` swallowing the close quote.
 *
 * The consequence is that the once-ubiquitous `value.replace(/"/g, '\\"')` is
 * not merely incomplete — it is a no-op that corrupts the query. Given a host
 * name `a" OR src_ip=10.0.0.9`, it emits:
 *
 *     src_host="a\" OR src_ip=\"10.0.0.9"
 *
 * which the parser rejects with `Unexpected token '='`. Attacker-controlled log
 * data (hostname, user, asset identity, IOC value) therefore breaks the
 * analyst's pivot. Stripping `"` — as the Rust pretty-printer already does in
 * `query::pretty_print::helpers::npl_quoted_body` — is the only representation
 * that keeps the value inside its literal.
 *
 * ## Why backslashes still need escaping
 *
 * `\\` collapses to `\` on parse, so a value carrying CONSECUTIVE backslashes
 * loses one unless it is doubled first. This is not hypothetical in a SIEM:
 * UNC paths (`\\fileserver\share`) are everywhere in Windows telemetry. A
 * single backslash round-trips either way, which is why the pre-existing
 * `.replace(/\\/g, '\\\\')` sites looked correct to CodeQL while still
 * carrying the broken `"` handling.
 *
 * Order matters: escape backslashes BEFORE stripping quotes, so a value ending
 * in `\` cannot pair with a doubling introduced afterwards.
 *
 * Newlines are stripped so a serialized query stays a single line.
 *
 * Characters such as `|`, backtick, `(`, `)`, `[`, `]` are deliberately KEPT —
 * they are inert inside the quotes, and preserving them lets legitimate values
 * (`cmd|powershell`) survive the round-trip.
 *
 * ## Divergence from the Rust helper (NAN-2241)
 *
 * The Rust side no longer strips: `query::pretty_print::helpers::npl_quoted_literal`
 * emits a COMPLETE literal and picks `'…'` when the value contains a `"`, so
 * the value survives byte-for-byte (a `rex` pattern's `[^"]+` was silently
 * becoming `[^]+`, a regex that matches nothing). These helpers still strip,
 * because every caller below wraps the BODY in its own `"…"` and the delimiter
 * choice has to be made where the quotes are written. Pivots built from a
 * `"`-bearing value are therefore still lossy — a drilldown concern, not a
 * correctness-of-the-executed-query one. Fixing it means moving callers onto
 * `nplQuoted`/`nplFieldEquals` (which own their delimiters) first.
 */
export function nplQuotedBody(value: string): string {
  let out = '';
  for (const ch of value.replace(/\\/g, '\\\\')) {
    if (ch === '"' || ch === '\n' || ch === '\r') continue;
    out += ch;
  }
  return out;
}

/**
 * Body of an nPL `/…/` regex literal (e.g. `tree … root=/<body>/`, NAN-5159).
 *
 * A different grammar from the double-quoted string: the regex scanner
 * (`parse_pattern_value` in `query/parser/commands_enrichment.rs`) treats a
 * backslash as escaping the NEXT character and ends the literal at the first
 * unescaped `/`. So a `/` in the value must become `\/` or everything after it
 * is parsed as more pipeline. The escaped pair reaches the Rust `regex` crate
 * unchanged, where `\/` is a literal `/`.
 *
 * Backslashes are doubled so a value ending in `\` cannot escape the
 * closing slash, and so a literal backslash stays literal in the regex (`\\`).
 * `"` needs no handling here (it is inert inside `/…/`); newlines are stripped
 * so the query stays one line.
 */
export function nplRegexBody(value: string): string {
  let out = '';
  for (const ch of value) {
    if (ch === '\n' || ch === '\r') continue;
    if (ch === '\\' || ch === '/') out += '\\';
    out += ch;
  }
  return out;
}

/**
 * [`nplQuotedBody`] wrapped in the double quotes it is designed for.
 *
 * Prefer this over hand-writing `` `"${nplQuotedBody(v)}"` `` so the quoting
 * and the wrapping can never drift apart.
 */
export function nplQuoted(value: string): string {
  return `"${nplQuotedBody(value)}"`;
}

/**
 * `field="value"` with the value quoted per [`nplQuoted`].
 *
 * The field name is emitted verbatim: every caller in the app passes a
 * hard-coded UDM/OCSF column (`src_ip`, `device.hostname`, …) or a field name
 * that already came back from the schema endpoint, so it is not an
 * interpolation point for log data.
 */
export function nplFieldEquals(field: string, value: string): string {
  return `${field}=${nplQuoted(value)}`;
}

/**
 * A COMPLETE nPL string literal that keeps the value byte-for-byte whenever
 * the grammar can express it. Mirrors the Rust
 * `query::pretty_print::helpers::npl_quoted_literal` (NAN-2241): `"…"` unless
 * the value contains a `"`, then `'…'` (nPL has both delimiters and neither
 * honours a backslash escape). Backslashes are doubled; newlines dropped.
 *
 * A value containing BOTH quote kinds cannot be represented; `lossy` is then
 * true and the `"` characters are dropped (the historical shape). Callers that
 * persist the result (a detection) must surface `lossy`, not ignore it.
 */
export function nplLiteral(value: string): { literal: string; lossy: boolean } {
  const hasDouble = value.includes('"');
  const hasSingle = value.includes("'");
  const delimiter = !hasDouble ? '"' : !hasSingle ? "'" : '"';
  let out = delimiter;
  for (const ch of value) {
    if (ch === delimiter || ch === '\n' || ch === '\r') continue;
    out += ch === '\\' ? '\\\\' : ch;
  }
  out += delimiter;
  return { literal: out, lossy: hasDouble && hasSingle };
}

/**
 * Exact (literal) equality on a field, for pivots built from log values
 * (NAN-4903). `field="v"` treats `*` and `?` inside the quotes as wildcards
 * (and `field="*"` is an existence test), so a value carrying either would
 * broaden the pivot. nPL's IN-list compiles to plain membership with no
 * wildcard expansion (search arm: `generate_in_list_filter`; pipeline arm:
 * `SearchExpr::InList`), so such values use `field IN ("v")`. Values without
 * wildcard metacharacters keep the familiar `field="v"` form, which is already
 * exact. The value itself goes through `nplLiteral` (quote-preserving).
 */
export function nplExactEquals(field: string, value: string): string {
  const { literal } = nplLiteral(value);
  return /[*?]/.test(value) ? `${field} IN (${literal})` : `${field}=${literal}`;
}
