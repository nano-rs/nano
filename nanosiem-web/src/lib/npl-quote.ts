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
