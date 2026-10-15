// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Dual-shape row accessors.
 *
 * Search results arrive in TWO shapes and always have: projected stages
 * (`| table`, `stats ... by`) return FLAT dotted keys, while full-event rows
 * return NESTED OCSF objects. A plain `row['a.b.c']` lookup resolves only the
 * first shape, so any consumer written against it is silently blank on the
 * other — which is exactly how the process tree's Signature row came to be
 * structurally unresolvable under OCSF.
 *
 * Arrays are traversed element-wise because OCSF holds repeated structures in
 * PLURAL arrays (`file.signatures[]`, `file.hashes[]`), not singular objects.
 */

/** Read a dotted path from a flat-dotted OR nested row. */
export function atPath(row: unknown, path: string): unknown {
  if (row == null) return undefined;
  if (
    typeof row === 'object' &&
    !Array.isArray(row) &&
    path in (row as Record<string, unknown>)
  ) {
    return (row as Record<string, unknown>)[path];
  }
  const [head, ...rest] = path.split('.');
  if (!head) return undefined;
  if (Array.isArray(row)) {
    // First populated element wins; an array of signatures/hashes is a set of
    // candidates, not an ordered record.
    for (const item of row) {
      const found = atPath(item, path);
      if (found != null && found !== '') return found;
    }
    return undefined;
  }
  if (typeof row !== 'object') return undefined;
  const next = (row as Record<string, unknown>)[head];
  return rest.length === 0 ? next : atPath(next, rest.join('.'));
}

/** First path yielding a non-empty string (numbers are stringified). */
export function firstStringAt(row: unknown, paths: string[]): string | undefined {
  for (const p of paths) {
    const v = atPath(row, p);
    if (typeof v === 'string' && v.length > 0) return v;
    if (typeof v === 'number') return String(v);
  }
  return undefined;
}

/**
 * First path yielding a recognised signed/unsigned verdict.
 *
 * Deliberately partial: OCSF `signature.state` carries verdicts beyond a clean
 * yes/no (`Expired`, `Untrusted`, `Revoked`). Those return `undefined` rather
 * than being coerced — "collected but not a clean pass" is a third state, and
 * folding it into `false` would report an expired-but-genuine signature as
 * unsigned.
 */
export function firstBoolAt(row: unknown, paths: string[]): boolean | undefined {
  for (const p of paths) {
    const v = atPath(row, p);
    if (typeof v === 'boolean') return v;
    if (typeof v === 'string') {
      const lc = v.toLowerCase();
      if (lc === 'true' || lc === 'signed' || lc === 'verified' || lc === 'valid') return true;
      if (lc === 'false' || lc === 'unsigned' || lc === 'invalid') return false;
    }
  }
  return undefined;
}
