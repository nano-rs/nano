// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Return the canonical query-facing name for a dynamic spill field.
 *
 * The lake returns OCSF spill paths as `unmapped.foo`; the legacy ClickHouse
 * discovery endpoint returns the relative path (`foo`). Accept both contracts
 * while collapsing stale/cached double prefixes from older frontends.
 */
export function canonicalSpillFieldName(name: string, isOcsf: boolean): string {
  const namespace = isOcsf ? 'unmapped' : 'ext';
  const segments = name.trim().split('.').filter(Boolean);
  while (segments[0] === namespace) segments.shift();
  return segments.length > 0 ? `${namespace}.${segments.join('.')}` : namespace;
}

/** True only for a field in the active schema's dynamic spill namespace. */
export function isSpillFieldName(name: string, isOcsf: boolean): boolean {
  const namespace = isOcsf ? 'unmapped' : 'ext';
  return name.startsWith(`${namespace}.`);
}

/** Whether a sampled OCSF spill leaf contained a real scalar value. */
export function hasObservedSpillValue(
  values: ReadonlyArray<{ value: string; count: number }>,
): boolean {
  return values.some(({ value, count }) => count > 0 && value.trim().length > 0);
}

/** Return a copy ordered by the query-facing field name. */
export function sortFieldStatsByName<T extends { field: string }>(stats: readonly T[]): T[] {
  return [...stats].sort((left, right) =>
    left.field.localeCompare(right.field, undefined, { sensitivity: 'base', numeric: true }),
  );
}
