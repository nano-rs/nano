// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Read a query-facing event field from either representation returned by Nano:
 *
 * - aggregate/projection rows use a literal dotted top-level key
 *   (`{"actor.user.name":"alice"}`)
 * - raw canonical OCSF events use nested objects
 *   (`{actor:{user:{name:"alice"}}}`)
 *
 * Literal dotted keys win so a projected value cannot be shadowed by a stale
 * nested payload carried alongside it.
 */
export function eventFieldValue(
  event: Record<string, unknown>,
  field: string,
): unknown {
  if (Object.prototype.hasOwnProperty.call(event, field)) return event[field];

  const descend = (current: unknown, components: string[]): unknown => {
    if (components.length === 0) return current;
    if (Array.isArray(current)) {
      const values = current.flatMap((item) => {
        const value = descend(item, components);
        if (value === undefined) return [];
        return Array.isArray(value) ? value : [value];
      });
      return values.length > 0 ? values : undefined;
    }
    if (current === null || typeof current !== 'object') return undefined;
    const [component, ...remaining] = components;
    return descend((current as Record<string, unknown>)[component], remaining);
  };

  return descend(event, field.split('.'));
}

/** Flatten nested/repeated event objects to canonical dotted leaf paths. */
export function flattenEventFieldEntries(
  event: Record<string, unknown>,
  prefix = '',
): Array<{ key: string; value: unknown }> {
  const flattenValue = (
    value: unknown,
    key: string,
  ): Array<{ key: string; value: unknown }> => {
    if (Array.isArray(value)) {
      if (!value.some((item) => item !== null && typeof item === 'object')) {
        return [{ key, value }];
      }
      const grouped = new Map<string, unknown[]>();
      for (const item of value) {
        for (const entry of flattenValue(item, key)) {
          const values = grouped.get(entry.key) ?? [];
          if (Array.isArray(entry.value)) values.push(...entry.value);
          else values.push(entry.value);
          grouped.set(entry.key, values);
        }
      }
      return [...grouped].map(([entryKey, values]) => ({ key: entryKey, value: values }));
    }
    if (value !== null && typeof value === 'object') {
      return Object.entries(value as Record<string, unknown>).flatMap(([name, child]) =>
        flattenValue(child, key ? `${key}.${name}` : name));
    }
    return [{ key, value }];
  };

  return Object.entries(event).flatMap(([name, value]) =>
    flattenValue(value, prefix ? `${prefix}.${name}` : name));
}
