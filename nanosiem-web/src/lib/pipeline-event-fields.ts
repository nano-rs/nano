// SPDX-License-Identifier: AGPL-3.0-or-later

export function flattened(
  value: unknown,
  path = '$',
  result = new Map<string, string>()
): Map<string, string> {
  if (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).length > 0
  ) {
    for (const [key, child] of Object.entries(value))
      flattened(child, `${path}.${key}`, result);
  } else result.set(path, JSON.stringify(value) ?? 'undefined');
  return result;
}
