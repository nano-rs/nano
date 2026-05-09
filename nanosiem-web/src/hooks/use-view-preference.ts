// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useCallback } from 'react';

/**
 * Persists a view mode preference (grid/list/table/kanban) in localStorage.
 * Falls back to `defaultValue` when nothing is stored.
 */
export function useViewPreference<T extends string>(
  key: string,
  defaultValue: T,
): [T, (value: T) => void] {
  const storageKey = `nanosiem:view:${key}`;

  const [value, setValue] = useState<T>(() => {
    try {
      const stored = localStorage.getItem(storageKey);
      return (stored as T) ?? defaultValue;
    } catch {
      return defaultValue;
    }
  });

  const set = useCallback(
    (newValue: T) => {
      setValue(newValue);
      try {
        localStorage.setItem(storageKey, newValue);
      } catch {
        // localStorage unavailable — state still works in-memory
      }
    },
    [storageKey],
  );

  return [value, set];
}
