// SPDX-License-Identifier: AGPL-3.0-or-later
import { lazy, type ComponentType } from 'react';
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function lazyWithRetry<T extends ComponentType<any>>(load: () => Promise<{ default: T }>) {
  return lazy(() => load().catch(() => {
    window.location.reload();
    return new Promise<{ default: T }>(() => {});
  }));
}
