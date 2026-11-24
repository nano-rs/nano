// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect } from 'react';

/**
 * NAN-5834: toasts render bottom-center. While a floating bulk-action bar
 * holds that band (Rules, Cases), `:root[data-toast-lift]` in index.css lifts
 * the toaster above it. Ref-counted, so two bars (or a remount) never clear
 * the flag early.
 */
let holders = 0;

export function liftToasts(): () => void {
  holders += 1;
  document.documentElement.setAttribute('data-toast-lift', '');
  let released = false;
  return () => {
    if (released) return;
    released = true;
    holders = Math.max(0, holders - 1);
    if (holders === 0) document.documentElement.removeAttribute('data-toast-lift');
  };
}

/** Lift the toasts for as long as the calling component is mounted. */
export function useLiftToasts(): void {
  useEffect(() => liftToasts(), []);
}
