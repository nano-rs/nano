// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ToasterProps } from 'sonner';

/**
 * NAN-5834: toasts must never sit on a primary action. Sonner's default
 * corner (bottom-right) is where the app pins its primary buttons (parser
 * Test lab "Test", sheet footers' Save/Create, the AI panel's Send), and a
 * hovered stack pauses its timers, so a toast there blocked the button until
 * the pointer moved away and the timer ran out. Bottom-center clears those
 * right-aligned actions; the bottom offset clears the 22px status bar. Every
 * toast is closable, and index.css caps a long description's height.
 */
export const TOASTER_DEFAULTS = {
  position: 'bottom-center',
  closeButton: true,
  offset: { bottom: 34 },
  visibleToasts: 3,
} as const satisfies Partial<ToasterProps>;

