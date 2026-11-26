// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * pivt's keyboard shortcuts (registered by AppLayout):
 *   ⌘. / Ctrl+.     → open or close pivt
 *   ⌘⇧. / Ctrl+⇧.  → switch dock ↔ float (and open it)
 *
 * Matched on the CHARACTER the layout produced (`key`), not the physical key:
 * `code: 'Period'` is "v" on Dvorak and ":"/"/" on AZERTY, so matching it
 * would hijack Cmd/Ctrl+V or Cmd/Ctrl+/ there. With Shift held a US layout
 * reports `key: '>'` for the period key, so that is accepted for the switch
 * (NAN-5864: matching `key === '.'` alone meant ⌘⇧. never fired). The
 * physical key is only a fallback when the browser could not name the
 * character (`Dead` / `Unidentified`).
 *
 * Exactly one of Cmd / Ctrl, and never Alt: AltGr arrives as Ctrl+Alt on
 * Windows and Linux, and Cmd+Option+. is a different chord on macOS.
 */
export type PivtShortcut = 'toggle' | 'switch' | null;

export function pivtShortcutFor(
  e: Pick<KeyboardEvent, 'metaKey' | 'ctrlKey' | 'altKey' | 'shiftKey' | 'key' | 'code'>,
): PivtShortcut {
  if (e.metaKey === e.ctrlKey || e.altKey) return null;
  const period =
    e.key === '.' ||
    (e.shiftKey && e.key === '>') ||
    ((e.key === 'Dead' || e.key === 'Unidentified') && e.code === 'Period');
  if (!period) return null;
  return e.shiftKey ? 'switch' : 'toggle';
}
