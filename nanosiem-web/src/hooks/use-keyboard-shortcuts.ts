// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Keyboard Shortcuts Hook
 *
 * Provides page-specific keyboard shortcuts for fast navigation and actions.
 * Inspired by Linear's keyboard-first UX.
 */

import { useEffect, useRef } from 'react';

type KeyHandler = (e: KeyboardEvent) => void;

interface ShortcutConfig {
  key: string;
  handler: KeyHandler;
  ctrl?: boolean;
  meta?: boolean;
  shift?: boolean;
  alt?: boolean;
  /** If true, prevents shortcut when focus is in an input/textarea */
  ignoreInputs?: boolean;
}

/**
 * Hook for registering keyboard shortcuts
 */
export function useKeyboardShortcuts(shortcuts: ShortcutConfig[]) {
  const shortcutsRef = useRef(shortcuts);
  shortcutsRef.current = shortcuts;

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Get the active element
      const activeElement = document.activeElement;
      const isInputFocused =
        activeElement instanceof HTMLInputElement ||
        activeElement instanceof HTMLTextAreaElement ||
        activeElement?.getAttribute('contenteditable') === 'true';

      for (const shortcut of shortcutsRef.current) {
        // Skip if we should ignore inputs and an input is focused
        if (shortcut.ignoreInputs !== false && isInputFocused) {
          continue;
        }

        // Check modifiers
        const ctrlMatch = shortcut.ctrl ? e.ctrlKey : !e.ctrlKey;
        const metaMatch = shortcut.meta ? e.metaKey : !e.metaKey;
        const shiftMatch = shortcut.shift ? e.shiftKey : !e.shiftKey;
        const altMatch = shortcut.alt ? e.altKey : !e.altKey;

        // Check key match (case insensitive)
        const keyMatch = e.key.toLowerCase() === shortcut.key.toLowerCase();

        if (keyMatch && ctrlMatch && metaMatch && shiftMatch && altMatch) {
          e.preventDefault();
          shortcut.handler(e);
          return;
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);
}

/**
 * Hook for focus shortcut (e.g., "/" to focus search)
 */
export function useFocusShortcut(
  key: string,
  ref: React.RefObject<HTMLInputElement | HTMLTextAreaElement | null>
) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const activeElement = document.activeElement;
      const isInputFocused =
        activeElement instanceof HTMLInputElement ||
        activeElement instanceof HTMLTextAreaElement;

      if (isInputFocused) return;

      if (e.key === key) {
        e.preventDefault();
        ref.current?.focus();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [key, ref]);
}

