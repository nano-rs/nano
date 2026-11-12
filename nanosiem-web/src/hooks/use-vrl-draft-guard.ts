// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5323: the log source VRL editor lost unsaved edits silently on reload or
 * navigation. While the editor is dirty this hook
 *
 * - warns on document unload (`beforeunload`), and
 * - keeps a tab-local (sessionStorage) copy of the edit, keyed by source and
 *   by the saved VRL it was based on, so a reload or an in-app navigation can
 *   offer it back. sessionStorage, not localStorage: parser code is not left
 *   behind in a shared browser after the tab closes.
 *
 * A stored draft is offered only while the source's saved VRL is still the one
 * it was based on: once anyone saves a newer VRL, restoring would silently
 * overwrite it, so the stale copy is dropped instead.
 *
 * Browser storage can be absent or throw (private mode, blocked site data);
 * every access is guarded and the editor works without it.
 */

import { useCallback, useEffect, useState } from 'react';

interface StoredDraft {
  base: string;
  vrl: string;
}

export function vrlDraftKey(id: string): string {
  return `nano:log-source-vrl-draft:${id}`;
}

export function writeVrlDraft(id: string, base: string, vrl: string): void {
  try {
    window.sessionStorage.setItem(vrlDraftKey(id), JSON.stringify({ base, vrl } satisfies StoredDraft));
  } catch {
    /* storage unavailable: the beforeunload warning still applies */
  }
}

export function clearVrlDraft(id: string): void {
  try {
    window.sessionStorage.removeItem(vrlDraftKey(id));
  } catch {
    /* ignore */
  }
}

/** The stored draft for `id` if it still applies to `base` and differs from it; stale drafts are removed. */
export function readVrlDraft(id: string, base: string): string | null {
  let raw: string | null = null;
  try {
    raw = window.sessionStorage.getItem(vrlDraftKey(id));
  } catch {
    return null;
  }
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<StoredDraft>;
    if (typeof parsed.vrl === 'string' && parsed.base === base && parsed.vrl !== base) return parsed.vrl;
  } catch {
    /* fall through: corrupt entry */
  }
  clearVrlDraft(id);
  return null;
}

export function useVrlDraftGuard({
  id,
  baseVrl,
  editing,
  editedVrl,
}: {
  id: string | undefined;
  /** The saved VRL the editor started from (`log_sources.parser_vrl`). */
  baseVrl: string | undefined;
  editing: boolean;
  editedVrl: string;
}) {
  const dirty = !!id && baseVrl !== undefined && editing && editedVrl !== baseVrl;

  // Warn on reload / tab close while dirty.
  useEffect(() => {
    if (!dirty) return;
    const warn = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty]);

  // Keep a local copy of the edit while dirty.
  useEffect(() => {
    if (dirty && id && baseVrl !== undefined) writeVrlDraft(id, baseVrl, editedVrl);
  }, [dirty, id, baseVrl, editedVrl]);

  // A draft left by an earlier visit, offered until restored or dismissed.
  const [restorable, setRestorable] = useState<string | null>(null);
  useEffect(() => {
    setRestorable(id && baseVrl !== undefined ? readVrlDraft(id, baseVrl) : null);
    // Only on (re)load of the source, not on every keystroke.
  }, [id, baseVrl]);

  const clear = useCallback(() => {
    if (id) clearVrlDraft(id);
    setRestorable(null);
  }, [id]);

  return { dirty, restorable: editing ? null : restorable, clear, dismissRestorable: () => setRestorable(null) };
}
