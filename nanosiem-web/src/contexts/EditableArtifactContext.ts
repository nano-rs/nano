// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-4653: the artifact open on the page that pivt can edit conversationally.
//
// A page with an editor (the SOAR flow editor first; searches and dashboards
// next, NAN-4654 / NAN-4655) registers what it has open: kind, id, the
// version it loaded, a reader for its CURRENT unsaved document, an `apply`
// that lands a revision as ONE undoable change, and its undo stack. The pivt
// panel reads the registration to word its composer ("Edit this flow with
// pivt…"), route edit requests, and hand the revised document back.
//
// A tiny module store (like the pivt draft store) rather than a provider: the
// panel and the page mount in different subtrees, and the edit runner reads
// the registration outside React when a job completes. One registration at a
// time; the page that registered it clears it on unmount.
//
// pivt never saves or activates through this: `apply` changes the editor's
// unsaved state only.
import { useEffect, useRef, useSyncExternalStore } from 'react';

/** Kinds with a server edit-session adapter (`EditArtifactKind`). */
export type EditableArtifactKind = 'flow';

export interface EditableArtifact<TDoc = unknown> {
  kind: EditableArtifactKind;
  id: string;
  /** Stored version the page loaded; the server refuses edits on a stale one. */
  version: number;
  /** Display name (the flow name). */
  name: string;
  /** Lowercase noun for copy: "flow". */
  noun: string;
  /** The page's current document, including unsaved edits. */
  getDoc: () => TDoc;
  /** Land a revision as ONE undoable, unsaved change and highlight `changed`. */
  apply: (doc: TDoc, changed: string[]) => void;
  /** The page's undo stack. */
  history: { depth: () => number; undo: () => void };
}

let current: EditableArtifact | null = null;
const listeners = new Set<() => void>();

function emit(next: EditableArtifact | null) {
  current = next;
  listeners.forEach((l) => l());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

const getSnapshot = () => current;

/** The registered artifact, outside React (edit runner, tests). */
export function getEditableArtifact(): EditableArtifact | null {
  return current;
}

/** The registered artifact (pivt panel, router). */
export function useEditableArtifact(): EditableArtifact | null {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

/** Stable key of an artifact for conversation bookkeeping. */
export function editableArtifactKey(a: Pick<EditableArtifact, 'kind' | 'id'>): string {
  return `${a.kind}:${a.id}`;
}

/**
 * Register the page's open artifact while the component is mounted. Pass
 * `null` to register nothing: a page registers only when the user can edit
 * it AND may use pivt on it (the artifact's write permissions plus meloD), so
 * a registration always means "pivt may propose edits here". `getDoc`, `apply` and `history` are read
 * through a ref, so callers can pass fresh closures every render; the store
 * only re-emits when the identity fields change.
 */
export function useRegisterEditableArtifact<TDoc>(artifact: EditableArtifact<TDoc> | null): void {
  const latest = useRef(artifact);
  latest.current = artifact;
  const key = artifact
    ? JSON.stringify([artifact.kind, artifact.id, artifact.version, artifact.name, artifact.noun])
    : null;
  useEffect(() => {
    const a = latest.current;
    if (!a || key === null) return;
    const registered: EditableArtifact = {
      kind: a.kind,
      id: a.id,
      version: a.version,
      name: a.name,
      noun: a.noun,
      getDoc: () => (latest.current ?? a).getDoc(),
      apply: (doc, changed) => (latest.current ?? a).apply(doc as TDoc, changed),
      history: {
        depth: () => (latest.current ?? a).history.depth(),
        undo: () => (latest.current ?? a).history.undo(),
      },
    };
    emit(registered);
    return () => {
      if (current === registered) emit(null);
    };
  }, [key]);
}

/** Test hook. */
export function resetEditableArtifact() {
  emit(null);
}
