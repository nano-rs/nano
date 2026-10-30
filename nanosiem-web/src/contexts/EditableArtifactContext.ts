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
import { diffArrays } from 'diff';
import { useEffect, useRef, useSyncExternalStore } from 'react';

/** Kinds with a server edit-session adapter (`EditArtifactKind`). */
export type EditableArtifactKind = 'flow' | 'parser';

export interface EditableProposal {
  document: unknown;
  reply: string;
  changed: string[];
  facts: Array<{label:string;value:string}>;
  carried_findings: string[];
  repaired: boolean;
}

/** Conservative three-way merge: disjoint edits rebase; overlapping edits require review. */
export function rebaseVrlPatch(before: string, current: string, proposed: string): string {
  if (before === current) return proposed;
  const base = before.split('\n');
  const changes = (text: string) => {
    const edits: Array<{start:number;end:number;insert:string[]}> = [];
    let position = 0;
    let pending: typeof edits[number] | null = null;
    for (const change of diffArrays(base, text.split('\n'))) {
      if (!change.added && !change.removed) { if (pending) edits.push(pending); pending=null; position+=change.count ?? change.value.length; continue; }
      pending ??= {start:position,end:position,insert:[]};
      if (change.removed) { position+=change.count ?? change.value.length; pending.end=position; }
      else pending.insert.push(...change.value);
    }
    if (pending) edits.push(pending);
    return edits;
  };
  const manual = changes(current);
  const proposal = changes(proposed);
  for (const patch of proposal) for (const edit of manual) {
    const overlaps = patch.start === patch.end || edit.start === edit.end
      ? Math.max(patch.start,edit.start) <= Math.min(patch.end,edit.end)
      : Math.max(patch.start,edit.start) < Math.min(patch.end,edit.end);
    if (overlaps) throw new Error('These VRL lines changed after the proposal. Ask pivt again to use your latest edits.');
  }
  const result = current.split('\n');
  for (const patch of proposal.reverse()) {
    const offset = manual.filter(edit=>edit.end<=patch.start).reduce((sum,edit)=>sum+edit.insert.length-(edit.end-edit.start),0);
    result.splice(patch.start+offset,patch.end-patch.start,...patch.insert);
  }
  return result.join('\n');
}

export interface EditableArtifact<TDoc = unknown> {
  kind: EditableArtifactKind;
  /** Refresh panel context and the single suggestion when the live buffer changes. */
  revision?: string;
  suggestion?: () => {label:string;run:string} | null;
  propose?: (instruction:string, signal:AbortSignal, progress:(message:string)=>void) => Promise<EditableProposal>;
  invoke?: (action:'get_more_samples' | 'run_tests', args:{n?:number;filter?:string}, signal:AbortSignal) => Promise<string>;
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
    ? JSON.stringify([artifact.kind, artifact.id, artifact.version, artifact.name, artifact.noun, artifact.revision])
    : null;
  useEffect(() => {
    const a = latest.current;
    if (!a || key === null) return;
    const registered: EditableArtifact = {
      kind: a.kind,
      revision: a.revision,
      suggestion: () => latest.current?.suggestion?.() ?? null,
      propose: a.propose ? (instruction, signal, progress) => (latest.current ?? a).propose!(instruction, signal, progress) : undefined,
      invoke: a.invoke ? (action, args, signal) => (latest.current ?? a).invoke!(action, args, signal) : undefined,
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
