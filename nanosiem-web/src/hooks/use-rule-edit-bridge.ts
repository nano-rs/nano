// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-4590: the rule-editor bridge for pivt panel runs (panel-first, NAN-4588).
//
// pivt work on a rule (AI tuning, triage hints) runs in the pivt panel, not in
// a sheet on the editor. When the analyst accepts a suggestion card, pivt
// writes the result into the open editor through this bridge: the editor's
// buffer changes and stays unsaved, so review + Save (rule version, audit)
// work exactly like a hand edit. Two synchronous window events:
//
//   pivt:rule-editor-context  pivt reads the focused editor (rule, current
//                             query, hints, whether the analyst can edit)
//   pivt:apply-rule-edit      pivt writes an edit; the editor marks it applied
//
// The events are dispatched synchronously, so the dispatcher reads the
// listener's answer from `detail` right after `dispatchEvent` returns. When no
// editor for that rule is mounted, pivt navigates to it with the edit in
// router state (`PivtRuleEditNavState`) and the editor applies it once the
// rule has loaded.
//
// This lives outside `enterprise/` because the editor (open code) mounts it.
// It is a meloD wizard bridge, not a Cases surface: no NotebookContext.

import { useEffect, useRef } from 'react';
import type { AiTriageHints } from '@/lib/api/types';

export const PIVT_APPLY_RULE_EDIT_EVENT = 'pivt:apply-rule-edit' as const;
export const PIVT_RULE_EDITOR_CONTEXT_EVENT = 'pivt:rule-editor-context' as const;

/** What pivt can write into the editor. Each lands as an unsaved edit. */
export type PivtRuleEdit =
  | { kind: 'query'; query: string }
  | { kind: 'triage-hints'; hints: AiTriageHints }
  /** NAN-4595: a whole rule (frontmatter + query) for the new-rule editor. The
      editor fills author / detection mode when the YAML leaves them out. */
  | { kind: 'content'; content: string };

/** The focused rule editor, as pivt sees it. */
export interface PivtRuleEditorSnapshot {
  /** Saved rule id; `null` for an unsaved new rule. */
  ruleId: string | null;
  ruleName: string;
  /** The query in the editor buffer (may differ from the saved rule). */
  query: string;
  hints: AiTriageHints;
  canEdit: boolean;
  /** meloD + the AI tuning entitlement are present. */
  tuneAvailable: boolean;
}

export interface PivtRuleEditorContextDetail {
  snapshot?: PivtRuleEditorSnapshot;
}

export interface PivtApplyRuleEditDetail {
  /** Target rule; `null` targets an unsaved new rule. */
  ruleId: string | null;
  edit: PivtRuleEdit;
  /** Set by the editor that took the edit. */
  applied?: boolean;
  /** Set by an editor for this rule that refused the edit (read-only). */
  error?: string;
}

/** Router state that carries an edit to an editor pivt navigates to. */
export interface PivtRuleEditNavState {
  /** `null` targets the new-rule editor (`/rules/editor/new`). */
  pivtRuleEdit: { ruleId: string | null; edit: PivtRuleEdit };
}

/** Read the mounted rule editor, if any. */
export function readRuleEditorContext(): PivtRuleEditorSnapshot | null {
  const detail: PivtRuleEditorContextDetail = {};
  window.dispatchEvent(new CustomEvent(PIVT_RULE_EDITOR_CONTEXT_EVENT, { detail }));
  return detail.snapshot ?? null;
}

/** Write an edit into the mounted editor for `ruleId`. */
export function applyRuleEdit(ruleId: string | null, edit: PivtRuleEdit): { applied: boolean; error?: string } {
  const detail: PivtApplyRuleEditDetail = { ruleId, edit };
  window.dispatchEvent(new CustomEvent(PIVT_APPLY_RULE_EDIT_EVENT, { detail }));
  return { applied: detail.applied === true, error: detail.error };
}

export interface UseRuleEditBridgeOptions {
  /** False until the editor holds the rule (load finished). */
  ready: boolean;
  snapshot: PivtRuleEditorSnapshot;
  /** Apply the edit to the buffer. Only called when `snapshot.canEdit`. */
  onApply: (edit: PivtRuleEdit) => void;
  /** Router state of the current location (`useLocation().state`). */
  navState: unknown;
  /** Drop the consumed nav state (e.g. `navigate(pathname, { replace: true })`). */
  clearNavState: () => void;
}

/** Mount the bridge on the rule editor. */
export function useRuleEditBridge({ ready, snapshot, onApply, navState, clearNavState }: UseRuleEditBridgeOptions) {
  const latest = useRef({ ready, snapshot, onApply });
  latest.current = { ready, snapshot, onApply };

  useEffect(() => {
    const onContext = (event: Event) => {
      const { ready: isReady, snapshot: snap } = latest.current;
      if (!isReady) return;
      (event as CustomEvent<PivtRuleEditorContextDetail>).detail.snapshot = snap;
    };
    const onEdit = (event: Event) => {
      const detail = (event as CustomEvent<PivtApplyRuleEditDetail>).detail;
      const { ready: isReady, snapshot: snap, onApply: apply } = latest.current;
      if (!isReady || detail.ruleId !== snap.ruleId) return;
      if (!snap.canEdit) {
        detail.error = 'You have read-only access to this rule.';
        return;
      }
      apply(detail.edit);
      detail.applied = true;
    };
    window.addEventListener(PIVT_RULE_EDITOR_CONTEXT_EVENT, onContext);
    window.addEventListener(PIVT_APPLY_RULE_EDIT_EVENT, onEdit);
    return () => {
      window.removeEventListener(PIVT_RULE_EDITOR_CONTEXT_EVENT, onContext);
      window.removeEventListener(PIVT_APPLY_RULE_EDIT_EVENT, onEdit);
    };
  }, []);

  // An edit pivt carried here by navigation: apply once the rule has loaded.
  const pending = (navState as Partial<PivtRuleEditNavState> | null | undefined)?.pivtRuleEdit;
  const clearRef = useRef(clearNavState);
  clearRef.current = clearNavState;
  useEffect(() => {
    if (!pending || !ready || pending.ruleId !== snapshot.ruleId) return;
    if (snapshot.canEdit) latest.current.onApply(pending.edit);
    clearRef.current();
  }, [pending, ready, snapshot.ruleId, snapshot.canEdit]);
}
