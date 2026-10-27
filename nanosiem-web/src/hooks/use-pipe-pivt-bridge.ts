// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-4609: the Pipe page bridge for pivt panel runs (panel-first, NAN-4588).
//
// `@pipe` runs in the pivt panel, not in a sheet on the Pipe page. The run
// reads the open pipeline through one synchronous window event and writes an
// accepted VRL proposal back through another; the page applies it to its
// draft as an unsaved edit, so Save draft / Publish work exactly like a hand
// edit:
//
//   pivt:pipe-context    pivt reads the open pipeline (source, draft, the
//                        selected step, sample, last preview, edit access)
//   pivt:apply-pipe-vrl  pivt writes a proposal; the page applies it to the
//                        draft unless the target step changed or is gone
//
// The events are dispatched synchronously, so the dispatcher reads the
// listener's answer from `detail` right after `dispatchEvent` returns. Lives
// outside `enterprise/` because the Pipe page (open code) mounts it. A meloD
// wizard bridge, not a Cases surface: no NotebookContext.

import { useEffect, useRef } from 'react';
import { applyPipeVrl, targetVrl, type PipePivtTarget } from '@/lib/pipe-pivt';
import type { CapturedEvent, PipelineDraft, PipelinePreview } from '@/lib/pipeline-types';

export const PIVT_PIPE_CONTEXT_EVENT = 'pivt:pipe-context' as const;
export const PIVT_APPLY_PIPE_VRL_EVENT = 'pivt:apply-pipe-vrl' as const;

/** The open pipeline, as pivt sees it. */
export interface PivtPipeSnapshot {
  sourceId: string;
  sourceName: string;
  sourceType?: string;
  draft: PipelineDraft;
  /** Step selected in the editor; null when there are no steps. */
  selectedStepId: string | null;
  /** The frozen sample, else the first loaded one. */
  sample: { name?: string; events: CapturedEvent[] } | null;
  preview: PipelinePreview | null;
  previewError: string | null;
  /** `log_sources:edit`: without it pivt can explain but not apply. */
  canApply: boolean;
  /** Why pivt is off for this viewer (edition, meloD, permission); null when on. */
  unavailableReason: string | null;
}

export interface PivtPipeContextDetail {
  snapshot?: PivtPipeSnapshot;
}

export interface PivtApplyPipeVrlDetail {
  sourceId: string;
  target: PipePivtTarget;
  /** The text pivt diffed against; the page refuses if the step changed since. */
  before: string;
  after: string;
  /** Set by the page that took the proposal. */
  applied?: boolean;
  /** Id of the step an insert created. */
  insertedStepId?: string;
  /** Set by the page for this pipeline when it refused (read-only, stale, gone). */
  error?: string;
}

export const PIPE_VRL_STALE_ERROR = 'The step changed after pivt proposed this. Ask again.';
export const PIPE_VRL_GONE_ERROR = 'The target step no longer exists. Ask again.';
export const PIPE_VRL_READ_ONLY_ERROR = 'You need permission to edit this pipeline to apply it.';

/** Read the open pipeline, if any. */
export function readPipePivtContext(): PivtPipeSnapshot | null {
  const detail: PivtPipeContextDetail = {};
  window.dispatchEvent(new CustomEvent(PIVT_PIPE_CONTEXT_EVENT, { detail }));
  return detail.snapshot ?? null;
}

/** Write a proposal into the open pipeline `sourceId`. */
export function applyPipeVrlOnPage(
  sourceId: string,
  target: PipePivtTarget,
  before: string,
  after: string,
): { applied: boolean; insertedStepId?: string; error?: string } {
  const detail: PivtApplyPipeVrlDetail = { sourceId, target, before, after };
  window.dispatchEvent(new CustomEvent(PIVT_APPLY_PIPE_VRL_EVENT, { detail }));
  return { applied: detail.applied === true, insertedStepId: detail.insertedStepId, error: detail.error };
}

export interface UsePipePivtBridgeOptions {
  /** Null until the pipeline and its draft have loaded. */
  snapshot: PivtPipeSnapshot | null;
  /** Replace the draft (unsaved). Only called when `snapshot.canApply`. */
  onApply: (next: PipelineDraft) => void;
}

/** Mount the bridge on the Pipe page. */
export function usePipePivtBridge({ snapshot, onApply }: UsePipePivtBridgeOptions) {
  const latest = useRef({ snapshot, onApply });
  latest.current = { snapshot, onApply };

  useEffect(() => {
    const onContext = (event: Event) => {
      const snap = latest.current.snapshot;
      if (snap) (event as CustomEvent<PivtPipeContextDetail>).detail.snapshot = snap;
    };
    const onApplyVrl = (event: Event) => {
      const detail = (event as CustomEvent<PivtApplyPipeVrlDetail>).detail;
      const { snapshot: snap, onApply: apply } = latest.current;
      if (!snap || detail.sourceId !== snap.sourceId) return;
      if (!snap.canApply) {
        detail.error = PIPE_VRL_READ_ONLY_ERROR;
        return;
      }
      const current = targetVrl(snap.draft, detail.target);
      if (current === null) {
        detail.error = PIPE_VRL_GONE_ERROR;
        return;
      }
      if (current !== detail.before) {
        detail.error = PIPE_VRL_STALE_ERROR;
        return;
      }
      const next = applyPipeVrl(snap.draft, detail.target, detail.after);
      if (!next) {
        detail.error = PIPE_VRL_GONE_ERROR;
        return;
      }
      if (detail.target.kind === 'insert') {
        detail.insertedStepId = next.steps.find((step) => !snap.draft.steps.some((prior) => prior.id === step.id))?.id;
      }
      apply(next);
      // The page re-renders later; keep a second apply in the same tick honest.
      latest.current = { ...latest.current, snapshot: { ...snap, draft: next } };
      detail.applied = true;
    };
    window.addEventListener(PIVT_PIPE_CONTEXT_EVENT, onContext);
    window.addEventListener(PIVT_APPLY_PIPE_VRL_EVENT, onApplyVrl);
    return () => {
      window.removeEventListener(PIVT_PIPE_CONTEXT_EVENT, onContext);
      window.removeEventListener(PIVT_APPLY_PIPE_VRL_EVENT, onApplyVrl);
    };
  }, []);
}
