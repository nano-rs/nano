// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-4609: pivt on the Pipe page runs in the pivt panel (panel-first,
// NAN-4588). This hook wires the page side: the bridge pivt reads the open
// pipeline through and applies accepted VRL with (unsaved, like a hand edit),
// the Here card with step-aware suggestions, and the editor's pivt button,
// which opens the panel with `@pipe ` ready for the request. Kept out of
// Pipelines.tsx so the page only gains one hook call and two props.

import { useCallback, useMemo, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { useHereCardOverride } from '@/contexts/PageContext';
import { useCapabilities } from '@/hooks/use-capabilities';
import { usePipePivtBridge, type PivtPipeSnapshot } from '@/hooks/use-pipe-pivt-bridge';
import type { usePipelineWorkspace } from '@/hooks/use-pipeline-workspace';
import { openPivtPanel } from '@/enterprise/components/pivt/commands/router';
import { pipeSampleLogs, previewIssue } from '@/lib/pipe-pivt';

type Workspace = ReturnType<typeof usePipelineWorkspace>;

/** Why pivt is off for this viewer, or null when it is available. */
export function pipePivtUnavailableReason(edition: 'open' | 'enterprise', melod: boolean, canUse: boolean): string | null {
  if (edition === 'open') return 'pivt is part of nano Enterprise';
  if (!melod) return 'pivt is not enabled for this workspace';
  if (!canUse) return 'pivt requires the melod:parser permission';
  return null;
}

export const PIPE_SUGGESTIONS = {
  explain: 'Explain the selected pipeline step',
  fix: 'Fix the preview error in this pipeline step',
  draft: 'Draft a pipeline step from the sample events',
} as const;

export function usePipePivt(sourceId: string, workspace: Workspace) {
  const { hasPermission } = useAuth();
  const { edition, capabilities } = useCapabilities();
  const reason = pipePivtUnavailableReason(edition, capabilities.melod, hasPermission('melod:parser'));
  const available = reason === null;
  const [selectedStepId, setSelectedStepId] = useState<string | null>(null);

  const { pipeline, draft, frozen, samples, preview, previewError, permissions, changeDraft } = workspace;
  const sample = frozen ?? samples[0] ?? null;
  const snapshot = useMemo<PivtPipeSnapshot | null>(
    () =>
      pipeline && draft
        ? {
            sourceId,
            sourceName: pipeline.sourceName,
            sourceType: pipeline.sourceType,
            draft,
            selectedStepId: draft.steps.some((step) => step.id === selectedStepId) ? selectedStepId : (draft.steps[0]?.id ?? null),
            sample,
            preview: preview ?? null,
            previewError: previewError ?? null,
            canApply: permissions.edit,
            unavailableReason: reason,
          }
        : null,
    [sourceId, pipeline, draft, selectedStepId, sample, preview, previewError, permissions.edit, reason],
  );
  usePipePivtBridge({ snapshot, onApply: changeDraft });

  const step = snapshot?.draft.steps.find((item) => item.id === snapshot.selectedStepId) ?? null;
  const sampleCount = pipeSampleLogs(sample).length;
  const hasIssue = !!previewIssue(preview, previewError, step?.id);
  useHereCardOverride(
    snapshot
      ? {
          icon: 'GitBranch',
          title: snapshot.sourceName,
          lines: [
            { label: 'step', value: step ? `${snapshot.draft.steps.indexOf(step) + 1} · ${step.name}` : 'none yet' },
            { label: 'samples', value: String(sampleCount) },
            ...(hasIssue ? [{ label: 'preview', value: 'error' }] : []),
          ],
          suggestions: available
            ? [
                ...(step ? [PIPE_SUGGESTIONS.explain] : []),
                ...(hasIssue ? [PIPE_SUGGESTIONS.fix] : []),
                ...(sampleCount ? [PIPE_SUGGESTIONS.draft] : []),
              ]
            : [],
        }
      : null,
  );

  const open = useCallback(() => openPivtPanel('@pipe '), []);
  return { available, reason, open, onSelectedStepChange: setSelectedStepId } as const;
}
