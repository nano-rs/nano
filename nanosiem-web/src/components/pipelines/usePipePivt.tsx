// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-3453: wires the Pipe editor's pivt button and pivt `@pipe` to the
// meloD-backed PipePivtWizard. Kept out of Pipelines.tsx so the page only
// gains one hook call, one prop and one element.

import { useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { useCapabilities } from '@/hooks/use-capabilities';
import { openPipeWizard, usePipeWizardListener } from '@/hooks/use-pipe-wizard-listener';
import { PipePivtWizard } from '@/enterprise/components/pipelines/PipePivtWizard';
import type { usePipelineWorkspace } from '@/hooks/use-pipeline-workspace';

type Workspace = ReturnType<typeof usePipelineWorkspace>;

/** Why pivt is off for this viewer, or null when it is available. */
export function pipePivtUnavailableReason(edition: 'open' | 'enterprise', melod: boolean, canUse: boolean): string | null {
  if (edition === 'open') return 'pivt is part of nano Enterprise';
  if (!melod) return 'pivt is not enabled for this workspace';
  if (!canUse) return 'pivt requires the melod:parser permission';
  return null;
}

export function usePipePivt(sourceId: string, workspace: Workspace) {
  const { hasPermission } = useAuth();
  const { edition, capabilities } = useCapabilities();
  const reason = pipePivtUnavailableReason(edition, capabilities.melod, hasPermission('melod:parser'));
  const available = reason === null;
  const { request, close } = usePipeWizardListener(sourceId, available);
  const [lastStepId, setLastStepId] = useState<string | null>(null);

  const open = (stepId: string | null) => {
    setLastStepId(stepId);
    openPipeWizard({ sourceId, stepId: stepId ?? undefined });
  };

  const { pipeline, draft } = workspace;
  const element =
    available && pipeline && draft ? (
      <PipePivtWizard
        open={!!request}
        onOpenChange={(next) => {
          if (!next) close();
        }}
        openSeq={request?.seq ?? 0}
        sourceId={sourceId}
        sourceName={pipeline.sourceName}
        sourceType={pipeline.sourceType}
        draft={draft}
        initialStepId={request?.stepId ?? lastStepId}
        initialPrompt={request?.prompt}
        sample={workspace.frozen ?? workspace.samples[0] ?? null}
        preview={workspace.preview}
        previewError={workspace.previewError}
        canApply={workspace.permissions.edit}
        onApply={workspace.changeDraft}
      />
    ) : null;

  return { available, reason, open, element } as const;
}
