// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-3453: the Pipe editor's pivt button and pivt `@pipe` open the pipeline
// assistant via `pivt:open-pipe-wizard`. This hook is the page-side listener,
// mirroring `use-tuning-wizard-listener`. It is a meloD wizard surface, not
// cases-coupled: nothing here touches NotebookContext.

import { useEffect, useState } from 'react';

export const PIPE_WIZARD_EVENT = 'pivt:open-pipe-wizard' as const;

export interface PipeWizardEventDetail {
  /** Pipeline (log source) the wizard is for. Absent = the open pipeline. */
  sourceId?: string;
  /** Step to focus. Absent = keep the current / first step. */
  stepId?: string;
  /** Optional request to pre-fill (pivt `@pipe <text>`). */
  prompt?: string;
}

export interface PipeWizardRequest {
  /** Bumped on every open so a repeat request re-opens a closed panel. */
  seq: number;
  stepId?: string;
  prompt?: string;
}

/**
 * Listen for `pivt:open-pipe-wizard` while `sourceId` is the open pipeline.
 * Events addressed to another pipeline are ignored.
 */
export function usePipeWizardListener(sourceId: string | undefined, enabled: boolean) {
  const [request, setRequest] = useState<PipeWizardRequest | null>(null);

  useEffect(() => {
    if (!enabled || !sourceId) return undefined;
    const handler = (event: Event) => {
      const detail = ((event as CustomEvent<PipeWizardEventDetail | undefined>).detail ?? {}) as PipeWizardEventDetail;
      if (detail.sourceId && detail.sourceId !== sourceId) return;
      const prompt = typeof detail.prompt === 'string' && detail.prompt.trim() ? detail.prompt : undefined;
      const stepId = typeof detail.stepId === 'string' && detail.stepId ? detail.stepId : undefined;
      setRequest((prev) => ({ seq: (prev?.seq ?? 0) + 1, stepId, prompt }));
    };
    window.addEventListener(PIPE_WIZARD_EVENT, handler);
    return () => window.removeEventListener(PIPE_WIZARD_EVENT, handler);
  }, [sourceId, enabled]);

  useEffect(() => {
    setRequest(null);
  }, [sourceId]);

  return { request, close: () => setRequest(null) } as const;
}

/** Open the pipe wizard on the current page (button path). */
export function openPipeWizard(detail: PipeWizardEventDetail = {}) {
  window.dispatchEvent(new CustomEvent<PipeWizardEventDetail>(PIPE_WIZARD_EVENT, { detail }));
}
