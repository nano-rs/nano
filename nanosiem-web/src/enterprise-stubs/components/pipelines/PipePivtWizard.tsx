// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub. PipePivtWizard is the meloD-backed pivt panel the Pipe
// editor opens on `pivt:open-pipe-wizard` (NAN-3453). Renders nothing in open
// builds; the editor's pivt button is disabled there with a reason.

import type { CapturedEvent, PipelineDraft, PipelinePreview } from '@/lib/pipeline-types';

export interface PipePivtWizardProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  openSeq: number;
  sourceId: string;
  sourceName: string;
  sourceType?: string;
  draft: PipelineDraft;
  initialStepId: string | null;
  initialPrompt?: string;
  sample?: { name?: string; events: CapturedEvent[] } | null;
  preview?: PipelinePreview | null;
  previewError?: string | null;
  canApply: boolean;
  onApply: (next: PipelineDraft) => void;
}

export function PipePivtWizard(props: PipePivtWizardProps) {
  void props;
  return null;
}
export default PipePivtWizard;
