// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  PipelineCapabilities,
  PipelineConflict,
  PipelineDraft,
  PipelineLaneInput,
  PipelineOperationErrors,
  PipelinePermissions,
  PipelinePreview,
  PipelineRelease,
  PipelineReleasePlan,
  PipelineSample,
  PipelineSummary,
  PipelineTap,
  PipelineTapOptions,
  PipelineValidation,
} from '@/lib/pipeline-types';

export interface PipelineListProps {
  pipelines: PipelineSummary[];
  loading: boolean;
  error?: string | null;
  canCreate: boolean;
  onCreate: () => void;
  onOpen: (id: string) => void;
  onRetry: () => void;
}

export interface PipelineEditorProps {
  pipeline: PipelineSummary;
  draft: PipelineDraft;
  capabilities: PipelineCapabilities;
  permissions: PipelinePermissions;
  dirty: boolean;
  /** The saved parser is plain VRL, shown as one Advanced VRL step. */
  imported?: boolean;
  busy?: string | null;
  /** Per-operation failures; publish/rollback errors belong to their own sheets. */
  errors?: PipelineOperationErrors;
  /** The server copy changed after this editor loaded it. */
  conflict?: PipelineConflict | null;
  /** Capability load failure (not a 404 "not available yet"). */
  capabilitiesError?: string | null;
  previewError?: string | null;
  validation?: PipelineValidation | null;
  tap: PipelineTap;
  sample?: PipelineSample | null;
  preview?: PipelinePreview | null;
  previewPending?: boolean;
  onDraftChange: (draft: PipelineDraft) => void;
  /** Inputs seen in captured events, for "Input is" route branches and preview. */
  laneInputs?: PipelineLaneInput[];
  /** Inputs the draft's route branches name. */
  routedInputs?: string[];
  /** Preview every event as arriving on this input; null = as recorded. */
  previewInput?: string | null;
  onPreviewInputChange?: (input: string | null) => void;
  onSave: () => void;
  onValidate: () => void;
  onReview: () => void;
  onHistory: () => void;
  onTapStart: (options: PipelineTapOptions) => void;
  onTapCancel: () => void;
  /** Use the tapped events as the preview input. */
  onTapPreview: () => void;
  onPreview: () => void;
  /** Load the source's newest stored raw events as browser-only preview input. */
  onLoadRecent?: (limit: number) => void;
  /** Use pasted raw events as browser-only preview input; throws on unusable text. */
  onPasteSample?: (text: string) => void;
  /** No usable events came back from the last load. */
  sampleNotice?: string | null;
  /** Opens pivt focused on the selected step. */
  onAssistant?: (selectedStepId: string | null) => void;
  /** The selected step, so pivt (`@pipe`) works on what the analyst is looking at. */
  onSelectedStepChange?: (stepId: string | null) => void;
  /** Conflict recovery: discard local edits and load the server's latest saved draft. */
  onReloadLatest?: () => void;
  /** Conflict recovery: keep local edits and save over the server's latest draft. */
  onKeepLocalEdits?: () => void;
  /** Reset the saved draft to the active published version (server discard-draft). */
  onDiscardDraft?: () => void;
  onRetryCapabilities?: () => void;
}

export interface PipelineReleaseReviewProps {
  open: boolean;
  plan: PipelineReleasePlan | null;
  canPublish: boolean;
  pending?: boolean;
  stale?: boolean;
  error?: string | null;
  onOpenChange: (open: boolean) => void;
  onPublish: () => void;
}

export interface PipelineReleaseHistoryProps {
  open: boolean;
  pipelineName: string;
  releases: PipelineRelease[];
  canRollback: boolean;
  pending?: boolean;
  /** Version history could not be loaded. */
  loadError?: string | null;
  /** The last rollback request failed. */
  error?: string | null;
  /** This editor has unsaved local edits that a rollback replaces. */
  unsavedEdits?: boolean;
  /** The server holds a saved, unpublished draft that a rollback replaces. */
  savedDraft?: boolean;
  onOpenChange: (open: boolean) => void;
  /** `unsavedEdits` echoes what the confirmation warned about, so a changed draft is refused. */
  onRollback: (release: PipelineRelease, confirmed: { unsavedEdits: boolean }) => void;
}
