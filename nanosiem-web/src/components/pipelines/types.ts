// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  PipelineCapabilities,
  PipelineCapture,
  PipelineCaptureOptions,
  PipelineConflict,
  PipelineDraft,
  PipelineLaneInput,
  PipelineOperationErrors,
  PipelinePermissions,
  PipelinePreview,
  PipelinePublishOptions,
  PipelineRelease,
  PipelineReleasePlan,
  PipelineSample,
  PipelineSummary,
  PipelineValidation,
} from '@/lib/pipeline-types';
import type { PipelineInputsPanelProps } from './PipelineInputs';
import type { PipeLaneInputCounts } from '@/lib/api/pipelines';

export interface PipelineListProps {
  pipelines: PipelineSummary[];
  loading: boolean;
  error?: string | null;
  canCreate: boolean;
  onCreate: () => void;
  onOpen: (id: string) => void;
  onRetry: () => void;
  /** NAN-3621: input counts by pipeline (log source) id; absent while loading or unsupported. */
  inputCounts?: Record<string, PipeLaneInputCounts>;
}

export interface PipelineEditorProps {
  pipeline: PipelineSummary;
  draft: PipelineDraft;
  capabilities: PipelineCapabilities;
  permissions: PipelinePermissions;
  dirty: boolean;
  busy?: string | null;
  /** Per-operation failures; publish/rollback errors belong to their own sheets. */
  errors?: PipelineOperationErrors;
  /** The server copy changed after this editor loaded it. */
  conflict?: PipelineConflict | null;
  /** Runtime capability load failure (not a 404 "not available yet"). */
  capabilitiesError?: string | null;
  previewError?: string | null;
  validation?: PipelineValidation | null;
  capture?: PipelineCapture | null;
  samples: PipelineSample[];
  sample?: PipelineSample | null;
  preview?: PipelinePreview | null;
  previewPending?: boolean;
  onDraftChange: (draft: PipelineDraft) => void;
  /** NAN-3625: the lane's inputs, for "Input is" route branches and preview. */
  laneInputs?: PipelineLaneInput[];
  /** NAN-3625: inputs the draft's route branches name (shown even when the lane does not list them). */
  routedInputs?: string[];
  /** NAN-3625: preview every event as arriving on this input; null = as recorded. */
  previewInput?: string | null;
  onPreviewInputChange?: (input: string | null) => void;
  onSave: () => void;
  onValidate: () => void;
  onReview: () => void;
  onHistory: () => void;
  onCaptureStart: (options: PipelineCaptureOptions) => void;
  onCaptureStop: () => void;
  onFreeze: () => void;
  onSampleSelect: (sample: PipelineSample) => void;
  onPreview: () => void;
  onSaveSample?: () => void;
  canSaveSample?: boolean;
  /** NAN-3447: load the source's newest stored raw events as browser-only preview input. */
  onLoadRecent?: (limit: number) => void;
  /** NAN-3447: use pasted raw events as browser-only preview input; throws on unusable text. */
  onPasteSample?: (text: string) => void;
  /** No usable events came back from the last load. */
  sampleNotice?: string | null;
  /** NAN-3621: the lane's inputs (push, connector, pull). Absent: the flow strip shows the source name. */
  inputs?: PipelineInputsPanelProps;
  /** Opens pivt focused on the selected step (NAN-3453). */
  onAssistant?: (selectedStepId: string | null) => void;
  /** NAN-4609: the selected step, so pivt (`@pipe`) works on what the analyst is looking at. */
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
  onPublish: (options: PipelinePublishOptions) => void;
}

export interface PipelineReleaseHistoryProps {
  open: boolean;
  pipelineName: string;
  releases: PipelineRelease[];
  canRollback: boolean;
  pending?: boolean;
  /** Release history could not be loaded. */
  loadError?: string | null;
  /** The last rollback request failed. */
  error?: string | null;
  /** This editor has unsaved local edits that a rollback replaces. */
  unsavedEdits?: boolean;
  /** The server holds a saved, unpublished draft that a rollback replaces. */
  savedDraft?: boolean;
  onOpenChange: (open: boolean) => void;
  /** `unsavedEdits` echoes what the confirmation warned about, so a changed draft is refused. */
  onRollback: (
    release: PipelineRelease,
    confirmed: { unsavedEdits: boolean }
  ) => void;
}
