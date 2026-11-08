// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * View models for the Nano Pipe workspace (NAN-4919). A pipeline is a log
 * source's parser written as ordered steps and stored in its `parser_vrl`.
 */
export type PipelineStepKind = 'parse' | 'rename' | 'remove' | 'set' | 'redact' | 'filter' | 'sample' | 'split' | 'fields' | 'mask' | 'combine' | 'lookup' | 'dedupe' | 'route' | 'vrl';
export interface PipelineStep {
  id: string;
  name: string;
  kind: PipelineStepKind;
  enabled: boolean;
  condition?: string;
  config: Record<string, unknown>;
}
export interface PipelineDraft {
  name: string;
  description: string;
  revision: number;
  steps: PipelineStep[];
}
/** One published version of the source (`GET /api/log-sources/{id}/versions`). */
export interface PipelineRelease {
  id: string;
  versionId: number;
  revision: number;
  active: boolean;
  createdAt: string;
  actor?: string;
  reason?: string;
}
export interface PipelineSummary {
  id: string;
  name: string;
  description: string;
  sourceId: string;
  sourceName: string;
  sourceType: string;
  /** Active published version number, when known. */
  activeRevision: number | null;
  draftRevision: number;
  hasDraft: boolean;
  /** Stored as a step plan (true) or plain VRL (false). */
  stepPlan: boolean;
  stepCount: number;
  enabled: boolean;
  deployed: boolean;
  deployedAt?: string;
  updatedAt: string;
}
/** A kind this deployment previews but refuses to publish, with the server's reason. */
export interface PreviewOnlyKind {
  kind: PipelineStepKind;
  reason: string;
}
export interface PipelineCapabilities {
  supportedSteps: PipelineStepKind[];
  previewOnly: PreviewOnlyKind[];
  preview: boolean;
  previewReason?: string;
  /** The preview worker runs without Linux resource limits (development host). */
  previewDegraded: boolean;
  tap: { available: boolean; reason?: string; maxEvents: number; maxSeconds: number };
  /** `not_available`: this backend does not serve the pipe endpoints (a quiet state, not an error). */
  runtime: 'loading' | 'ready' | 'not_available' | 'error';
  maxSteps: number;
  ai: boolean;
  /** Why pivt is off (open edition, not enabled, missing permission); shown on the disabled button. */
  aiReason?: string;
}
export interface PipelinePermissions {
  view: boolean;
  edit: boolean;
  /** Read raw source events (live tap, recent events, preview payloads): `search:execute`. */
  events: boolean;
  release: boolean;
}
export interface CapturedEvent {
  id: string;
  input: unknown;
  capturedAt?: string;
  /** The input identity it arrived on (`push:<credential id>` / `pull:<source id>`), when known. */
  nanoInput?: string;
}
export interface PipelineLaneInput {
  /** Canonical `push:<credential id>` or `pull:<pull source id>`. */
  id: string;
  kind: 'push' | 'pull' | 'feed';
  label: string;
}
export interface PipelineTapOptions {
  seconds: number;
  maxEvents: number;
}
export interface PipelineTap {
  state: 'ready' | 'capturing' | 'completed' | 'no_traffic' | 'cancelled' | 'failed' | 'busy' | 'unavailable' | 'forbidden';
  events: CapturedEvent[];
  /** Capture window of the running/last tap. */
  seconds?: number;
  startedAt?: number;
  /** `deadline`, `max_events`, `max_bytes` or `stream_closed`. */
  ended?: string;
  droppedOversize?: number;
  component?: string;
  reason?: string;
  /** 429: seconds until a retry can be admitted. */
  retryAfter?: number;
}
export interface PipelinePreviewEvent {
  inputId: string;
  input: unknown;
  outputs: unknown[];
  outcome: string;
  error?: string;
  trace?: Array<{ stepId: string; outputs: unknown[]; error?: string; bypassed?: boolean }>;
}
export interface PipelinePreviewSummary {
  inputEvents: number;
  outputEvents: number;
  droppedEvents: number;
  errorEvents: number;
  inputBytes: number;
  outputBytes: number;
}
export interface PipelinePreview {
  warnings?: string[];
  revision: number;
  fingerprint: string;
  engine: string;
  degraded: boolean;
  events: PipelinePreviewEvent[];
  summary: PipelinePreviewSummary;
  stale: boolean;
}
export interface PipelineValidation {
  valid: boolean;
  errors: string[];
  warnings: string[];
}
/** The frozen release snapshot: exactly what Publish sends. */
export interface PipelineReleasePlan {
  fingerprint: string;
  revision: number;
  /** The source row as reviewed; publish refuses if the server moved past it. */
  snapshot: import('./api/pipelines').PipePublicationSnapshot;
  validation: PipelineValidation;
  /** The steps of the reviewed plan (empty for plain VRL). */
  steps: PipelineStep[];
  activeVrl: string;
  activeVersion: number | null;
  /** Enabled step kinds that this deployment refuses to publish. */
  previewOnly: PreviewOnlyKind[];
}
export interface PipelineSample {
  id: string;
  name: string;
  events: CapturedEvent[];
  /** All origins are browser-only: never saved or attached to a release. */
  origin: 'tap' | 'recent' | 'pasted';
}
/** Each operation owns its error so a banner names the operation that failed and clears when it next succeeds. */
export type PipelineOperation = 'save' | 'validate' | 'review' | 'publish' | 'rollback' | 'tap' | 'load' | 'discard' | 'reload';
export type PipelineOperationErrors = Partial<Record<PipelineOperation, string>>;
/** The server copy moved past this editor's save/review baseline. Saving or publishing fails until resolved. */
export interface PipelineConflict {
  operation: 'save' | 'review' | 'publish' | 'remote';
  message: string;
}
