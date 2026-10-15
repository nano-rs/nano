// SPDX-License-Identifier: AGPL-3.0-or-later

/** Host-independent view models for the shared-lake pipeline workspace. */
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
export interface PipelineRelease {
  id: string;
  revision: number | null;
  state: string;
  createdAt: string;
  actor?: string;
  error?: string;
  versionId?: number;
}
export interface PipelineSummary {
  id: string;
  name: string;
  description: string;
  sourceId: string;
  sourceName: string;
  sourceType: string;
  activeRevision: number | null;
  draftRevision: number;
  hasDraft: boolean;
  health: 'healthy' | 'warning' | 'unknown';
  latestRelease: PipelineRelease | null;
}
export interface PipelineCapabilities {
  supportedSteps: PipelineStepKind[];
  capture: { available: boolean; reason?: string; maxEvents?: number; maxDurationSeconds?: number; maxBytes?: number };
  previewReason?: string;
  preview: boolean;
  /** `not_available`: this backend does not serve the pipe runtime endpoints yet (a quiet state, not an error). */
  runtime?: 'loading' | 'ready' | 'not_available' | 'error';
  ai: boolean;
  /** Why pivt is off (open edition, not enabled, missing permission); shown on the disabled button. */
  aiReason?: string;
}
export interface PipelinePermissions {
  view: boolean;
  edit: boolean;
  capture: boolean;
  release: boolean;
}
export interface CapturedEvent {
  id: string;
  input: unknown;
  capturedAt?: string;
  /** NAN-3625: the input it arrived on (`push:<credential id>` / `pull:<source id>`), when known. */
  nanoInput?: string;
}
/** NAN-3625: one input feeding a lane, as the lane inputs API lists it. */
export interface PipelineLaneInput {
  /** Canonical `push:<credential id>` or `pull:<pull source id>`; feeds use their ingest credential. */
  id: string;
  kind: 'push' | 'pull' | 'feed';
  label: string;
}
export interface PipelineCaptureOptions {
  sourceId: string;
  point: 'input';
  durationSeconds: number;
  eventLimit: number;
  filter?: string;
}
export interface PipelineCapture {
  state: 'ready' | 'connecting' | 'capturing' | 'completed' | 'stopped' | 'no_traffic' | 'unavailable' | 'failed' | 'forbidden' | 'no_matches' | 'interrupted' | 'limit' | 'release_changed' | 'expired';
  events: CapturedEvent[];
  sourceId: string;
  point: 'input';
  startedAt?: string;
  reason?: string;
  sessionId?: string;
  activeBundleSha256?: string | null;
  truncated?: boolean;
  /** Count the runtime reports; `events` holds only what was read from the edge snapshot. */
  observedEvents?: number;
  /** The server purges the snapshot at this time; the live view expires with it. */
  retainUntil?: string;
  snapshotAvailable?: boolean;
}
export interface PipelinePreviewEvent {
  inputId: string;
  input: unknown;
  outputs: unknown[];
  outcome: 'retained' | 'filtered' | 'sampled_out' | 'split' | 'combined' | 'pending' | 'error';
  error?: string;
  trace?: Array<{ stepId: string; outputs: unknown[]; error?: string }>;
}
export interface PipelinePreview {
  warnings?: string[];
  revision: number;
  fingerprint: string;
  events: PipelinePreviewEvent[];
  inputCount: number;
  outputCount: number;
  stale: boolean;
}
export interface PipelineValidation {
  valid: boolean;
  errors: string[];
  warnings: string[];
  compiledVrl?: string;
}
export interface PipelineReleasePlan {
  fingerprint: string;
  revision: number;
  compiledVrl: string;
  validation: PipelineValidation;
  activeVrl: string;
  /**
   * Raw messages from a live capture that publishing could save as this
   * version's test samples. Unset when the reviewed sample is not a capture.
   * Saving them is opt-in: they would outlive the 10-minute capture purge.
   */
  capturedSampleCount?: number;
}
/** The reviewer's explicit choices for one publication. */
export interface PipelinePublishOptions {
  /** Store the reviewed captured events with the version (default false). */
  persistCapturedSamples: boolean;
}
export interface PipelineSample {
  id: string;
  name: string;
  events: CapturedEvent[];
  /**
   * `capture`: frozen from a live capture; captured bodies are never persisted without explicit consent.
   * `recent` / `pasted`: loaded from stored events or pasted (NAN-3447); browser-only, never
   * attached to a release and never written server-side.
   */
  origin?: 'capture' | 'supplied' | 'recent' | 'pasted';
}
/** Each operation owns its error so a banner names the operation that failed and clears when it next succeeds. */
export type PipelineOperation = 'save' | 'validate' | 'review' | 'publish' | 'rollback' | 'capture' | 'stop' | 'sample' | 'load' | 'discard' | 'reload';
export type PipelineOperationErrors = Partial<Record<PipelineOperation, string>>;
/** The server copy moved past this editor's save/review baseline. Saving or publishing fails until resolved. */
export interface PipelineConflict {
  operation: 'save' | 'review' | 'publish' | 'remote';
  message: string;
}
