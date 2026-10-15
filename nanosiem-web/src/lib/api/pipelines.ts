// SPDX-License-Identifier: AGPL-3.0-or-later

import type { LogSource } from './types';
import type { PipelineLaneInput } from '../pipeline-types';
import { canonicalInput } from '../pipeline-model';

type PublicationSource = Pick<LogSource, 'id' | 'updated_at' | 'parser_vrl' | 'extension_vrl' | 'extension_enabled'>;
/** Exact source state reviewed; a query refetch must never advance this timestamp. */
export interface PipePublicationSnapshot {
  readonly sourceId: string;
  readonly expectedUpdatedAt: string;
  readonly parserVrl: string;
  readonly extensionVrl: string | null;
  readonly extensionEnabled: boolean;
}
export function publicationSnapshot(source: PublicationSource): PipePublicationSnapshot {
  return Object.freeze({ sourceId: source.id, expectedUpdatedAt: source.updated_at, parserVrl: source.parser_vrl,
    extensionVrl: source.extension_vrl ?? null, extensionEnabled: source.extension_enabled !== false });
}
/** The server copy no longer matches the snapshot the editor saved or reviewed against. */
export class PipeSnapshotConflictError extends Error {
  readonly status = 409;
  constructor(message = 'The reviewed pipeline changed on the server. Reload and review the latest parser and extension before publishing.') {
    super(message);
    this.name = 'PipeSnapshotConflictError';
  }
}
export function samePublicationSnapshot(a: PipePublicationSnapshot, b: PipePublicationSnapshot): boolean {
  return a.sourceId === b.sourceId && a.expectedUpdatedAt === b.expectedUpdatedAt && a.parserVrl === b.parserVrl && a.extensionVrl === b.extensionVrl && a.extensionEnabled === b.extensionEnabled;
}
export function assertPublicationSnapshot(snapshot: PipePublicationSnapshot, source: PublicationSource): void {
  if (!samePublicationSnapshot(snapshot, publicationSnapshot(source))) throw new PipeSnapshotConflictError();
}
/** True when `source` was written after `snapshot` (a stale cached read is never newer). */
export function newerThanSnapshot(snapshot: PipePublicationSnapshot, source: PublicationSource): boolean {
  if (samePublicationSnapshot(snapshot, publicationSnapshot(source))) return false;
  const before = Date.parse(snapshot.expectedUpdatedAt), after = Date.parse(source.updated_at);
  return Number.isNaN(before) || Number.isNaN(after) ? snapshot.expectedUpdatedAt !== source.updated_at : after > before;
}

export interface PipeRuntimeCapabilities {
  engine: string;
  supported_step_kinds: string[];
  /** False: this deployment has preview turned off and POST /pipe-preview answers 503. Absent on older backends. */
  preview_enabled?: boolean;
  capture: {
    stages: Array<'input' | 'output'>;
    default_duration_seconds: number;
    max_duration_seconds: number;
    default_max_events: number;
    max_events: number;
    max_bytes: number;
    enabled: boolean;
    reason?: string;
  };
  warnings: string[];
}
export interface PipePreviewRequest {
  draft_revision: string;
  steps: Array<{ id: string; name: string; enabled: boolean; vrl: string }>;
  events: unknown[];
  /** Separate production remap program; local variables do not cross this boundary. */
  extension_vrl?: string;
  /** NAN-3625: per-event input (`push:<credential id>` / `pull:<source id>` / null), parallel to `events`. */
  event_inputs?: Array<string | null>;
}
export interface PipePreviewResponse {
  draft_revision: string;
  draft_hash: string;
  engine: string;
  results: Array<{
    index: number;
    input: unknown;
    output?: unknown;
    error?: string;
    disposition: 'retained' | 'filtered' | 'sampled_out' | 'split' | 'combined' | 'pending' | 'error';
    steps: Array<{ step_id: string; output?: unknown; error?: string; bypassed: boolean }>;
  }>;
  warnings: string[];
}
export interface PipeCaptureRequest {
  stage: 'input' | 'output';
  duration_seconds: number;
  max_events: number;
  max_bytes?: number;
}
/**
 * The server defines observed states; never infer successful capture from request acceptance.
 * The session carries progress only. Observed events are never stored server-side: read them
 * from edge storage with `captureSnapshot` while `snapshot_available`, before `retain_until`.
 */
export interface PipeCaptureSession {
  id: string;
  tenant_id: string;
  requested_by?: string;
  state: 'queued' | 'running' | 'complete' | 'cancelled' | 'expired' | 'failed';
  stage: 'input' | 'output';
  log_source_id: string;
  source_slug: string;
  active_bundle_sha256: string | null;
  max_events: number;
  max_bytes: number;
  duration_seconds: number;
  created_at: string;
  expires_at: string;
  /** Snapshot and session metadata are purged at this time (ten minutes). */
  retain_until: string;
  observed_events: number;
  observed_bytes: number;
  snapshot_available: boolean;
  truncated: boolean;
  stop_reason: string | null;
  error: string | null;
}
export interface PipeCaptureEvent { sequence: number; observed_at: string; event: Record<string, unknown> }
/** 404: unknown, expired/purged, or revoked. 409: not available yet. 503: edge read path unavailable. */
export interface PipeCaptureSnapshot {
  session_id: string;
  state: PipeCaptureSession['state'];
  truncated: boolean;
  retain_until: string;
  events: PipeCaptureEvent[];
}
/** Load-recent-events bounds (NAN-3447); the server refuses a limit outside 1–100. */
export const DEFAULT_RECENT_EVENTS = 20;
export const MAX_RECENT_EVENTS = 100;
/**
 * An authorized, audited read of one source's newest stored events. The client
 * runs `query` over `time_range` through `POST /api/search` (tenant and source
 * scope enforced there); `raw_field` holds each event's original pre-parse text.
 */
export interface PipeRecentEventsPlan {
  query: string;
  time_range: { start: string; end: string };
  limit: number;
  source_labels: string[];
  raw_field: string;
}
/**
 * Samples stored with a published version. Captured events need the reviewer's
 * explicit consent (`persistCaptured: true`); the server refuses them otherwise.
 */
export type PipeReleaseSamples =
  | { origin: 'supplied'; samples: string[] }
  | { origin: 'capture'; samples: string[]; persistCaptured: true };
/** NAN-3621: one push credential that writes the lane (no secret material). */
export interface PipePushInput {
  credential_id: string;
  label: string;
  kind: 'http' | 'hec' | 'otlp' | string;
  protocol: string;
  /** `source` (one lane) or `collector` (an allowlist of lanes). */
  credential_kind: string;
  writes: string[];
  /** A collector that writes this lane only as unattributed events. */
  implicit: boolean;
  last_seen_at: string | null;
}
/** NAN-3621: a cloud pull source stamped with the lane's label. */
export interface PipePullInput {
  id: string;
  name: string;
  provider: string;
  source_slug: string;
  state: string;
  last_error: string | null;
  /** NAN-3661: last broker verification (the pull's last success). Absent on older backends. */
  verified_at?: string | null;
  updated_at: string;
  /**
   * NAN-3662 / NAN-3604: pre-activation messages skipped on purpose (point-forward
   * start; acked, never ingested, not loss). Absent until the backend reports it.
   */
  skipped_backlog?: number | null;
}
/** NAN-3621: a connector feed bound to the lane's label. */
export interface PipeConnectorInput {
  id: string;
  name: string;
  /** Marketplace collector slug. */
  connector: string;
  source_slug: string;
  enabled: boolean;
  status: string;
  last_run_at: string | null;
  last_success_at: string | null;
  last_error: string | null;
  next_run_at: string;
  marketplace: boolean;
  /** The feed's platform-held push credential; its events route as `push:<id>` (NAN-3625). Null until issued. */
  ingest_credential_id: string | null;
}
/** `GET /api/log-sources/{id}/pipe-inputs`. */
export interface PipeLaneInputs {
  log_source_id: string;
  source_slugs: string[];
  push: PipePushInput[];
  pull: PipePullInput[];
  connectors: PipeConnectorInput[];
  /** A pull input next to a push or connector input: the lane runs in more than one Vector process. */
  mixed_processes: boolean;
}
export interface PipeLaneInputCounts {
  log_source_id: string;
  source_slugs: string[];
  push: number;
  pull: number;
  connectors: number;
  mixed_processes: boolean;
  /** NAN-3661: failed, blocked or paused deliveries into this lane. Absent on older backends. */
  attention?: PipeInputAttention[];
}
/** NAN-3661: a pull source or connector feed that needs attention. */
export interface PipeInputAttention {
  kind: 'pull' | 'connector' | string;
  id: string;
  name: string;
  source_slug: string;
  level: 'failed' | 'blocked' | 'paused' | string;
  /** A stored error code or generic reason; never free text. */
  reason: string;
}
/** `GET /api/log-sources/pipe-inputs`: counts for every visible pipeline. */
export interface PipeLaneInputSummary {
  sources: PipeLaneInputCounts[];
}
export class PipelinesApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}
  capabilities(sourceId: string, signal?: AbortSignal): Promise<PipeRuntimeCapabilities> {
    return this.request(`/api/log-sources/${encodeURIComponent(sourceId)}/pipe-capabilities`, { signal });
  }
  /** NAN-3621: push credentials, pull sources and connector feeds of one lane. */
  inputs(sourceId: string, signal?: AbortSignal): Promise<PipeLaneInputs> {
    return this.request(`/api/log-sources/${encodeURIComponent(sourceId)}/pipe-inputs`, { signal });
  }
  /** NAN-3621: input counts for every visible pipeline. */
  inputSummary(signal?: AbortSignal): Promise<PipeLaneInputSummary> {
    return this.request('/api/log-sources/pipe-inputs', { signal });
  }
  preview(sourceId: string, body: PipePreviewRequest, signal?: AbortSignal): Promise<PipePreviewResponse> {
    return this.request(`/api/log-sources/${encodeURIComponent(sourceId)}/pipe-preview`, { method: 'POST', body: JSON.stringify(body), signal });
  }
  recentEvents(sourceId: string, limit: number, signal?: AbortSignal): Promise<PipeRecentEventsPlan> {
    return this.request(`/api/log-sources/${encodeURIComponent(sourceId)}/pipe-recent-events`, { method: 'POST', body: JSON.stringify({ limit }), signal, cache: 'no-store' });
  }
  startCapture(sourceId: string, body: PipeCaptureRequest, signal?: AbortSignal): Promise<PipeCaptureSession> {
    return this.request(`/api/log-sources/${encodeURIComponent(sourceId)}/capture-sessions`, { method: 'POST', body: JSON.stringify(body), signal });
  }
  capture(sourceId: string, id: string, signal?: AbortSignal): Promise<PipeCaptureSession> {
    return this.request(`/api/log-sources/${encodeURIComponent(sourceId)}/capture-sessions/${encodeURIComponent(id)}`, { signal, cache: 'no-store' });
  }
  captureSnapshot(sourceId: string, id: string, signal?: AbortSignal): Promise<PipeCaptureSnapshot> {
    return this.request(`/api/log-sources/${encodeURIComponent(sourceId)}/capture-sessions/${encodeURIComponent(id)}/snapshot`, { signal, cache: 'no-store' });
  }
  /** Without `release`, the server carries the source's saved samples over to the new version. */
  publish(sourceId: string, expectedUpdatedAt: string, release?: PipeReleaseSamples) {
    const samples = release && (release.origin === 'capture'
      ? { samples: release.samples, samples_origin: 'capture', persist_captured_samples: release.persistCaptured }
      : { samples: release.samples, samples_origin: 'supplied' });
    return this.request<import('./types').SharedDeploymentResponse>(`/api/log-sources/${encodeURIComponent(sourceId)}/publish`, {
      method: 'POST', body: JSON.stringify({ expected_updated_at: expectedUpdatedAt, ...(samples ?? {}) }),
    });
  }
  publishReviewed(snapshot: PipePublicationSnapshot, release?: PipeReleaseSamples) {
    return this.publish(snapshot.sourceId, snapshot.expectedUpdatedAt, release);
  }
  stopCapture(sourceId: string, id: string): Promise<PipeCaptureSession> {
    return this.request(`/api/log-sources/${encodeURIComponent(sourceId)}/capture-sessions/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }
}

const errorStatus = (error: unknown) => error instanceof Error && 'status' in error && typeof error.status === 'number' ? error.status : undefined;
/** Event access can be revoked independently of broad configuration permissions. */
export function pipeEventAccessDenied(error: unknown): boolean {
  const status = errorStatus(error);
  return status === 401 || status === 403;
}
/**
 * NAN-3625: routable inputs from the NAN-3621 lane inputs response
 * (`push[].credential_id`, `pull[].id`, `connectors[].id`). Push credentials
 * route as `push:<credential id>` and pull sources as `pull:<id>`. A connector
 * feed pushes with its own platform-held credential, so it routes as that
 * credential's push input: it is pickable only when the response carries the
 * feed's `ingest_credential_id`. Unknown shapes yield [].
 */
export function laneInputsFrom(body: unknown): PipelineLaneInput[] {
  const object = body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : {};
  const rows = (key: string): Array<Record<string, unknown>> => {
    const value = object[key];
    return Array.isArray(value) ? value.filter((row): row is Record<string, unknown> => !!row && typeof row === 'object' && !Array.isArray(row)) : [];
  };
  const str = (row: Record<string, unknown>, key: string) => typeof row[key] === 'string' && row[key] !== '' ? row[key] as string : undefined;
  const out: PipelineLaneInput[] = [];
  const add = (kind: PipelineLaneInput['kind'], prefix: 'push' | 'pull', id: string | undefined, label: string | undefined) => {
    if (!id) return;
    try {
      const canonical = canonicalInput(`${prefix}:${id}`);
      if (!out.some((input) => input.id === canonical)) out.push({ id: canonical, kind, label: label || canonical });
    } catch { /* not routable */ }
  };
  // Feeds first: a feed's credential must be labeled as the feed.
  for (const row of rows('connectors')) add('feed', 'push', str(row, 'ingest_credential_id'), str(row, 'name') ?? str(row, 'connector'));
  for (const row of rows('pull')) add('pull', 'pull', str(row, 'id'), str(row, 'name'));
  for (const row of rows('push')) add('push', 'push', str(row, 'credential_id'), str(row, 'label'));
  return out;
}
/** Optimistic-concurrency failure: someone else changed the source after this editor loaded it. */
export function pipeConflict(error: unknown): boolean {
  return error instanceof PipeSnapshotConflictError || errorStatus(error) === 409;
}
/** A backend older than the SPA does not serve the pipe endpoints yet (or a capture snapshot was purged). */
export function pipeEndpointMissing(error: unknown): boolean {
  return errorStatus(error) === 404;
}
/** The deployment has preview turned off (503 with the documented message), as opposed to a worker failure. */
export function pipePreviewDisabled(error: unknown): boolean {
  return errorStatus(error) === 503 && error instanceof Error && /not enabled/i.test(error.message);
}
/** The preview or capture slot is busy (429); the request can be retried shortly. */
export function pipeBusy(error: unknown): boolean {
  return errorStatus(error) === 429;
}
export function pipeErrorStatus(error: unknown): number | undefined {
  return errorStatus(error);
}

export function pipeCaptureBounds(capture?: Pick<PipeRuntimeCapabilities['capture'], 'max_bytes' | 'max_events' | 'max_duration_seconds'>) {
  const bound = (advertised: number | undefined, hard: number) => advertised && Number.isFinite(advertised) && advertised > 0 ? Math.min(Math.floor(advertised), hard) : hard;
  return { max_bytes: bound(capture?.max_bytes, 65536), max_events: bound(capture?.max_events, 1000), max_duration_seconds: bound(capture?.max_duration_seconds, 60) };
}
export function boundedPipeCaptureRequest(durationSeconds: number, maxEvents: number, capture?: Pick<PipeRuntimeCapabilities['capture'], 'max_bytes' | 'max_events' | 'max_duration_seconds'>): PipeCaptureRequest {
  const bounds = pipeCaptureBounds(capture);
  if (!Number.isInteger(durationSeconds) || durationSeconds < 1 || durationSeconds > bounds.max_duration_seconds) throw new Error(`Capture duration must be 1–${bounds.max_duration_seconds} seconds.`);
  if (!Number.isInteger(maxEvents) || maxEvents < 1 || maxEvents > bounds.max_events) throw new Error(`Capture limit must be 1–${bounds.max_events} events.`);
  return { stage: 'input', duration_seconds: durationSeconds, max_events: maxEvents, max_bytes: bounds.max_bytes };
}

/** Total inputs on a lane (push credentials, pull sources, connector feeds). */
export function pipeInputTotal(counts: Pick<PipeLaneInputCounts, 'push' | 'pull' | 'connectors'>): number {
  return counts.push + counts.pull + counts.connectors;
}
/** The pipeline(s) whose lane label is `slug` (a pull source or feed → its pipeline). */
export function pipelinesForSlug(summary: PipeLaneInputSummary | undefined, slug: string): string[] {
  const wanted = slug.trim().toLowerCase();
  return (summary?.sources ?? []).filter((source) => source.source_slugs.includes(wanted)).map((source) => source.log_source_id);
}
/** Inputs listed for one lane. */
export function pipeInputCount(inputs: PipeLaneInputs | null | undefined): number {
  return inputs ? inputs.push.length + inputs.pull.length + inputs.connectors.length : 0;
}
/** The marketplace page that manages a connector feed. */
export function collectorPath(connector: string): string {
  return `/marketplace?slug=${encodeURIComponent(connector)}`;
}
