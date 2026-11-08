// SPDX-License-Identifier: AGPL-3.0-or-later

// Nano Pipe API (NAN-4919). Save, publish, versions, revert and discard use
// the existing log-source endpoints (`LogSourcesApi`); this client adds the
// authoring endpoints (`nanosiem-api/src/handlers/pipelines.rs`,
// `pipeline_tap.rs`). Events loaded through it live in browser memory only.

import type { LogSource } from './types';

type Request = <T>(endpoint: string, options?: RequestInit) => Promise<T>;
/** Like `Request`, with a client timeout long enough for a blocking capture. */
type LongRequest = <T>(endpoint: string, options: RequestInit, timeoutMs: number) => Promise<T>;

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
  return Object.freeze({
    sourceId: source.id, expectedUpdatedAt: source.updated_at, parserVrl: source.parser_vrl,
    extensionVrl: source.extension_vrl ?? null, extensionEnabled: source.extension_enabled !== false,
  });
}
/** The server copy no longer matches the snapshot the editor saved or reviewed against. */
export class PipeSnapshotConflictError extends Error {
  readonly status = 409;
  constructor(message = 'The reviewed pipeline changed on the server. Close this review and review the latest saved draft before publishing.') {
    super(message);
    this.name = 'PipeSnapshotConflictError';
  }
}
export function samePublicationSnapshot(a: PipePublicationSnapshot, b: PipePublicationSnapshot): boolean {
  return a.sourceId === b.sourceId && a.expectedUpdatedAt === b.expectedUpdatedAt && a.parserVrl === b.parserVrl
    && a.extensionVrl === b.extensionVrl && a.extensionEnabled === b.extensionEnabled;
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

export interface PipeBounds {
  max_steps: number;
  max_preview_events: number;
  max_preview_event_bytes: number;
  max_lookup_rows: number;
  max_lookup_bytes: number;
  max_dedupe_cache: number;
  max_combine_events: number;
  max_combine_groups: number;
  max_combine_expire_seconds: number;
  max_route_branches: number;
  max_split_outputs: number;
}
/** `GET /api/log-sources/{id}/pipe-capabilities`. */
export interface PipeCapabilities {
  preview_enabled: boolean;
  preview_degraded_isolation: boolean;
  live_tap_enabled: boolean;
  step_kinds: string[];
  /** Kinds this deployment's Vector cannot run: they preview, but publish refuses them. */
  preview_only_kinds: Array<{ kind: string; reason: string }>;
  bounds: PipeBounds;
}
/** `POST /api/log-sources/{id}/pipe-preview`. Omitted parser/extension = the saved working copy. */
export interface PipePreviewRequest {
  parser_vrl?: string;
  extension_vrl?: string;
  events: unknown[];
  /** Per-event input identity (`push:<credential id>`), parallel to `events`. */
  inputs?: Array<string | null>;
}
export interface PipePreviewTrace {
  step_id: string;
  outputs: unknown[];
  error: string | null;
  bypassed: boolean;
}
export interface PipePreviewResponse {
  /** `vrl`, `pipeline` or `pipeline+native`. */
  engine: string;
  degraded_isolation: boolean;
  results: Array<{
    index: number;
    disposition: string;
    outputs: unknown[];
    error: string | null;
    traces: PipePreviewTrace[];
  }>;
  summary: {
    input_events: number;
    output_events: number;
    dropped_events: number;
    error_events: number;
    input_bytes: number;
    output_bytes: number;
  };
  warnings: string[];
}
/** `POST /api/log-sources/{id}/pipe-samples`: `{message}` per event, newest first. */
export interface PipeSamplesResponse {
  events: Array<Record<string, unknown>>;
}
export interface PipeTapRequest {
  seconds?: number;
  max_events?: number;
}
/** `POST /api/log-sources/{id}/pipe-tap` (blocks for the capture window). */
export interface PipeTapResponse {
  component: string;
  seconds: number;
  events: Array<{ event: unknown; input: string | null }>;
  dropped_oversize: number;
  /** `deadline`, `max_events`, `max_bytes` or `stream_closed`. */
  ended: string;
}

/** Recent-events bounds; the server clamps to 1–100. */
export const DEFAULT_RECENT_EVENTS = 20;
export const MAX_RECENT_EVENTS = 100;
/** Live tap bounds (server: 1–60 s, 1–1000 events). */
export const TAP_DEFAULT_SECONDS = 30;
export const TAP_MAX_SECONDS = 60;
export const TAP_DEFAULT_EVENTS = 100;
export const TAP_MAX_EVENTS = 1000;
/** The tap response arrives after the window; leave room for the relay round trip. */
const TAP_GRACE_MS = 20_000;

const path = (sourceId: string, suffix: string) => `/api/log-sources/${encodeURIComponent(sourceId)}/${suffix}`;

export class PipelinesApi {
  constructor(private request: Request, private longRequest: LongRequest) {}

  capabilities(sourceId: string): Promise<PipeCapabilities> {
    return this.request(path(sourceId, 'pipe-capabilities'));
  }
  preview(sourceId: string, body: PipePreviewRequest, signal?: AbortSignal): Promise<PipePreviewResponse> {
    return this.request(path(sourceId, 'pipe-preview'), { method: 'POST', body: JSON.stringify(body), signal });
  }
  samples(sourceId: string, limit: number, signal?: AbortSignal): Promise<PipeSamplesResponse> {
    return this.request(path(sourceId, 'pipe-samples'), { method: 'POST', body: JSON.stringify({ limit }), signal, cache: 'no-store' });
  }
  /** Blocks for the capture window; abort with `signal` to cancel. */
  tap(sourceId: string, body: Required<PipeTapRequest>, signal?: AbortSignal): Promise<PipeTapResponse> {
    const request = boundedTapRequest(body.seconds, body.max_events);
    return this.longRequest(path(sourceId, 'pipe-tap'), { method: 'POST', body: JSON.stringify(request), signal, cache: 'no-store' }, request.seconds * 1000 + TAP_GRACE_MS);
  }
}

export function boundedTapRequest(seconds: number, maxEvents: number): Required<PipeTapRequest> {
  if (!Number.isInteger(seconds) || seconds < 1 || seconds > TAP_MAX_SECONDS) throw new Error(`Capture window must be 1–${TAP_MAX_SECONDS} seconds.`);
  if (!Number.isInteger(maxEvents) || maxEvents < 1 || maxEvents > TAP_MAX_EVENTS) throw new Error(`Capture limit must be 1–${TAP_MAX_EVENTS} events.`);
  return { seconds, max_events: maxEvents };
}

const errorStatus = (error: unknown) => error instanceof Error && 'status' in error && typeof error.status === 'number' ? error.status : undefined;
export function pipeErrorStatus(error: unknown): number | undefined {
  return errorStatus(error);
}
/** Event access can be revoked independently of broad configuration permissions. */
export function pipeEventAccessDenied(error: unknown): boolean {
  const status = errorStatus(error);
  return status === 401 || status === 403;
}
/** Optimistic-concurrency failure: someone else changed the source after this editor loaded it. */
export function pipeConflict(error: unknown): boolean {
  return error instanceof PipeSnapshotConflictError || errorStatus(error) === 409;
}
/** A backend older than the SPA does not serve the pipe endpoints yet. */
export function pipeEndpointMissing(error: unknown): boolean {
  return errorStatus(error) === 404;
}
/** 503: preview/tap is turned off on this deployment (or its worker/relay is down). */
export function pipeUnavailable(error: unknown): boolean {
  return errorStatus(error) === 503;
}
/** The preview or tap slot is busy (429); never auto-queued. */
export function pipeBusy(error: unknown): boolean {
  return errorStatus(error) === 429;
}
/** Seconds from a 429's `Retry-After`, when the server sent one. */
export function pipeRetryAfter(error: unknown): number | undefined {
  if (!pipeBusy(error) || !error || typeof error !== 'object' || !('retryAfter' in error)) return undefined;
  const value = (error as { retryAfter?: unknown }).retryAfter;
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : undefined;
}
export function pipeAborted(error: unknown): boolean {
  return !!error && typeof error === 'object' && 'code' in error && (error as { code?: unknown }).code === 'ABORTED';
}
