// SPDX-License-Identifier: AGPL-3.0-or-later

import { expect, test } from 'vitest';
import { PipelinesApi, assertPublicationSnapshot, publicationSnapshot, newerThanSnapshot, pipeConflict, pipeEndpointMissing, pipePreviewDisabled, pipeBusy } from './pipelines';

const original = { id: 'lsrc_test', updated_at: '2026-10-09T10:00:00Z', parser_vrl: '.message = "reviewed"', extension_vrl: '.reviewed = true', extension_enabled: true };

test('a refetched extension cannot advance the reviewed publication identity', () => {
  const snapshot = publicationSnapshot(original);
  const refreshed = { ...original, updated_at: '2026-10-09T10:01:00Z', extension_vrl: '.unreviewed = true' };
  expect(() => assertPublicationSnapshot(snapshot, refreshed)).toThrow(/reviewed pipeline changed/);
  expect(Reflect.set(snapshot, 'expectedUpdatedAt', refreshed.updated_at)).toBe(false);
  expect(snapshot.expectedUpdatedAt).toBe(original.updated_at);
  expect(snapshot.extensionVrl).toBe(original.extension_vrl);
});

test('parser, extension activation, and source binding are part of the reviewed state', () => {
  const snapshot = publicationSnapshot(original);
  expect(() => assertPublicationSnapshot(snapshot, { ...original })).not.toThrow();
  for (const change of [{ parser_vrl: '.unreviewed = true' }, { extension_enabled: false }, { id: 'lsrc_other' }]) {
    expect(() => assertPublicationSnapshot(snapshot, { ...original, ...change })).toThrow(/reviewed pipeline changed/);
  }
});

test('publication always sends the reviewed CAS even when query state has refreshed', async () => {
  const snapshot = publicationSnapshot(original);
  let currentServer = { ...original };
  let expectedSent: string | undefined;
  const client = new PipelinesApi(async <T,>(endpoint: string, options?: RequestInit): Promise<T> => {
    expect(endpoint).toBe('/api/log-sources/lsrc_test/publish');
    const body = JSON.parse(String(options?.body));
    expectedSent = body.expected_updated_at;
    // Model an update between the preflight GET and the locked publish handler.
    if (body.expected_updated_at !== currentServer.updated_at) throw new Error('stale_draft');
    return {} as T;
  });
  assertPublicationSnapshot(snapshot, currentServer);
  currentServer = { ...original, updated_at: '2026-10-09T10:02:00Z', extension_vrl: '.changed_after_read = true' };
  await expect(client.publishReviewed(snapshot, { origin: 'supplied', samples: ['reviewed sample'] })).rejects.toThrow(/stale_draft/);
  expect(expectedSent).toBe(original.updated_at);
});

test('reviewed samples and timestamp are sent unchanged on successful publication', async () => {
  const snapshot = publicationSnapshot(original);
  let body: Record<string, unknown> | undefined;
  const client = new PipelinesApi(async <T,>(_endpoint: string, options?: RequestInit): Promise<T> => {
    body = JSON.parse(String(options?.body));
    return {} as T;
  });
  await client.publishReviewed(snapshot, { origin: 'supplied', samples: ['{"action":"deny"}'] });
  expect(body).toEqual({ expected_updated_at: original.updated_at, samples: ['{"action":"deny"}'], samples_origin: 'supplied' });
});

test('captured samples carry their origin and the explicit consent flag; no release sends no samples', async () => {
  const snapshot = publicationSnapshot(original);
  const bodies: Record<string, unknown>[] = [];
  const client = new PipelinesApi(async <T,>(_endpoint: string, options?: RequestInit): Promise<T> => {
    bodies.push(JSON.parse(String(options?.body)));
    return {} as T;
  });
  await client.publishReviewed(snapshot, { origin: 'capture', samples: ['captured'], persistCaptured: true });
  await client.publishReviewed(snapshot);
  expect(bodies).toEqual([
    { expected_updated_at: original.updated_at, samples: ['captured'], samples_origin: 'capture', persist_captured_samples: true },
    { expected_updated_at: original.updated_at },
  ]);
});

test('event access denial recognizes scoped 401/403 even when broad permission remains', async () => {
  const { pipeEventAccessDenied } = await import('./pipelines');
  expect(pipeEventAccessDenied(Object.assign(new Error('Source scope revoked'), { status: 403 }))).toBe(true);
  expect(pipeEventAccessDenied(Object.assign(new Error('Session expired'), { status: 401 }))).toBe(true);
  expect(pipeEventAccessDenied(Object.assign(new Error('Runtime unavailable'), { status: 503 }))).toBe(false);
  expect(pipeEventAccessDenied(new Error('Network interruption'))).toBe(false);
});

test('capture UI and requests respect actual pilot bounds even if capabilities advertise more', async () => {
  const { pipeCaptureBounds, boundedPipeCaptureRequest } = await import('./pipelines');
  const tooBroad = { max_bytes: 10 * 1024 * 1024, max_events: 10000, max_duration_seconds: 600 };
  expect(pipeCaptureBounds(tooBroad)).toEqual({ max_bytes: 65536, max_events: 1000, max_duration_seconds: 60 });
  expect(boundedPipeCaptureRequest(30, 100, tooBroad)).toEqual({ stage: 'input', duration_seconds: 30, max_events: 100, max_bytes: 65536 });
  expect(() => boundedPipeCaptureRequest(61, 100, tooBroad)).toThrow(/1–60 seconds/);
  expect(() => boundedPipeCaptureRequest(30, 1001, tooBroad)).toThrow(/1–1000 events/);
  expect(() => boundedPipeCaptureRequest(Number.NaN, 100, tooBroad)).toThrow(/seconds/);
  expect(pipeCaptureBounds({ max_bytes: 32768, max_events: 50, max_duration_seconds: 10 }).max_bytes).toBe(32768);
});

test('conflicts, missing endpoints, and disabled preview are classified for recovery UI', () => {
  const snapshot = publicationSnapshot(original);
  let thrown: unknown;
  try { assertPublicationSnapshot(snapshot, { ...original, parser_vrl: '.other = true' }); } catch (error) { thrown = error; }
  expect(pipeConflict(thrown)).toBe(true);
  expect(pipeConflict(Object.assign(new Error('stale_draft'), { status: 409 }))).toBe(true);
  expect(pipeConflict(Object.assign(new Error('nope'), { status: 400 }))).toBe(false);
  expect(pipeEndpointMissing(Object.assign(new Error('Not Found'), { status: 404 }))).toBe(true);
  expect(pipePreviewDisabled(Object.assign(new Error('Pipeline preview is not enabled on this deployment'), { status: 503 }))).toBe(true);
  expect(pipePreviewDisabled(Object.assign(new Error('Preview worker failed or exceeded its CPU or memory bound'), { status: 503 }))).toBe(false);
  expect(pipeBusy(Object.assign(new Error('Preview capacity is busy; retry shortly'), { status: 429 }))).toBe(true);
});

test('only a later server write counts as newer than the saved baseline', () => {
  const snapshot = publicationSnapshot(original);
  expect(newerThanSnapshot(snapshot, original)).toBe(false);
  expect(newerThanSnapshot(snapshot, { ...original, updated_at: '2026-10-09T09:59:00Z', parser_vrl: '.cached = true' })).toBe(false);
  expect(newerThanSnapshot(snapshot, { ...original, updated_at: '2026-10-09T10:01:00Z' })).toBe(true);
});

test('capture snapshots are read from their own no-store endpoint', async () => {
  const calls: Array<[string, RequestInit | undefined]> = [];
  const client = new PipelinesApi(async <T,>(endpoint: string, options?: RequestInit): Promise<T> => { calls.push([endpoint, options]); return {} as T; });
  await client.captureSnapshot('lsrc_test', 'session/1');
  expect(calls[0][0]).toBe('/api/log-sources/lsrc_test/capture-sessions/session%2F1/snapshot');
  expect(calls[0][1]?.cache).toBe('no-store');
});
