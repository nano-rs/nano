// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it, vi } from 'vitest';
import {
  assertPublicationSnapshot, boundedTapRequest, newerThanSnapshot, pipeBusy, pipeConflict, pipeRetryAfter, publicationSnapshot,
  PipelinesApi, PipeSnapshotConflictError,
} from './pipelines';
import { ApiClientError } from './index';

const row = { id: 'lsrc_1', updated_at: '2026-10-09T10:00:00Z', parser_vrl: '.a = 1', extension_vrl: null, extension_enabled: true };

describe('PipelinesApi', () => {
  it('sends the documented requests and gives the blocking tap a window-sized timeout', async () => {
    const request = vi.fn().mockResolvedValue({});
    const longRequest = vi.fn().mockResolvedValue({ events: [] });
    const client = new PipelinesApi(request, longRequest);
    await client.capabilities('lsrc_1');
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/lsrc_1/pipe-capabilities');
    await client.preview('lsrc_1', { parser_vrl: '.', events: [{ message: 'x' }] });
    expect(request.mock.lastCall?.[0]).toBe('/api/log-sources/lsrc_1/pipe-preview');
    expect(JSON.parse(request.mock.lastCall?.[1].body)).toEqual({ parser_vrl: '.', events: [{ message: 'x' }] });
    await client.samples('lsrc_1', 20);
    expect(JSON.parse(request.mock.lastCall?.[1].body)).toEqual({ limit: 20 });
    const controller = new AbortController();
    await client.tap('lsrc_1', { seconds: 45, max_events: 200 }, controller.signal);
    const [endpoint, options, timeout] = longRequest.mock.lastCall!;
    expect(endpoint).toBe('/api/log-sources/lsrc_1/pipe-tap');
    expect(JSON.parse(options.body)).toEqual({ seconds: 45, max_events: 200 });
    expect(options.signal).toBe(controller.signal);
    expect(timeout).toBeGreaterThan(45_000);
  });
  it('refuses tap bounds outside 1–60 s and 1–1000 events', () => {
    expect(() => boundedTapRequest(0, 10)).toThrow();
    expect(() => boundedTapRequest(61, 10)).toThrow();
    expect(() => boundedTapRequest(30, 1001)).toThrow();
    expect(boundedTapRequest(60, 1000)).toEqual({ seconds: 60, max_events: 1000 });
  });
});

describe('error classification', () => {
  it('reads Retry-After only from a 429', () => {
    const busy = new ApiClientError('busy', 'TOO_MANY_REQUESTS', undefined, 429, 7);
    expect(pipeBusy(busy)).toBe(true);
    expect(pipeRetryAfter(busy)).toBe(7);
    expect(pipeRetryAfter(new ApiClientError('x', 'X', undefined, 503, 7))).toBeUndefined();
    expect(pipeConflict(new ApiClientError('stale', 'CONFLICT', undefined, 409))).toBe(true);
    expect(pipeConflict(new PipeSnapshotConflictError())).toBe(true);
  });
});

describe('publication snapshot', () => {
  it('is frozen and refuses any moved field', () => {
    const snapshot = publicationSnapshot(row);
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(() => assertPublicationSnapshot(snapshot, row)).not.toThrow();
    expect(() => assertPublicationSnapshot(snapshot, { ...row, updated_at: '2026-10-09T10:00:01Z' })).toThrow(PipeSnapshotConflictError);
    expect(() => assertPublicationSnapshot(snapshot, { ...row, parser_vrl: '.a = 2' })).toThrow(PipeSnapshotConflictError);
    expect(() => assertPublicationSnapshot(snapshot, { ...row, extension_enabled: false })).toThrow(PipeSnapshotConflictError);
  });
  it('never treats an older cached read as newer', () => {
    const snapshot = publicationSnapshot(row);
    expect(newerThanSnapshot(snapshot, { ...row, updated_at: '2026-10-09T09:00:00Z', parser_vrl: 'old' })).toBe(false);
    expect(newerThanSnapshot(snapshot, { ...row, updated_at: '2026-10-09T11:00:00Z', parser_vrl: 'new' })).toBe(true);
  });
});
