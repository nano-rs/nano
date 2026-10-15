// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

import type { ReactNode } from 'react';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { captureView, usePipelineWorkspace } from './use-pipeline-workspace';
import type { PipeCaptureSession } from '@/lib/api/pipelines';

const mocked = vi.hoisted(() => ({ allowedPermissions: null as string[] | null, api: {
  getLogSourceDraftStatus: vi.fn(), listLogSourceRollouts: vi.fn(), listParserRollouts: vi.fn(), getLogSourceVersions: vi.fn(), getLogSourceSamples: vi.fn(), updateLogSource: vi.fn(),
  discardLogSourceDraft: vi.fn(), revertLogSourceVersion: vi.fn(), validateLogSourceVrl: vi.fn(), getLogSource: vi.fn(), search: vi.fn(), putLogSourceSamples: vi.fn(),
  pipelines: { capabilities: vi.fn(), preview: vi.fn(), startCapture: vi.fn(), capture: vi.fn(), captureSnapshot: vi.fn(), stopCapture: vi.fn(), publishReviewed: vi.fn(), recentEvents: vi.fn(), inputs: vi.fn() },
}, source: { id: 'lsrc_firewall', name: 'Firewall', description: '', source_type: 'firewall', parser_vrl: '.message = "saved"', updated_at: '2026-10-09T10:00:00Z', extension_enabled: true, extension_vrl: '.extension = true', deployed: true, deployed_at: '2026-10-09T09:00:00Z', has_draft_changes: false } }));
vi.mock('@/lib/api', () => ({ api: mocked.api }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: (permission: string) => mocked.allowedPermissions === null || mocked.allowedPermissions.includes(permission), tenantRuntime: { key: 'tenant-a:user-a:epoch-1' } }) }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));

const session = { id: 'session-1', state: 'running', stage: 'input', log_source_id: 'lsrc_firewall', active_bundle_sha256: 'abc', created_at: '2026-10-09T10:00:00Z', retain_until: '2099-01-01T00:10:00Z', observed_events: 1, observed_bytes: 40, snapshot_available: true, truncated: false, error: null, stop_reason: null };
const snapshot = { session_id: 'session-1', state: 'running', truncated: false, retain_until: '2099-01-01T00:10:00Z', events: [{ sequence: 1, observed_at: '2026-10-09T10:00:00Z', event: { message: 'private captured payload' } }] };
const conflictError = () => Object.assign(new Error('stale_draft'), { status: 409 });
const denied = () => Object.assign(new Error('Source scope revoked'), { status: 403 });
const previewResult = { draft_revision: '1', draft_hash: 'hash', engine: 'native_vrl', warnings: [], results: [{ index: 0, input: { message: 'private captured payload' }, output: { message: 'private transformed payload' }, disposition: 'retained', steps: [] }] };

function harness(client = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  return { client, wrapper };
}
beforeEach(() => {
  vi.resetAllMocks();
  mocked.allowedPermissions = null;
  mocked.api.getLogSourceDraftStatus.mockResolvedValue(mocked.source);
  mocked.api.listLogSourceRollouts.mockResolvedValue([]);
  mocked.api.listParserRollouts.mockResolvedValue([]);
  mocked.api.getLogSourceVersions.mockResolvedValue([]);
  mocked.api.getLogSourceSamples.mockResolvedValue({ samples: ['private saved payload'], max_samples: 32 });
  mocked.api.pipelines.capabilities.mockResolvedValue({ engine: 'native_vrl', supported_step_kinds: ['vrl'], warnings: [], capture: { enabled: true, max_bytes: 65536, max_events: 1000, max_duration_seconds: 60 } });
  mocked.api.pipelines.startCapture.mockResolvedValue({ ...session, state: 'queued', observed_events: 0, snapshot_available: false });
  mocked.api.pipelines.capture.mockResolvedValue(session);
  mocked.api.pipelines.captureSnapshot.mockResolvedValue(snapshot);
  mocked.api.pipelines.stopCapture.mockResolvedValue({ ...session, state: 'cancelled' });
  mocked.api.pipelines.preview.mockResolvedValue(previewResult);
  mocked.api.validateLogSourceVrl.mockResolvedValue({ valid: true, errors: [] });
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe('pipeline workspace access and route recovery', () => {
  it('serves the Inputs panel and the route-by-input picker from one lane inputs request (NAN-3621)', async () => {
    const lane = { log_source_id: 'lsrc_firewall', source_slugs: ['firewall'], mixed_processes: true,
      push: [{ credential_id: 'c0ffee00-0000-4000-8000-000000000001', label: 'HEC', kind: 'hec', protocol: 'hec', credential_kind: 'source', writes: ['firewall'], implicit: false, last_seen_at: null }],
      pull: [{ id: '11111111-2222-4333-8444-555555555555', name: 'Queue', provider: 'aws_sqs', source_slug: 'firewall', state: 'active', last_error: null, updated_at: '2026-10-11T00:00:00Z' }],
      connectors: [] };
    mocked.api.pipelines.inputs.mockResolvedValue(lane);
    const { wrapper } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.inputs.inputs).toEqual(lane));
    expect(result.current.laneInputs.map((input) => input.id)).toEqual(['pull:11111111-2222-4333-8444-555555555555', 'push:c0ffee00-0000-4000-8000-000000000001']);
    expect(mocked.api.pipelines.inputs).toHaveBeenCalledTimes(1);
  });
  it('keeps polling running captures with a truncated observation prefix and preserves failures', () => {
    const observed = { ...session, tenant_id: 'tenant-a', stage: 'input', source_slug: 'firewall', max_events: 1000, max_bytes: 65536, duration_seconds: 30, expires_at: '2026-10-09T10:00:30Z', truncated: true } as PipeCaptureSession;
    expect(captureView(observed).state).toBe('capturing');
    expect(captureView({ ...observed, state: 'complete' }).state).toBe('limit');
    expect(captureView({ ...observed, state: 'failed' }).state).toBe('failed');
    expect(captureView({ ...observed, state: 'cancelled' }).state).toBe('stopped');
    // Events now come from the edge snapshot; the observed count decides "no traffic".
    expect(captureView({ ...observed, state: 'complete', truncated: false, observed_events: 0 }).state).toBe('no_traffic');
    expect(captureView({ ...observed, state: 'complete', truncated: false, observed_events: 3 }).state).toBe('completed');
    expect(captureView({ ...observed, state: 'complete', stop_reason: 'release_changed' }).state).toBe('release_changed');
    expect(captureView(observed, snapshot.events).events).toEqual([{ id: 'session-1-1', input: { message: 'private captured payload' }, capturedAt: '2026-10-09T10:00:00Z' }]);
  });

  it('previews the first 100 events and preserves the full frozen input without inventing drops', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    const events = Array.from({ length: 101 }, (_, index) => ({ id: `input-${index}`, input: { message: `raw-${index}` } }));
    mocked.api.pipelines.preview.mockImplementation(async (_sourceId, request) => ({ ...previewResult, results: request.events.map((input: unknown, index: number) => ({ index, input, output: input, disposition: 'retained', steps: [] })) }));
    act(() => result.current.selectSample({ id: 'large-capture', name: 'Large capture', events }));
    await act(async () => { await result.current.runPreview(); });
    const body = mocked.api.pipelines.preview.mock.calls[0][1];
    expect(body.events).toEqual(events.slice(0, 100).map(event => event.input));
    expect(result.current.frozen?.events).toEqual(events);
    expect(result.current.preview?.inputCount).toBe(100);
    expect(result.current.preview?.events).toHaveLength(100);
    expect(result.current.preview?.events.at(-1)?.inputId).toBe('input-99');
    expect(result.current.preview?.events.every(event => event.outcome === 'retained')).toBe(true);
    expect(result.current.preview?.warnings?.[0]).toMatch(/first 100 of 101.*not previewed.*not dropped/);
    client.clear();
  });

  it('previews all 33 processing steps as one parser program with a separate existing extension', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    const steps = Array.from({ length: 33 }, (_, index) => ({ id: `step-${index}`, name: `Step ${index}`, kind: 'vrl' as const, enabled: true, config: { code: index === 0 ? 'counter = 1\n.count = counter' : 'counter = counter + 1\n.count = counter' } }));
    act(() => result.current.changeDraft({ ...result.current.draft!, steps }));
    act(() => result.current.selectSample({ id: 'input', name: 'Input', events: [{ id: 'in-1', input: { message: 'input' } }] }));
    await act(async () => { await result.current.runPreview(); });
    const body = mocked.api.pipelines.preview.mock.calls[0][1];
    expect(body.steps[0]).toMatchObject({ id: 'combined-draft-parser', name: 'Complete draft parser', enabled: true });
    expect(JSON.parse(body.steps[0].vrl.split('\n')[0].slice('# nano-pipe-v2 '.length)).steps).toEqual(steps);
    expect(body.extension_vrl).toBe(mocked.source.extension_vrl);
    expect(body.steps[0].vrl).not.toContain('.extension = true');
    expect(result.current.draft?.steps).toHaveLength(33);
    expect(result.current.preview?.warnings?.[0]).toMatch(/all 33 processing steps.*one complete plan.*Per-step traces are unavailable.*no processing steps were omitted/);
    client.clear();
  });

  it('collapses large repeated lookup snapshots without omitting processing steps', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    const steps = [
      { id: 'lookup', name: 'Lookup', kind: 'lookup' as const, enabled: true, config: { table: 'owners', version: '1', match: { key: 'message' }, outputs: { value: 'owner' }, rows: Array.from({ length: 30 }, (_, index) => ({ key: String(index), value: 'x'.repeat(3000) })) } },
      ...Array.from({ length: 19 }, (_, index) => ({ id: `set-${index}`, name: 'Set', kind: 'set' as const, enabled: true, config: { field: `field_${index}`, value: true } })),
    ];
    act(() => result.current.changeDraft({ ...result.current.draft!, steps }));
    act(() => result.current.selectSample({ id: 'input', name: 'Input', events: [{ id: 'in-1', input: { message: '0' } }] }));
    await act(async () => { await result.current.runPreview(); });
    const body = mocked.api.pipelines.preview.mock.calls[0][1];
    expect(body.steps).toHaveLength(1);
    expect(JSON.parse(body.steps[0].vrl.split('\n')[0].slice('# nano-pipe-v2 '.length)).steps).toEqual(steps);
    expect(new TextEncoder().encode(JSON.stringify(body)).length).toBeLessThan(1024 * 1024);
    expect(result.current.preview?.warnings?.[0]).toMatch(/all 20 processing steps.*no processing steps were omitted/);
    client.clear();
  });

  it('selects a fitting prefix when serialized events exceed the 1 MiB request bound', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    const events = Array.from({ length: 20 }, (_, index) => ({ id: `input-${index}`, input: { message: 'é'.repeat(30_000), index } }));
    mocked.api.pipelines.preview.mockImplementation(async (_sourceId, request) => ({ ...previewResult, results: request.events.map((input: unknown, index: number) => ({ index, input, output: input, disposition: 'retained', steps: [] })) }));
    act(() => result.current.selectSample({ id: 'large-bytes', name: 'Large input', events }));
    await act(async () => { await result.current.runPreview(); });
    const body = mocked.api.pipelines.preview.mock.calls[0][1];
    const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value)).byteLength;
    const normalized = { ...body, extension_vrl: body.extension_vrl ?? null };
    expect(body.events.length).toBeGreaterThan(0);
    expect(body.events.length).toBeLessThan(events.length);
    expect(bytes(normalized)).toBeLessThanOrEqual(1024 * 1024);
    expect(bytes({ ...normalized, events: [...body.events, events[body.events.length].input] })).toBeGreaterThan(1024 * 1024);
    expect(body.events).toEqual(events.slice(0, body.events.length).map(event => event.input));
    expect(result.current.frozen?.events).toHaveLength(20);
    expect(result.current.preview?.warnings?.[0]).toContain(`first ${body.events.length} of 20`);
    client.clear();
  });

  it('reports an oversized input event before sending and keeps the frozen capture', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    const events = [{ id: 'oversized', input: { message: 'é'.repeat(32_768) } }];
    act(() => result.current.selectSample({ id: 'too-large', name: 'Oversized input', events }));
    await act(async () => { await result.current.runPreview(); });
    expect(mocked.api.pipelines.preview).not.toHaveBeenCalled();
    expect(result.current.previewError).toMatch(/Sample event 1 exceeds the 64 KiB preview event limit/);
    // A preview failure belongs to the preview panel, never to release/save surfaces.
    expect(result.current.errors).toEqual({});
    expect(result.current.frozen?.events).toEqual(events);
    expect(result.current.preview).toBeNull();
    expect(result.current.previewPending).toBe(false);
    client.clear();
  });
  it('requires event execution authority even when search navigation is visible', async () => {
    mocked.allowedPermissions = ['log_sources:view', 'search:view'];
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    expect(result.current.permissions.capture).toBe(false);
    expect(mocked.api.getLogSourceSamples).not.toHaveBeenCalled();
    await act(async () => { await result.current.startCapture({ sourceId: 'lsrc_firewall', point: 'input', durationSeconds: 30, eventLimit: 100 }); });
    expect(result.current.errors.capture).toBe('Source event access is required for capture.');
    expect(mocked.api.pipelines.startCapture).not.toHaveBeenCalled();
    client.clear();
  });

  it('permits event execution authority without requiring search navigation', async () => {
    mocked.allowedPermissions = ['log_sources:view', 'search:execute'];
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.samples.length).toBe(1));
    expect(result.current.permissions.capture).toBe(true);
    client.clear();
  });

  it('purges capture, frozen inputs, saved samples, and preview on a scoped preview403', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    await act(async () => { await result.current.startCapture({ sourceId: 'lsrc_firewall', point: 'input', durationSeconds: 30, eventLimit: 100 }); });
    await waitFor(() => expect(result.current.capture.events).toHaveLength(1), { timeout: 3000 });
    await act(async () => { await result.current.freeze(); });
    await act(async () => { await result.current.runPreview(); });
    expect(result.current.preview?.events[0].outputs).toEqual([{ message: 'private transformed payload' }]);
    mocked.api.pipelines.preview.mockRejectedValueOnce(denied());
    await act(async () => { await result.current.runPreview(); });
    expect(result.current.capture).toMatchObject({ state: 'forbidden', events: [] });
    expect(result.current.frozen).toBeNull();
    expect(result.current.preview).toBeNull();
    expect(result.current.samples).toEqual([]);
    expect(result.current.permissions.capture).toBe(false);
    expect(client.getQueryData(['pipe-samples', 'tenant-a:user-a:epoch-1', 'lsrc_firewall'])).toBeUndefined();
    expect(mocked.api.pipelines.startCapture.mock.calls[0][1]).toMatchObject({ max_bytes: 65536, duration_seconds: 30, max_events: 100 });
    client.clear();
  });

  it('ignores a successful late preview after a capture poll403 has revoked access', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.samples.length).toBe(1));
    vi.useFakeTimers();
    await act(async () => { await result.current.startCapture({ sourceId: 'lsrc_firewall', point: 'input', durationSeconds: 30, eventLimit: 100 }); });
    act(() => result.current.selectSample(result.current.samples[0]));
    const finishPreviews: Array<(value: typeof previewResult) => void> = [];
    mocked.api.pipelines.preview.mockImplementation(() => new Promise(resolve => { finishPreviews.push(resolve); }));
    let pending: Promise<void> | undefined;
    act(() => { pending = result.current.runPreview(); });
    mocked.api.pipelines.capture.mockRejectedValueOnce(denied());
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(result.current.capture).toMatchObject({ state: 'forbidden', events: [] });
    await act(async () => { finishPreviews.forEach(finish => finish(previewResult)); await pending; });
    expect(result.current.preview).toBeNull();
    expect(result.current.frozen).toBeNull();
    expect(result.current.samples).toEqual([]);
    client.clear();
  });

  it('publishes captured events as release samples only when the reviewer opts in', async () => {
    const { wrapper, client } = harness();
    mocked.api.getLogSource.mockResolvedValue(mocked.source);
    mocked.api.pipelines.publishReviewed.mockResolvedValue({ rollout: null });
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    await act(async () => { await result.current.startCapture({ sourceId: 'lsrc_firewall', point: 'input', durationSeconds: 30, eventLimit: 100 }); });
    await waitFor(() => expect(result.current.capture.events).toHaveLength(1), { timeout: 3000 });
    await act(async () => { await result.current.freeze(); });
    await act(async () => { await result.current.review(); });
    expect(result.current.plan?.capturedSampleCount).toBe(1);
    // Default: nothing captured is sent; the server keeps the source's saved samples.
    await act(async () => { await result.current.publish(); });
    expect(mocked.api.pipelines.publishReviewed.mock.calls[0][1]).toBeUndefined();
    await act(async () => { await result.current.review(); });
    await act(async () => { await result.current.publish({ persistCapturedSamples: true }); });
    expect(mocked.api.pipelines.publishReviewed.mock.calls[1][1]).toEqual({ origin: 'capture', samples: ['private captured payload'], persistCaptured: true });
    client.clear();
  });

  it('publishes saved (non-capture) samples as before, labelled as supplied', async () => {
    const { wrapper, client } = harness();
    mocked.api.getLogSource.mockResolvedValue(mocked.source);
    mocked.api.pipelines.publishReviewed.mockResolvedValue({ rollout: null });
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.samples.length).toBe(1));
    act(() => result.current.selectSample(result.current.samples[0]));
    await act(async () => { await result.current.review(); });
    expect(result.current.plan?.capturedSampleCount).toBeUndefined();
    await act(async () => { await result.current.publish(); });
    expect(mocked.api.pipelines.publishReviewed.mock.calls[0][1]).toEqual({ origin: 'supplied', samples: ['private saved payload'] });
    client.clear();
  });

  it('restores unsaved edits after route unmount while keeping the original save CAS', async () => {
    const { wrapper, client } = harness();
    const first = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(first.result.current.draft).not.toBeNull());
    act(() => first.result.current.changeDraft({ ...first.result.current.draft!, steps: [{ id: 'edited', name: 'Edited', kind: 'vrl', enabled: true, config: { code: '.unsaved = true' } }] }));
    first.unmount();
    mocked.api.getLogSourceDraftStatus.mockResolvedValue({ ...mocked.source, updated_at: '2026-10-09T11:00:00Z', extension_vrl: '.external_change = true' });
    mocked.api.updateLogSource.mockRejectedValue(conflictError());
    const second = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    expect(second.result.current.draft?.steps[0].config.code).toBe('.unsaved = true');
    expect(second.result.current.dirty).toBe(true);
    await act(async () => { await second.result.current.save(); });
    expect(mocked.api.updateLogSource.mock.calls[0][1].expected_updated_at).toBe(mocked.source.updated_at);
    expect(second.result.current.draft?.steps[0].config.code).toBe('.unsaved = true');
    expect(second.result.current.errors.save).toBe('stale_draft');
    expect(second.result.current.conflict).not.toBeNull();
    client.clear();
  });
});

describe('pipeline workspace conflicts and recovery', () => {
  const edited = { id: 'edited', name: 'Edited', kind: 'vrl' as const, enabled: true, config: { code: '.mine = true' } };
  const theirs = { ...mocked.source, updated_at: '2026-10-09T12:00:00Z', parser_vrl: '.theirs = true', has_draft_changes: true };

  it('turns a 409 save into a recoverable conflict and reloads the latest server draft', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    act(() => result.current.changeDraft({ ...result.current.draft!, steps: [edited] }));
    mocked.api.updateLogSource.mockRejectedValueOnce(conflictError());
    await act(async () => { await result.current.save(); });
    expect(result.current.conflict).toMatchObject({ operation: 'save' });
    mocked.api.getLogSourceDraftStatus.mockResolvedValue(theirs);
    await act(async () => { await result.current.reloadLatest(); });
    expect(result.current.conflict).toBeNull();
    expect(result.current.dirty).toBe(false);
    expect(result.current.draft?.steps[0].config.code).toBe('.theirs = true');
    expect(result.current.errors).toEqual({});
    // The next save uses the reloaded CAS instead of failing forever.
    act(() => result.current.changeDraft({ ...result.current.draft!, steps: [edited] }));
    mocked.api.updateLogSource.mockResolvedValueOnce({ ...theirs, updated_at: '2026-10-09T12:05:00Z', parser_vrl: 'saved' });
    await act(async () => { await result.current.save(); });
    expect(mocked.api.updateLogSource.mock.calls.at(-1)?.[1].expected_updated_at).toBe(theirs.updated_at);
    expect(result.current.errors.save).toBeUndefined();
    client.clear();
  });

  it('discards only the server draft this editor has seen; a newer one is refused, not wiped', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    act(() => result.current.changeDraft({ ...result.current.draft!, steps: [edited] }));
    // The save conflict refetches the source, so the editor learns of their draft.
    mocked.api.getLogSourceDraftStatus.mockResolvedValue(theirs);
    mocked.api.updateLogSource.mockRejectedValueOnce(conflictError());
    await act(async () => { await result.current.save(); });
    await waitFor(() => expect(mocked.api.getLogSourceDraftStatus).toHaveBeenCalledTimes(2));
    // A third editor saved after that: the discard's CAS refuses it.
    mocked.api.discardLogSourceDraft.mockRejectedValueOnce(conflictError());
    await act(async () => { await result.current.discardDraft(); });
    expect(mocked.api.discardLogSourceDraft).toHaveBeenLastCalledWith('lsrc_firewall', theirs.updated_at);
    expect(result.current.conflict).not.toBeNull();
    expect(result.current.dirty).toBe(true);
    expect(result.current.draft?.steps[0].config.code).toBe('.mine = true');
    client.clear();
  });

  it('keeps local edits on top of the latest server draft so the next save knowingly replaces it', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    act(() => result.current.changeDraft({ ...result.current.draft!, steps: [edited] }));
    mocked.api.updateLogSource.mockRejectedValueOnce(conflictError());
    await act(async () => { await result.current.save(); });
    mocked.api.getLogSourceDraftStatus.mockResolvedValue(theirs);
    await act(async () => { await result.current.keepLocalEdits(); });
    expect(result.current.conflict).toBeNull();
    expect(result.current.dirty).toBe(true);
    expect(result.current.draft?.steps[0].config.code).toBe('.mine = true');
    mocked.api.updateLogSource.mockResolvedValueOnce({ ...theirs, updated_at: '2026-10-09T12:05:00Z' });
    await act(async () => { await result.current.save(); });
    expect(mocked.api.updateLogSource.mock.calls.at(-1)?.[1].expected_updated_at).toBe(theirs.updated_at);
    client.clear();
  });

  it('discards the saved server draft through discard-draft and adopts the active version', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    act(() => result.current.changeDraft({ ...result.current.draft!, steps: [edited] }));
    mocked.api.updateLogSource.mockRejectedValueOnce(conflictError());
    await act(async () => { await result.current.save(); });
    const active = { ...mocked.source, updated_at: '2026-10-09T12:10:00Z', parser_vrl: '.active = true' };
    mocked.api.discardLogSourceDraft.mockResolvedValue(active);
    mocked.api.getLogSourceDraftStatus.mockResolvedValue(active);
    await act(async () => { await result.current.discardDraft(); });
    expect(mocked.api.discardLogSourceDraft).toHaveBeenCalledWith('lsrc_firewall', mocked.source.updated_at);
    expect(result.current.conflict).toBeNull();
    expect(result.current.dirty).toBe(false);
    expect(result.current.draft?.steps[0].config.code).toBe('.active = true');
    expect(client.getQueryData(['pipe-editor-draft', 'tenant-a:user-a:epoch-1', 'lsrc_firewall'])).toBeUndefined();
    client.clear();
  });

  it('flags a remote change as a conflict while edited, and follows it while pristine', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    mocked.api.getLogSourceDraftStatus.mockResolvedValue(theirs);
    await act(async () => { await client.refetchQueries({ queryKey: ['pipe-source'] }); });
    await waitFor(() => expect(result.current.draft?.steps[0].config.code).toBe('.theirs = true'));
    expect(result.current.conflict).toBeNull();
    act(() => result.current.changeDraft({ ...result.current.draft!, steps: [edited] }));
    mocked.api.getLogSourceDraftStatus.mockResolvedValue({ ...theirs, updated_at: '2026-10-09T12:30:00Z', parser_vrl: '.third = true' });
    await act(async () => { await client.refetchQueries({ queryKey: ['pipe-source'] }); });
    await waitFor(() => expect(result.current.conflict).toMatchObject({ operation: 'remote' }));
    expect(result.current.draft?.steps[0].config.code).toBe('.mine = true');
    client.clear();
  });

  it('records the saved baseline when the editor unmounts mid-save, so returning does not self-conflict', async () => {
    const { wrapper, client } = harness();
    const first = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(first.result.current.draft).not.toBeNull());
    act(() => first.result.current.changeDraft({ ...first.result.current.draft!, steps: [edited] }));
    let finish!: (value: unknown) => void;
    mocked.api.updateLogSource.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    let saving!: Promise<unknown>;
    act(() => { saving = first.result.current.save(); });
    first.unmount();
    const saved = { ...mocked.source, updated_at: '2026-10-09T13:00:00Z', parser_vrl: 'saved-by-me', has_draft_changes: true };
    mocked.api.getLogSourceDraftStatus.mockResolvedValue(saved);
    await act(async () => { finish(saved); await saving; });
    const second = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(second.result.current.pipeline).not.toBeNull());
    expect(second.result.current.draft?.steps[0].config.code).toBe('.mine = true');
    expect(second.result.current.dirty).toBe(false);
    expect(second.result.current.conflict).toBeNull();
    act(() => second.result.current.changeDraft({ ...second.result.current.draft!, steps: [{ ...edited, config: { code: '.again = true' } }] }));
    mocked.api.updateLogSource.mockResolvedValueOnce({ ...saved, updated_at: '2026-10-09T13:05:00Z' });
    await act(async () => { await second.result.current.save(); });
    expect(mocked.api.updateLogSource.mock.calls.at(-1)?.[1].expected_updated_at).toBe(saved.updated_at);
    expect(second.result.current.errors.save).toBeUndefined();
    client.clear();
  });

  it('refuses a rollback that would replace unconfirmed unsaved edits', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    act(() => result.current.changeDraft({ ...result.current.draft!, steps: [edited] }));
    await act(async () => { await result.current.rollback(3, { unsavedEdits: false }); });
    expect(mocked.api.revertLogSourceVersion).not.toHaveBeenCalled();
    expect(result.current.errors.rollback).toMatch(/unsaved edits/);
    expect(result.current.draft?.steps[0].config.code).toBe('.mine = true');
    const reverted = { ...mocked.source, updated_at: '2026-10-09T14:00:00Z', parser_vrl: '.v3 = true' };
    mocked.api.revertLogSourceVersion.mockResolvedValue({});
    mocked.api.getLogSourceDraftStatus.mockResolvedValue(reverted);
    await act(async () => { await result.current.rollback(3, { unsavedEdits: true }); });
    expect(mocked.api.revertLogSourceVersion).toHaveBeenCalledWith('lsrc_firewall', 3);
    expect(result.current.draft?.steps[0].config.code).toBe('.v3 = true');
    expect(result.current.dirty).toBe(false);
    expect(result.current.errors.rollback).toBeUndefined();
    client.clear();
  });
});

describe('pipeline workspace runtime availability', () => {
  it('treats missing pipe endpoints (404) as not available yet, not as an error', async () => {
    mocked.api.pipelines.capabilities.mockRejectedValue(Object.assign(new Error('Not Found'), { status: 404 }));
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.capabilities.runtime).toBe('not_available'));
    expect(mocked.api.pipelines.capabilities).toHaveBeenCalledTimes(1);
    expect(result.current.capabilitiesError).toBeNull();
    expect(result.current.capabilities.preview).toBe(false);
    expect(result.current.capabilities.capture.available).toBe(false);
    expect(result.current.capabilities.previewReason).toMatch(/not available for this workspace yet/);
    act(() => result.current.selectSample({ id: 's', name: 'S', events: [{ id: 'e', input: { message: 'm' } }] }));
    await act(async () => { await result.current.runPreview(); });
    expect(mocked.api.pipelines.preview).not.toHaveBeenCalled();
    expect(result.current.previewError).toBeNull();
    client.clear();
  });

  it('shows preview as not enabled from capabilities or a 503 not-enabled answer', async () => {
    mocked.api.pipelines.capabilities.mockResolvedValue({ engine: 'native_vrl', supported_step_kinds: ['vrl'], preview_enabled: false, warnings: [], capture: { enabled: true, max_bytes: 65536, max_events: 1000, max_duration_seconds: 60 } });
    const first = harness();
    const disabled = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper: first.wrapper });
    await waitFor(() => expect(disabled.result.current.capabilities.runtime).toBe('ready'));
    expect(disabled.result.current.capabilities.preview).toBe(false);
    expect(disabled.result.current.capabilities.previewReason).toMatch(/not enabled for this workspace/);
    disabled.unmount(); first.client.clear();

    mocked.api.pipelines.capabilities.mockResolvedValue({ engine: 'native_vrl', supported_step_kinds: ['vrl'], preview_enabled: true, warnings: [], capture: { enabled: true, max_bytes: 65536, max_events: 1000, max_duration_seconds: 60 } });
    mocked.api.pipelines.preview.mockRejectedValue(Object.assign(new Error('Pipeline preview is not enabled on this deployment'), { status: 503 }));
    const second = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper: second.wrapper });
    await waitFor(() => expect(result.current.capabilities.preview).toBe(true));
    act(() => result.current.selectSample({ id: 's', name: 'S', events: [{ id: 'e', input: { message: 'm' } }] }));
    await act(async () => { await result.current.runPreview(); });
    expect(result.current.capabilities.preview).toBe(false);
    expect(result.current.previewError).toBeNull();
    expect(result.current.capabilities.previewReason).toMatch(/not enabled for this workspace/);
    second.client.clear();
  });

  it('reads observed events from the edge snapshot and shows an expired snapshot with a recapture path', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.capabilities.capture.available).toBe(true));
    await act(async () => { await result.current.startCapture({ sourceId: 'lsrc_firewall', point: 'input', durationSeconds: 30, eventLimit: 100 }); });
    expect(result.current.capture.state).toBe('connecting');
    expect(mocked.api.pipelines.captureSnapshot).not.toHaveBeenCalled();
    await waitFor(() => expect(result.current.capture.events).toHaveLength(1), { timeout: 3000 });
    expect(result.current.capture).toMatchObject({ state: 'capturing', observedEvents: 1, retainUntil: '2099-01-01T00:10:00Z' });
    // Completion re-reads the final snapshot; a purged snapshot answers 404.
    mocked.api.pipelines.capture.mockResolvedValue({ ...session, state: 'complete', observed_events: 1 });
    mocked.api.pipelines.captureSnapshot.mockRejectedValue(Object.assign(new Error('Not Found'), { status: 404 }));
    await waitFor(() => expect(result.current.capture.state).toBe('expired'), { timeout: 3000 });
    expect(result.current.capture.events).toEqual([]);
    expect(result.current.capture.reason).toMatch(/10 minutes/);
    expect(result.current.errors).toEqual({});
    client.clear();
  });
});

describe('load recent events and paste (NAN-3447)', () => {
  const plan = { query: 'metadata.log_source="firewall" | head 20 | table time, metadata.log_source, raw_data', time_range: { start: '2026-10-08T10:00:00Z', end: '2026-10-09T10:00:00Z' }, limit: 20, source_labels: ['firewall'], raw_field: 'raw_data' };
  const rows = (count: number) => Array.from({ length: count }, (_, index) => ({ time: `2026-10-09T09:59:${String(index % 60).padStart(2, '0')}Z`, 'metadata.log_source': 'firewall', raw_data: `<134>fw01 action=allow seq=${index}` }));
  const noPersistence = () => {
    expect(mocked.api.putLogSourceSamples).not.toHaveBeenCalled();
    expect(mocked.api.updateLogSource).not.toHaveBeenCalled();
    expect(mocked.api.pipelines.publishReviewed).not.toHaveBeenCalled();
  };

  it('loads the newest raw events through the audited plan and Search, then previews them', async () => {
    const { wrapper, client } = harness();
    mocked.api.pipelines.recentEvents.mockResolvedValue(plan);
    mocked.api.search.mockResolvedValue({ results: rows(3), total_count: 3, execution_time_ms: 1, fields: [] });
    mocked.api.pipelines.preview.mockImplementation(async (_sourceId, request) => ({ ...previewResult, results: request.events.map((input: unknown, index: number) => ({ index, input, output: input, disposition: 'retained', steps: [] })) }));
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    await act(async () => { await result.current.loadRecentEvents(); });
    expect(mocked.api.pipelines.recentEvents).toHaveBeenCalledWith('lsrc_firewall', 20);
    expect(mocked.api.search).toHaveBeenCalledWith(expect.objectContaining({ query: plan.query, time_range: plan.time_range, limit: 20, skip_histogram: true }));
    expect(result.current.frozen).toMatchObject({ origin: 'recent', name: 'Recent events · 3' });
    expect(result.current.frozen?.events[0]).toMatchObject({ input: { message: '<134>fw01 action=allow seq=0', source_type: 'firewall' }, capturedAt: '2026-10-09T09:59:00Z' });
    await act(async () => { await result.current.runPreview(); });
    const body = mocked.api.pipelines.preview.mock.calls.at(-1)![1];
    expect(body.events).toEqual(rows(3).map(row => ({ message: row.raw_data, source_type: 'firewall' })));
    expect(result.current.preview?.inputCount).toBe(3);
    noPersistence();
    client.clear();
  });

  it('refuses without source-event permission and revokes on a 403 plan', async () => {
    const { wrapper, client } = harness();
    mocked.allowedPermissions = ['log_sources:view', 'log_sources:edit'];
    const limited = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(limited.result.current.draft).not.toBeNull());
    await act(async () => { await limited.result.current.loadRecentEvents(); });
    expect(mocked.api.pipelines.recentEvents).not.toHaveBeenCalled();
    expect(limited.result.current.errors.load).toMatch(/Source event access is required/);
    expect(() => limited.result.current.pasteSample('raw line')).toThrow(/Source event access/);
    limited.unmount();

    mocked.allowedPermissions = null;
    mocked.api.pipelines.recentEvents.mockRejectedValue(denied());
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    await act(async () => { await result.current.loadRecentEvents(); });
    expect(mocked.api.search).not.toHaveBeenCalled();
    expect(result.current.permissions.capture).toBe(false);
    expect(result.current.frozen).toBeNull();
    client.clear();
  });

  it('keeps a sample chosen while a load is in flight', async () => {
    const { wrapper, client } = harness();
    let finish: (value: unknown) => void = () => undefined;
    mocked.api.pipelines.recentEvents.mockResolvedValue(plan);
    mocked.api.search.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    let loading: Promise<unknown> | undefined;
    act(() => { loading = result.current.loadRecentEvents(); });
    await waitFor(() => expect(mocked.api.search).toHaveBeenCalled());
    act(() => result.current.pasteSample('pasted while loading'));
    await act(async () => { finish({ results: rows(2), total_count: 2, execution_time_ms: 1, fields: [] }); await loading; });
    expect(result.current.frozen).toMatchObject({ origin: 'pasted' });
    client.clear();
  });

  it('explains an empty result and keeps rows without raw text out of the input', async () => {
    const { wrapper, client } = harness();
    mocked.api.pipelines.recentEvents.mockResolvedValue(plan);
    mocked.api.search.mockResolvedValue({ results: [{ time: '2026-10-09T09:00:00Z', raw_data: '' }, { time: '2026-10-09T09:00:01Z' }], total_count: 2, execution_time_ms: 1, fields: [] });
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    await act(async () => { await result.current.loadRecentEvents(); });
    expect(result.current.frozen).toBeNull();
    expect(result.current.sampleNotice).toMatch(/No stored events with raw text/);
    expect(mocked.api.pipelines.preview).not.toHaveBeenCalled();
    client.clear();
  });

  it('bounds a load at 100 events', async () => {
    const { wrapper, client } = harness();
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    await act(async () => { await result.current.loadRecentEvents(101); });
    expect(mocked.api.pipelines.recentEvents).not.toHaveBeenCalled();
    expect(result.current.errors.load).toMatch(/1–100/);
    mocked.api.pipelines.recentEvents.mockResolvedValue({ ...plan, limit: 100 });
    mocked.api.search.mockResolvedValue({ results: rows(150), total_count: 150, execution_time_ms: 1, fields: [] });
    await act(async () => { await result.current.loadRecentEvents(100); });
    expect(mocked.api.search.mock.calls[0][0].limit).toBe(100);
    expect(result.current.frozen?.events).toHaveLength(100);
    // The server's bound wins over a larger client request.
    mocked.api.pipelines.recentEvents.mockResolvedValue({ ...plan, limit: 10 });
    await act(async () => { await result.current.loadRecentEvents(50); });
    expect(mocked.api.search.mock.calls[1][0].limit).toBe(10);
    expect(result.current.frozen?.events).toHaveLength(10);
    client.clear();
  });

  it('pastes newline-delimited events or a JSON array as browser-only input that never reaches a release', async () => {
    const { wrapper, client } = harness();
    mocked.api.getLogSource.mockResolvedValue(mocked.source);
    mocked.api.pipelines.publishReviewed.mockResolvedValue({ rollout: null });
    const { result } = renderHook(() => usePipelineWorkspace('lsrc_firewall'), { wrapper });
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    act(() => result.current.pasteSample('line one\n\nline two\r\n'));
    expect(result.current.frozen?.events.map(event => event.input)).toEqual([{ message: 'line one', source_type: 'firewall' }, { message: 'line two', source_type: 'firewall' }]);
    act(() => result.current.pasteSample('[{"EventID":1,"Image":"cmd.exe"}, "raw text"]'));
    expect(result.current.frozen).toMatchObject({ origin: 'pasted' });
    expect(result.current.frozen?.events.map(event => event.input)).toEqual([{ message: '{"EventID":1,"Image":"cmd.exe"}', source_type: 'firewall' }, { message: 'raw text', source_type: 'firewall' }]);
    act(() => result.current.pasteSample('{\n  "EventID": 1,\n  "Image": "cmd.exe"\n}'));
    expect(result.current.frozen?.events.map(event => event.input)).toEqual([{ message: '{"EventID":1,"Image":"cmd.exe"}', source_type: 'firewall' }]);
    expect(() => result.current.pasteSample('   ')).toThrow(/at least one/);
    expect(() => result.current.pasteSample(Array.from({ length: 101 }, (_, index) => `e${index}`).join('\n'))).toThrow(/at most 100/);
    await act(async () => { await result.current.review(); });
    expect(result.current.plan?.samples).toBeUndefined();
    await act(async () => { await result.current.publish(); });
    // No release samples: the version keeps the source's saved samples.
    expect(mocked.api.pipelines.publishReviewed.mock.calls[0][1]).toBeUndefined();
    expect(mocked.api.putLogSourceSamples).not.toHaveBeenCalled();
    client.clear();
  });
});
