// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

import type { ReactNode } from 'react';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { usePipelineWorkspace } from './use-pipeline-workspace';
import { REVIEW_STALE_MESSAGE } from './use-pipeline-workspace-core';
import { serializePipeline } from '@/lib/pipeline-model';
import type { PipelineDraft } from '@/lib/pipeline-types';

const mocked = vi.hoisted(() => ({
  permissions: null as string[] | null,
  api: {
    getLogSourceDraftStatus: vi.fn(), getLogSourceVersions: vi.fn(), updateLogSource: vi.fn(), validateLogSourceVrl: vi.fn(),
    publishLogSource: vi.fn(), revertLogSourceVersion: vi.fn(), deployLogSource: vi.fn(), discardLogSourceDraft: vi.fn(),
    pipelines: { capabilities: vi.fn(), preview: vi.fn(), samples: vi.fn(), tap: vi.fn() },
  },
}));
vi.mock('@/lib/api', () => ({ api: mocked.api }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: (p: string) => mocked.permissions === null || mocked.permissions.includes(p), user: { id: 'user-a' } }) }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));

const base: PipelineDraft = { name: 'Firewall', description: '', revision: 1, steps: [{ id: 'v1', name: 'Parse', kind: 'vrl', enabled: true, config: { code: '.a = 1' } }] };
const T0 = '2026-10-09T10:00:00Z';
const T1 = '2026-10-09T10:05:00Z';
const T2 = '2026-10-09T10:09:00Z';
const source = (over: Record<string, unknown> = {}) => ({
  id: 'lsrc_1', name: 'Firewall', description: '', source_type: 'firewall', parser_vrl: serializePipeline(base), updated_at: T0,
  extension_vrl: null, extension_enabled: true, deployed: true, deployed_at: T0, enabled: true, has_draft_changes: false, active_version_number: 2, ...over,
});
const capabilities = {
  preview_enabled: true, preview_degraded_isolation: false, live_tap_enabled: true,
  step_kinds: ['parse', 'rename', 'remove', 'set', 'redact', 'fields', 'mask', 'filter', 'sample', 'split', 'vrl', 'dedupe', 'combine', 'route', 'lookup'],
  preview_only_kinds: [{ kind: 'combine', reason: 'This Vector build has no reduce transform' }],
  bounds: { max_steps: 50 },
};
const httpError = (status: number, message: string, retryAfter?: number) => Object.assign(new Error(message), { status, retryAfter, code: 'X' });
const previewOk = { engine: 'pipeline', degraded_isolation: false, warnings: [], results: [{ index: 0, disposition: 'retained', outputs: [{ a: 1 }], error: null, traces: [] }], summary: { input_events: 1, output_events: 1, dropped_events: 0, error_events: 0, input_bytes: 10, output_bytes: 8 } };

function harness() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  return renderHook(() => usePipelineWorkspace('lsrc_1'), { wrapper });
}
const edited = (draft: PipelineDraft, code: string): PipelineDraft => ({ ...draft, steps: [{ ...draft.steps[0], config: { code } }] });

beforeEach(() => {
  vi.resetAllMocks();
  mocked.permissions = null;
  mocked.api.getLogSourceDraftStatus.mockResolvedValue(source());
  mocked.api.getLogSourceVersions.mockResolvedValue([{ id: 20, log_source_id: 'lsrc_1', version_number: 2, parser_vrl: '.old = 1', is_active: true, created_at: T0, change_reason: 'publish' }]);
  mocked.api.pipelines.capabilities.mockResolvedValue(capabilities);
  mocked.api.pipelines.preview.mockResolvedValue(previewOk);
  mocked.api.validateLogSourceVrl.mockResolvedValue({ valid: true, errors: [] });
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe('save conflicts', () => {
  it('turns a 409 into a conflict and "keep my edits" re-saves against the new updated_at', async () => {
    const { result } = harness();
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    act(() => result.current.changeDraft(edited(result.current.draft!, '.mine = 1')));
    mocked.api.updateLogSource.mockRejectedValueOnce(httpError(409, 'stale'));
    mocked.api.getLogSourceDraftStatus.mockResolvedValue(source({ updated_at: T1, parser_vrl: serializePipeline(edited(base, '.theirs = 1')) }));
    await act(async () => { await result.current.save(); });
    expect(mocked.api.updateLogSource.mock.calls[0][1].expected_updated_at).toBe(T0);
    expect(result.current.conflict?.operation).toBe('save');
    await act(async () => { await result.current.keepLocalEdits(); });
    expect(result.current.conflict).toBeNull();
    expect(result.current.dirty).toBe(true);
    mocked.api.updateLogSource.mockResolvedValueOnce(source({ updated_at: T2, parser_vrl: serializePipeline(result.current.draft!) }));
    await act(async () => { await result.current.save(); });
    const body = mocked.api.updateLogSource.mock.calls[1][1];
    expect(body.expected_updated_at).toBe(T1);
    expect(body.parser_vrl).toContain('.mine = 1');
  });

  it('"reload latest" discards local edits for the server copy', async () => {
    const { result } = harness();
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    act(() => result.current.changeDraft(edited(result.current.draft!, '.mine = 1')));
    mocked.api.getLogSourceDraftStatus.mockResolvedValue(source({ updated_at: T1, parser_vrl: serializePipeline(edited(base, '.theirs = 1')) }));
    await act(async () => { await result.current.reloadLatest(); });
    expect(result.current.draft!.steps[0].config.code).toBe('.theirs = 1');
    expect(result.current.dirty).toBe(false);
  });

  it('refuses to discard when a newer draft was saved than the one this editor saw', async () => {
    const { result } = harness();
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    mocked.api.getLogSourceDraftStatus.mockResolvedValue(source({ updated_at: T2, parser_vrl: '.someone_else = 1' }));
    await act(async () => { await result.current.discardDraft(); });
    expect(mocked.api.discardLogSourceDraft).not.toHaveBeenCalled();
    expect(result.current.errors.discard).toMatch(/Another draft/);
  });
});

describe('preview', () => {
  it('sends the serialized draft and reports a 429 with its retry time without re-queuing', async () => {
    const { result } = harness();
    await waitFor(() => expect(result.current.capabilities.preview).toBe(true));
    mocked.api.pipelines.preview.mockRejectedValue(httpError(429, 'busy', 9));
    act(() => result.current.pasteSample('{"message":"x"}'));
    await waitFor(() => expect(result.current.previewError).toBe('Preview is busy. Retry in 9s.'));
    expect(mocked.api.pipelines.preview).toHaveBeenCalledTimes(1);
    const request = mocked.api.pipelines.preview.mock.calls[0][1];
    expect(request.parser_vrl).toBe(serializePipeline(result.current.draft!));
    expect(request.events).toEqual([{ message: '{"message":"x"}' }]);
    // An edit during the back-off does not auto-run another request.
    act(() => result.current.changeDraft(edited(result.current.draft!, '.b = 2')));
    await new Promise((resolve) => setTimeout(resolve, 600));
    expect(mocked.api.pipelines.preview).toHaveBeenCalledTimes(1);
  });

  it('marks preview-only kinds from capabilities', async () => {
    const { result } = harness();
    await waitFor(() => expect(result.current.capabilities.previewOnly).toEqual([{ kind: 'combine', reason: 'This Vector build has no reduce transform' }]));
  });
});

describe('live tap', () => {
  it('captures, then previews the tapped events with their input identity', async () => {
    mocked.api.pipelines.tap.mockResolvedValue({ component: 'lsrc_1_parse', seconds: 5, ended: 'deadline', dropped_oversize: 0, events: [{ event: { message: 'tapped' }, input: 'push:c0ffee00-0000-4000-8000-000000000001' }] });
    const { result } = harness();
    await waitFor(() => expect(result.current.capabilities.tap.available).toBe(true));
    await act(async () => { await result.current.startTap({ seconds: 5, maxEvents: 10 }); });
    expect(mocked.api.pipelines.tap.mock.calls[0][1]).toEqual({ seconds: 5, max_events: 10 });
    expect(result.current.tap.state).toBe('completed');
    act(() => result.current.previewTapEvents());
    await waitFor(() => expect(mocked.api.pipelines.preview).toHaveBeenCalled());
    expect(mocked.api.pipelines.preview.mock.lastCall![1].inputs).toEqual(['push:c0ffee00-0000-4000-8000-000000000001']);
  });

  it('cancels through the abort signal and reports a busy tap with Retry-After', async () => {
    mocked.api.pipelines.tap.mockImplementation((_id: string, _body: unknown, signal: AbortSignal) => new Promise((_, reject) => {
      signal.addEventListener('abort', () => reject(Object.assign(new Error('Request aborted'), { code: 'ABORTED' })));
    }));
    const { result } = harness();
    await waitFor(() => expect(result.current.capabilities.tap.available).toBe(true));
    let running!: Promise<void>;
    act(() => { running = result.current.startTap({ seconds: 30, maxEvents: 100 }); });
    expect(result.current.tap.state).toBe('capturing');
    await act(async () => { result.current.cancelTap(); await running; });
    expect(result.current.tap.state).toBe('cancelled');
    mocked.api.pipelines.tap.mockRejectedValueOnce(httpError(429, 'busy', 5));
    await act(async () => { await result.current.startTap({ seconds: 30, maxEvents: 100 }); });
    expect(result.current.tap).toMatchObject({ state: 'busy', retryAfter: 5, reason: 'Live tap is busy. Retry in 5s.' });
  });

  it('needs search:execute', async () => {
    mocked.permissions = ['log_sources:view', 'log_sources:edit'];
    const { result } = harness();
    await waitFor(() => expect(result.current.capabilities.tap.available).toBe(true));
    await act(async () => { await result.current.startTap({ seconds: 5, maxEvents: 10 }); });
    expect(mocked.api.pipelines.tap).not.toHaveBeenCalled();
    expect(result.current.tap.state).toBe('forbidden');
  });
});

describe('release review', () => {
  it('freezes the reviewed row and publishes only when the server still matches it', async () => {
    mocked.api.publishLogSource.mockResolvedValue({ success: true, message: 'deployed' });
    const { result } = harness();
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    await act(async () => { await result.current.review(); });
    expect(result.current.plan?.snapshot.expectedUpdatedAt).toBe(T0);
    expect(Object.isFrozen(result.current.plan)).toBe(true);
    expect(mocked.api.validateLogSourceVrl).toHaveBeenCalledWith(serializePipeline(base));
    await act(async () => { await result.current.publish(); });
    expect(mocked.api.publishLogSource).toHaveBeenCalledTimes(1);
  });

  it('blocks publish when the saved draft moved after review', async () => {
    const { result } = harness();
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    await act(async () => { await result.current.review(); });
    mocked.api.getLogSourceDraftStatus.mockResolvedValue(source({ updated_at: T1, parser_vrl: '.changed = 1' }));
    await act(async () => { await result.current.publish(); });
    expect(mocked.api.publishLogSource).not.toHaveBeenCalled();
    expect(result.current.errors.publish).toBe(REVIEW_STALE_MESSAGE);
    // The pristine editor follows the newer server copy; the stale plan is gone.
    await waitFor(() => expect(result.current.plan).toBeNull());
    expect(result.current.errors.publish).toBe(REVIEW_STALE_MESSAGE);
  });

  it('refuses to review unsaved edits and surfaces a refused publish', async () => {
    mocked.api.publishLogSource.mockResolvedValue({ success: false, message: 'combine is not supported by this Vector' });
    const { result } = harness();
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    act(() => result.current.changeDraft(edited(result.current.draft!, '.x = 2')));
    await act(async () => { await result.current.review(); });
    expect(result.current.plan).toBeNull();
    expect(result.current.errors.review).toMatch(/Save this draft/);
    await act(async () => { await result.current.reloadLatest(); });
    await act(async () => { await result.current.review(); });
    await act(async () => { await result.current.publish(); });
    expect(result.current.errors.publish).toBe('combine is not supported by this Vector');
  });
});

describe('rollback', () => {
  it('reverts, then deploys, and refuses to drop unconfirmed unsaved edits', async () => {
    mocked.api.revertLogSourceVersion.mockResolvedValue({ id: 30, version_number: 3 });
    mocked.api.deployLogSource.mockResolvedValue({ success: true, message: 'ok' });
    const { result } = harness();
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    act(() => result.current.changeDraft(edited(result.current.draft!, '.x = 2')));
    await act(async () => { await result.current.rollback(20, { unsavedEdits: false }); });
    expect(mocked.api.revertLogSourceVersion).not.toHaveBeenCalled();
    await act(async () => { await result.current.rollback(20, { unsavedEdits: true }); });
    expect(mocked.api.revertLogSourceVersion).toHaveBeenCalledWith('lsrc_1', 20);
    expect(mocked.api.deployLogSource).toHaveBeenCalledWith('lsrc_1');
    expect(result.current.errors.rollback).toBeUndefined();
  });

  it('reports a failed deploy after revert', async () => {
    mocked.api.revertLogSourceVersion.mockResolvedValue({ id: 30, version_number: 3 });
    mocked.api.deployLogSource.mockResolvedValue({ success: false, message: 'vector validate failed' });
    const { result } = harness();
    await waitFor(() => expect(result.current.draft).not.toBeNull());
    await act(async () => { await result.current.rollback(20, { unsavedEdits: false }); });
    expect(result.current.errors.rollback).toMatch(/vector validate failed/);
  });
});
