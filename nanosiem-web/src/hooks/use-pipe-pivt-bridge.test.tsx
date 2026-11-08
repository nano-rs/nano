// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

import { cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  applyPipeVrlOnPage, readPipePivtContext, usePipePivtBridge, PIPE_VRL_READ_ONLY_ERROR, PIPE_VRL_STALE_ERROR, type PivtPipeSnapshot,
} from './use-pipe-pivt-bridge';
import type { PipelineDraft } from '@/lib/pipeline-types';

const draft: PipelineDraft = { name: 'fw', description: '', revision: 1, steps: [{ id: 'v1', name: 'Parse', kind: 'vrl', enabled: true, config: { code: '.a = 1' } }] };
const snapshot = (over: Partial<PivtPipeSnapshot> = {}): PivtPipeSnapshot => ({
  sourceId: 'lsrc_1', sourceName: 'fw', draft, selectedStepId: 'v1', sample: null, preview: null, previewError: null, canApply: true, unavailableReason: null, ...over,
});
afterEach(cleanup);

describe('pipe pivt bridge (pivt:pipe-context / pivt:apply-pipe-vrl)', () => {
  it('answers the context event and applies a fresh proposal as an unsaved draft edit', () => {
    const onApply = vi.fn();
    renderHook(() => usePipePivtBridge({ snapshot: snapshot(), onApply }));
    expect(readPipePivtContext()?.sourceId).toBe('lsrc_1');
    const result = applyPipeVrlOnPage('lsrc_1', { kind: 'replace', stepId: 'v1' }, '.a = 1', '.a = 2');
    expect(result.applied).toBe(true);
    expect(onApply.mock.calls[0][0].steps[0].config).toEqual({ code: '.a = 2' });
  });
  it('refuses stale steps, read-only viewers and other pipelines', () => {
    const onApply = vi.fn();
    const { rerender } = renderHook(({ snap }) => usePipePivtBridge({ snapshot: snap, onApply }), { initialProps: { snap: snapshot() } });
    expect(applyPipeVrlOnPage('lsrc_1', { kind: 'replace', stepId: 'v1' }, '.old = 1', '.a = 2').error).toBe(PIPE_VRL_STALE_ERROR);
    expect(applyPipeVrlOnPage('lsrc_other', { kind: 'replace', stepId: 'v1' }, '.a = 1', '.a = 2').applied).toBe(false);
    rerender({ snap: snapshot({ canApply: false }) });
    expect(applyPipeVrlOnPage('lsrc_1', { kind: 'replace', stepId: 'v1' }, '.a = 1', '.a = 2').error).toBe(PIPE_VRL_READ_ONLY_ERROR);
    expect(onApply).not.toHaveBeenCalled();
  });
});
