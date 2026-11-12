// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { clearVrlDraft, readVrlDraft, useVrlDraftGuard, vrlDraftKey, writeVrlDraft } from './use-vrl-draft-guard';

// NAN-5323: unsaved VRL edits were lost silently on reload / navigation.
describe('VRL draft storage', () => {
  afterEach(() => window.sessionStorage.clear());

  it('offers a draft only while the saved VRL is unchanged', () => {
    writeVrlDraft('ls1', 'base', 'edited');
    expect(readVrlDraft('ls1', 'base')).toBe('edited');
    // Someone saved a newer VRL: the stale draft is dropped, never offered.
    expect(readVrlDraft('ls1', 'newer')).toBeNull();
    expect(window.sessionStorage.getItem(vrlDraftKey('ls1'))).toBeNull();
  });

  it('ignores a draft equal to the base and corrupt entries', () => {
    writeVrlDraft('ls1', 'same', 'same');
    expect(readVrlDraft('ls1', 'same')).toBeNull();
    window.sessionStorage.setItem(vrlDraftKey('ls2'), '{not json');
    expect(readVrlDraft('ls2', 'x')).toBeNull();
  });

  it('clear removes the draft', () => {
    writeVrlDraft('ls1', 'b', 'e');
    clearVrlDraft('ls1');
    expect(readVrlDraft('ls1', 'b')).toBeNull();
  });
});

describe('useVrlDraftGuard', () => {
  afterEach(() => window.sessionStorage.clear());

  it('warns on unload and stores the edit while dirty', () => {
    const add = vi.spyOn(window, 'addEventListener');
    const { rerender } = renderHook((p: { editing: boolean; editedVrl: string }) =>
      useVrlDraftGuard({ id: 'ls1', baseVrl: 'base', ...p }), { initialProps: { editing: true, editedVrl: 'base' } });
    expect(add.mock.calls.some(([t]) => t === 'beforeunload')).toBe(false);
    rerender({ editing: true, editedVrl: 'base + edit' });
    expect(add.mock.calls.some(([t]) => t === 'beforeunload')).toBe(true);
    expect(readVrlDraft('ls1', 'base')).toBe('base + edit');
    add.mockRestore();
  });

  it('offers a stored draft on the next visit, then clears it', () => {
    writeVrlDraft('ls1', 'base', 'edited');
    const { result } = renderHook(() => useVrlDraftGuard({ id: 'ls1', baseVrl: 'base', editing: false, editedVrl: '' }));
    expect(result.current.restorable).toBe('edited');
    act(() => result.current.clear());
    expect(result.current.restorable).toBeNull();
    expect(readVrlDraft('ls1', 'base')).toBeNull();
  });
});
