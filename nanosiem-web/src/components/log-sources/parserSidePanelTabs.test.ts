// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-4132 (ported by NAN-4922): the parser side panel drops its pivt tab without AI and falls back to Test events. */
import { expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';

const caps = vi.hoisted(() => ({ melod: undefined as boolean | undefined }));
vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ capabilities: { melod: caps.melod } }) }));
import { useParserSidePanelTabs } from './parserSidePanelTabs';

it('fails closed: unknown or absent AI hides the pivt tab', () => {
  for (const melod of [undefined, false]) {
    caps.melod = melod;
    const { result } = renderHook(() => useParserSidePanelTabs('ai'));
    expect(result.current.tabs.map((t) => t.id)).toEqual(['test', 'diag']);
    expect(result.current.active).toBe('test');
  }
});

it('keeps the pivt tab when AI is available', () => {
  caps.melod = true;
  const { result } = renderHook(() => useParserSidePanelTabs('ai'));
  expect(result.current.tabs.map((t) => t.id)).toEqual(['ai', 'test', 'diag']);
  expect(result.current.active).toBe('ai');
});
