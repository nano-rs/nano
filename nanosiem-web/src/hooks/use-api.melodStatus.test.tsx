// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
/**
 * NAN-5724: `GET /api/settings/ai-availability` admits settings:ai or any
 * melod:* grant. useMelodStatus (the PIVT dock mounts it on every page) skips
 * the read for a role holding none of them instead of drawing a 403.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, renderHook, waitFor } from '@testing-library/react';

let granted: string[] = [];
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => granted.includes(p) }),
}));
const getAiAvailability = vi.fn(async () => ({ connected: true }));
vi.mock('@/lib/api', async (orig) => {
  const actual = await orig<typeof import('@/lib/api')>();
  return { ...actual, api: { ...actual.api, getAiAvailability: () => getAiAvailability() } };
});

import { useMelodStatus } from './use-api';

afterEach(() => {
  cleanup();
  getAiAvailability.mockClear();
});

describe('useMelodStatus gating (NAN-5724)', () => {
  it('skips the read without settings:ai or a melod:* grant', async () => {
    granted = ['search:view', 'alerts:view'];
    const { result } = renderHook(() => useMelodStatus());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(getAiAvailability).not.toHaveBeenCalled();
    expect(result.current.data).toBeNull();
  });

  it.each(['settings:ai', 'melod:chat', 'melod:dashboard'])('reads with %s', async (perm) => {
    granted = [perm];
    const { result } = renderHook(() => useMelodStatus());
    await waitFor(() => expect(result.current.data).toEqual({ connected: true }));
    expect(getAiAvailability).toHaveBeenCalledTimes(1);
  });

  it('still honours an explicit skip', async () => {
    granted = ['settings:ai'];
    const { result } = renderHook(() => useMelodStatus({ skip: true }));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(getAiAvailability).not.toHaveBeenCalled();
  });
});
