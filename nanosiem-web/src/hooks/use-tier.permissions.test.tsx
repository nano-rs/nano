// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-5325: the shell's tier read is admin-only; other roles never send it.
import { renderHook, waitFor } from '@testing-library/react';
import { expect, test, vi } from 'vitest';

const perms = vi.hoisted(() => ({ value: new Set<string>() }));
const getStatus = vi.hoisted(() => vi.fn().mockResolvedValue({ limits: null, warnings: [] }));
vi.mock('@/lib/api', () => ({ api: { tier: { getStatus } } }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => perms.value.has(p) }),
}));

import { useTier } from './use-tier';

test('without settings:system the tier status is not requested', async () => {
  perms.value = new Set(['search:view']);
  const { result } = renderHook(() => useTier());
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(getStatus).not.toHaveBeenCalled();
});

test('with settings:system it is', async () => {
  perms.value = new Set(['settings:system']);
  renderHook(() => useTier());
  await waitFor(() => expect(getStatus).toHaveBeenCalledOnce());
});
