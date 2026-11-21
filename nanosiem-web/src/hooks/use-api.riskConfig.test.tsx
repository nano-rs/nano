// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
/**
 * NAN-5713: `/risk` opens for `risk:view`, but `GET /api/settings/risk` needs
 * `risk:configure`. The page skips the call without it instead of drawing a
 * 403 (the weight chip that links to /settings/risk stays hidden). The page
 * wiring is pinned in enterprise/pages/__tests__/risk-config-gate.test.ts.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, renderHook, waitFor } from '@testing-library/react';

const getRiskConfig = vi.fn(async () => ({ risk_weight: 1 }));
vi.mock('@/lib/api', async (orig) => {
  const actual = await orig<typeof import('@/lib/api')>();
  return { ...actual, api: { ...actual.api, getRiskConfig: () => getRiskConfig() } };
});

import { useRiskConfig } from './use-api';

afterEach(() => {
  cleanup();
  getRiskConfig.mockClear();
});

describe('useRiskConfig gating (NAN-5713)', () => {
  it('skips the call when told to', async () => {
    const { result } = renderHook(() => useRiskConfig({ skip: true }));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(getRiskConfig).not.toHaveBeenCalled();
    expect(result.current.data).toBeNull();
  });

  it('fetches by default (the Risk settings page)', async () => {
    const { result } = renderHook(() => useRiskConfig());
    await waitFor(() => expect(result.current.data).toEqual({ risk_weight: 1 }));
    expect(getRiskConfig).toHaveBeenCalledTimes(1);
  });
});
