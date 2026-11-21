// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
/**
 * NAN-5717: coverage must follow a promote / demote / pause made on another
 * page. The hook sends the modes it is given and refetches on every mount
 * instead of serving the global one-minute staleTime.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';

const fetched: string[] = [];
vi.mock('@/lib/authenticated-fetch', () => ({
  authenticatedFetch: vi.fn(async (path: string) => {
    fetched.push(path);
    return new Response(JSON.stringify({ tactics: [], techniques: [], summary: {} }), { status: 200 });
  }),
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user_1' }, isAuthenticated: true, isLoading: false }),
}));
vi.mock('@/lib/auth-token', () => ({ getAccessToken: () => null }));

import { useMitreCoverage } from './useMitreData';

afterEach(() => {
  cleanup();
  fetched.length = 0;
});

describe('useMitreCoverage freshness (NAN-5717)', () => {
  it('sends every requested mode and refetches on remount within the global staleTime', async () => {
    const client = new QueryClient({ defaultOptions: { queries: { staleTime: 60_000, retry: false } } });
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    );
    const filters = { severity: [], mode: ['staging', 'live', 'alerting', 'paused'] };

    const first = renderHook(() => useMitreCoverage(filters), { wrapper });
    await waitFor(() => expect(first.result.current.loading).toBe(false));
    expect(fetched).toEqual(['/api/mitre/coverage?mode=alerting%2Clive%2Cpaused%2Cstaging']);
    first.unmount();

    const second = renderHook(() => useMitreCoverage(filters), { wrapper });
    await waitFor(() => expect(fetched).toHaveLength(2));
    second.unmount();
  });
});
