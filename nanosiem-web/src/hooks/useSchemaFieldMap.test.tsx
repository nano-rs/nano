// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-4903: the field map never guesses the tenant's schema profile. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';

const mocks = vi.hoisted(() => ({ getSchemaFields: vi.fn(), toast: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { getSchemaFields: mocks.getSchemaFields } }));
vi.mock('@/hooks/use-toast', () => ({ toast: mocks.toast, useToast: () => ({ toast: mocks.toast }) }));

import {
  SCHEMA_PROFILE_ERROR_REASON,
  SCHEMA_PROFILE_LOADING_REASON,
  useSchemaFieldMap,
} from './useSchemaFieldMap';

afterEach(() => {
  cleanup();
  mocks.getSchemaFields.mockReset();
  mocks.toast.mockReset();
});

function wrapperFor(client: QueryClient) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
}

describe('useSchemaFieldMap', () => {
  it('is unresolved while loading and never reports OCSF as a guess', () => {
    mocks.getSchemaFields.mockReturnValue(new Promise(() => {}));
    const client = new QueryClient();
    const { result } = renderHook(() => useSchemaFieldMap(), { wrapper: wrapperFor(client) });
    expect(result.current.ready).toBe(false);
    expect(result.current.unresolved).toBe(true);
    expect(result.current.isOcsf).toBe(false);
    expect(result.current.unresolvedReason).toBe(SCHEMA_PROFILE_LOADING_REASON);
  });

  it('guard refuses while unresolved: no call, an error toast, and a refetch', () => {
    mocks.getSchemaFields.mockReturnValue(new Promise(() => {}));
    const client = new QueryClient();
    const { result } = renderHook(() => useSchemaFieldMap(), { wrapper: wrapperFor(client) });
    const action = vi.fn();
    act(() => result.current.guard(action)('x'));
    expect(action).not.toHaveBeenCalled();
    expect(mocks.toast).toHaveBeenCalledWith(expect.objectContaining({ variant: 'destructive' }));
  });

  it('reports an error (not a profile) when the endpoint fails', async () => {
    mocks.getSchemaFields.mockRejectedValue(new Error('503'));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { result } = renderHook(() => useSchemaFieldMap(), { wrapper: wrapperFor(client) });
    await waitFor(() => expect(result.current.error).toBe(true));
    expect(result.current.unresolved).toBe(true);
    expect(result.current.unresolvedReason).toBe(SCHEMA_PROFILE_ERROR_REASON);
  });

  it('an unknown discriminator stays unresolved', async () => {
    mocks.getSchemaFields.mockResolvedValue({ schema: 'spans', fields: [] });
    const client = new QueryClient();
    const { result } = renderHook(() => useSchemaFieldMap(), { wrapper: wrapperFor(client) });
    await waitFor(() => expect(mocks.getSchemaFields).toHaveBeenCalled());
    expect(result.current.unresolved).toBe(true);
  });

  it.each(['udm', 'ocsf'] as const)('resolves to %s and guard runs the action', async (schema) => {
    mocks.getSchemaFields.mockResolvedValue({ schema, fields: [] });
    const client = new QueryClient();
    const { result } = renderHook(() => useSchemaFieldMap(), { wrapper: wrapperFor(client) });
    await waitFor(() => expect(result.current.ready).toBe(true));
    expect(result.current.profile).toBe(schema);
    expect(result.current.filter('srcIp', '1.2.3.4')).toBe(
      schema === 'udm' ? 'src_ip="1.2.3.4"' : 'src_endpoint.ip="1.2.3.4"',
    );
    const action = vi.fn();
    act(() => result.current.guard(action)('x'));
    expect(action).toHaveBeenCalledWith('x');
    expect(mocks.toast).not.toHaveBeenCalled();
  });
});
