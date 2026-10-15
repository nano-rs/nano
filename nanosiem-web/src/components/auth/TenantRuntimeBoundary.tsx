// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useAuth } from '@/contexts/AuthContext';
import { resetAutocompleteCaches } from '@/lib/query-autocomplete';

function createTenantQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 1000 * 60,
        retry: 1,
      },
    },
  });
}

function TenantRuntimeMount({ children }: { children: ReactNode }) {
  const [queryClient] = useState(createTenantQueryClient);

  useEffect(() => () => {
    // Stop observers and discard every cache owned by the departed identity.
    void queryClient.cancelQueries();
    queryClient.clear();
    resetAutocompleteCaches();
  }, [queryClient]);

  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

/** Remounts the complete product-provider subtree on an auth/tenant epoch. */
export function TenantRuntimeBoundary({ children }: { children: ReactNode }) {
  const { tenantRuntime } = useAuth();
  return (
    <TenantRuntimeMount key={tenantRuntime.key}>
      {children}
    </TenantRuntimeMount>
  );
}
