// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-3247: `/platform/feeds` is the platform-operator console. Its backend
 * requires an owner-managed operator identity that tenant IAM never carries,
 * so a tenant admin (settings:system) must not see an "Operator feeds" link on
 * the health page, and the tenant app must not register the route.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

const mocks = vi.hoisted(() => ({
  latest: vi.fn(),
  suppressions: vi.fn(),
}));

vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: () => {} }));
vi.mock('@/hooks/useBreadcrumbTitle', () => ({ useBreadcrumbTitle: () => {} }));
vi.mock('@/hooks/use-shared-tenant', () => ({ useSharedTenant: () => false }));
vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ capabilities: { melod: false } }) }));
// Tenant admin: every tenant permission, including settings:system.
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ user: { id: 'tenant-admin' }, hasPermission: () => true }) }));
vi.mock('@/components/system-health/SystemHealthEventsPanel', () => ({ SystemHealthEventsPanel: () => null }));
vi.mock('@/components/log-sources/LogSourceHealthChart', () => ({ LogSourceHealthList: () => null }));
vi.mock('@/lib/api', () => {
  class ApiClientError extends Error {
    constructor(message: string, public status: number) { super(message); }
  }
  return {
    ApiClientError,
    api: {
      getSiemHealthLatest: mocks.latest,
      triggerSiemHealthCheck: vi.fn(),
      siemHealth: { listSuppressions: mocks.suppressions },
    },
  };
});

const { SiemHealth } = await import('./SiemHealth');
const { ApiClientError } = await import('@/lib/api');

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <SiemHealth />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('SiemHealth operator feeds link (NAN-3247)', () => {
  it('shows a tenant admin no Operator feeds link while loading', () => {
    mocks.latest.mockReturnValue(new Promise(() => {}));
    mocks.suppressions.mockResolvedValue({ suppressions: [] });
    renderPage();
    expect(screen.getByText('Loading latest health report…')).toBeTruthy();
    expect(screen.queryByText('Operator feeds')).toBeNull();
    expect(document.querySelector('a[href="/platform/feeds"]')).toBeNull();
  });

  it('shows a tenant admin no Operator feeds link when no report exists', async () => {
    mocks.latest.mockRejectedValue(new (ApiClientError as unknown as new (m: string, s: number) => Error)('not found', 404));
    mocks.suppressions.mockResolvedValue({ suppressions: [] });
    renderPage();
    await screen.findByText('No health report yet');
    expect(screen.queryByText('Operator feeds')).toBeNull();
    expect(document.querySelector('a[href="/platform/feeds"]')).toBeNull();
  });

  it('shows a tenant admin no Operator feeds link when the report fails to load', async () => {
    mocks.latest.mockRejectedValue(new (ApiClientError as unknown as new (m: string, s: number) => Error)('boom', 500));
    mocks.suppressions.mockResolvedValue({ suppressions: [] });
    renderPage();
    await screen.findByText('Health report unavailable');
    expect(screen.queryByText('Operator feeds')).toBeNull();
  });

  it('does not register the operator console route in the tenant app', () => {
    const app = readFileSync(resolve(__dirname, '../App.tsx'), 'utf8');
    expect(app).not.toContain('/platform/feeds');
    expect(app).not.toContain('PlatformFeeds');
  });
});
