// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4435: the shared-tenant provider path, end to end through the real
 * bootstrap parser. A `lean-soar` plan serializes an extra `soar` component;
 * the parser used to refuse it, the provider failed closed, and the shell hid
 * Search, Investigate, Cases, Notebooks, Risk, Health and most settings.
 */
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  ENTERPRISE_SHARED_FEATURE_FLAG_CODES,
  TENANT_COMPONENT_CODES,
} from '@/lib/tenant-capabilities';

const USER_ID = '018f6f72-84b6-7a10-9f11-7ab36f022001';
const TENANT = { id: '018f6f72-84b6-7a10-9f11-7ab36f02200a', slug: 'soar-e2e-1' };
const ROLES = ['admin'];
const PERMISSIONS = ['*'];

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: {
      id: USER_ID,
      roles: ROLES,
      permissions: PERMISSIONS,
      deployment_mode: 'enterprise_shared',
    },
    isAuthenticated: true,
    isLoading: false,
    tenantRuntime: { key: 'rt-1', epoch: 1, scope: { kind: 'enterprise_shared', tenant: TENANT } },
  }),
}));

// The runtime authority and refresh-aware fetch are covered by their own
// suites; here they pass straight through so the provider's parse path runs.
vi.mock('@/lib/tenant-runtime', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/tenant-runtime')>();
  return { ...actual, browserTenantRuntime: { assertCurrent: () => undefined } };
});
vi.mock('@/lib/authenticated-fetch', () => ({
  authenticatedFetch: (path: string) => fetch(path),
}));

import { CapabilitiesProvider } from './CapabilitiesProvider';
import { useCapabilities } from '@/hooks/use-capabilities';

/** Every capability a primary nav or settings entry gates on (AppLayout / settings sections). */
const NAV_CAPABILITIES = [
  'search', 'cases', 'notebooks', 'risk', 'melod', 'customEnrichment', 'agentEnrichment',
  'aiTuning', 'playbooks', 'incidents', 'siemHealth', 'sso', 'iocLists',
] as const;

function Probe() {
  const { capabilities, tenantPlan } = useCapabilities();
  return (
    <>
      <span data-testid="caps">{JSON.stringify(capabilities)}</span>
      <span data-testid="soar">{tenantPlan ? String(tenantPlan.components.soar.enabled) : 'no-plan'}</span>
    </>
  );
}

function bootstrap(extraComponents: Record<string, unknown> = {}, planCode = 'lean') {
  return {
    edition: 'enterprise',
    version: '0.1.0',
    deploymentMode: 'enterprise_shared',
    tenant: TENANT,
    identity: { userId: USER_ID, roles: ROLES, permissions: PERMISSIONS, authorizationRevision: 3 },
    plan: { code: planCode, revision: 1, assignmentRevision: 2 },
    limits: { ha_enabled: true, retention_days: 30 },
    haEnabled: true,
    components: {
      ...Object.fromEntries(TENANT_COMPONENT_CODES.map((code) => [code, { enabled: true, configuration: {} }])),
      ...extraComponents,
    },
    featureFlags: {
      revision: 4,
      flags: Object.fromEntries(ENTERPRISE_SHARED_FEATURE_FLAG_CODES.map((code) => [code, false])),
    },
  };
}

function serve(body: unknown) {
  vi.stubGlobal('fetch', vi.fn(async (path: string) => {
    const json = path === '/api/settings/ai-availability'
      ? { connected: true, model_available: true }
      : body;
    return { ok: true, status: 200, json: async () => json } as Response;
  }));
}

function renderProvider() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/t/soar-e2e-1/search']}>
        <CapabilitiesProvider>
          <Probe />
        </CapabilitiesProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function capabilities(): Record<string, boolean> {
  return JSON.parse(screen.getByTestId('caps').textContent ?? '{}');
}

async function expectFullNav() {
  await waitFor(() => expect(screen.getByTestId('soar').textContent).not.toBe('no-plan'));
  for (const capability of NAV_CAPABILITIES) {
    expect(capabilities()[capability], capability).toBe(true);
  }
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it('a lean bootstrap (no soar row) renders the full nav and leaves SOAR disabled', async () => {
  serve(bootstrap());
  renderProvider();
  await expectFullNav();
  expect(screen.getByTestId('soar').textContent).toBe('false');
});

it('a lean-soar bootstrap with soar enabled renders the full nav and the SOAR grant', async () => {
  serve(bootstrap({ soar: { enabled: true, configuration: {} } }, 'lean-soar'));
  renderProvider();
  await expectFullNav();
  expect(screen.getByTestId('soar').textContent).toBe('true');
});

it('a lean-soar bootstrap with soar disabled keeps the full nav and disables only SOAR', async () => {
  serve(bootstrap({ soar: { enabled: false, configuration: {} } }, 'lean-soar'));
  renderProvider();
  await expectFullNav();
  expect(screen.getByTestId('soar').textContent).toBe('false');
});

it('an unknown component still fails the whole provider closed', async () => {
  serve(bootstrap({ unrecognized: { enabled: true, configuration: {} } }));
  renderProvider();
  // Fail-closed value carries no plan and denies every gated surface.
  await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalled());
  await new Promise((resolve) => setTimeout(resolve, 50));
  expect(screen.getByTestId('soar').textContent).toBe('no-plan');
  for (const capability of NAV_CAPABILITIES) {
    expect(capabilities()[capability], capability).toBe(false);
  }
});
