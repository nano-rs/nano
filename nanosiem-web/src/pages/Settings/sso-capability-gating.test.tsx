// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-3378 — every core SSO entry point follows `capabilities.sso`. Open-core
// builds have no OIDC API (`/api/settings/oidc` 404s), so the Settings tile,
// the onboarding step, and the provider routes must disappear when the
// capability is false and stay when it is true.
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';

const mock = vi.hoisted(() => ({ sso: false, hasSso: true }));

function caps(sso: boolean): Capabilities {
  return {
    search: true, cases: false, notebooks: false, risk: false, melod: false,
    queryCorrection: false, customEnrichment: false, agentEnrichment: false,
    aiTuning: false, playbooks: false, incidents: false, siemHealth: true,
    sso, observabilityConvergence: false, iocLists: false, soar: false,
  };
}

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ edition: mock.sso ? 'enterprise' : 'open', version: 'test', capabilities: caps(mock.sso) }),
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    hasPermission: () => true,
    hasAnyPermission: () => true,
    isDemoUser: false,
    user: { deployment_mode: 'standard' },
  }),
}));
vi.mock('@/hooks/use-tier', () => ({ useTierContext: () => ({ hasSso: mock.hasSso }) }));
vi.mock('@/hooks/use-shared-tenant', () => ({ useSharedTenant: () => false }));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }));
vi.mock('@/hooks/use-api', () => ({
  useSystemConfig: () => ({ data: { deployment_mode: 'standard', air_gap: false } }),
  useRecentAuditChanges: () => ({ data: { entries: [] }, loading: false }),
  useOnboardingProgress: () => ({
    data: { completed_steps: [], skipped_steps: [], dismissed: false, completed_at: null },
    loading: false,
    refetch: vi.fn(),
  }),
  useOnboardingStatus: () => ({
    data: {
      has_ai_provider: false, has_org_context: false, has_users: true, has_sso: false,
      has_log_sources: true, has_parsers: false, has_search_history: false,
    },
    refetch: vi.fn(),
  }),
  useCompleteOnboardingStep: () => ({ mutate: vi.fn() }),
  useSkipOnboardingStep: () => ({ mutate: vi.fn() }),
  useDismissOnboarding: () => ({ mutate: vi.fn() }),
  useLogSources: () => ({ data: undefined, refetch: vi.fn() }),
  useTenantAiSettings: () => ({ data: undefined, refetch: vi.fn() }),
  useUserList: () => ({ data: undefined, refetch: vi.fn() }),
}));

import { SettingsLanding } from './SettingsLanding';
import { OnboardingWizard } from '../OnboardingWizard';
import { SsoRouteGate } from './SsoRouteGate';

function renderAt(node: React.ReactNode) {
  return render(<MemoryRouter>{node}</MemoryRouter>);
}

beforeEach(() => {
  mock.sso = false;
  mock.hasSso = true;
});
afterEach(cleanup);

test('settings landing hides the Single Sign-On tile when sso is unavailable', () => {
  renderAt(<SettingsLanding />);
  expect(screen.queryByText('Single Sign-On')).toBeNull();
  expect(screen.queryByText(/JIT provisioning/)).toBeNull();
});

test('settings landing shows the Single Sign-On tile when sso is available', () => {
  mock.sso = true;
  renderAt(<SettingsLanding />);
  expect(screen.getByText('Single Sign-On')).toBeTruthy();
});

test('onboarding drops the sso_setup step and its slot in the progress total', () => {
  // The tier still says SSO is entitled (stale `sso_enabled: true`); the
  // build capability alone must remove the step.
  renderAt(<OnboardingWizard />);
  expect(screen.queryByText('Single Sign-On')).toBeNull();
  expect(screen.queryByText(/Connect your identity provider/)).toBeNull();
  // Open build with melod off: team, log source, parser, first search = 4.
  expect(screen.getByText('/4')).toBeTruthy();
  expect(screen.getAllByRole('progressbar')[0].children.length).toBe(4);
});

test('onboarding keeps the sso_setup step when sso is available', () => {
  mock.sso = true;
  renderAt(<OnboardingWizard />);
  expect(screen.getByText('Single Sign-On')).toBeTruthy();
  expect(screen.getByText('/5')).toBeTruthy();
});

test('SSO provider route renders a notice instead of the page when sso is unavailable', () => {
  renderAt(<SsoRouteGate><div>providers page</div></SsoRouteGate>);
  expect(screen.queryByText('providers page')).toBeNull();
  expect(screen.getByText('Single sign-on is not available')).toBeTruthy();
});

test('SSO provider route renders the page when sso is available', () => {
  mock.sso = true;
  renderAt(<SsoRouteGate><div>providers page</div></SsoRouteGate>);
  expect(screen.getByText('providers page')).toBeTruthy();
});
