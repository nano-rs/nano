// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4779 — Getting Started items must clear once the user has done them.
// Hosted-shared: the shell's status probe reports AI Guidance, Team (pending
// invite), Log Source and Log Parser as false because it cannot read those
// tenant tables; the page folds in the tenant APIs the matching settings pages
// read. Every shape: coming back to the tab re-probes.
import { act, cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import type { OnboardingStatus } from '@/lib/api/onboarding';

const NOT_DONE: OnboardingStatus = {
  has_ai_provider: true,
  has_org_context: false,
  has_users: false,
  has_sso: false,
  has_log_sources: false,
  has_parsers: false,
  has_search_history: false,
};

const mock = vi.hoisted(() => ({
  shared: true,
  status: null as unknown,
  sources: undefined as unknown,
  aiSettings: undefined as unknown,
  users: undefined as unknown,
  completedSteps: [] as string[],
  refetchStatus: vi.fn(),
  refetchProgress: vi.fn(),
  refetchSources: vi.fn(),
  refetchAiSettings: vi.fn(),
  refetchUsers: vi.fn(),
}));

const caps: Capabilities = {
  search: true, cases: true, notebooks: true, risk: true, melod: true,
  queryCorrection: false, customEnrichment: false, agentEnrichment: false,
  aiTuning: false, playbooks: false, incidents: false, siemHealth: true,
  sso: false, observabilityConvergence: false, iocLists: false, soar: false,
};

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ edition: 'enterprise', version: 'test', capabilities: caps }),
}));
vi.mock('@/hooks/use-tier', () => ({ useTierContext: () => ({ hasSso: false }) }));
vi.mock('@/hooks/use-shared-tenant', () => ({ useSharedTenant: () => mock.shared }));
vi.mock('@/hooks/use-api', () => ({
  useSystemConfig: () => ({ data: { deployment_mode: 'standard' } }),
  useOnboardingProgress: () => ({
    data: { completed_steps: mock.completedSteps, skipped_steps: [], dismissed: false, completed_at: null },
    loading: false,
    refetch: mock.refetchProgress,
  }),
  useOnboardingStatus: () => ({ data: mock.status, refetch: mock.refetchStatus }),
  useCompleteOnboardingStep: () => ({ mutate: vi.fn() }),
  useSkipOnboardingStep: () => ({ mutate: vi.fn() }),
  useDismissOnboarding: () => ({ mutate: vi.fn() }),
  useLogSources: (o?: { skip?: boolean }) => ({ data: o?.skip ? null : mock.sources, refetch: mock.refetchSources }),
  useTenantAiSettings: (o?: { skip?: boolean }) => ({ data: o?.skip ? null : mock.aiSettings, refetch: mock.refetchAiSettings }),
  useUserList: (o?: { skip?: boolean }) => ({ data: o?.skip ? null : mock.users, refetch: mock.refetchUsers }),
}));

import { OnboardingWizard } from './OnboardingWizard';

function stepPill(label: string): string {
  const row = screen.getByText(label).closest('.group') as HTMLElement;
  return within(row).getAllByText(/./, { selector: 'span' }).map((n) => n.textContent).join('|');
}

function renderWizard() {
  return render(
    <MemoryRouter>
      <OnboardingWizard />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mock.shared = true;
  mock.status = { ...NOT_DONE };
  mock.sources = undefined;
  mock.aiSettings = undefined;
  mock.users = undefined;
  mock.completedSteps = [];
  vi.clearAllMocks();
});
afterEach(cleanup);

test('hosted: nothing the user did yet → the probe answer stands', () => {
  renderWizard();
  expect(stepPill('AI Guidance')).toContain('Not configured');
  expect(stepPill('Team Setup')).toContain('Only you so far');
  expect(stepPill('Log Source')).toContain('No feeds yet');
  expect(stepPill('Log Parser')).toContain('No parsers yet');
});

test('hosted: guidance without a name, a pending invite and a saved feed clear their steps', () => {
  mock.aiSettings = {
    organizational_context: {
      organization_name: null, industry: 'Healthcare', environment: null,
      attack_vectors: null, compliance_frameworks: [], custom_context: null,
    },
  };
  mock.users = {
    users: [
      { status: 'active', membership_status: 'active', invitation_state: 'consumed', roles: [] },
      { status: 'active', membership_status: 'suspended', invitation_state: 'pending', roles: [] },
    ],
    total: 2,
  };
  mock.sources = [{ deployed: false, parser_vrl: '. = parse_json!(.message)' }];
  renderWizard();
  expect(stepPill('AI Guidance')).toContain('Guidance set');
  expect(stepPill('Team Setup')).toContain('Team members added');
  expect(stepPill('Log Source')).toContain('Feed connected');
  expect(stepPill('Log Parser')).toContain('Parser created');
});

test('hosted: a revoked invite or a suspended member does not count as a teammate', () => {
  mock.users = {
    users: [
      { status: 'active', membership_status: 'active', invitation_state: null, roles: [] },
      { status: 'active', membership_status: 'suspended', invitation_state: 'revoked', roles: [] },
      { status: 'active', membership_status: 'suspended', invitation_state: 'consumed', roles: [] },
    ],
    total: 3,
  };
  renderWizard();
  expect(stepPill('Team Setup')).toContain('Only you so far');
});

test('dedicated: the server probe is authoritative and tenant APIs are not called', () => {
  mock.shared = false;
  mock.status = { ...NOT_DONE, has_parsers: true, has_org_context: true };
  mock.sources = [];
  renderWizard();
  expect(stepPill('Log Parser')).toContain('Parser created');
  expect(stepPill('AI Guidance')).toContain('Guidance set');
  expect(stepPill('Log Source')).toContain('No feeds yet');
});

test('coming back to the tab re-probes status, progress and the hosted signals', () => {
  renderWizard();
  act(() => {
    window.dispatchEvent(new Event('focus'));
  });
  expect(mock.refetchStatus).toHaveBeenCalledTimes(1);
  expect(mock.refetchProgress).toHaveBeenCalledTimes(1);
  expect(mock.refetchSources).toHaveBeenCalledTimes(1);
  expect(mock.refetchAiSettings).toHaveBeenCalledTimes(1);
  expect(mock.refetchUsers).toHaveBeenCalledTimes(1);
});

test('dedicated: focus re-probes status and progress only', () => {
  mock.shared = false;
  renderWizard();
  act(() => {
    window.dispatchEvent(new Event('focus'));
  });
  expect(mock.refetchStatus).toHaveBeenCalledTimes(1);
  expect(mock.refetchProgress).toHaveBeenCalledTimes(1);
  expect(mock.refetchSources).not.toHaveBeenCalled();
});

test('a search with history disabled clears First Search from its persisted step flag', () => {
  mock.completedSteps = ['first_searches'];
  renderWizard();
  expect(stepPill('First Search')).toContain('Searches run');
});
