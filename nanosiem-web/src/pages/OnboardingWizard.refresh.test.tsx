// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, test, vi } from 'vitest';
import type { OnboardingStatus } from '@/lib/api/onboarding';

const state = vi.hoisted(() => ({ completed: false }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ capabilities: { melod: true, sso: true } }),
}));
vi.mock('@/hooks/use-tier', () => ({ useTierContext: () => ({ hasSso: true }) }));
vi.mock('@/hooks/use-shared-tenant', () => ({ useSharedTenant: () => true }));
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error {},
  api: {
    onboarding: {
      getProgress: vi.fn(async () => ({
        completed_steps: state.completed ? ['first_searches'] : [],
        skipped_steps: [], dismissed: false, completed_at: null,
      })),
      getStatus: vi.fn(async (): Promise<OnboardingStatus> => ({
        has_ai_provider: state.completed, has_org_context: false,
        has_users: false, has_sso: state.completed, has_log_sources: false,
        has_parsers: false, has_search_history: false,
      })),
    },
    getSystemConfig: async () => ({ deployment_mode: 'standard' }),
    listLogSources: vi.fn(async () => state.completed ? [{ parser_vrl: '. = parse_json!(.message)', deployed: false }] : []),
    getTenantAiSettings: vi.fn(async () => ({ organizational_context: state.completed ? { industry: 'Healthcare' } : {} })),
    listUsers: vi.fn(async () => ({ users: state.completed
      ? [{ status: 'active', membership_status: 'active' }, { status: 'disabled', membership_status: 'suspended', invitation_state: 'pending' }]
      : [{ status: 'active', membership_status: 'active' }] })),
  },
}));

import { OnboardingWizard } from './OnboardingWizard';
import { api } from '@/lib/api';

afterEach(cleanup);

test('the mounted checklist fetches completion through the real query hooks on focus', async () => {
  render(<MemoryRouter><OnboardingWizard /></MemoryRouter>);
  await waitFor(() => expect(screen.getByText('Only you so far')).toBeTruthy());
  expect(screen.getByText('No feeds yet')).toBeTruthy();
  expect(screen.getByText('No parsers yet')).toBeTruthy();
  expect(screen.getByText('No searches yet')).toBeTruthy();

  state.completed = true;
  act(() => { window.dispatchEvent(new Event('focus')); });
  await waitFor(() => expect(screen.getByText('Finish setup')).toBeTruthy());
  for (const label of ['Providers configured', 'Guidance set', 'Team members added', 'SSO configured', 'Feed connected', 'Parser created', 'Searches run']) {
    expect(screen.getByText(label)).toBeTruthy();
  }
  for (const fetcher of [api.onboarding.getProgress, api.onboarding.getStatus, api.listLogSources, api.getTenantAiSettings, api.listUsers]) {
    expect(fetcher).toHaveBeenCalledTimes(2);
  }
});
