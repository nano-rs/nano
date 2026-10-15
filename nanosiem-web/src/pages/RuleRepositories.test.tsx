// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-3250: /rules/repositories (and the /rules/marketplace alias) flows in the
 * app scroller; the master-detail grid keeps a bounded box that cannot collapse.
 */
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { RepositoryRule, RuleRepository } from '@/lib/api/rule-repositories';
import { RuleRepositories } from './RuleRepositories';

const ts = '2026-10-07T12:00:00Z';
const repo: RuleRepository = {
  id: 'repo1', name: 'nano rules', slug: 'nano-rules', description: null, url: 'https://github.com/nano-rs/rules',
  branch: 'main', rules_path: null, rule_format: 'nanosiem', auto_sync_enabled: true, sync_interval_hours: 24,
  last_synced_at: ts, last_sync_commit: 'abcdef1234567', last_sync_status: 'success', last_sync_error: null,
  rule_count: 1, enabled: true, created_at: ts, updated_at: ts, created_by: null, selected_paths: null,
};
const rule: RepositoryRule = {
  id: 'rule1', repository_id: 'repo1', file_path: 'auth/impossible_travel.yml', file_sha: null, raw_content: '',
  is_imported: false, title: 'Impossible travel', description: null, severity: 'high', mitre_tactics: null,
  mitre_techniques: ['T1078'], tags: null, requires_fields: null, requires_source_types: ['okta'],
  conversion_status: 'success', converted_npl: null, conversion_confidence: null, conversion_warnings: null,
  conversion_field_mappings: null, coverage_status: null, coverage_missing_fields: null, created_at: ts, updated_at: ts,
};

const fixture = vi.hoisted(() => ({
  user: undefined as undefined | { deployment_mode: string },
  repositories: null as null | unknown[],
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: () => true, user: fixture.user }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/lib/api', () => ({
  api: {
    getSystemConfig: () => Promise.resolve({ air_gap: false }),
    getSourceTypes: () => Promise.resolve([]),
    ruleRepositories: {
      listRepositories: () => Promise.resolve({ repositories: fixture.repositories ?? [repo] }),
      listRules: () => Promise.resolve([rule]),
      getUpstreamUpdates: () => Promise.resolve({ updates: [], total_count: 0 }),
    },
    detectionCodeTargets: { listTargets: () => Promise.resolve([]) },
  },
}));

afterEach(() => {
  cleanup();
  fixture.user = undefined;
  fixture.repositories = null;
});

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <RuleRepositories />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// NAN-3436: activation no longer waits for the platform catalogs; until the
// background follow lands, a new hosted-shared workspace sees "setting up
// content", never "no repositories" with a connect button racing the platform.
it('shows setting up content on a new shared tenant before the catalog row exists', async () => {
  fixture.user = { deployment_mode: 'enterprise_shared' };
  fixture.repositories = [];
  renderPage();
  const status = await screen.findByTestId('platform-catalog-setting-up');
  expect(status.textContent).toContain('Setting up content');
  expect(status.textContent).toContain('nano-rs/rules');
  expect(screen.queryByText('No repositories connected')).toBeNull();
  expect(screen.queryByText('Connect a repo')).toBeNull();
});

it('shows setting up content while the platform catalog first sync is in flight', async () => {
  fixture.user = { deployment_mode: 'enterprise_shared' };
  fixture.repositories = [{ ...repo, last_synced_at: null, last_sync_commit: null, last_sync_status: 'syncing', rule_count: 0 }];
  renderPage();
  expect(await screen.findByTestId('platform-catalog-setting-up')).toBeTruthy();
});

it('keeps the normal empty state on a dedicated deployment', async () => {
  fixture.repositories = [];
  renderPage();
  expect(await screen.findByText('No repositories connected')).toBeTruthy();
  expect(screen.queryByTestId('platform-catalog-setting-up')).toBeNull();
});

it('flows in the app scroller: no fill-height page; the rule grid is bounded but cannot collapse', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <RuleRepositories />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  const grid = await screen.findByTestId('rule-repositories-grid');
  const page = screen.getByTestId('rule-repositories-page');
  expect(page.className).not.toMatch(/(^|\s)(min-h-0|overflow-hidden)(\s|$)/);
  expect(page.className).not.toMatch(/(^|\s)h-\[calc\(100%/);

  // Not a leftover-height flex child; a definite height with a floor.
  expect(grid.className).not.toMatch(/(^|\s)(min-h-0|flex-1)(\s|$)/);
  expect(grid.className).toContain('h-[max(36rem,');
  await waitFor(() => expect(within(grid).getByText('Impossible travel')).toBeTruthy());
});
