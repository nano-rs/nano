// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ParserRepositories } from './ParserRepositories';
import { RuleRepositories } from './RuleRepositories';
import { AddRepoDrawer as AddParserRepo } from '@/components/parser-repositories/ParserRepoDrawers';
import { AddRepoDrawer as AddRuleRepo } from '@/components/repositories/RepoDrawers';

const requests = vi.hoisted(() => ({
  parsers: vi.fn().mockRejectedValue(new Error('creation captured')),
  rules: vi.fn().mockRejectedValue(new Error('creation captured')),
}));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true }) }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/lib/api', () => ({ api: {
  getSystemConfig: () => Promise.resolve({ air_gap: false }),
  getSourceTypes: () => Promise.resolve([]),
  listSourceConfigs: () => Promise.resolve([]),
  parserRepositories: { listRepositories: () => Promise.resolve({ repositories: [] }), createRepository: requests.parsers },
  ruleRepositories: { listRepositories: () => Promise.resolve({ repositories: [] }), createRepository: requests.rules },
  detectionCodeTargets: { listTargets: () => Promise.resolve([]) },
} }));

afterEach(() => { cleanup(); vi.clearAllMocks(); });

it.each([
  ['parsers', ParserRepositories, requests.parsers, 'parsers/'],
  ['rules', RuleRepositories, requests.rules, ''],
] as const)('one-click Add nano %s requests the main branch with auto-sync on', async (kind, Page, create, path) => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><Page /></MemoryRouter></QueryClientProvider>);
  fireEvent.click(await screen.findByRole('button', { name: `Add nano ${kind}` }));
  await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({
    url: `https://github.com/nano-rs/${kind}`, branch: 'main', auto_sync_enabled: true,
    [kind === 'parsers' ? 'parsers_path' : 'rules_path']: path,
  })));
  client.clear();
});

it.each([
  ['parsers', AddParserRepo], ['rules', AddRuleRepo],
] as const)('manual %s creation lets the server choose defaults and preserves an explicit pin', (kind, Drawer) => {
  const submit = vi.fn();
  render(<Drawer open onClose={vi.fn()} onSubmit={submit} />);
  fireEvent.change(screen.getByPlaceholderText(kind === 'parsers' ? 'acme parsers (internal)' : 'acme rules (internal)'), { target: { value: 'Custom catalog' } });
  fireEvent.change(screen.getByPlaceholderText(kind === 'parsers' ? 'https://github.com/acme-corp/parsers' : 'https://github.com/acme-corp/nano-rules'), { target: { value: `https://github.com/nano-rs/${kind}` } });
  fireEvent.click(screen.getByRole('button', { name: /Connect & sync/ }));
  expect(submit).toHaveBeenLastCalledWith(expect.objectContaining({ branch: undefined }));
  fireEvent.change(screen.getByPlaceholderText('Automatic'), { target: { value: 'operator-pin' } });
  fireEvent.click(screen.getByRole('button', { name: /Connect & sync/ }));
  expect(submit).toHaveBeenLastCalledWith(expect.objectContaining({ branch: 'operator-pin' }));
});
