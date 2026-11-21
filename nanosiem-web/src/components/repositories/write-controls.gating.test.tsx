// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
/**
 * NAN-5709: /rules/repositories opens for rule_repositories:view (every user),
 * so its write controls render only when the page passes the handler, which it
 * does per permission: Sync on rule_repositories:sync, Configure folders on
 * :manage + :sync, Add nano rules on :manage.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { TooltipProvider } from '@/components/ui/tooltip';
import { RepoSidebar } from './RepoSidebar';
import { ReposHeader } from './ReposTable';
import { SyncHistoryDrawer } from './RepoDrawers';
import type { RepoView } from './helpers';

afterEach(cleanup);

const repo = {
  id: 'rrepo_1',
  slug: 'nano-rs/rules',
  org: 'nano-rs',
  name: 'rules',
  url: 'https://github.com/nano-rs/rules',
  branch: 'main',
  visibility: 'public',
  total: 3,
  counts: { available: 1, needsUpdate: 0, imported: 2, drift: 0, deleted: 0 },
  lastCommit: { sha: 'abc1234' },
  lastSync: { ts: null, relative: '1m ago', result: 'ok' },
  nextSync: { in: '59m', cadence: 'hourly' },
  autoSync: 'hourly',
  raw: {},
} as unknown as RepoView;

const noop = () => {};

describe('repository write controls (NAN-5709)', () => {
  it('a view-only viewer gets no Sync or Configure folders', () => {
    render(
      <TooltipProvider>
        <ReposHeader repo={repo} onOpenHistory={noop} syncing={false} />
        <RepoSidebar repos={[repo]} activeRepoId={repo.id} onActivate={noop} onOpenHistory={noop} syncingId={null} />
        <SyncHistoryDrawer open onClose={noop} repo={repo} syncing={false} />
      </TooltipProvider>,
    );
    expect(screen.queryByRole('button', { name: /^Sync( now)?$/ })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Configure folders' })).toBeNull();
  });

  it('with the handlers, Sync and Configure folders render', () => {
    render(
      <TooltipProvider>
        <ReposHeader repo={repo} onSyncNow={noop} onOpenHistory={noop} syncing={false} />
        <RepoSidebar
          repos={[repo]}
          activeRepoId={repo.id}
          onActivate={noop}
          onSyncNow={noop}
          onOpenHistory={noop}
          onConfigureFolders={noop}
          syncingId={null}
        />
      </TooltipProvider>,
    );
    expect(screen.getAllByRole('button', { name: /^Sync( now)?$/ }).length).toBeGreaterThanOrEqual(2);
    expect(screen.getByRole('button', { name: 'Configure folders' })).toBeTruthy();
  });

  it('the page passes each handler only with its permission', () => {
    const page = readFileSync(resolve(__dirname, '../../pages/RuleRepositories.tsx'), 'utf8');
    expect(page).toContain("const canSync = hasPermission('rule_repositories:sync');");
    expect(page).toContain("const canManageRepos = hasPermission('rule_repositories:manage');");
    expect(page).toContain('const canConfigureFolders = canManageRepos && canSync;');
    expect(page.match(/onSyncNow=\{canSync \?/g)?.length).toBe(3);
    expect(page).toMatch(/onConfigureFolders=\{\s*canConfigureFolders/);
    expect(page).toMatch(/\{canManageRepos \? \(\s*<div[^>]*>\s*<button/);
  });
});
