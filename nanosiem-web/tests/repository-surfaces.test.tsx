// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { SourcesMenu } from '../src/pages/Marketplace';
import { SyncHistoryDrawer } from '../src/components/repositories/RepoDrawers';
import { ReposHeader } from '../src/components/repositories/ReposTable';
import { RepoSidebar } from '../src/components/repositories/RepoSidebar';
import { buildRepoView } from '../src/components/repositories/helpers';
import { TooltipProvider } from '../src/components/ui/tooltip';
import { MarketplaceApi } from '../src/lib/api/marketplace';
import type { EnrichmentMarketplaceRepo } from '../src/lib/api/marketplace';
import type { RuleRepository } from '../src/lib/api/rule-repositories';

afterEach(cleanup);

const marketplace = (managed: boolean): EnrichmentMarketplaceRepo => ({
  id: managed ? 'platform' : 'tenant', name: managed ? 'nano Enrichments' : 'My enrichments',
  slug: 'enrichments', url: 'https://github.com/nano-rs/enrichments', branch: 'main',
  enrichments_path: 'enrichments', auto_sync_enabled: true, sync_interval_hours: 24,
  enrichment_count: 0, enabled: true, created_at: '', updated_at: '', managed_by_platform: managed,
});

const rule = (managed: boolean): RuleRepository => ({
  id: 'rules', name: 'nano rules', slug: 'rules', url: 'https://github.com/nano-rs/rules',
  description: null, branch: 'main', rules_path: null, rule_format: 'sigma',
  auto_sync_enabled: true, sync_interval_hours: 24, last_synced_at: null,
  last_sync_commit: null, last_sync_status: null, last_sync_error: null, rule_count: 0,
  enabled: true, created_at: '', updated_at: '', created_by: null, selected_paths: null,
  managed_by_platform: managed,
});

describe('repository ownership', () => {
  it('preserves the accepted contract on the existing sync endpoint', async () => {
    const accepted = { request_id: 'request', repository_id: 'platform', managed_by_platform: true, status: 'accepted' };
    const request = vi.fn().mockResolvedValue(accepted);
    expect(await new MarketplaceApi(request).syncRepo('platform')).toEqual(accepted);
    expect(request).toHaveBeenCalledWith('/api/marketplace/repos/platform/sync', { method: 'POST' });
  });

  it('keeps Sync now available in platform repository history', () => {
    const sync = vi.fn();
    render(<SyncHistoryDrawer open onClose={vi.fn()} repo={buildRepoView(rule(true), [], [])} syncing={false} onSyncNow={sync} />);
    fireEvent.click(screen.getByRole('button', { name: 'Sync now' }));
    expect(sync).toHaveBeenCalledWith('rules');
  });

  it('disables duplicate clicks while a platform sync request is being sent', () => {
    const sync = vi.fn();
    render(<ReposHeader repo={buildRepoView(rule(true), [], [])} syncing onSyncNow={sync} onOpenHistory={vi.fn()} />);
    const button = screen.getByRole('button', { name: 'Syncing…' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.click(button);
    expect(sync).not.toHaveBeenCalled();
  });
  it('shows ownership and sends platform Sync now and tenant Sync through the same callback', () => {
    const sync = vi.fn();
    render(<SourcesMenu repos={[marketplace(true), marketplace(false)]} syncingId={null} onSync={sync} />);
    fireEvent.click(screen.getByRole('button', { name: /Show repository sources/ }));
    expect(screen.getByText('Managed by nano · last synced never')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Sync now nano Enrichments' }));
    expect(sync).toHaveBeenCalledWith('platform');
    fireEvent.click(screen.getByRole('button', { name: 'Sync My enrichments' }));
    expect(sync).toHaveBeenCalledWith('tenant');
  });

  it.each([true, false])('rule header respects explicit platform ownership %s', (managed) => {
    const sync = vi.fn();
    const repo = buildRepoView(rule(managed), [], []);
    render(<ReposHeader repo={repo} syncing={false} onSyncNow={sync} onOpenHistory={vi.fn()} />);
    const button = screen.queryByRole('button', { name: 'Sync now' });
    expect(button).toBeTruthy();
    if (button) { fireEvent.click(button); expect(sync).toHaveBeenCalledOnce(); }
    if (managed) expect(screen.getByText(/Managed by nano · last synced/)).toBeTruthy();
  });

  it.each([true, false])('rule sidebar respects explicit platform ownership %s', (managed) => {
    const sync = vi.fn();
    render(<TooltipProvider><RepoSidebar repos={[buildRepoView(rule(managed), [], [])]}
      activeRepoId="rules" syncingId={null} onActivate={vi.fn()} onSyncNow={sync}
      onOpenHistory={vi.fn()} onConfigureFolders={vi.fn()} /></TooltipProvider>);
    fireEvent.click(screen.getByRole('button', { name: managed ? 'Sync now' : 'Sync' }));
    expect(sync).toHaveBeenCalledWith('rules');
  });
});
