// SPDX-License-Identifier: AGPL-3.0-or-later
export interface SyncRow {
  id: string;
  last_sync_status?: string | null;
  last_synced_at?: string | null;
  updated_at?: string;
  sync_started_at?: string | null;
  sync_lease_expires_at?: string | null;
}

export function repositorySyncPollInterval(repos: readonly SyncRow[], now = Date.now()): number | false {
  return repos.some((repo) => repo.last_sync_status === 'syncing' &&
    (!repo.sync_started_at || now - Date.parse(repo.sync_started_at) < 65 * 60_000)) ? 1500 : false;
}

/** Tracks accepted work even if it finishes before the first GET poll. */
export class RepositorySyncTracker {
  private previous = new Map<string, string>();
  private accepted = new Map<string, number>();

  start(id: string, startedAt?: string) {
    this.accepted.set(id, startedAt ? Date.parse(startedAt) : Date.now());
  }

  observe<R extends SyncRow>(repo: R): boolean {
    const previous = this.previous.get(repo.id);
    const accepted = this.accepted.get(repo.id);
    this.previous.set(repo.id, repo.last_sync_status ?? '');
    if (!repo.last_sync_status || repo.last_sync_status === 'syncing') return false;
    const completedAt = Math.max(Date.parse(repo.updated_at ?? '') || 0, Date.parse(repo.last_synced_at ?? '') || 0);
    if (accepted !== undefined && completedAt < accepted) return false;
    if (previous !== 'syncing' && accepted === undefined) return false;
    this.accepted.delete(repo.id);
    return true;
  }
}

/** A hosted-shared tenant's platform catalogs (NAN-2975 / NAN-3203). */
export type PlatformCatalog = 'nano-rs/parsers' | 'nano-rs/rules' | 'nano-rs/playbooks';

/** Poll cadence while a platform catalog is still being set up (NAN-3436). */
export const PLATFORM_CATALOG_SETUP_POLL_MS = 5_000;

function isPlatformCatalogUrl(url: string, catalog: PlatformCatalog): boolean {
  const normalized = url.trim().toLowerCase().replace(/\/+$/, '').replace(/\.git$/, '');
  return normalized === `https://github.com/${catalog}` || normalized.endsWith(`//github.com/${catalog}`);
}

/**
 * NAN-3436: a new hosted-shared tenant's platform catalogs are copied in the
 * background after activation (and retried every minute by the platform), so
 * for a short while after first login the catalog row is missing or has never
 * synced. That is "setting up content", not "no repositories": the page must
 * not offer to connect the catalog by hand (racing the platform) or show an
 * empty catalog as final.
 */
export function platformCatalogSettingUp(
  sharedTenant: boolean,
  repos: readonly (SyncRow & { url: string })[],
  catalog: PlatformCatalog,
): boolean {
  if (!sharedTenant) return false;
  const row = repos.find((repo) => isPlatformCatalogUrl(repo.url, catalog));
  if (!row) return true;
  return !row.last_synced_at && row.last_sync_status !== 'failed';
}

/** Whether the page should show the full setting-up state: the platform
 * catalog is being set up and no other repository has synced content yet. */
export function platformCatalogSetupBlocksPage(
  sharedTenant: boolean,
  repos: readonly (SyncRow & { url: string })[],
  catalog: PlatformCatalog,
): boolean {
  return platformCatalogSettingUp(sharedTenant, repos, catalog) && repos.every((repo) => !repo.last_synced_at);
}
