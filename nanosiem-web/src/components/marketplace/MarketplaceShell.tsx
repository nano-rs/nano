// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, Bot, Check, ChevronDown, Cloud, Database, Package, Plug, RefreshCw, Search as SearchIcon, Shield, Star, Users, X as XIcon, Box, FileDown } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import type { CatalogStats, EnrichmentMarketplaceRepo } from '@/lib/api/marketplace';
import { formatUTCCompact } from '@/lib/date-utils';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

export type CategoryFilter = 'all' | 'data' | 'agent' | 'identity' | 'collector';

export interface CategoryChip {
  id: CategoryFilter;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

export const CATEGORY_CHIPS: CategoryChip[] = [
  { id: 'all',      label: 'All',      icon: Box },
  { id: 'data',     label: 'Data',     icon: Database },
  { id: 'agent',    label: 'Agent',    icon: Bot },
  { id: 'identity', label: 'Identity', icon: Users },
  { id: 'collector', label: 'Collector', icon: Plug },
];

interface SectionDef {
  key: 'popular' | 'security' | 'cloud';
  title: string;
  icon: React.ReactNode;
  slugs: string[];
}

export const SECTIONS: SectionDef[] = [
  {
    key: 'popular',
    title: 'Popular integrations',
    icon: <Star className="w-[12px] h-[12px] text-muted-foreground" />,
    slugs: ['abuseipdb', 'virustotal', 'google-workspace', 'greynoise'],
  },
  {
    key: 'security',
    title: 'Security tools',
    icon: <Shield className="w-[12px] h-[12px] text-muted-foreground" />,
    slugs: ['malwarebazaar', 'otx-alienvault', 'shodan', 'urlhaus', 'threatfox', 'tor-exit-nodes'],
  },
  {
    key: 'cloud',
    title: 'Cloud infrastructure',
    icon: <Cloud className="w-[12px] h-[12px] text-muted-foreground" />,
    slugs: ['ipinfo-lite', 'ipinfo_lite', 'active-directory', 'entra-id', 'okta', 'workday'],
  },
];

export const SECTIONED_SLUGS = new Set(SECTIONS.flatMap(s => s.slugs));

/** Where connectivity-required items + the hero CTA route to side-load bundles. */
export const AIRGAP_IMPORT_ROUTE = '/settings/airgap-import';

interface MarketplacePageShellProps<Filter extends string> {
  totalCount: number;
  repos: EnrichmentMarketplaceRepo[];
  airGap: boolean;
  headerActions?: React.ReactNode;
  statsStrip: React.ReactNode;
  coverage?: React.ReactNode;
  chips: { id: Filter; label: string; icon: React.ComponentType<{ className?: string }>; count: number }[];
  categoryFilter: Filter;
  setCategoryFilter: (value: Filter) => void;
  searchQuery: string;
  setSearchQuery: (value: string) => void;
  installedOnly: boolean;
  toggleInstalledOnly: () => void;
  toggleLabel?: string;
  sourcesMenu: React.ReactNode;
  children: React.ReactNode;
  overlays?: React.ReactNode;
}

export function MarketplacePageShell<Filter extends string>({
  totalCount, repos, airGap, headerActions, statsStrip, coverage, chips,
  categoryFilter, setCategoryFilter, searchQuery, setSearchQuery, installedOnly,
  toggleInstalledOnly, toggleLabel = 'installed only', sourcesMenu, children, overlays,
}: MarketplacePageShellProps<Filter>) {
  const repoCount = repos.length;
  const lastSyncedAt = repos
    .map(r => r.last_synced_at)
    .filter((s): s is string => !!s)
    .sort()
    .at(-1);

  // Hotkeys: ⌘K focus search, Esc clear search, "/" focus search.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const isInput = (e.target as HTMLElement)?.tagName === 'INPUT' || (e.target as HTMLElement)?.tagName === 'TEXTAREA';
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        document.getElementById('marketplace-search')?.focus();
      } else if (e.key === '/' && !isInput) {
        e.preventDefault();
        document.getElementById('marketplace-search')?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <div className="flex flex-col px-6 pt-5 pb-6">
      {/* Header */}
      <div className="flex items-end gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground/80">
            <Package className="h-[11px] w-[11px]" />
            Marketplace · SIEM
          </div>
          <h1 className="mt-1 text-[20px] font-semibold tracking-[-0.015em] text-foreground">
            Install, configure and orchestrate your integrations
          </h1>
          <p className="mt-0.5 text-[12px] text-muted-foreground">
            <span className="tabular-nums text-foreground">{totalCount}</span> integrations from{' '}
            <span className="tabular-nums text-foreground">{repoCount}</span>{' '}
            {repoCount === 1 ? 'repository' : 'repositories'}
            {repoCount > 0 && <> · {repoCadenceLabel(repos)}</>}
            {lastSyncedAt && (
              <>
                {' · '}last sync <span className="font-mono text-foreground">{formatUTCCompact(lastSyncedAt)}</span>
              </>
            )}
          </p>
        </div>
        <span className="flex-1" />
        <div className="flex items-center gap-2">
          {/* Air-gap: threat-intel/data comes in via signed bundles, so make
              import a first-class, prominent CTA. */}
          {airGap && (
            <Link to={AIRGAP_IMPORT_ROUTE}>
              <Button size="sm" className="h-8 rounded-md text-[12px]">
                <FileDown className="w-3.5 h-3.5" /> Import enrichment bundle
              </Button>
            </Link>
          )}
          {headerActions}
        </div>
      </div>

      {/* Stats strip */}
      {statsStrip}

      {/* Coverage hero — fetched independently from catalog/repos. The
          server returns a 6h effective-scope-partitioned Dragonfly cache
          hit, so the typical load is sub-millisecond; the manual-refresh
          button invalidates only the caller's partition. Skeleton renders
          while the first fetch is in flight so the catalog grid is unblocked. */}
      {coverage}

      {/* Repository controls are hidden in air-gap mode (GitHub-backed,
          egress-only). A side-load banner keeps that surface honest. */}
      {airGap && (
        <div className="mt-4 bg-card border border-border/60 rounded-lg px-4 py-3 flex items-center gap-3 shadow-none">
          <FileDown className="w-[14px] h-[14px] text-primary shrink-0" />
          <div className="min-w-0 flex-1">
            <div className="text-[12.5px] text-foreground font-medium">Air-gapped install</div>
            <div className="text-[11.5px] text-muted-foreground mt-0.5">
              Repository sync is disabled. Bring in threat-intel and data feeds by importing
              signed, offline bundles.
            </div>
          </div>
          <Link to={AIRGAP_IMPORT_ROUTE} className="shrink-0">
            <Button size="sm" className="h-7 rounded-md text-[11.5px]">
              <FileDown className="w-3 h-3" /> Import bundle
            </Button>
          </Link>
        </div>
      )}

      {/* Filter bar */}
      <div className="mt-4 bg-card border border-border/60 rounded-lg p-2.5 flex items-center gap-2 flex-wrap">
        <div className="flex items-center gap-1.5 flex-wrap">
          {chips.map(c => {
            const Icon = c.icon;
            const active = categoryFilter === c.id;
            const count = c.count;
            return (
              <button
                key={c.id}
                type="button"
                onClick={() => setCategoryFilter(c.id)}
                className={cn(
                  'inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md border text-[12px] transition-colors',
                  active
                    ? 'bg-primary/12 border-primary/40 text-primary'
                    : 'bg-muted/20 border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/40',
                )}
              >
                <Icon className="w-[12px] h-[12px]" />
                <span>{c.label}</span>
                <span
                  className={cn(
                    'font-mono text-[10px] tabular-nums px-1 rounded',
                    active ? 'bg-primary/20 text-primary' : 'bg-muted/40 text-muted-foreground',
                  )}
                >
                  {count}
                </span>
              </button>
            );
          })}
        </div>
        <div className="w-px h-6 bg-border mx-1" />
        <div className="flex items-center gap-2 flex-1 min-w-[200px] h-8 px-2.5 rounded-md bg-muted/20 border border-border/60 focus-within:border-primary/50">
          <SearchIcon className="w-[13px] h-[13px] text-muted-foreground" />
          <Input
            id="marketplace-search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search enrichments, telemetry, vendors…"
            className="flex-1 bg-transparent border-0 p-0 h-auto text-[12.5px] focus-visible:ring-0 focus-visible:ring-offset-0 shadow-none"
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              className="text-muted-foreground hover:text-foreground"
              aria-label="Clear search"
            >
              <XIcon className="w-[11px] h-[11px]" />
            </button>
          )}
        </div>
        <button
          type="button"
          onClick={toggleInstalledOnly}
          className={cn(
            'h-7 px-2.5 rounded-md border text-[11.5px] flex items-center gap-1.5 font-mono transition-colors',
            installedOnly
              ? 'bg-primary/10 border-primary/40 text-primary'
              : 'bg-muted/20 border-border/60 text-muted-foreground hover:text-foreground',
          )}
        >
          <Check className="w-[11px] h-[11px]" /> {toggleLabel}
        </button>
        {!airGap && (
          <>
            <div className="w-px h-6 bg-border mx-0.5" />
            {sourcesMenu}
          </>
        )}
      </div>

      {/* Card grid */}
      {children}

      {/* Footer hint row */}
      <div className="mt-3 pt-3 border-t border-border/60 flex items-center font-mono text-[10.5px] text-muted-foreground tabular-nums">
        <span className="text-foreground">{repoCadenceLabel(repos)}</span>
        <span className="mx-2 text-muted-foreground/40">·</span>
        new integrations install in <span className="text-foreground px-1">~ 8s</span>
        <span className="flex-1" />
        <span>⌘K search · / search</span>
      </div>

      {overlays}
    </div>
  );
}

export function countForCategory(cat: CategoryFilter, stats: CatalogStats | null, collectorCount: number): number {
  if (!stats) return 0;
  if (cat === 'all') return stats.total_entries;
  if (cat === 'data') return stats.data_count;
  if (cat === 'agent') return stats.agent_count;
  if (cat === 'identity') return stats.identity_count;
  if (cat === 'collector') return collectorCount;
  return 0;
}

export function StatsStrip({ stats, tiles }: { stats: CatalogStats; tiles?: { label: string; value: number }[] }) {
  const cards = [
    { label: 'Active',   value: stats.installed_count, icon: Box,     tone: 'var(--primary)' },
    { label: 'Data',     value: stats.data_count,     icon: Database, tone: 'oklch(72% 0.18 28)' },
    { label: 'Agent',    value: stats.agent_count,    icon: Bot,      tone: 'oklch(80% 0.13 78)' },
    { label: 'Identity', value: stats.identity_count, icon: Users,    tone: 'oklch(70% 0.16 160)' },
  ];
  return (
    <div className="mt-4 grid grid-cols-2 lg:grid-cols-4 gap-3">
      {cards.map((card, index) => {
        const c = { ...card, ...tiles?.[index] };
        const Icon = c.icon;
        return (
          <div key={c.label} className="bg-card border border-border/60 rounded-lg px-4 py-3 shadow-none">
            <div className="flex items-center gap-2 mb-1.5">
              <Icon className="w-[12px] h-[12px]" style={{ color: c.tone }} />
              <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
                {c.label}
              </div>
            </div>
            <div className="font-semibold tabular-nums text-foreground leading-none" style={{ fontSize: '24px' }}>
              {c.value}
            </div>
          </div>
        );
      })}
    </div>
  );
}

type RepoHealth = 'good' | 'warn' | 'danger';

function getRepoHealth(repo: EnrichmentMarketplaceRepo, syncingId: string | null): RepoHealth {
  if (repo.last_sync_status === 'failed') return 'danger';
  if (
    syncingId === repo.id ||
    repo.last_sync_status === 'syncing' ||
    repo.last_sync_status === 'pending' ||
    repo.last_sync_status === 'stale'
  ) {
    return 'warn';
  }
  if (repo.last_sync_status !== 'success' || !repo.last_synced_at) return 'warn';

  const lastSyncedAt = Date.parse(repo.last_synced_at);
  const staleAfterMs = Math.max(repo.sync_interval_hours, 1) * 60 * 60 * 1000;
  return Number.isNaN(lastSyncedAt) || Date.now() - lastSyncedAt > staleAfterMs ? 'warn' : 'good';
}

function repoTone(repo: EnrichmentMarketplaceRepo, syncingId: string | null): string {
  const health = getRepoHealth(repo, syncingId);
  if (health === 'danger') return 'var(--color-danger)';
  if (health === 'warn') return 'var(--color-warn)';
  return 'var(--color-good)';
}

function rollupTone(repos: EnrichmentMarketplaceRepo[], syncingId: string | null): string {
  const health = repos.map(repo => getRepoHealth(repo, syncingId));
  if (health.includes('danger')) return 'var(--color-danger)';
  if (health.includes('warn') || repos.length === 0) return 'var(--color-warn)';
  return 'var(--color-good)';
}

function rollupLabel(repos: EnrichmentMarketplaceRepo[], syncingId: string | null): string {
  if (repos.length === 0) return 'No repository sources configured';
  const health = repos.map(repo => getRepoHealth(repo, syncingId));
  const failed = health.filter(value => value === 'danger').length;
  const attention = health.filter(value => value === 'warn').length;
  if (failed > 0) return `${failed} source${failed === 1 ? '' : 's'} failed to sync`;
  if (attention > 0) return `${attention} source${attention === 1 ? '' : 's'} need attention`;
  return `All ${repos.length} source${repos.length === 1 ? '' : 's'} synced`;
}

function repoStatusLabel(repo: EnrichmentMarketplaceRepo, syncingId: string | null): string {
  if (syncingId === repo.id || repo.last_sync_status === 'syncing' || repo.last_sync_status === 'pending') {
    return 'syncing';
  }
  if (repo.last_sync_status === 'failed') return 'sync failed';
  if (getRepoHealth(repo, syncingId) === 'warn' && repo.last_synced_at) return 'behind';
  if (repo.last_sync_status === 'success' && repo.last_synced_at) {
    return `synced ${formatUTCCompact(repo.last_synced_at)}`;
  }
  return 'not synced';
}

function repoPurpose(repo: EnrichmentMarketplaceRepo): { kind: string; detail: string } {
  const identity = `${repo.slug} ${repo.name} ${repo.url}`.toLowerCase();
  if (identity.includes('nano-integrations') || identity.includes('nano integrations')) {
    return {
      kind: 'Data collection',
      detail: 'Scheduled pull collectors that connect to external platforms and bring their primary events and logs into nano.',
    };
  }
  if (identity.includes('nano-enrichments') || identity.includes('nano enrichments')) {
    return {
      kind: 'Data enrichment',
      detail: 'Threat-intel, lookup, and transformation content that adds context to telemetry already in nano; it does not collect source events.',
    };
  }
  return {
    kind: 'Marketplace source',
    detail: repo.description || 'A Git-backed source of installable marketplace content.',
  };
}

function repoContentCount(repo: EnrichmentMarketplaceRepo): string {
  const kind = repoPurpose(repo).kind;
  const noun = kind === 'Data enrichment'
    ? 'enrichments'
    : kind === 'Data collection'
      ? 'collectors'
      : 'items';
  return `${repo.enrichment_count} ${noun}`;
}

export function repoCadenceLabel(repos: EnrichmentMarketplaceRepo[]): string {
  const intervals = [...new Set(
    repos
      .filter(repo => repo.auto_sync_enabled)
      .map(repo => repo.sync_interval_hours)
      .filter(hours => Number.isFinite(hours) && hours > 0),
  )];
  if (intervals.length === 0) return 'auto-sync disabled';
  if (intervals.length > 1) return 'auto-sync by source schedule';
  const hours = intervals[0];
  return `auto-sync every ${hours}h`;
}

interface SourcesMenuProps {
  repos: EnrichmentMarketplaceRepo[];
  syncingId: string | null;
  onSync: (id: string) => void;
}

export function SourcesMenu({ repos, syncingId, onSync }: SourcesMenuProps) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  const tone = rollupTone(repos, syncingId);
  const summary = rollupLabel(repos, syncingId);

  return (
    <div className="relative shrink-0" ref={menuRef}>
      <button
        type="button"
        onClick={() => setOpen(value => !value)}
        aria-expanded={open}
        aria-controls="marketplace-repository-sources"
        aria-haspopup="dialog"
        aria-label={`${summary}. ${open ? 'Hide' : 'Show'} repository sources`}
        title={summary}
        className={cn(
          'h-7 px-2.5 rounded-md border text-[11.5px] font-mono flex items-center gap-2 whitespace-nowrap transition-colors',
          open
            ? 'bg-muted/50 border-border text-foreground'
            : 'bg-muted/20 border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/40',
        )}
      >
        <span
          className="w-[5px] h-[5px] rounded-full shrink-0"
          style={{ background: tone, boxShadow: `0 0 5px ${tone}` }}
        />
        <span>sources</span>
        <span className="text-foreground tabular-nums">{repos.length}</span>
        <ChevronDown className={cn('w-[11px] h-[11px] transition-transform', open && 'rotate-180')} />
      </button>

      {open && (
        <div
          id="marketplace-repository-sources"
          role="dialog"
          aria-label="Repository sources"
          className="absolute right-0 top-9 z-50 w-[min(520px,calc(100vw-3rem))] rounded-lg border border-border bg-popover p-1.5 text-popover-foreground shadow-[0_18px_40px_-12px_rgba(0,0,0,0.7)]"
        >
          <div className="flex items-center justify-between px-2 pt-1.5 pb-2">
            <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
              Repository sources
            </div>
            <span className="min-w-0 truncate font-mono text-[10px] text-muted-foreground">{summary}</span>
          </div>

          <TooltipProvider delayDuration={250}>
            <div className="max-h-[min(420px,70vh)] overflow-y-auto">
              {repos.length === 0 ? (
                <div className="px-2 py-5 text-center font-mono text-[10.5px] text-muted-foreground">
                  No repository sources configured
                </div>
              ) : repos.map(repo => {
                const isSyncing = syncingId === repo.id || repo.last_sync_status === 'syncing' || repo.last_sync_status === 'pending';
                const statusTone = repoTone(repo, syncingId);
                const purpose = repoPurpose(repo);
                return (
                  <div key={repo.id} className="flex items-center gap-2.5 rounded-md px-2 py-2 hover:bg-muted/30">
                    <span className="w-[5px] h-[5px] rounded-full shrink-0" style={{ background: statusTone }} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="truncate text-[12px] text-foreground underline decoration-dotted decoration-muted-foreground/60 underline-offset-2 cursor-help" tabIndex={0}>
                              {repo.name}
                            </span>
                          </TooltipTrigger>
                          <TooltipContent side="top" align="start" sideOffset={7} className="max-w-[320px] px-3 py-2">
                            <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-primary">
                              {purpose.kind}
                            </div>
                            <div className="mt-1 text-[11px] leading-relaxed text-popover-foreground">
                              {purpose.detail}
                            </div>
                          </TooltipContent>
                        </Tooltip>
                        <span className="shrink-0 rounded border border-primary/30 bg-primary/10 px-1 font-mono text-[9px] uppercase leading-[14px] tracking-[0.1em] text-primary">
                          official
                        </span>
                        <span className="hidden shrink-0 font-mono text-[10px] tabular-nums text-muted-foreground sm:inline">
                          {repoContentCount(repo)}
                        </span>
                      </div>
                      <div className="mt-0.5 truncate font-mono text-[10.5px] text-muted-foreground">{repo.url}</div>
                      {repo.managed_by_platform && (
                        <div className="font-mono text-[10.5px] text-muted-foreground">
                          Managed by nano · last synced {repo.last_synced_at ? formatUTCCompact(repo.last_synced_at) : 'never'}
                        </div>
                      )}
                    </div>
                    <div className="hidden shrink-0 flex-col items-end gap-0.5 sm:flex">
                      <span className="font-mono text-[10.5px] text-muted-foreground">
                        {repo.branch}
                        {repo.last_sync_commit && <> · {repo.last_sync_commit.slice(0, 7)}</>}
                      </span>
                      <span className="font-mono text-[10px]" style={{ color: statusTone }}>
                        {repoStatusLabel(repo, syncingId)}
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => onSync(repo.id)}
                      disabled={isSyncing}
                      aria-label={`${repo.managed_by_platform ? 'Sync now' : 'Sync'} ${repo.name}`}
                      className="inline-flex h-6 shrink-0 items-center gap-1 rounded px-2 font-mono text-[10.5px] text-muted-foreground hover:bg-primary/10 hover:text-primary disabled:opacity-50"
                    >
                      <RefreshCw className={cn('w-[10px] h-[10px]', isSyncing && 'animate-spin')} />
                      {repo.managed_by_platform ? 'Sync now' : 'sync'}
                    </button>
                  </div>
                );
              })}
            </div>
          </TooltipProvider>

          <div className="mt-1 flex items-center justify-end border-t border-border/60 px-2 pt-2 pb-1">
            <span className="font-mono text-[10px] text-muted-foreground/70">{repoCadenceLabel(repos)}</span>
          </div>
        </div>
      )}
    </div>
  );
}

interface SectionProps {
  icon: React.ReactNode;
  title: string;
  count: number;
  children: React.ReactNode;
}

export function Section({ icon, title, count, children }: SectionProps) {
  return (
    <section>
      <div className="flex items-center gap-2 mb-2.5">
        {icon}
        <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
          {title}
        </div>
        <span className="font-mono text-[10px] text-muted-foreground/60 tabular-nums">· {count}</span>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
        {children}
      </div>
    </section>
  );
}

export function EmptyState() {
  return (
    <div className="mt-8 bg-card border border-border/60 rounded-lg p-10 text-center shadow-none">
      <SearchIcon className="w-6 h-6 text-muted-foreground/60 mx-auto mb-3" />
      <div className="text-[14px] text-foreground">No integrations matched.</div>
      <div className="text-[12px] text-muted-foreground mt-1">
        Try clearing filters or check the repository sources in the filter bar.
      </div>
    </div>
  );
}

/**
 * NAN-3761: the catalog could not be loaded. Never rendered as "No
 * integrations matched": an empty list after a failed load is unknown, not
 * empty.
 */
export function LoadErrorState({ what, onRetry, retrying = false }: { what: string; onRetry: () => void; retrying?: boolean }) {
  return (
    <div role="alert" className="mt-8 bg-card border border-border/60 rounded-lg p-10 text-center shadow-none">
      <AlertTriangle className="w-6 h-6 text-destructive/80 mx-auto mb-3" />
      <div className="text-[14px] text-foreground">Could not load {what}.</div>
      <div className="text-[12px] text-muted-foreground mt-1">
        The list below is incomplete, not empty. Retry to load it again.
      </div>
      <Button size="sm" variant="outline" className="mt-3 h-7 rounded-md text-[12px]" onClick={onRetry} disabled={retrying}>
        <RefreshCw className={cn('w-3.5 h-3.5', retrying && 'animate-spin')} /> Retry
      </Button>
    </div>
  );
}
