// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-571 — Marketplace top-level page (Phase 1 of [NAN-570](https://linear.app/nanos-sh/issue/NAN-570)).
 *
 * Source of truth: design-ref/ui_kits/search/marketplace.html (design system 13).
 * Eyebrow + 20px H1 + meta line; flat 4-tile stats strip; flat repo source row;
 * mono-monogram cards with state badges; section grouping (Popular/Security/Cloud);
 * 4-tab drawer (About/Config/Code/Permissions) preserves all existing actions
 * (Sync Now, Export, Disable toggle, Edit-in-wizard, etc.).
 *
 * `security` 4th category, coverage hero, and "preview output" land in Phases 2-4.
 * Custom-enrichment wizard at /enrichments/custom/* is intentionally untouched.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Bot, Check, CheckCircle, Cloud, Database, GitBranch, Loader2,
  Package, Plus, RefreshCw, Search as SearchIcon, Shield, Star,
  Users, X as XIcon, Box,
} from 'lucide-react';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { useCapabilities } from '@/hooks/use-capabilities';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api } from '@/lib/api';
import type {
  CatalogStats,
  EnrichmentMarketplaceRepo,
  MarketplaceCatalogEntry,
} from '@/lib/api/marketplace';
import { useToast } from '@/hooks/use-toast';
import { formatUTCCompact } from '@/lib/date-utils';
import { cn } from '@/lib/utils';
import { IntegrationCard } from '@/components/marketplace/IntegrationCard';
import { MarketplaceDrawer } from '@/components/marketplace/MarketplaceDrawer';
import { InstallDialog } from '@/components/marketplace/InstallDialog';
import { CoverageHero } from '@/components/marketplace/CoverageHero';

type CategoryFilter = 'all' | 'data' | 'agent' | 'identity' | 'security';

interface CategoryChip {
  id: CategoryFilter;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

const CATEGORY_CHIPS: CategoryChip[] = [
  { id: 'all',      label: 'All',      icon: Box },
  { id: 'data',     label: 'Data',     icon: Database },
  { id: 'agent',    label: 'Agent',    icon: Bot },
  { id: 'identity', label: 'Identity', icon: Users },
  { id: 'security', label: 'Security', icon: Shield },
];

interface SectionDef {
  key: 'popular' | 'security' | 'cloud';
  title: string;
  icon: React.ReactNode;
  slugs: string[];
}

const SECTIONS: SectionDef[] = [
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

const SECTIONED_SLUGS = new Set(SECTIONS.flatMap(s => s.slugs));

export function Marketplace() {
  useDocumentTitle('Marketplace');
  useBreadcrumbTitle('Marketplace');

  const { capabilities } = useCapabilities();
  const { toast } = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const [entries, setEntries] = useState<MarketplaceCatalogEntry[]>([]);
  const [stats, setStats] = useState<CatalogStats | null>(null);
  const [repos, setRepos] = useState<EnrichmentMarketplaceRepo[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [installEntry, setInstallEntry] = useState<MarketplaceCatalogEntry | null>(null);
  const [detailSlug, setDetailSlug] = useState<string | null>(null);
  const [syncingRepo, setSyncingRepo] = useState<string | null>(null);

  const categoryFilter = (searchParams.get('category') as CategoryFilter | null) || 'all';
  const installedOnly = searchParams.get('installed') === 'true';

  const mountedRef = useRef(true);
  useEffect(() => () => { mountedRef.current = false; }, []);

  // Coverage is computed by a 12-countIf ClickHouse aggregate over the last 24h
  // of `logs` — it's the slowest piece on this page. Decouple it from the
  // catalog/repos load so the grid renders immediately, and cache aggressively
  // on both sides:
  //
  // - Server-side (NAN-609): a Dragonfly-backed shared cache (6h TTL) so a
  //   slow recompute on one replica warms every user's hero on every replica.
  //   `computed_at` in the response stamps the hero with "as of HH:MM".
  // - Client-side: a long React Query staleTime so navigating between pages
  //   in the same tab doesn't even hit the (already cheap) GET endpoint.
  //
  // The manual-refresh button calls the dedicated POST refresh endpoint —
  // that invalidates the *server-side* cache for everyone, then writes the
  // freshly-computed payload back into the React Query cache.
  const SIX_HOURS_MS = 6 * 60 * 60 * 1000;
  const queryClient = useQueryClient();
  const COVERAGE_QUERY_KEY = ['marketplace', 'coverage'] as const;
  const coverageQuery = useQuery({
    queryKey: COVERAGE_QUERY_KEY,
    queryFn: () => api.marketplace.getCoverage(),
    staleTime: SIX_HOURS_MS,
    gcTime: SIX_HOURS_MS,
    retry: false,
    refetchOnWindowFocus: false,
  });
  const coverageRefreshMutation = useMutation({
    mutationFn: () => api.marketplace.refreshCoverage(),
    onSuccess: (fresh) => {
      // Skip a second GET — the POST already returned the fresh payload.
      queryClient.setQueryData(COVERAGE_QUERY_KEY, fresh);
    },
    onError: () => {
      toast({
        title: 'Refresh failed',
        description: 'Coverage couldn’t be recomputed. Try again in a moment.',
        variant: 'destructive',
      });
    },
  });

  const loadAll = useCallback(async () => {
    try {
      const filter: Record<string, string | boolean> = {};
      if (categoryFilter !== 'all') filter.category = categoryFilter;
      if (installedOnly) filter.installed = true;

      const [catalog, repoList] = await Promise.all([
        api.marketplace.listCatalog(filter),
        api.marketplace.listRepos().catch(() => []),
      ]);
      setEntries(catalog.entries);
      setStats(catalog.stats);
      setRepos(repoList);
    } catch {
      toast({ title: 'Error', description: 'Failed to load marketplace', variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [categoryFilter, installedOnly, toast]);

  useEffect(() => { void loadAll(); }, [loadAll]);

  const filtered = useMemo(() => {
    if (!searchQuery.trim()) return entries;
    const q = searchQuery.toLowerCase();
    return entries.filter(e =>
      e.name.toLowerCase().includes(q) ||
      e.description?.toLowerCase().includes(q) ||
      e.tags.some(t => t.toLowerCase().includes(q)),
    );
  }, [entries, searchQuery]);

  const grouped = useMemo(() => {
    const slugMap = new Map(filtered.map(e => [e.slug, e]));
    const sections = SECTIONS.map(section => ({
      section,
      entries: section.slugs
        .map(s => slugMap.get(s))
        .filter((e): e is MarketplaceCatalogEntry => !!e),
    })).filter(s => s.entries.length > 0);
    const other = filtered.filter(e => !SECTIONED_SLUGS.has(e.slug));
    return { sections, other };
  }, [filtered]);

  const showSections = categoryFilter === 'all' && !searchQuery.trim() && !installedOnly;

  const setCategoryFilter = (value: CategoryFilter) => {
    const params = new URLSearchParams(searchParams);
    if (value === 'all') params.delete('category');
    else params.set('category', value);
    setSearchParams(params);
  };

  const toggleInstalledOnly = () => {
    const params = new URLSearchParams(searchParams);
    if (installedOnly) params.delete('installed');
    else params.set('installed', 'true');
    setSearchParams(params);
  };

  const handleCardOpen = (slug: string) => setDetailSlug(slug);
  const handleInstallClick = (slug: string) => {
    const entry = entries.find(e => e.slug === slug);
    if (!entry) return;
    if (entry.requires_credential !== 'none' && entry.credential_fields.length > 0) {
      setInstallEntry(entry);
    } else {
      void doInstall(slug);
    }
  };

  const doInstall = async (slug: string, credentials?: Record<string, string>) => {
    try {
      await api.marketplace.installEnrichment(slug, credentials ? { credentials } : undefined);
      toast({ title: 'Installed', description: 'Enrichment installed and enabled' });
      void loadAll();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to install';
      toast({ title: 'Error', description: msg, variant: 'destructive' });
      throw e;
    }
  };

  const handleSyncRepo = async (id: string) => {
    setSyncingRepo(id);
    try {
      await api.marketplace.syncRepo(id);
      toast({ title: 'Sync started', description: 'Repository sync running in the background' });
      // Poll a few times for the row to settle.
      const delays = [2000, 4000, 8000];
      for (const ms of delays) {
        await new Promise(r => setTimeout(r, ms));
        if (!mountedRef.current) return;
        const list = await api.marketplace.listRepos();
        if (!mountedRef.current) return;
        setRepos(list);
        const repo = list.find(r => r.id === id);
        if (!repo || (repo.last_sync_status !== 'syncing' && repo.last_sync_status !== 'pending')) {
          break;
        }
      }
      if (mountedRef.current) void loadAll();
    } catch {
      if (mountedRef.current) toast({ title: 'Error', description: 'Failed to start sync', variant: 'destructive' });
    } finally {
      if (mountedRef.current) setSyncingRepo(null);
    }
  };

  // Derive meta line numbers from real data.
  const totalCount = stats?.total_entries ?? 0;
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
            {' · '}pulls every 30 min
            {lastSyncedAt && (
              <>
                {' · '}last sync <span className="font-mono text-foreground">{formatUTCCompact(lastSyncedAt)}</span>
              </>
            )}
          </p>
        </div>
        <span className="flex-1" />
        {capabilities.customEnrichment && (
          <div className="flex items-center gap-2">
            <Link to="/enrichments/custom/new">
              <Button size="sm" className="h-8 rounded-md text-[12px]">
                <Plus className="w-3.5 h-3.5 mr-1" /> Create custom
              </Button>
            </Link>
          </div>
        )}
      </div>

      {/* Stats strip */}
      {stats && <StatsStrip stats={stats} />}

      {/* Coverage hero — fetched independently from catalog/repos. The
          server returns a 6h-shared Dragonfly cache hit, so the typical
          load is sub-millisecond; the manual-refresh button calls the
          dedicated POST endpoint which invalidates the shared cache for
          everyone. Skeleton renders while the very first fetch is in
          flight so the catalog grid is unblocked. */}
      <div className="mt-4">
        <CoverageHero
          coverage={coverageQuery.data ?? null}
          isLoading={coverageQuery.isLoading}
          isFetching={coverageQuery.isFetching || coverageRefreshMutation.isPending}
          isError={coverageQuery.isError}
          onRefresh={() => {
            // Don't double-fire while a refresh is already in flight.
            if (coverageRefreshMutation.isPending) return;
            coverageRefreshMutation.mutate();
          }}
          onAddMissing={(name) => {
            setSearchQuery(name);
            document.getElementById('marketplace-search')?.focus();
          }}
        />
      </div>

      {/* Repo sources */}
      {repos.length > 0 && (
        <div className="mt-4">
          <RepoSources repos={repos} syncingId={syncingRepo} onSync={handleSyncRepo} />
        </div>
      )}

      {/* Filter bar */}
      <div className="mt-4 bg-card border border-border/60 rounded-lg p-2.5 flex items-center gap-2 flex-wrap">
        <div className="flex items-center gap-1.5 flex-wrap">
          {CATEGORY_CHIPS.map(c => {
            const Icon = c.icon;
            const active = categoryFilter === c.id;
            const count = countForCategory(c.id, stats);
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
          <Check className="w-[11px] h-[11px]" /> installed only
        </button>
      </div>

      {/* Card grid */}
      {loading ? (
        <div className="mt-8 flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState />
      ) : showSections ? (
        <div className="mt-5 space-y-6">
          {grouped.sections.map(({ section, entries: secEntries }) => (
            <Section
              key={section.key}
              icon={section.icon}
              title={section.title}
              count={secEntries.length}
              entries={secEntries}
              onOpen={handleCardOpen}
              onInstall={handleInstallClick}
            />
          ))}
          {grouped.other.length > 0 && (
            <Section
              icon={<Package className="w-[12px] h-[12px] text-muted-foreground" />}
              title="Other integrations"
              count={grouped.other.length}
              entries={grouped.other}
              onOpen={handleCardOpen}
              onInstall={handleInstallClick}
            />
          )}
        </div>
      ) : (
        <div className="mt-5 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
          {filtered.map(entry => (
            <IntegrationCard
              key={entry.slug}
              entry={entry}
              onOpen={handleCardOpen}
              onInstall={handleInstallClick}
            />
          ))}
        </div>
      )}

      {/* Footer hint row */}
      <div className="mt-3 pt-3 border-t border-border/60 flex items-center font-mono text-[10.5px] text-muted-foreground tabular-nums">
        repositories sync every <span className="text-foreground px-1">30m</span>
        <span className="mx-2 text-muted-foreground/40">·</span>
        new integrations install in <span className="text-foreground px-1">~ 8s</span>
        <span className="flex-1" />
        <span>⌘K search · / search</span>
      </div>

      <InstallDialog
        entry={installEntry}
        open={!!installEntry}
        onOpenChange={(open) => !open && setInstallEntry(null)}
        onInstall={doInstall}
      />

      <MarketplaceDrawer
        slug={detailSlug}
        open={!!detailSlug}
        onOpenChange={(open) => !open && setDetailSlug(null)}
        onUpdated={loadAll}
      />
    </div>
  );
}

function countForCategory(cat: CategoryFilter, stats: CatalogStats | null): number {
  if (!stats) return 0;
  if (cat === 'all') return stats.total_entries;
  if (cat === 'data') return stats.data_count;
  if (cat === 'agent') return stats.agent_count;
  if (cat === 'identity') return stats.identity_count;
  if (cat === 'security') return stats.security_count ?? 0;
  return 0;
}

function StatsStrip({ stats }: { stats: CatalogStats }) {
  const cards = [
    { label: 'Active',   value: stats.installed_count, icon: Box,     tone: 'var(--primary)' },
    { label: 'Data',     value: stats.data_count,     icon: Database, tone: 'oklch(72% 0.18 28)' },
    { label: 'Agent',    value: stats.agent_count,    icon: Bot,      tone: 'oklch(80% 0.13 78)' },
    { label: 'Identity', value: stats.identity_count, icon: Users,    tone: 'oklch(70% 0.16 160)' },
  ];
  return (
    <div className="mt-4 grid grid-cols-2 lg:grid-cols-4 gap-3">
      {cards.map(c => {
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

interface RepoSourcesProps {
  repos: EnrichmentMarketplaceRepo[];
  syncingId: string | null;
  onSync: (id: string) => void;
}

function RepoSources({ repos, syncingId, onSync }: RepoSourcesProps) {
  return (
    <div className="bg-card border border-border/60 rounded-lg overflow-hidden shadow-none">
      <div className="px-4 py-2.5 flex items-center gap-2 border-b border-border/60 bg-muted/20">
        <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
          Repository source
        </div>
        <span className="font-mono text-[10px] text-muted-foreground/60">· git-backed enrichment bundle</span>
      </div>
      <div className="divide-y divide-border/60">
        {repos.map(r => {
          const synced = r.last_sync_status === 'success';
          const isSyncing = syncingId === r.id || r.last_sync_status === 'syncing' || r.last_sync_status === 'pending';
          return (
            <div key={r.id} className="flex items-center gap-3 px-4 py-2.5 hover:bg-muted/20">
              <GitBranch className="w-[13px] h-[13px] text-muted-foreground shrink-0" />
              <div className="flex items-center gap-2 min-w-0 shrink-0">
                <span className="text-[12.5px] text-foreground font-medium">{r.name}</span>
                <span className="text-[9.5px] font-mono uppercase tracking-[0.1em] px-1.5 py-px rounded border bg-primary/10 border-primary/30 text-primary">
                  official
                </span>
              </div>
              <span className="font-mono text-[11px] text-muted-foreground truncate min-w-0 flex-1">{r.url}</span>
              <span className="font-mono text-[10.5px] text-muted-foreground shrink-0">
                {r.branch}{r.last_sync_commit && (
                  <> · <span className="text-foreground">{r.last_sync_commit.slice(0, 7)}</span></>
                )}
              </span>
              <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums shrink-0">
                {r.enrichment_count} integrations
              </span>
              {synced && r.last_synced_at && !isSyncing && (
                <span className="inline-flex items-center gap-1 text-[10.5px] font-mono text-emerald-500 shrink-0">
                  <CheckCircle className="w-[11px] h-[11px]" />
                  synced {formatUTCCompact(r.last_synced_at)}
                </span>
              )}
              {isSyncing && (
                <span className="inline-flex items-center gap-1 text-[10.5px] font-mono text-amber-500 shrink-0">
                  <Loader2 className="w-[11px] h-[11px] animate-spin" />
                  syncing
                </span>
              )}
              <button
                type="button"
                onClick={() => onSync(r.id)}
                disabled={isSyncing}
                className="h-6 px-2 rounded text-[11px] text-muted-foreground hover:text-foreground hover:bg-muted/40 disabled:opacity-50 inline-flex items-center gap-1 font-mono"
              >
                <RefreshCw className={cn('w-[10px] h-[10px]', isSyncing && 'animate-spin')} />
                sync
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

interface SectionProps {
  icon: React.ReactNode;
  title: string;
  count: number;
  entries: MarketplaceCatalogEntry[];
  onOpen: (slug: string) => void;
  onInstall: (slug: string) => void;
}

function Section({ icon, title, count, entries, onOpen, onInstall }: SectionProps) {
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
        {entries.map(entry => (
          <IntegrationCard
            key={entry.slug}
            entry={entry}
            onOpen={onOpen}
            onInstall={onInstall}
          />
        ))}
      </div>
    </section>
  );
}

function EmptyState() {
  return (
    <div className="mt-8 bg-card border border-border/60 rounded-lg p-10 text-center shadow-none">
      <SearchIcon className="w-6 h-6 text-muted-foreground/60 mx-auto mb-3" />
      <div className="text-[14px] text-foreground">No integrations matched.</div>
      <div className="text-[12px] text-muted-foreground mt-1">
        Try clearing filters or check the repository sources above.
      </div>
    </div>
  );
}

export default Marketplace;
