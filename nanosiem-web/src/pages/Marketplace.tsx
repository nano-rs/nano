// SPDX-License-Identifier: AGPL-3.0-or-later
import { lazyWithRetry } from '@/lib/lazyWithRetry';

/**
 * NAN-571 — Marketplace top-level page (Phase 1 of [NAN-570](https://linear.app/nanos-sh/issue/NAN-570)).
 *
 * Source of truth: design-ref/ui_kits/search/marketplace.html (design system 13).
 * Eyebrow + 20px H1 + meta line; flat 4-tile stats strip; mono-monogram cards
 * with state badges; compact repository-source menu in the
 * filter bar; section grouping (Popular/Security/Cloud);
 * 4-tab drawer (About/Config/Code/Permissions) preserves all existing actions
 * (Sync Now, Export, Disable toggle, Edit-in-wizard, etc.).
 *
 * `security` 4th category, coverage hero, and "preview output" land in Phases 2-4.
 * Custom-enrichment wizard at /enrichments/custom/* is intentionally untouched.
 */

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { DatabaseZap, Package, Plus, TableProperties } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import type {
  CatalogStats,
  EnrichmentMarketplaceRepo,
  MarketplaceCatalogEntry,
} from '@/lib/api/marketplace';
import { useToast } from '@/hooks/use-toast';
import { IntegrationCard } from '@/components/marketplace/IntegrationCard';
import {
  MarketplaceDrawer,
  type MarketplaceDrawerTab,
} from '@/components/marketplace/MarketplaceDrawer';
import { InstallDialog } from '@/components/marketplace/InstallDialog';
import { CoverageHero } from '@/components/marketplace/CoverageHero';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

import { AIRGAP_IMPORT_ROUTE, CATEGORY_CHIPS, SECTIONS, SECTIONED_SLUGS, type CategoryFilter, countForCategory, StatsStrip, Section, EmptyState, LoadErrorState, SourcesMenu, MarketplacePageShell } from '@/components/marketplace/MarketplaceShell';
export { SourcesMenu } from '@/components/marketplace/MarketplaceShell';

const HostedInventory = lazyWithRetry(() => import('./MarketplaceInventory').then(m => ({ default: m.MarketplaceInventory })));

export function Marketplace() {
  const { user } = useAuth();
  return user?.deployment_mode === 'enterprise_shared'
    ? <Suspense fallback={<p>Loading marketplace…</p>}><HostedInventory /></Suspense>
    : <DedicatedMarketplace />;
}

function DedicatedMarketplace() {
  useDocumentTitle('Marketplace');
  useBreadcrumbTitle('Marketplace');

  const { capabilities } = useCapabilities();
  const { hasAllPermissions, user } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  // Air-gap mode (no outbound internet). Drives the honest-marketplace reshape:
  // connectivity badges on every card, egress actions disabled in favor of
  // import-from-file, repo controls hidden, and a top-of-page import CTA.
  // Static for the session, so cache it hard. Defaults to false until resolved
  // (a transient failure just shows the normal online marketplace).
  const airGapQuery = useQuery({
    queryKey: ['system', 'config'],
    queryFn: () => api.getSystemConfig(),
    staleTime: Infinity,
    gcTime: Infinity,
    retry: 1,
    refetchOnWindowFocus: false,
  });
  const airGap = airGapQuery.data?.air_gap ?? false;
  const goImport = useCallback(() => navigate(AIRGAP_IMPORT_ROUTE), [navigate]);
  const [entries, setEntries] = useState<MarketplaceCatalogEntry[]>([]);
  const [stats, setStats] = useState<CatalogStats | null>(null);
  const [collectorCount, setCollectorCount] = useState(0);
  const [repos, setRepos] = useState<EnrichmentMarketplaceRepo[]>([]);
  const [loading, setLoading] = useState(true);
  // NAN-3761: the catalog read failed; an empty list is unknown, not empty.
  const [loadFailed, setLoadFailed] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [installEntry, setInstallEntry] = useState<MarketplaceCatalogEntry | null>(null);
  const [detailSlug, setDetailSlug] = useState<string | null>(null);
  const [detailTab, setDetailTab] = useState<MarketplaceDrawerTab>('config');
  const [syncingRepo, setSyncingRepo] = useState<string | null>(null);

  const categoryFilter = (searchParams.get('category') as CategoryFilter | null) || 'all';
  const installedOnly = searchParams.get('installed') === 'true';

  // NAN-1111: legacy deep-link routes (/enrichments/threatfox etc.) redirect
  // here with `?slug=<slug>` so the drawer opens directly on the right entry
  // instead of dumping users onto the catalog grid. Strip the param after
  // opening so a refresh of the marketplace page doesn't keep re-opening it.
  useEffect(() => {
    const slug = searchParams.get('slug');
    if (!slug) return;
    const requestedTab = searchParams.get('tab');
    setDetailTab(requestedTab === 'connections' ? 'connections' : 'config');
    setDetailSlug(slug);
    const next = new URLSearchParams(searchParams);
    next.delete('slug');
    next.delete('tab');
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);

  const mountedRef = useRef(true);
  useEffect(() => () => { mountedRef.current = false; }, []);

  // Coverage is computed by a 12-countIf ClickHouse aggregate over the last 24h
  // of `logs` — it's the slowest piece on this page. Decouple it from the
  // catalog/repos load so the grid renders immediately, and cache aggressively
  // on both sides:
  //
  // - Server-side (NAN-609/NAN-2061): a Dragonfly-backed, effective-source-scope
  //   partitioned cache (6h TTL), shared across replicas. `computed_at` in the
  //   response stamps the hero with "as of HH:MM".
  // - Client-side: a long React Query staleTime so navigating between pages
  //   in the same tab doesn't even hit the (already cheap) GET endpoint.
  //
  // The manual-refresh button calls the dedicated POST refresh endpoint —
  // that invalidates only the caller's effective-scope partition, then writes
  // the freshly-computed payload back into the React Query cache.
  const SIX_HOURS_MS = 6 * 60 * 60 * 1000;
  const queryClient = useQueryClient();
  // Keep the browser cache caller-bound as well; the server applies the
  // finer-grained effective-source-scope partition.
  const COVERAGE_QUERY_KEY = ['marketplace', 'coverage', user?.id] as const;
  const canViewCoverage = hasAllPermissions(['enrichments:view', 'search:execute']);
  const canCreateIntegration = capabilities.customEnrichment
    && hasAllPermissions(['log_sources:create', 'enrichments:code']);
  const coverageQuery = useQuery({
    queryKey: COVERAGE_QUERY_KEY,
    queryFn: () => api.marketplace.getCoverage(),
    enabled: canViewCoverage,
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
      // Keep the live page compatible with an API process that predates the
      // collector_count field. The unfiltered response already has every
      // collector, so HMR can populate the chip without a service restart.
      if (typeof catalog.stats.collector_count === 'number') {
        setCollectorCount(catalog.stats.collector_count);
      } else if (categoryFilter === 'all') {
        setCollectorCount(catalog.entries.filter(entry => entry.category === 'collector').length);
      }
      setRepos(repoList);
      setLoadFailed(false);
    } catch {
      setLoadFailed(true);
      toast({ title: 'Error', description: 'Failed to load marketplace', variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [categoryFilter, installedOnly, toast]);

  useEffect(() => { void loadAll(); }, [loadAll]);

  // NAN-1108: while any entry is mid-sync, refetch the catalog every ~3.5s
  // so the card transitions from `syncing…` → `synced just now` without the
  // user having to refresh. `anySyncing` is a plain boolean so the effect
  // only re-runs when the syncing-vs-not state itself flips, not on every
  // catalog refresh. Caps at 2 minutes to avoid burning CPU on a stuck run
  // — at that point the user can refresh manually.
  const anySyncing = useMemo(() => entries.some(e => e.is_syncing), [entries]);
  useEffect(() => {
    if (!anySyncing) return;
    const startedAt = Date.now();
    const MAX_MS = 2 * 60_000;
    const POLL_MS = 3_500;
    const interval = setInterval(() => {
      if (Date.now() - startedAt > MAX_MS) {
        clearInterval(interval);
        return;
      }
      void loadAll();
    }, POLL_MS);
    return () => clearInterval(interval);
  }, [anySyncing, loadAll]);

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

  const handleCardOpen = (slug: string) => {
    setDetailTab('config');
    setDetailSlug(slug);
  };
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
      const result = await api.marketplace.syncRepo(id);
      toast({ title: result.managed_by_platform ? 'Sync requested' : 'Sync started', description: result.managed_by_platform ? 'Platform sync queued; the scheduler checks within 60 seconds' : 'Repository sync running in the background' });
      // Poll a few times for the row to settle.
      const delays = result.managed_by_platform ? [2000, 4000, 8000, 16000, 30000, 30000] : [2000, 4000, 8000];
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
    } catch (error) {
      if (mountedRef.current) toast({ title: 'Error', description: error instanceof Error ? error.message : 'Failed to start sync', variant: 'destructive' });
    } finally {
      if (mountedRef.current) setSyncingRepo(null);
    }
  };

  return (
    <MarketplacePageShell
      totalCount={stats?.total_entries ?? 0}
      repos={repos}
      airGap={airGap}
      headerActions={<>
          {(capabilities.customEnrichment || canCreateIntegration) && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
              <Button
                size="sm"
                variant={airGap ? 'outline' : 'default'}
                className="h-8 rounded-md text-[12px]"
              >
                <Plus className="w-3.5 h-3.5" /> Create custom
              </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-72">
                <DropdownMenuLabel className="text-[10px] font-mono uppercase tracking-[0.1em] text-muted-foreground">
                  What are you building?
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                {capabilities.customEnrichment && (
                  <DropdownMenuItem
                    className="items-start gap-2 py-2.5"
                    onSelect={() => navigate('/enrichments/custom/new')}
                  >
                    <TableProperties className="mt-0.5 h-4 w-4 text-primary" />
                    <div>
                      <div className="text-[12px] font-medium">Enrichment</div>
                      <div className="mt-0.5 text-[10.5px] leading-snug text-muted-foreground">
                        Lookup data or on-demand artifact context.
                      </div>
                    </div>
                  </DropdownMenuItem>
                )}
                {canCreateIntegration && !airGap && (
                  <DropdownMenuItem
                    className="items-start gap-2 py-2.5"
                    onSelect={() => navigate('/integrations/custom/new')}
                  >
                    <DatabaseZap className="mt-0.5 h-4 w-4 text-primary" />
                    <div>
                      <div className="text-[12px] font-medium">Scheduled API integration</div>
                      <div className="mt-0.5 text-[10.5px] leading-snug text-muted-foreground">
                        Harvest bounded API data into raw event streams.
                      </div>
                    </div>
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
      </>}
      statsStrip={stats && <StatsStrip stats={stats} />}
      coverage={<>
      {canViewCoverage && (
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
      )}
      </>}
      chips={CATEGORY_CHIPS.map(chip => ({ ...chip, count: countForCategory(chip.id, stats, collectorCount) }))}
      categoryFilter={categoryFilter}
      setCategoryFilter={setCategoryFilter}
      searchQuery={searchQuery}
      setSearchQuery={setSearchQuery}
      installedOnly={installedOnly}
      toggleInstalledOnly={toggleInstalledOnly}
      sourcesMenu={<SourcesMenu repos={repos} syncingId={syncingRepo} onSync={handleSyncRepo} />}
      overlays={<>
      <InstallDialog
        entry={installEntry}
        open={!!installEntry}
        onOpenChange={(open) => !open && setInstallEntry(null)}
        onInstall={doInstall}
      />

      <MarketplaceDrawer
        slug={detailSlug}
        open={!!detailSlug}
        onOpenChange={(open) => {
          if (!open) {
            setDetailSlug(null);
            setDetailTab('config');
          }
        }}
        onUpdated={loadAll}
        initialTab={detailTab}
      />
      </>}
    >
      {loading ? (
        <div className="mt-8 flex items-center justify-center py-12">
          <LoadingIcon className="w-6 h-6 text-muted-foreground" />
        </div>
      ) : filtered.length === 0 ? (
        loadFailed ? <LoadErrorState what="the marketplace catalog" onRetry={() => { void loadAll(); }} /> : <EmptyState />
      ) : showSections ? (
        <div className="mt-5 space-y-6">
          {grouped.sections.map(({ section, entries: secEntries }) => (
            <Section
              key={section.key}
              icon={section.icon}
              title={section.title}
              count={secEntries.length}
            >
              {secEntries.map(entry => (
                <IntegrationCard key={entry.slug} entry={entry} onOpen={handleCardOpen} onInstall={handleInstallClick} airGap={airGap} onImportBundle={goImport} />
              ))}
            </Section>
          ))}
          {grouped.other.length > 0 && (
            <Section
              icon={<Package className="w-[12px] h-[12px] text-muted-foreground" />}
              title="Other integrations"
              count={grouped.other.length}
            >
              {grouped.other.map(entry => (
                <IntegrationCard key={entry.slug} entry={entry} onOpen={handleCardOpen} onInstall={handleInstallClick} airGap={airGap} onImportBundle={goImport} />
              ))}
            </Section>
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
              airGap={airGap}
              onImportBundle={goImport}
            />
          ))}
        </div>
      )}
    </MarketplacePageShell>
  );
}

export default Marketplace;
