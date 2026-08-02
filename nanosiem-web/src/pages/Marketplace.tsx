// SPDX-License-Identifier: AGPL-3.0-or-later

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

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Bot, Check, ChevronDown, Cloud, Database, DatabaseZap, Loader2,
  Package, Plug, Plus, RefreshCw, Search as SearchIcon, Shield, Star,
  TableProperties, Users, X as XIcon, Box, FileDown,
} from 'lucide-react';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useAuth } from '@/contexts/AuthContext';
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
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

type CategoryFilter = 'all' | 'data' | 'agent' | 'identity' | 'collector';

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
  { id: 'collector', label: 'Collector', icon: Plug },
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

/** Where connectivity-required items + the hero CTA route to side-load bundles. */
const AIRGAP_IMPORT_ROUTE = '/settings/airgap-import';

export function Marketplace() {
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
  const [searchQuery, setSearchQuery] = useState('');
  const [installEntry, setInstallEntry] = useState<MarketplaceCatalogEntry | null>(null);
  const [detailSlug, setDetailSlug] = useState<string | null>(null);
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
    setDetailSlug(slug);
    const next = new URLSearchParams(searchParams);
    next.delete('slug');
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
    } catch {
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
                <FileDown className="w-3.5 h-3.5 mr-1" /> Import enrichment bundle
              </Button>
            </Link>
          )}
          {(capabilities.customEnrichment || canCreateIntegration) && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
              <Button
                size="sm"
                variant={airGap ? 'outline' : 'default'}
                className="h-8 rounded-md text-[12px]"
              >
                <Plus className="w-3.5 h-3.5 mr-1" /> Create custom
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
        </div>
      </div>

      {/* Stats strip */}
      {stats && <StatsStrip stats={stats} />}

      {/* Coverage hero — fetched independently from catalog/repos. The
          server returns a 6h effective-scope-partitioned Dragonfly cache
          hit, so the typical load is sub-millisecond; the manual-refresh
          button invalidates only the caller's partition. Skeleton renders
          while the first fetch is in flight so the catalog grid is unblocked. */}
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
              <FileDown className="w-3 h-3 mr-1" /> Import bundle
            </Button>
          </Link>
        </div>
      )}

      {/* Filter bar */}
      <div className="mt-4 bg-card border border-border/60 rounded-lg p-2.5 flex items-center gap-2 flex-wrap">
        <div className="flex items-center gap-1.5 flex-wrap">
          {CATEGORY_CHIPS.map(c => {
            const Icon = c.icon;
            const active = categoryFilter === c.id;
            const count = countForCategory(c.id, stats, collectorCount);
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
        {!airGap && (
          <>
            <div className="w-px h-6 bg-border mx-0.5" />
            <SourcesMenu repos={repos} syncingId={syncingRepo} onSync={handleSyncRepo} />
          </>
        )}
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
              airGap={airGap}
              onImportBundle={goImport}
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
              airGap={airGap}
              onImportBundle={goImport}
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
              airGap={airGap}
              onImportBundle={goImport}
            />
          ))}
        </div>
      )}

      {/* Footer hint row */}
      <div className="mt-3 pt-3 border-t border-border/60 flex items-center font-mono text-[10.5px] text-muted-foreground tabular-nums">
        <span className="text-foreground">{repoCadenceLabel(repos)}</span>
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

function countForCategory(cat: CategoryFilter, stats: CatalogStats | null, collectorCount: number): number {
  if (!stats) return 0;
  if (cat === 'all') return stats.total_entries;
  if (cat === 'data') return stats.data_count;
  if (cat === 'agent') return stats.agent_count;
  if (cat === 'identity') return stats.identity_count;
  if (cat === 'collector') return collectorCount;
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

function repoCadenceLabel(repos: EnrichmentMarketplaceRepo[]): string {
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

function SourcesMenu({ repos, syncingId, onSync }: SourcesMenuProps) {
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
                      aria-label={`Sync ${repo.name}`}
                      className="inline-flex h-6 shrink-0 items-center gap-1 rounded px-2 font-mono text-[10.5px] text-muted-foreground hover:bg-primary/10 hover:text-primary disabled:opacity-50"
                    >
                      <RefreshCw className={cn('w-[10px] h-[10px]', isSyncing && 'animate-spin')} />
                      sync
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
  entries: MarketplaceCatalogEntry[];
  onOpen: (slug: string) => void;
  onInstall: (slug: string) => void;
  airGap: boolean;
  onImportBundle: () => void;
}

function Section({ icon, title, count, entries, onOpen, onInstall, airGap, onImportBundle }: SectionProps) {
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
            airGap={airGap}
            onImportBundle={onImportBundle}
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
        Try clearing filters or check the repository sources in the filter bar.
      </div>
    </div>
  );
}

export default Marketplace;
