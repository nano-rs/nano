// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Marketplace (NAN-4946): main's redone inventory Marketplace, the one
 * marketplace for single-tenant open and enterprise installs.
 *
 * Main rendered this inventory only for hosted-shared tenants, projected by
 * `/api/marketplace/items` from hosted entitlement tables. Here the same UX is
 * re-backed on this deployment's dedicated APIs:
 *
 * - catalog + repositories: `/api/marketplace/catalog`, `/api/marketplace/repos`
 * - custom providers: `/api/custom-enrichments` (enterprise capability)
 * - pull collectors: connector specs + feeds (`/api/connector-specs`,
 *   `/api/connector-feeds`, NAN-4914), including identity directory feeds
 * - cloud pull: source configurations, deep-linking to Log Sources → Cloud pull
 * - threat-intel lookup providers: `/api/threat-intel/*` (enterprise, NAN-4931)
 * - coverage: `/api/marketplace/coverage`
 *
 * Hosted entitlements (included/premium, purchase, checkout) have no
 * single-tenant meaning; what an item can run on comes from
 * `/api/capabilities`, never from a hosted/shared flag.
 */
import { lazyWithRetry } from '@/lib/lazyWithRetry';
import { Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowDownToLine, Bot, Box, Cloud, KeyRound, Package, Plus, Users } from 'lucide-react';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { useToast } from '@/hooks/use-toast';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import type { MarketplaceCatalogEntry } from '@/lib/api/marketplace';
import { CoverageHero } from '@/components/marketplace/CoverageHero';
import { InstallDialog } from '@/components/marketplace/InstallDialog';
import { MarketplacePageShell, StatsStrip, Section, SECTIONS, EmptyState, LoadErrorState, SourcesMenu } from '@/components/marketplace/MarketplaceShell';
import { CloudPullCard } from '@/components/marketplace/CloudPullCard';
import { cloudPullMatches, useCloudPullEntry } from '@/components/marketplace/useCloudPullEntry';
import { CollectorCard } from '@/components/marketplace/CollectorCard';
import { collectorMatches, collectorSection, collectorState, useConnectorCollectors, type CollectorRow } from '@/components/marketplace/useConnectorCollectors';
import { InventoryCard } from '@/components/marketplace/InventoryCard';
import { InventoryEntitlement } from '@/components/marketplace/InventoryEntitlement';
import type { MarketplaceDrawerTab } from '@/components/marketplace/MarketplaceDrawer';
import type { InventoryEditorMode } from '@/components/marketplace/InventoryEditor';
import { applyFeedBundle, buildInventory, syncPollInterval, type InventoryItem } from '@/lib/api/marketplace-inventory';
import { PlatformFeedsPanel } from '@/components/marketplace/PlatformFeedsPanel';

/** Same key as `PlatformFeedsPanel` (NAN-4948), so the panel and the card markers share one fetch. */
const PLATFORM_FEEDS_QUERY_KEY = ['enrichment', 'platform-feeds'] as const;
// Threat-intel lookup providers (enterprise, NAN-4931); the open stub renders nothing.
import { ThreatIntelProvidersSection } from '@/enterprise/components/threat-intel/ThreatIntelProviders';
import { useThreatIntelEnabled, useThreatIntelProviders } from '@/enterprise/components/threat-intel/use-threat-intel';
export { SourcesMenu } from '@/components/marketplace/MarketplaceShell';

const InventoryDrawer = lazyWithRetry(() => import('@/components/marketplace/InventoryDrawer').then(m => ({ default: m.InventoryDrawer })));
const InventoryEditor = lazyWithRetry(() => import('@/components/marketplace/InventoryEditor').then(m => ({ default: m.InventoryEditor })));
const ConnectionDrawer = lazyWithRetry(() => import('@/components/marketplace/MarketplaceDrawer').then(m => ({ default: m.MarketplaceDrawer })));

type Category = 'all' | 'platform' | 'custom' | 'pull' | 'agent';
const CATEGORIES: readonly Category[] = ['all', 'platform', 'custom', 'pull', 'agent'];
const SIX_HOURS_MS = 6 * 60 * 60 * 1000;
const MARKETPLACE_REPOSITORIES_KEY = ['marketplace-repositories'] as const;
const DRAWER_TABS: readonly MarketplaceDrawerTab[] = ['about', 'config', 'connections', 'code', 'perms'];

export function Marketplace() {
  useDocumentTitle('Marketplace'); useBreadcrumbTitle('Marketplace');
  const { user, hasAllPermissions, hasPermission } = useAuth();
  const { capabilities, edition } = useCapabilities();
  const { toast } = useToast();
  const client = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [searchQuery, setSearchQuery] = useState('');
  const [confirm, setConfirm] = useState<{ item: InventoryItem; action: 'toggle' | 'uninstall' } | null>(null);
  const [installEntry, setInstallEntry] = useState<MarketplaceCatalogEntry | null>(null);
  const [syncingRepo, setSyncingRepo] = useState<string | null>(null);
  const mountedRef = useRef(true);
  useEffect(() => { mountedRef.current = true; return () => { mountedRef.current = false; }; }, []);

  // ── Data ────────────────────────────────────────────────────────────
  const catalogKey = ['marketplace', 'catalog', user?.id] as const;
  const syncPollStarted = useRef<number | null>(null);
  const catalog = useQuery({
    queryKey: catalogKey,
    queryFn: () => api.marketplace.listCatalog(),
    // NAN-1108: while an entry is mid-sync, poll so its card settles without a
    // reload, capped at two minutes per sync episode (a stuck run stops costing
    // requests; a manual refresh still works).
    refetchInterval: query => syncPollInterval(!!query.state.data?.entries.some(entry => entry.is_syncing), syncPollStarted),
  });
  const reposKey = [...MARKETPLACE_REPOSITORIES_KEY, user?.id];
  // A failed repository read is surfaced, and catalog items then read as
  // unknown provenance (never as first-party).
  const reposQuery = useQuery({ queryKey: reposKey, queryFn: () => api.marketplace.listRepos(), retry: false });
  const repos = useMemo(() => reposQuery.data ?? [], [reposQuery.data]);
  // Custom providers are an enterprise capability; the open build never asks.
  const canListCustom = capabilities.customEnrichment && hasPermission('enrichments:view');
  const customs = useQuery({ queryKey: ['custom-enrichments', user?.id], queryFn: () => api.listCustomEnrichments(), enabled: canListCustom, retry: false });
  // Pull collectors (connector specs) also dedupe their catalog collector twins.
  const collectors = useConnectorCollectors({ pollFeeds: !['platform', 'custom', 'agent'].includes(params.get('category') ?? '') });
  const connectorNames = useMemo(() => new Set(collectors.rows.map(row => row.spec.name)), [collectors.rows]);
  // NAN-4948: nano's signed platform feed bundle (shared query with the panel).
  // Unavailable (no bundle support, or an error) leaves the cards untouched.
  const feedBundle = useQuery({ queryKey: PLATFORM_FEEDS_QUERY_KEY, queryFn: () => api.getPlatformFeeds(), enabled: hasPermission('enrichments:view'), staleTime: 60_000, retry: false, refetchOnWindowFocus: false });
  const items = useMemo(() => applyFeedBundle(buildInventory(catalog.data?.entries ?? [], canListCustom ? customs.data ?? [] : [], repos, capabilities, edition, connectorNames), feedBundle.data),
    [catalog.data, customs.data, canListCustom, repos, capabilities, edition, connectorNames, feedBundle.data]);
  const refreshInventory = () => {
    void client.invalidateQueries({ queryKey: catalogKey });
    void client.invalidateQueries({ queryKey: ['custom-enrichments', user?.id] });
  };

  const airGapQuery = useQuery({ queryKey: ['system', 'config'], queryFn: () => api.getSystemConfig(), staleTime: Infinity, gcTime: Infinity, retry: 1, refetchOnWindowFocus: false });
  const airGap = airGapQuery.data?.air_gap ?? false;

  const coverageKey = ['marketplace', 'coverage', user?.id] as const;
  const canViewCoverage = hasAllPermissions(['enrichments:view', 'search:execute']);
  const coverageQuery = useQuery({ queryKey: coverageKey, queryFn: () => api.marketplace.getCoverage(), enabled: canViewCoverage, staleTime: SIX_HOURS_MS, gcTime: SIX_HOURS_MS, retry: false, refetchOnWindowFocus: false });
  const coverageRefresh = useMutation({
    mutationFn: () => api.marketplace.refreshCoverage(),
    onSuccess: fresh => { client.setQueryData(coverageKey, fresh); },
    onError: () => { toast({ title: 'Refresh failed', description: 'Coverage couldn’t be recomputed. Try again in a moment.', variant: 'destructive' }); },
  });

  // ── URL state ───────────────────────────────────────────────────────
  const requestedCategory = params.get('category');
  const categoryFilter: Category = CATEGORIES.includes(requestedCategory as Category) ? requestedCategory as Category : 'all';
  const installedOnly = params.get('installed') === 'true';
  // `?slug=` is the legacy deep link (NAN-1111 redirects); `?item=` is main's.
  const selectedId = params.get('item') ?? params.get('slug') ?? '';
  const selected = selectedId ? items.find(item => item.id === selectedId) : undefined;
  const unavailable = !!selectedId && catalog.isSuccess && (!canListCustom || customs.isSuccess) && !selected;
  const author = params.get('author');
  const requestedTab = params.get('tab');
  const connectionTab: MarketplaceDrawerTab = DRAWER_TABS.includes(requestedTab as MarketplaceDrawerTab) ? requestedTab as MarketplaceDrawerTab : 'config';
  const update = (mutate: (next: URLSearchParams) => void) => { const next = new URLSearchParams(params); mutate(next); setParams(next); };
  const select = (id?: string) => update(next => {
    for (const key of ['slug', 'tab', 'author', 'mode']) next.delete(key);
    if (id) next.set('item', id); else next.delete('item');
  });
  const openAuthor = (mode: 'new' | 'edit' | 'connect', extra?: Record<string, string>) => update(next => {
    next.set('author', mode);
    for (const [key, value] of Object.entries(extra ?? {})) next.set(key, value);
  });
  const setCategoryFilter = (value: Category) => update(next => { if (value === 'all') next.delete('category'); else next.set('category', value); });
  const toggleInstalledOnly = () => update(next => { if (installedOnly) next.delete('installed'); else next.set('installed', 'true'); });

  // ── Permissions ─────────────────────────────────────────────────────
  const canConfigure = hasPermission('enrichments:configure');
  const canAuthor = capabilities.customEnrichment && hasAllPermissions(['enrichments:view', 'enrichments:configure', 'enrichments:code']);
  const canOpenCreate = (canAuthor && hasPermission('enrichments:custom:create')) || hasAllPermissions(['lookup:view', 'lookup:create']);
  const editing = (canOpenCreate && author === 'new')
    || (canAuthor && author === 'edit' && selected?.source === 'custom_enrichment' && selected.can_edit);
  const connecting = author === 'connect' && selected?.source === 'catalog' && canConfigure;

  // ── Mutations ───────────────────────────────────────────────────────
  const install = async (slug: string, credentials?: Record<string, string>) => {
    try {
      await api.marketplace.installEnrichment(slug, credentials ? { credentials } : undefined);
      toast({ title: 'Installed', description: 'Integration installed and enabled' });
      refreshInventory();
    } catch (error) {
      toast({ title: 'Install failed', description: error instanceof Error ? error.message : 'Failed to install', variant: 'destructive' });
      throw error;
    }
  };
  const startInstall = (item: InventoryItem) => {
    const entry = item.entry;
    if (!entry) return;
    if (entry.requires_credential !== 'none' && entry.credential_fields.length > 0) setInstallEntry(entry);
    else void install(entry.slug).catch(() => {});
  };
  const mutation = useMutation({
    mutationFn: async ({ item, action }: { item: InventoryItem; action: 'toggle' | 'uninstall' }) => {
      if (item.source === 'catalog') {
        if (action === 'uninstall') await api.marketplace.uninstallEnrichment(item.connector);
        else await api.marketplace.configureEnrichment(item.connector, { enabled: !item.enabled });
      } else {
        const id = item.id.slice('custom:'.length);
        if (item.enabled) await api.disableCustomEnrichment(id); else await api.deployCustomEnrichment(id);
      }
    },
    onSettled: refreshInventory,
  });

  const handleSyncRepo = async (id: string) => {
    setSyncingRepo(id);
    try {
      await api.marketplace.syncRepo(id);
      toast({ title: 'Sync started', description: 'Repository sync running in the background' });
      for (const ms of [2000, 4000, 8000]) {
        await new Promise(resolve => setTimeout(resolve, ms));
        if (!mountedRef.current) return;
        const list = await client.fetchQuery({ queryKey: reposKey, queryFn: () => api.marketplace.listRepos(), staleTime: 0 });
        const repo = list.find(r => r.id === id);
        if (!repo || (repo.last_sync_status !== 'syncing' && repo.last_sync_status !== 'pending')) break;
      }
      if (mountedRef.current) refreshInventory();
    } catch (error) {
      if (mountedRef.current) toast({ title: 'Error', description: error instanceof Error ? error.message : 'Failed to start sync', variant: 'destructive' });
    } finally {
      if (mountedRef.current) setSyncingRepo(null);
    }
  };

  // ── Collectors, cloud pull ──────────────────────────────────────────
  const cloudPull = useCloudPullEntry();

  // ── Filtering + grouping ────────────────────────────────────────────
  const q = searchQuery.toLowerCase().trim();
  const matchesItem = (item: InventoryItem) => !q || `${item.name} ${item.id} ${item.description ?? ''} ${item.capabilities.join(' ')}`.toLowerCase().includes(q);
  const filtered = categoryFilter === 'pull' ? [] : items.filter(item => (!installedOnly || item.enabled)
    && (categoryFilter === 'all' || (categoryFilter === 'agent' ? item.category === 'agent' : item.kind === categoryFilter))
    && matchesItem(item));
  const filteredCollectors = categoryFilter === 'all' || categoryFilter === 'pull'
    ? collectors.rows.filter(row => (!installedOnly || collectorState(row.feeds, collectors.feedStatus).installed) && collectorMatches(row.spec, searchQuery))
    : [];
  const identityCollectors = filteredCollectors.filter(row => collectorSection(row.spec) === 'identity');
  const otherCollectors = filteredCollectors.filter(row => collectorSection(row.spec) !== 'identity');
  const showCloudPull = cloudPull.available && (categoryFilter === 'all' || categoryFilter === 'pull')
    && (!installedOnly || cloudPull.sources.length > 0) && cloudPullMatches(searchQuery);
  const cloudPullCard = showCloudPull ? <CloudPullCard key="cloud-pull" sources={cloudPull.sources} /> : null;
  const pullCount = collectors.rows.length + (cloudPull.available ? 1 : 0);
  const threatIntelEnabled = useThreatIntelEnabled();
  const threatIntel = capabilities.threatIntel && threatIntelEnabled;
  const threatIntelCount = useThreatIntelProviders().data?.providers.length ?? 0;
  const threatIntelSection = threatIntel && (categoryFilter === 'all' || categoryFilter === 'agent')
    ? <ThreatIntelProvidersSection searchQuery={searchQuery} installedOnly={installedOnly} /> : null;

  const grouped = useMemo(() => {
    const byId = new Map(items.map(item => [item.id, item]));
    const assigned = new Set<string>();
    const sections = SECTIONS.map(section => ({
      section,
      items: [...new Set(section.slugs)].flatMap(slug => {
        const item = byId.get(slug);
        if (!item || assigned.has(item.id)) return [];
        assigned.add(item.id);
        return [item];
      }),
    })).filter(group => group.items.length > 0);
    const custom = items.filter(item => !assigned.has(item.id) && item.kind === 'custom');
    custom.forEach(item => assigned.add(item.id));
    const other = items.filter(item => !assigned.has(item.id));
    return { sections, custom, other };
  }, [items]);
  const showSections = categoryFilter === 'all' && !q && !installedOnly;
  // Cloud pull sits in Cloud infrastructure; keep that group even when no curated item fills it.
  const sectionGroups = showCloudPull && !grouped.sections.some(group => group.section.key === 'cloud')
    ? SECTIONS.flatMap(section => section.key === 'cloud' ? [{ section, items: [] as InventoryItem[] }] : grouped.sections.filter(group => group.section.key === section.key))
    : grouped.sections;

  const platformCount = items.filter(item => item.kind === 'platform').length;
  const customCount = items.filter(item => item.kind === 'custom').length;
  const agentCount = items.filter(item => item.category === 'agent').length + (threatIntel ? threatIntelCount : 0);
  // Live pull: enabled connector feeds plus enabled cloud pull source configurations.
  const installedPullCount = collectors.rows.reduce((n, row) => n + row.feeds.filter(feed => feed.enabled).length, 0) + cloudPull.sources.filter(source => source.enabled).length;
  const cards = (list: InventoryItem[]) => list.map(item => <InventoryCard key={item.id} item={item} airGap={airGap} onOpen={() => select(item.id)} />);
  const collectorCards = (list: CollectorRow[]) => list.map(row => <CollectorCard key={row.spec.name} {...row} feedStatus={collectors.feedStatus}
    permissions={collectors.permissionsFor(row.spec)} />);
  const visibleCount = filtered.length + filteredCollectors.length + (showCloudPull ? 1 : 0);
  const inventoryPending = catalog.isPending || (canListCustom && customs.isPending);
  // NAN-3761: a failed load is never rendered as "No integrations matched".
  const loadFailures = [...(catalog.isError ? ['the marketplace catalog'] : []), ...(collectors.isError ? ['pull collectors'] : [])];
  const retryLoad = () => { if (catalog.isError) void catalog.refetch(); if (collectors.isError) collectors.refetch(); };

  const busy = mutation.isPending;
  // NAN-4959: a feed the bundle provides (IPinfo Lite, ThreatFox, Tor) has
  // nothing to configure or toggle here: no direct fetcher. A code ThreatFox /
  // Tor install from before keeps Uninstall (it removes stored credentials).
  const bundleManaged = !!selected?.provided_by_bundle;
  const keepsUninstall = !!selected?.installed && selected.entry?.execution_backend !== 'native';
  const drawerActions = selected ? {
    // An entry whose backend this edition lacks (requirement) gets no Install /
    // Configure: the server refuses it, so the buttons would be dead (NAN-5056).
    onInstall: selected.source === 'catalog' && canConfigure && !airGap && !selected.provided_by_bundle && !selected.requirement ? () => startInstall(selected) : undefined,
    onToggle: canConfigure ? () => setConfirm({ item: selected, action: 'toggle' }) : undefined,
    onConfigure: selected.source === 'catalog' && canConfigure && !bundleManaged && !selected.requirement ? () => openAuthor('connect', { tab: 'config' }) : undefined,
    onConnect: selected.source === 'catalog' && selected.category === 'collector' && canConfigure && !selected.requirement ? () => openAuthor('connect', { tab: 'connections' }) : undefined,
    onEdit: canAuthor && selected.source === 'custom_enrichment' ? () => openAuthor('edit') : undefined,
    onUninstall: selected.source === 'catalog' && canConfigure && (!bundleManaged || keepsUninstall) ? () => setConfirm({ item: selected, action: 'uninstall' }) : undefined,
  } : {};

  return <MarketplacePageShell
    totalCount={items.length + collectors.rows.length + (cloudPull.available ? 1 : 0)} repos={repos} airGap={airGap}
    headerActions={canOpenCreate && <Button size="sm" variant={airGap ? 'outline' : 'default'} className="h-8 rounded-md text-[12px]" onClick={() => openAuthor('new')}>
      <Plus className="w-3.5 h-3.5" /> Create / Connect
    </Button>}
    statsStrip={<StatsStrip stats={{ total_entries: items.length, installed_count: 0, data_count: 0, agent_count: 0, identity_count: 0, collector_count: 0 }} tiles={[
      { label: 'Enabled', value: items.filter(item => item.enabled).length },
      { label: 'Platform', value: platformCount },
      { label: 'Custom', value: customCount },
      { label: 'Pull feeds', value: installedPullCount },
    ]} />}
    coverage={<>
      {/* NAN-4948: nano's signed platform feed bundle (IPinfo Lite, ThreatFox, Tor): installed feeds, freshness, check now / air-gap import. */}
      <PlatformFeedsPanel className="mt-4" />
      {canViewCoverage && <div className="mt-4">
      <CoverageHero
        coverage={coverageQuery.data ?? null}
        isLoading={coverageQuery.isLoading}
        isFetching={coverageQuery.isFetching || coverageRefresh.isPending}
        isError={coverageQuery.isError}
        onRefresh={() => { if (!coverageRefresh.isPending) coverageRefresh.mutate(); }}
        onAddMissing={name => { setSearchQuery(name); document.getElementById('marketplace-search')?.focus(); }}
      />
    </div>}
    </>}
    chips={[
      { id: 'all' as const, label: 'All', icon: Box, count: items.length + pullCount + (threatIntel ? threatIntelCount : 0) },
      { id: 'platform' as const, label: 'Platform', icon: Cloud, count: platformCount },
      { id: 'custom' as const, label: 'Custom', icon: Users, count: customCount },
      ...(pullCount ? [{ id: 'pull' as const, label: 'Pull', icon: ArrowDownToLine, count: pullCount }] : []),
      ...(agentCount || threatIntel ? [{ id: 'agent' as const, label: 'Agent', icon: Bot, count: agentCount }] : []),
    ]}
    categoryFilter={categoryFilter} setCategoryFilter={setCategoryFilter}
    searchQuery={searchQuery} setSearchQuery={setSearchQuery}
    installedOnly={installedOnly} toggleInstalledOnly={toggleInstalledOnly} toggleLabel="enabled only"
    sourcesMenu={<SourcesMenu repos={repos} syncingId={syncingRepo} onSync={canConfigure ? id => { void handleSyncRepo(id); } : undefined} />}
    overlays={<>
      {editing ? <Suspense fallback={<p role="status">Loading provider editor…</p>}>
        <InventoryEditor key={`${user?.id}:${author}:${selected?.id ?? 'new'}`}
          definitionId={author === 'new' ? 'new' : selected!.id.slice('custom:'.length)}
          initialMode={(params.get('mode') as InventoryEditorMode | null) ?? undefined}
          onClose={() => { refreshInventory(); select(author === 'new' ? undefined : selected?.id); }}
          onSaved={id => { refreshInventory(); select(`custom:${id}`); }} />
      </Suspense>
      : connecting && selected ? <Suspense fallback={<p role="status">Loading connection…</p>}>
        <ConnectionDrawer key={`${user?.id}:${selected.id}`} slug={selected.connector} open
          onOpenChange={open => { if (!open) select(selected.id); }} onUpdated={refreshInventory} initialTab={connectionTab} />
      </Suspense>
      : selected && <Suspense fallback={<p role="status">Loading details…</p>}>
        <InventoryDrawer item={selected} onClose={() => select()} busy={busy}
          entitlement={selected.requirement ? <InventoryEntitlement requirement={selected.requirement} edition={edition} canManageLicence={hasPermission('settings:system')} /> : undefined}
          actions={drawerActions} />
      </Suspense>}
      {/* Keyed by slug: a cancelled secret never survives into another install. */}
      <InstallDialog key={installEntry?.slug ?? 'closed'} entry={installEntry} open={!!installEntry} onOpenChange={open => { if (!open) setInstallEntry(null); }} onInstall={install} />
      <ConfirmDialog open={!!confirm} onOpenChange={open => { if (!open) setConfirm(null); }}
        title={confirm?.action === 'uninstall' ? `Uninstall ${confirm.item.name}?` : `${confirm?.item.enabled ? 'Disable' : 'Enable'} ${confirm?.item.name ?? 'provider'}?`}
        description={confirm?.action === 'uninstall' ? 'Removes the integration and its stored credentials from this deployment. It stays in the catalog to reinstall.' : 'This changes the provider state for this deployment.'}
        variant={confirm?.action === 'uninstall' ? 'danger' : undefined}
        confirmLabel={confirm?.action === 'uninstall' ? 'Uninstall' : confirm?.item.enabled ? 'Disable' : 'Enable'}
        onConfirm={() => { if (confirm) mutation.mutate(confirm); setConfirm(null); }} loading={mutation.isPending} />
    </>}
  >
    {reposQuery.isError && <p role="alert" className="mt-4 text-[12px] text-destructive">Could not load catalog sources; repository provenance is unknown until they load. <button className="underline" onClick={() => { void reposQuery.refetch(); }}>Retry</button></p>}
    {catalog.isError && visibleCount > 0 && <p role="alert" className="mt-4 text-[12px] text-destructive">Could not load the catalog. <button className="underline" onClick={() => { void catalog.refetch(); }}>Retry</button></p>}
    {mutation.isError && <p role="alert" className="mt-4 text-[12px] text-destructive">{mutation.error.message} Reloaded current provider state.</p>}
    {unavailable && <p className="mt-4 text-[12px] text-muted-foreground">That integration isn't available on this deployment.</p>}
    {collectors.isError && visibleCount > 0 && <p role="alert" className="mt-4 text-[12px] text-destructive">Could not load pull collectors. <button className="underline" onClick={collectors.refetch}>Retry</button></p>}
    {categoryFilter === 'agent' && filtered.length === 0 && threatIntelSection ? (
      <div className="mt-5">{threatIntelSection}</div>
    ) : inventoryPending && categoryFilter !== 'pull' ? (
      <div className="mt-8 flex items-center justify-center py-12"><LoadingIcon className="w-6 h-6 text-muted-foreground" /></div>
    ) : visibleCount === 0 ? (loadFailures.length > 0
      ? <LoadErrorState what={loadFailures.join(' and ')} retrying={catalog.isFetching || collectors.isRefetching} onRetry={retryLoad} />
      : <EmptyState />) : showSections ? (
      <div className="mt-5 space-y-6">
        {sectionGroups.map(({ section, items: sectionItems }) => {
          const extra = section.key === 'cloud' ? cloudPullCard : null;
          return <Section key={section.key} icon={section.icon} title={section.title} count={sectionItems.length + (extra ? 1 : 0)}>{cards(sectionItems)}{extra}</Section>;
        })}
        {identityCollectors.length > 0 && <Section icon={<KeyRound className="w-[12px] h-[12px] text-muted-foreground" />} title="Identity" count={identityCollectors.length}>{collectorCards(identityCollectors)}</Section>}
        {grouped.custom.length > 0 && <Section icon={<Users className="w-[12px] h-[12px] text-muted-foreground" />} title="Custom providers" count={grouped.custom.length}>{cards(grouped.custom)}</Section>}
        {threatIntelSection}
        {grouped.other.length + otherCollectors.length > 0 && <Section icon={<Package className="w-[12px] h-[12px] text-muted-foreground" />} title="Other integrations" count={grouped.other.length + otherCollectors.length}>{cards(grouped.other)}{collectorCards(otherCollectors)}</Section>}
      </div>
    ) : (
      <>
        <div className="mt-5 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">{cards(filtered)}{collectorCards(filteredCollectors)}{cloudPullCard}</div>
        {threatIntelSection && <div className="mt-6">{threatIntelSection}</div>}
      </>
    )}
  </MarketplacePageShell>;
}

export default Marketplace;
