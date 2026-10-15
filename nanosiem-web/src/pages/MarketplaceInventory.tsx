// SPDX-License-Identifier: AGPL-3.0-or-later
import { lazyWithRetry } from '@/lib/lazyWithRetry';
import { Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiClientError } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { ArrowDownToLine, Bot, Box, Cloud, KeyRound, Package, Users } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { useToast } from '@/hooks/use-toast';
import type { EnrichmentMarketplaceRepo } from '@/lib/api/marketplace';
import { CoverageHero } from '@/components/marketplace/CoverageHero';
import { MarketplacePageShell, StatsStrip, Section, SECTIONS, EmptyState, LoadErrorState, SourcesMenu } from '@/components/marketplace/MarketplaceShell';
import { CollectorCard } from '@/enterprise/components/marketplace/HostedCollectors';
import { CloudPullCard } from '@/components/marketplace/CloudPullCard';
import { cloudPullMatches, useCloudPullEntry } from '@/components/marketplace/useCloudPullEntry';
import { collectorMatches, collectorSection, collectorState, useHostedCollectors, type CollectorRow } from '@/enterprise/components/marketplace/useHostedCollectors';
import { InventoryCard } from '@/components/marketplace/InventoryCard';
import type { MarketplaceDrawerTab } from '@/components/marketplace/MarketplaceDrawer';
import { InventoryEntitlement } from '@/components/marketplace/InventoryEntitlement';
import { inventoryRouteId, type InventoryItem } from '@/lib/api/marketplace-inventory';
import { ThreatIntelProvidersSection } from '@/components/threat-intel/ThreatIntelProviders';
import { useThreatIntelEnabled, useThreatIntelProviders } from '@/components/threat-intel/use-threat-intel';
const InventoryDrawer = lazyWithRetry(() => import('@/components/marketplace/InventoryDrawer').then(m => ({ default: m.InventoryDrawer })));
const InventoryEditor = lazyWithRetry(() => import('@/components/marketplace/InventoryEditor').then(m => ({ default: m.InventoryEditor })));
const ConnectionDrawer = lazyWithRetry(() => import('@/components/marketplace/MarketplaceDrawer').then(m => ({ default: m.MarketplaceDrawer })));
export function MarketplaceInventory() {
  useDocumentTitle('Marketplace'); useBreadcrumbTitle('Marketplace');
  const { user, hasAllPermissions } = useAuth();
  const [params, setParams] = useSearchParams();
  const [confirm, setConfirm] = useState<InventoryItem | null>(null);
  const client = useQueryClient();
  const queryKey = ['marketplace-inventory', user?.active_tenant?.id, user?.id];
  const inventory = useQuery({ queryKey, queryFn: () => api.marketplace.listInventory() });
  const selectedId = inventoryRouteId(params.get('item') ?? params.get('slug') ?? '');
  const detail = useQuery({ queryKey: [...queryKey, selectedId], queryFn: () => api.marketplace.inventoryDetail(selectedId), enabled: !!selectedId, retry: false });
  const unavailable = !!selectedId && inventory.isSuccess && !inventory.data.some(item => item.id === selectedId)
    && detail.error instanceof ApiClientError && detail.error.status === 404;
  const selected = unavailable ? undefined : detail.data;
  const canReadPurchase = selected?.kind === 'premium' && hasAllPermissions(['settings:system']);
  const entitlement = useQuery({
    queryKey: [...queryKey, selectedId, 'entitlement'],
    enabled: !!canReadPurchase,
    queryFn: async () => {
      try { return await api.marketplace.inventoryEntitlement(selectedId); }
      catch (error) { if (error instanceof ApiClientError && error.status === 404) return null; throw error; }
    },
    refetchInterval: query => !query.state.data || query.state.data.state === 'pending' ? 5000 : false,
  });
  const { revision } = entitlement.data ?? {};
  useEffect(() => {
    if (revision !== undefined) {
      void client.invalidateQueries({ queryKey: ['marketplace-inventory', user?.active_tenant?.id, user?.id], exact: true });
      void client.invalidateQueries({ queryKey: ['marketplace-inventory', user?.active_tenant?.id, user?.id, selectedId], exact: true });
    }
  }, [client, user?.active_tenant?.id, user?.id, selectedId, revision]);
  const checkoutIntent = useQuery({
    queryKey: [...queryKey, selectedId, 'checkout'], enabled: !!canReadPurchase,
    queryFn: async () => {
      try { return await api.marketplace.checkout(selectedId); }
      catch (error) { if (error instanceof ApiClientError && error.status === 404) return null; throw error; }
    },
    retry: false,
  });
  const checkout = useMutation({
    mutationFn: () => api.marketplace.checkout(selectedId, params.get('origin') === 'signup' ? 'signup' : 'later'),
    onSuccess: response => { window.location.assign(response.redirect_url); },
  });
  const purchaseStatus = canReadPurchase ? <InventoryEntitlement status={entitlement.data} checkoutPending={!!checkoutIntent.data && !entitlement.data} loading={entitlement.isFetching} failed={entitlement.isError}
    onRefresh={() => { void client.invalidateQueries({ queryKey }); }} /> : undefined;
  const canAuthor = hasAllPermissions(['enrichments:view', 'enrichments:configure', 'enrichments:code']);
  const canCreate = canAuthor && hasAllPermissions(['enrichments:custom:create']);
  const canOpenCreate = canCreate || hasAllPermissions(['lookup:view', 'lookup:create']) || hasAllPermissions(['enrichments:configure']);
  const editing = (canOpenCreate && params.get('author') === 'new') || (canAuthor && (params.get('author') === 'edit' && selected?.kind === 'custom' && selected.can_edit && selected.id.startsWith('custom:')));
  const canConnect = selected?.kind === 'custom' && (selected.id.startsWith('connector:') || !!selected.repository_id) && hasAllPermissions(['enrichments:configure']);
  const connecting = canConnect && params.get('author') === 'connect';
  const requestedTab = params.get('tab');
  const connectionTab: MarketplaceDrawerTab = requestedTab && ['about', 'config', 'connections', 'code', 'perms'].includes(requestedTab) ? requestedTab as MarketplaceDrawerTab : 'config';
  const mutation = useMutation({ mutationFn: (item: InventoryItem) => api.marketplace.toggleInventory(item),
    onSettled: () => client.invalidateQueries({ queryKey }) });
  const select = (id?: string) => { const next = new URLSearchParams(params); next.delete('slug'); next.delete('tab'); next.delete('author'); if (id) next.set('item', id); else next.delete('item'); setParams(next); };
  const author = (mode: 'new' | 'edit' | 'connect') => { const next = new URLSearchParams(params); next.set('author', mode); setParams(next); };
  const saved = (id: string) => { void client.invalidateQueries({ queryKey }); select(`custom:${id}`); };
  const mayToggle = selected && hasAllPermissions(selected.kind === 'premium' ? ['enrichments:configure', 'settings:system'] : ['enrichments:configure']);
  const { toast } = useToast();
  const [searchQuery, setSearchQuery] = useState('');
  const [repos, setRepos] = useState<EnrichmentMarketplaceRepo[]>([]);
  const [syncingRepo, setSyncingRepo] = useState<string | null>(null);
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    void api.marketplace.listRepos().catch(() => []).then(list => {
      if (mountedRef.current) setRepos(list);
    });
    return () => { mountedRef.current = false; };
  }, []);
  const airGapQuery = useQuery({
    queryKey: ['system', 'config'],
    queryFn: () => api.getSystemConfig(),
    staleTime: Infinity,
    gcTime: Infinity,
    retry: 1,
    refetchOnWindowFocus: false,
  });
  const airGap = airGapQuery.data?.air_gap ?? false;
  const SIX_HOURS_MS = 6 * 60 * 60 * 1000;
  const queryClient = client;
  // Keep the browser cache caller-bound as well; the server applies the
  // finer-grained effective-source-scope partition.
  const COVERAGE_QUERY_KEY = ['marketplace', 'coverage', user?.id] as const;
  const canViewCoverage = hasAllPermissions(['enrichments:view', 'search:execute']);
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
      if (mountedRef.current) void client.invalidateQueries({ queryKey });
    } catch (error) {
      if (mountedRef.current) toast({ title: 'Error', description: error instanceof Error ? error.message : 'Failed to start sync', variant: 'destructive' });
    } finally {
      if (mountedRef.current) setSyncingRepo(null);
    }
  };

  const items = inventory.data ?? [];
  type HostedCategory = 'all' | 'platform' | 'custom' | 'pull' | 'agent';
  const requestedCategory = params.get('category');
  const categoryFilter: HostedCategory = requestedCategory === 'platform' || requestedCategory === 'custom' || requestedCategory === 'pull' || requestedCategory === 'agent' ? requestedCategory : 'all';
  // Feed status (and its 30 s polling of installed collectors) only runs while collectors can be on screen.
  const collectors = useHostedCollectors({ pollFeeds: categoryFilter === 'all' || categoryFilter === 'pull' });
  const installedOnly = params.get('installed') === 'true';
  // NAN-3596: cloud pull links to Log Sources → Cloud pull; shown only to admitted tenants.
  const cloudPull = useCloudPullEntry();
  const setCategoryFilter = (value: HostedCategory) => {
    const next = new URLSearchParams(params);
    if (value === 'all') next.delete('category'); else next.set('category', value);
    setParams(next);
  };
  const toggleInstalledOnly = () => {
    const next = new URLSearchParams(params);
    if (installedOnly) next.delete('installed'); else next.set('installed', 'true');
    setParams(next);
  };
  const filtered = categoryFilter === 'pull' || categoryFilter === 'agent' ? [] : items.filter(item => {
    const q = searchQuery.toLowerCase().trim();
    return (!installedOnly || item.enabled)
      && (categoryFilter === 'all' || (categoryFilter === 'custom' ? item.kind === 'custom' : item.kind !== 'custom'))
      && (!q || item.name.toLowerCase().includes(q) || item.id.toLowerCase().includes(q));
  });
  // Installed collectors count as enabled for "enabled only", matching inventory toggles.
  const filteredCollectors = categoryFilter === 'all' || categoryFilter === 'pull'
    ? collectors.rows.filter(row => (!installedOnly || collectorState(row.feeds).installed) && collectorMatches(row.entry, searchQuery))
    : [];
  const identityCollectors = filteredCollectors.filter(row => collectorSection(row.entry) === 'identity');
  const otherCollectors = filteredCollectors.filter(row => collectorSection(row.entry) !== 'identity');
  const showCloudPull = cloudPull.available && (categoryFilter === 'all' || categoryFilter === 'pull')
    && (!installedOnly || cloudPull.sources.length > 0) && cloudPullMatches(searchQuery);
  const cloudPullCard = showCloudPull ? <CloudPullCard key="cloud-pull" sources={cloudPull.sources} /> : null;
  const pullCount = collectors.rows.length + (cloudPull.available ? 1 : 0);
  // Threat-intel lookup providers (category agent) on hosted-shared tenants.
  const threatIntel = useThreatIntelEnabled();
  const threatIntelCount = useThreatIntelProviders().data?.providers.length ?? 0;
  const threatIntelSection = threatIntel && (categoryFilter === 'all' || categoryFilter === 'agent')
    ? <ThreatIntelProvidersSection searchQuery={searchQuery} installedOnly={installedOnly} /> : null;
  const grouped = useMemo(() => {
    // Platform feeds key on their canonical feed id (`ipinfo_lite`,
    // `tor_exit_nodes`). A repo-installed connector keys on `connector:<uuid>`
    // instead, so it would never match a curated slug — group it by the catalog
    // slug the backend records in `connector` (see `inventory_connectors`), which
    // is what put AbuseIPDB/VirusTotal under "Popular" on the dedicated page.
    // A hand-authored custom provider carries its enrichment_type there
    // ('data'/'agent'), which matches no curated slug, so it stays uncategorised.
    const byId = new Map<string, InventoryItem>();
    for (const item of inventory.data ?? []) {
      byId.set(item.id, item);
      if (item.kind === 'custom') {
        const alias = inventoryRouteId(item.connector);
        if (!byId.has(alias)) byId.set(alias, item);
      }
    }
    const assigned = new Set<string>();
    const sections = SECTIONS.map(section => ({
      section,
      // Normalize every curated slug, and deduplicate the two IPinfo aliases.
      items: [...new Set(section.slugs.map(inventoryRouteId))].flatMap(slug => {
        const item = byId.get(slug);
        if (!item || assigned.has(item.id)) return [];
        assigned.add(item.id);
        return [item];
      }),
    })).filter(group => group.items.length > 0);
    const custom = (inventory.data ?? []).filter(item => !assigned.has(item.id) && (item.id.startsWith('custom:') || item.id.startsWith('connector:')));
    custom.forEach(item => assigned.add(item.id));
    const other = (inventory.data ?? []).filter(item => !assigned.has(item.id));
    return { sections, custom, other };
  }, [inventory.data]);
  const showSections = categoryFilter === 'all' && !searchQuery.trim() && !installedOnly;
  // Cloud pull sits in Cloud infrastructure (NAN-3596); keep that group even when no curated item fills it.
  const sectionGroups = showCloudPull && !grouped.sections.some(group => group.section.key === 'cloud')
    ? SECTIONS.flatMap(section => section.key === 'cloud' ? [{ section, items: [] as InventoryItem[] }] : grouped.sections.filter(group => group.section.key === section.key))
    : grouped.sections;
  const platformCount = items.filter(item => item.kind === 'baseline' || item.kind === 'premium').length;
  const customCount = items.filter(item => item.kind === 'custom').length;
  const cards = (list: InventoryItem[]) => list.map(item => <InventoryCard key={item.id} item={item} airGap={airGap} onOpen={() => select(item.id)} />);
  const collectorCards = (list: CollectorRow[]) => list.map(row => <CollectorCard key={`${user?.active_tenant?.id}:${user?.id}:${row.entry.slug}`} {...row}
    canInstall={collectors.canInstall} canRemove={collectors.canRemove} canRotate={collectors.canRotate} queryKey={collectors.queryKey} />);
  const allCount = items.length + pullCount;
  const visibleCount = filtered.length + filteredCollectors.length + (showCloudPull ? 1 : 0);
  // NAN-3761: a failed load is never rendered as "No integrations matched".
  const loadFailures = [...(inventory.isError ? ['inventory'] : []), ...(collectors.isError ? ['pull collectors'] : [])];
  return <MarketplacePageShell
    totalCount={items.length} repos={repos} airGap={airGap}
    headerActions={canOpenCreate && <Button variant="outline" onClick={() => author('new')}>Create / Connect</Button>}
    statsStrip={<StatsStrip stats={{ total_entries: items.length, installed_count: 0, data_count: 0, agent_count: 0, identity_count: 0, collector_count: 0 }} tiles={[
      { label: 'Enabled', value: items.filter(item => item.enabled).length },
      { label: 'Platform', value: platformCount },
      { label: 'Premium', value: items.filter(item => item.kind === 'premium').length },
      { label: 'Custom', value: customCount },
    ]} />}
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
    chips={[
      { id: 'all' as const, label: 'All', icon: Box, count: allCount },
      { id: 'platform' as const, label: 'Platform', icon: Cloud, count: platformCount },
      { id: 'custom' as const, label: 'Custom', icon: Users, count: customCount },
      ...(pullCount ? [{ id: 'pull' as const, label: 'Pull', icon: ArrowDownToLine, count: pullCount }] : []),
      ...(threatIntel ? [{ id: 'agent' as const, label: 'Agent', icon: Bot, count: threatIntelCount }] : []),
    ]}
    categoryFilter={categoryFilter} setCategoryFilter={setCategoryFilter}
    searchQuery={searchQuery} setSearchQuery={setSearchQuery}
    installedOnly={installedOnly} toggleInstalledOnly={toggleInstalledOnly} toggleLabel="enabled only"
    sourcesMenu={<SourcesMenu repos={repos} syncingId={syncingRepo} onSync={handleSyncRepo} />}
    overlays={<>
    {selectedId && detail.isPending && <p role="status">Loading provider details…</p>}
    {selectedId && detail.isError && !unavailable && <p role="alert">Could not load this item: {detail.error.message}</p>}
    {editing ? <Suspense fallback={<p role="status">Loading provider editor…</p>}><InventoryEditor key={`${user?.active_tenant?.id}:${user?.id}`} definitionId={params.get('author') === 'new' ? 'new' : selected!.id.slice(7)} onClose={() => select(selected?.id)} onSaved={saved} /></Suspense>
      : connecting && selected?.kind === 'custom' ? <Suspense fallback={<p role="status">Loading connection…</p>}><ConnectionDrawer key={`${user?.active_tenant?.id}:${user?.id}:${selected.id}`} slug={selected.connector} open onOpenChange={open => { if (!open) select(selected.id); }} onUpdated={() => { void client.invalidateQueries({ queryKey }); }} initialTab={connectionTab} /></Suspense>
      : selected && <Suspense fallback={<p>Loading details…</p>}><InventoryDrawer item={selected} onClose={() => select()} busy={(airGap && selected.kind === 'premium' && !selected.entitled) || mutation.isPending || checkout.isPending || (selected.kind === 'premium' && !selected.entitled ? !canReadPurchase : !mayToggle)} onPurchase={canReadPurchase && !airGap ? () => checkout.mutate() : undefined} onToggle={() => setConfirm(selected)} onEdit={canAuthor && selected.id.startsWith('custom:') ? () => author('edit') : undefined} onConnect={canConnect ? () => author('connect') : undefined} purchaseStatus={purchaseStatus} /></Suspense>}
    <ConfirmDialog open={!!confirm} onOpenChange={open => { if (!open) setConfirm(null); }} title={`${confirm?.enabled ? 'Disable' : 'Enable'} ${confirm?.name ?? 'provider'}?`}
      description="This changes the provider state for this tenant." onConfirm={() => { if (confirm) mutation.mutate(confirm); setConfirm(null); }} loading={mutation.isPending} />
    </>}
  >
    {inventory.isError && visibleCount > 0 && <p role="alert" className="mt-4 text-[12px] text-destructive">Could not load inventory. <button className="underline" onClick={() => { void inventory.refetch(); }}>Retry</button></p>}
    {checkout.isError && <p role="alert">Checkout is unavailable. Retry to resume the same purchase.</p>}
    {mutation.isError && <p role="alert">{mutation.error.message} Reloaded current provider state.</p>}
    {unavailable && <p className="mt-4 text-[12px] text-muted-foreground">That integration isn't available on this tenant</p>}
    {collectors.isError && visibleCount > 0 && <p role="alert" className="mt-4 text-[12px] text-destructive">Could not load pull collectors. <button className="underline" onClick={collectors.refetch}>Retry</button></p>}
    {categoryFilter === 'agent' ? (
      <div className="mt-5">{threatIntelSection}</div>
    ) : inventory.isPending && categoryFilter !== 'pull' ? (
      <div className="mt-8 flex items-center justify-center py-12"><LoadingIcon className="w-6 h-6 text-muted-foreground" /></div>
    ) : visibleCount === 0 ? (loadFailures.length > 0
      ? <LoadErrorState what={loadFailures.join(' and ')} retrying={inventory.isFetching || collectors.isRefetching}
          onRetry={() => { if (inventory.isError) void inventory.refetch(); if (collectors.isError) collectors.refetch(); }} />
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
    ) : <>
      <div className="mt-5 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">{cards(filtered)}{collectorCards(filteredCollectors)}{cloudPullCard}</div>
      {threatIntelSection && <div className="mt-6">{threatIntelSection}</div>}
    </>}
  </MarketplacePageShell>;
}
