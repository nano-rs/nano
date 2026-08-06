// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  AlertTriangle, Check, CheckCircle, Code as CodeIcon, Copy, Download,
  Eye, EyeOff, FileDown, Info, KeyRound, Loader2, Lock, Plug, RefreshCw, Save,
  Settings as SettingsIcon, Trash2, Zap,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Sheet, SheetContent } from '@/components/ui/sheet';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { PreviewModal } from './PreviewModal';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import type { CredentialFieldDef, MarketplaceCatalogEntry } from '@/lib/api/marketplace';
import { useToast } from '@/hooks/use-toast';
import { formatNumber, formatUTCCompact } from '@/lib/date-utils';
import { cn } from '@/lib/utils';
import { isDataFeed, isIpInfoEntry } from '@/lib/api/marketplace';
import { ConnectionsTab } from './ConnectionsTab';
import { MonoSwatch, getCategoryTone } from './MonoSwatch';
import { StateBadge, getIntegrationState, IpInfoCredit } from './IntegrationCard';

const TABS = [
  { id: 'about',  label: 'About',       icon: Info },
  { id: 'config', label: 'Config',      icon: SettingsIcon },
  // NAN-2192: collectors only. A marketplace entry is 1:1 with its config, but
  // a collector is 1:N — one integration, many vendor tenants — so it needs a
  // place to manage connections. Filtered out for enrichments, which have none.
  { id: 'connections', label: 'Connections', icon: Plug },
  { id: 'code',   label: 'Code',        icon: CodeIcon },
  { id: 'perms',  label: 'Permissions', icon: Lock },
] as const;
export type MarketplaceDrawerTab = typeof TABS[number]['id'];
type TabId = MarketplaceDrawerTab;

/** How long to keep polling an open drawer after triggering a sync (NAN-2343). */
const SYNC_WATCH_MS = 30_000;
/** Gap between those polls. */
const SYNC_POLL_MS = 2_500;
/** Absolute cap, so a sync wedged in `in_progress` cannot poll forever. */
const SYNC_WATCH_MAX_MS = 5 * 60_000;

interface MarketplaceDrawerProps {
  slug: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onUpdated: () => void;
  initialTab?: MarketplaceDrawerTab;
}

export function MarketplaceDrawer({
  slug,
  open,
  onOpenChange,
  onUpdated,
  initialTab = 'config',
}: MarketplaceDrawerProps) {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canPreview = hasPermission('enrichments:configure');
  const canViewCode =
    hasPermission('enrichments:view') && hasPermission('enrichments:code');
  const canDeleteCustomCollector =
    hasPermission('log_sources:delete') && hasPermission('enrichments:code');
  // Air-gap mode — shared cache with the catalog page's query key. When the
  // entry needs network, the egress "Sync now" action is replaced by an
  // import-from-file route so the drawer stays honest offline (NAN-1212).
  const airGapQuery = useQuery({
    queryKey: ['system', 'config'],
    queryFn: () => api.getSystemConfig(),
    staleTime: Infinity,
    gcTime: Infinity,
    retry: 1,
    refetchOnWindowFocus: false,
  });
  const airGap = airGapQuery.data?.air_gap ?? false;
  const [entry, setEntry] = useState<MarketplaceCatalogEntry | null>(null);
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<TabId>('config');
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  // Stored values as loaded from the server, so a save can submit only the
  // fields the operator actually changed (NAN-2343).
  const [pristineCredentials, setPristineCredentials] = useState<Record<string, string>>({});
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({});
  const [savingCreds, setSavingCreds] = useState(false);
  const [credsDirty, setCredsDirty] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [checkingDelete, setCheckingDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  // Bumped on each sync trigger to (re)arm the watch interval (NAN-2343).
  const [syncWatchToken, setSyncWatchToken] = useState(0);

  useEffect(() => {
    if (!slug || !open) return;
    setLoading(true);
    setCredentials({});
    setPristineCredentials({});
    setShowSecrets({});
    setCredsDirty(false);
    setDeleteOpen(false);
    setTab(initialTab);
    api.marketplace.getCatalogEntry(slug)
      .then(loaded => {
        setEntry(loaded);
        void hydrateReadableCredentials(loaded);
      })
      .catch(() => toast({ title: 'Error', description: 'Failed to load details', variant: 'destructive' }))
      .finally(() => setLoading(false));
    // hydrateReadableCredentials is stable for a given render pass and depends
    // only on setters; including it would re-run this loader on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [slug, open, toast, initialTab]);

  // Show the operator what is actually stored, for credential fields that are
  // not secrets.
  //
  // NAN-2343: unmasking `download_url` (migration 285) is only half the fix —
  // the input's value comes from `credentials`, which starts empty, so a
  // configured entry still rendered a placeholder and the saved string stayed
  // unreadable. That was the whole reason the legacy /enrichments/ipinfo_lite
  // page had to exist, and this PR retires it.
  //
  // Native sources keep their operational values in their own tables, not in
  // `marketplace_catalog.credentials_encrypted` (which is deliberately never
  // serialized), so read them from the enrichment sources API. Fields still
  // declared `secret` are intentionally NOT hydrated — those stay write-only.
  const hydrateReadableCredentials = async (loaded: MarketplaceCatalogEntry) => {
    const readable = (loaded.credential_fields ?? []).filter(f => f.field_type !== 'secret');
    if (!loaded.native_source_id || readable.length === 0) return;
    try {
      const sources = await api.listEnrichmentSources();
      const source = sources.find(s => s.id === loaded.native_source_id);
      if (!source) return;
      const stored: Record<string, string> = {};
      if (readable.some(f => f.name === 'download_url') && source.download_url) {
        stored.download_url = source.download_url;
      }
      if (Object.keys(stored).length === 0) return;
      setPristineCredentials(stored);
      setCredentials(prev => ({ ...stored, ...prev }));
    } catch {
      // Requires enrichments:view, which a marketplace-only operator may lack.
      // Falling back to an empty field is the pre-existing behaviour, so this
      // degrades rather than breaking the drawer.
    }
  };

  // Re-read this drawer's own entry. `onUpdated()` only refreshes the parent
  // catalog list, which the drawer does not read from (NAN-2343).
  const refreshEntry = useCallback(async () => {
    if (!slug) return;
    try {
      setEntry(await api.marketplace.getCatalogEntry(slug));
    } catch {
      // Keep the last-known entry; a transient refresh failure should not blank
      // an open drawer or raise a toast the operator did not ask for.
    }
  }, [slug]);

  // Follow a freshly triggered sync to a terminal state. A sync can finish (or
  // fail) either side of the refresh in `handleSync`, so poll rather than
  // assume a single read lands after the outcome.
  //
  // A fixed interval with a hard deadline, deliberately not a chain of
  // timeouts keyed on `entry`: that shape stalls permanently if one refresh
  // throws (no state change, so nothing reschedules) and conversely never
  // stops while `is_syncing` stays true. `refreshEntry` swallows its errors,
  // so a transient failure just means one missed tick (NAN-2343).
  useEffect(() => {
    if (!open || !slug || !syncWatchToken) return;
    const deadline = Date.now() + SYNC_WATCH_MS;
    const poll = setInterval(() => {
      if (Date.now() >= deadline && !entryRef.current?.is_syncing) {
        clearInterval(poll);
        return;
      }
      void refreshEntry();
    }, SYNC_POLL_MS);
    const hardStop = setTimeout(() => clearInterval(poll), SYNC_WATCH_MAX_MS);
    return () => {
      clearInterval(poll);
      clearTimeout(hardStop);
    };
  }, [open, slug, syncWatchToken, refreshEntry]);

  // Latest entry for the interval above, which must not re-subscribe per poll.
  const entryRef = useRef<MarketplaceCatalogEntry | null>(null);
  useEffect(() => {
    entryRef.current = entry;
  }, [entry]);

  // Always-current handle on the save routine.
  //
  // NAN-2343: the ⌘↵ listener below is (deliberately) only re-installed when
  // `open`/`credsDirty` change, but `handleSaveCredentials` closes over
  // `credentials`. `credsDirty` flips true on the *first* keystroke and never
  // flips again while editing, so the listener kept forever whichever snapshot
  // existed at that first change — pressing ⌘↵ after typing a URL persisted
  // the single character typed first. Routing through a ref keeps the listener
  // stable while the behaviour it invokes stays current.
  const saveCredentialsRef = useRef<(() => Promise<void>) | null>(null);
  useEffect(() => {
    saveCredentialsRef.current = handleSaveCredentials;
  });

  // ⌘↵ to apply (Esc handled by Sheet itself)
  useEffect(() => {
    if (!open || !credsDirty) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
        e.preventDefault();
        void saveCredentialsRef.current?.();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, credsDirty]);

  const generateToken = () => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    const token = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    setCredentials(prev => ({ ...prev, collector_token: token }));
    setShowSecrets(prev => ({ ...prev, collector_token: true }));
    setCredsDirty(true);
  };

  const handleToggleEnabled = async (enabled: boolean) => {
    if (!entry) return;
    try {
      const updated = await api.marketplace.configureEnrichment(entry.slug, { enabled });
      setEntry(updated);
      onUpdated();
      toast({ title: enabled ? 'Enabled' : 'Disabled', description: `${entry.name} has been ${enabled ? 'enabled' : 'disabled'}` });
    } catch {
      toast({ title: 'Error', description: 'Failed to update', variant: 'destructive' });
    }
  };

  const handleSync = async () => {
    if (!entry) return;
    setSyncing(true);
    try {
      await api.marketplace.syncEnrichment(entry.slug);
      toast({ title: 'Sync triggered', description: 'Data sync is running' });
      // NAN-1108: fire the parent refetch so the catalog page sees
      // is_syncing=true on the next load and kicks off polling. Without
      // this, the card stays on `synced Xago` until the user navigates
      // away — the polling effect waits for a positive signal that never
      // arrives.
      onUpdated();
      // NAN-2343: `onUpdated` refreshes the *parent* catalog; this drawer holds
      // its own `entry` and would otherwise sit on pre-sync state until closed
      // and reopened. That is why a sync which fails immediately — a malformed
      // URL fails before any network I/O — left "Data sync is running" on
      // screen indefinitely while the failure was already recorded.
      setSyncWatchToken(t => t + 1);
      await refreshEntry();
    } catch {
      toast({ title: 'Error', description: 'Failed to trigger sync', variant: 'destructive' });
    } finally {
      setSyncing(false);
    }
  };

  const handleUninstall = async () => {
    if (!entry) return;
    try {
      await api.marketplace.uninstallEnrichment(entry.slug);
      toast({ title: 'Uninstalled', description: `${entry.name} has been uninstalled` });
      onUpdated();
      onOpenChange(false);
    } catch {
      toast({ title: 'Error', description: 'Failed to uninstall', variant: 'destructive' });
    }
  };

  const prepareCustomCollectorDelete = async () => {
    if (!entry) return;
    setCheckingDelete(true);
    try {
      const { instances } = await api.integrations.listInstances(entry.slug);
      if (instances.length > 0) {
        setTab('connections');
        toast({
          title: 'Delete connections first',
          description: `${instances.length} connection${instances.length === 1 ? '' : 's'} still belong to this integration. Remove them from Connections, then delete the integration.`,
          variant: 'destructive',
        });
        return;
      }
      setDeleteOpen(true);
    } catch (error) {
      toast({
        title: 'Could not check connections',
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setCheckingDelete(false);
    }
  };

  const handleDeleteCustomCollector = async () => {
    if (!entry) return;
    setDeleting(true);
    try {
      await api.integrations.deleteCustomCollector(entry.id);
      setDeleteOpen(false);
      toast({
        title: 'Integration deleted',
        description: `${entry.name} was permanently removed. Its Log Sources were kept.`,
      });
      onUpdated();
      onOpenChange(false);
    } catch (error) {
      toast({
        title: 'Could not delete integration',
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setDeleting(false);
    }
  };

  const handleUpdate = async () => {
    if (!entry) return;
    setUpdating(true);
    try {
      const updated = await api.marketplace.updateEnrichment(entry.slug);
      setEntry(updated);
      onUpdated();
      toast({ title: 'Updated', description: `${entry.name} updated to v${updated.manifest_version}` });
    } catch {
      toast({ title: 'Error', description: 'Failed to update', variant: 'destructive' });
    } finally {
      setUpdating(false);
    }
  };

  const handleExport = async () => {
    if (!entry) return;
    setExporting(true);
    try {
      const exported = await api.marketplace.exportEnrichment(entry.slug);
      const files = [
        { name: `${exported.slug}-manifest.yaml`, content: exported.manifest_yaml },
        { name: `${exported.slug}-code.ts`, content: exported.code },
      ];
      for (const file of files) {
        const blob = new Blob([file.content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = file.name;
        a.click();
        URL.revokeObjectURL(url);
      }
      toast({ title: 'Exported', description: `Place files in ${exported.directory} and submit a PR` });
    } catch {
      toast({ title: 'Error', description: 'Failed to export enrichment', variant: 'destructive' });
    } finally {
      setExporting(false);
    }
  };

  const handleSaveCredentials = async () => {
    if (!entry) return;
    setSavingCreds(true);
    try {
      // Submit only what the operator actually changed. `credentials` is now
      // pre-filled with readable stored values (see `hydrateReadableCredentials`),
      // so posting it wholesale would re-send an untouched download URL and
      // re-queue a multi-million-row sync for a save that changed nothing
      // (NAN-2343).
      const changed = Object.fromEntries(
        Object.entries(credentials).filter(([k, v]) => v !== (pristineCredentials[k] ?? '')),
      );
      if (Object.keys(changed).length === 0) {
        setCredsDirty(false);
        toast({ title: 'No changes', description: 'Credentials are unchanged' });
        return;
      }
      const updated = await api.marketplace.configureEnrichment(entry.slug, { credentials: changed });
      setEntry(updated);
      setCredsDirty(false);
      // Keep readable values on screen after saving; what was just written is
      // now the pristine baseline. Write-only secrets stay cleared.
      setPristineCredentials(prev => ({ ...prev, ...changed }));
      setCredentials(prev =>
        Object.fromEntries(Object.entries(prev).filter(([k]) => k in pristineCredentials)),
      );
      onUpdated();
      toast({ title: 'Credentials saved', description: 'Credentials have been encrypted and stored' });
    } catch (err) {
      // NAN-2343: the server now rejects a malformed download URL with 422 and
      // names the field and reason. Swallowing that into a generic "Failed to
      // save" was the difference between the operator fixing a typo in seconds
      // and filing a support ticket, so show what the server said.
      const description = err instanceof Error && err.message
        ? err.message
        : 'Failed to save credentials';
      toast({ title: 'Could not save credentials', description, variant: 'destructive' });
      // Leave the edit in place and still dirty — the operator needs the bad
      // value on screen to correct it, and clearing it would repeat the
      // original sin of hiding what was actually submitted.
    } finally {
      setSavingCreds(false);
    }
  };

  return (
    <>
      <Sheet open={open} onOpenChange={onOpenChange}>
        <SheetContent
          className="!w-[600px] !max-w-[600px] sm:!max-w-[600px] p-0 flex flex-col overflow-hidden"
          style={{ background: 'var(--color-inspector, var(--card))' }}
        >
          {loading || !entry ? (
            <div className="flex-1 flex items-center justify-center">
              <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <DrawerInner
              entry={entry}
              canViewCode={canViewCode}
              airGap={airGap}
              tab={tab}
              setTab={setTab}
              credentials={credentials}
              setCredentials={setCredentials}
              credsDirty={credsDirty}
              markCredsDirty={() => setCredsDirty(true)}
              showSecrets={showSecrets}
              setShowSecrets={setShowSecrets}
              generateToken={generateToken}
              handleToggleEnabled={handleToggleEnabled}
              handleSync={handleSync}
              handleUninstall={handleUninstall}
              prepareCustomCollectorDelete={prepareCustomCollectorDelete}
              canDeleteCustomCollector={canDeleteCustomCollector}
              checkingDelete={checkingDelete}
              handleUpdate={handleUpdate}
              handleExport={handleExport}
              handleSaveCredentials={handleSaveCredentials}
              syncing={syncing}
              updating={updating}
              exporting={exporting}
              savingCreds={savingCreds}
              canPreview={canPreview}
              onOpenPreview={() => setPreviewOpen(true)}
            />
          )}
        </SheetContent>
      </Sheet>
      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Permanently delete this integration?"
        description={
          <>
            <span className="font-medium text-foreground">{entry?.name}</span> and its authored
            collector code will be removed from Marketplace. Previously-created Log Sources are
            retained so their parser configuration and history are not destroyed.
          </>
        }
        confirmLabel="Delete integration"
        loadingLabel="Deleting…"
        variant="danger"
        loading={deleting}
        confirmIcon={<Trash2 className="h-3 w-3" />}
        onConfirm={() => void handleDeleteCustomCollector()}
      />
      <PreviewModal
        slug={previewOpen ? entry?.slug ?? null : null}
        name={entry?.name ?? null}
        open={previewOpen}
        onOpenChange={setPreviewOpen}
      />
    </>
  );
}

interface DrawerInnerProps {
  entry: MarketplaceCatalogEntry;
  canViewCode: boolean;
  airGap: boolean;
  tab: TabId;
  setTab: (t: TabId) => void;
  credentials: Record<string, string>;
  setCredentials: React.Dispatch<React.SetStateAction<Record<string, string>>>;
  credsDirty: boolean;
  markCredsDirty: () => void;
  showSecrets: Record<string, boolean>;
  setShowSecrets: React.Dispatch<React.SetStateAction<Record<string, boolean>>>;
  generateToken: () => void;
  handleToggleEnabled: (enabled: boolean) => Promise<void>;
  handleSync: () => Promise<void>;
  handleUninstall: () => Promise<void>;
  prepareCustomCollectorDelete: () => Promise<void>;
  canDeleteCustomCollector: boolean;
  checkingDelete: boolean;
  handleUpdate: () => Promise<void>;
  handleExport: () => Promise<void>;
  handleSaveCredentials: () => Promise<void>;
  syncing: boolean;
  updating: boolean;
  exporting: boolean;
  savingCreds: boolean;
  canPreview: boolean;
  onOpenPreview: () => void;
}

function DrawerInner(props: DrawerInnerProps) {
  const {
    entry, canViewCode, airGap, tab, setTab,
    credentials, setCredentials, credsDirty, markCredsDirty,
    showSecrets, setShowSecrets, generateToken,
    handleToggleEnabled, handleSync, handleUninstall, prepareCustomCollectorDelete,
    handleUpdate, handleExport, handleSaveCredentials,
    syncing, updating, exporting, savingCreds,
    canPreview, canDeleteCustomCollector, checkingDelete,
    onOpenPreview,
  } = props;

  const state = getIntegrationState(entry);
  const tone = getCategoryTone(entry.category);
  const monogram = (entry.name?.trim()?.[0] || '?').toUpperCase();
  const hasUpdate = entry.installed && entry.manifest_version > (entry.installed_version ?? 0);

  return (
    <>
      {/* Header */}
      <div className="px-5 py-4 border-b border-border flex items-start gap-3 bg-muted/20">
        <MonoSwatch ch={monogram} tone={tone} size={42} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-[16px] font-semibold text-foreground">{entry.name}</h3>
            <StateBadge state={state} />
          </div>
          <div className="text-[11.5px] text-muted-foreground mt-1 line-clamp-2" style={{ textWrap: 'pretty' }}>
            {entry.description}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-[10px] font-mono text-muted-foreground">
            <span className="px-1.5 py-px rounded bg-muted/40 border border-border/60 uppercase tracking-[0.08em]">
              {entry.category}
            </span>
            <span>·</span>
            <span>{entry.author || 'core-enrichments'}@v{entry.installed_version ?? entry.manifest_version}</span>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-border flex items-center px-2 bg-muted/20">
        {TABS
          .filter(t => t.id !== 'code' || canViewCode)
          .filter(t => t.id !== 'connections' || entry.execution_backend === 'collector')
          .map(t => {
          const Tg = t.icon;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={cn(
                'h-9 px-3 inline-flex items-center gap-1.5 text-[12px] border-b-2 -mb-px',
                tab === t.id ? 'text-foreground border-primary' : 'text-muted-foreground border-transparent hover:text-foreground',
              )}
            >
              <Tg className="w-[12px] h-[12px]" /> {t.label}
            </button>
          );
        })}
        <div className="flex-1" />
        <button
          type="button"
          onClick={onOpenPreview}
          disabled={!entry.installed || !canPreview}
          title={
            !canPreview
              ? 'Requires permission to configure enrichments'
              : entry.installed
                ? 'Run the enrichment against a sample artifact'
                : 'Install first to preview'
          }
          className="h-7 px-2 rounded text-[11px] text-muted-foreground hover:text-foreground hover:bg-muted/40 disabled:opacity-50 disabled:cursor-not-allowed inline-flex items-center gap-1 font-mono"
        >
          <Eye className="w-[11px] h-[11px]" /> preview output
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto scrollbar-thin">
        {tab === 'about' && <AboutTab entry={entry} />}
        {tab === 'config' && (
          <ConfigTab
            entry={entry}
            airGap={airGap}
            credentials={credentials}
            setCredentials={setCredentials}
            credsDirty={credsDirty}
            markCredsDirty={markCredsDirty}
            showSecrets={showSecrets}
            setShowSecrets={setShowSecrets}
            generateToken={generateToken}
            handleToggleEnabled={handleToggleEnabled}
            handleSync={handleSync}
            handleUninstall={handleUninstall}
            prepareCustomCollectorDelete={prepareCustomCollectorDelete}
            canDeleteCustomCollector={canDeleteCustomCollector}
            checkingDelete={checkingDelete}
            handleSaveCredentials={handleSaveCredentials}
            syncing={syncing}
            savingCreds={savingCreds}
            hasUpdate={hasUpdate}
            handleUpdate={handleUpdate}
            updating={updating}
          />
        )}
        {tab === 'connections' && entry.execution_backend === 'collector' && (
          <ConnectionsTab entry={entry} />
        )}
        {tab === 'code' && canViewCode && (
          <CodeTab entry={entry} handleExport={handleExport} exporting={exporting} />
        )}
        {tab === 'perms' && <PermissionsTab entry={entry} />}
      </div>

      <div className="px-5 py-2.5 border-t border-border flex items-center justify-between text-[10.5px] font-mono text-muted-foreground bg-muted/20">
        <span>esc to close{credsDirty ? ' · ⌘↵ to apply' : ''}</span>
        <span>{entry.slug}@v{entry.manifest_version}</span>
      </div>
    </>
  );
}

function Eyebrow({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground', className)}>
      {children}
    </div>
  );
}

function AboutTab({ entry }: { entry: MarketplaceCatalogEntry }) {
  const installedVersion = entry.installed_version ?? entry.manifest_version;
  return (
    <div className="p-5 space-y-5 text-[13px] leading-[1.55] text-muted-foreground" style={{ textWrap: 'pretty' }}>
      <p className="text-foreground">{entry.description || 'No description.'}</p>
      <div className="grid grid-cols-2 gap-3">
        {[
          ['version', `v${installedVersion}`],
          ['license', 'MIT'],
          ['publisher', entry.author || 'core-enrichments'],
          ['source', entry.source_type],
        ].map(([k, v]) => (
          <div key={k} className="rounded border border-border/60 bg-card px-3 py-2">
            <div className="font-mono text-[10px] text-muted-foreground uppercase tracking-[0.1em]">{k}</div>
            <div className="text-[13px] text-foreground mt-0.5 font-mono">{v}</div>
          </div>
        ))}
      </div>
      {entry.tags?.length > 0 && (
        <div>
          <Eyebrow className="mb-2">Tags</Eyebrow>
          <div className="flex flex-wrap gap-1.5">
            {entry.tags.map(t => (
              <span key={t} className="font-mono text-[11px] text-foreground px-2 py-1 rounded bg-muted/40 border border-border/60">
                {t}
              </span>
            ))}
          </div>
        </div>
      )}
      <p>
        Once installed, this enrichment is invoked automatically by detection rules and notebooks that call{' '}
        <code className="font-mono text-primary text-[12px] px-1 bg-primary/10 rounded">
          {`enrich(ev, {provider:"${entry.slug}"})`}
        </code>{' '}
        on matching artifact types.
      </p>
      {/* CC BY-SA 4.0 redistribution credit for the native IPinfo Lite feed. */}
      {isIpInfoEntry(entry) && (
        <div className="pt-1 border-t border-border/60">
          <IpInfoCredit className="pt-3" />
        </div>
      )}
    </div>
  );
}

interface ConfigTabProps {
  entry: MarketplaceCatalogEntry;
  airGap: boolean;
  credentials: Record<string, string>;
  setCredentials: React.Dispatch<React.SetStateAction<Record<string, string>>>;
  credsDirty: boolean;
  markCredsDirty: () => void;
  showSecrets: Record<string, boolean>;
  setShowSecrets: React.Dispatch<React.SetStateAction<Record<string, boolean>>>;
  generateToken: () => void;
  handleToggleEnabled: (enabled: boolean) => Promise<void>;
  handleSync: () => Promise<void>;
  handleUninstall: () => Promise<void>;
  prepareCustomCollectorDelete: () => Promise<void>;
  canDeleteCustomCollector: boolean;
  checkingDelete: boolean;
  handleSaveCredentials: () => Promise<void>;
  syncing: boolean;
  savingCreds: boolean;
  hasUpdate: boolean;
  handleUpdate: () => Promise<void>;
  updating: boolean;
}

function ConfigTab(props: ConfigTabProps) {
  const {
    entry, airGap, credentials, setCredentials, credsDirty, markCredsDirty,
    showSecrets, setShowSecrets, generateToken,
    handleToggleEnabled, handleSync, handleUninstall, prepareCustomCollectorDelete,
    handleSaveCredentials, canDeleteCustomCollector, checkingDelete,
    syncing, savingCreds, hasUpdate, handleUpdate, updating,
  } = props;

  const credentialFields: CredentialFieldDef[] = entry.credential_fields ?? [];
  const needsCreds = entry.requires_credential !== 'none' && credentialFields.length > 0;
  const isSystem = entry.source_type === 'system';
  const isCustomCollector = entry.source_type === 'custom'
    && entry.execution_backend === 'collector';
  // Air-gap + connectivity-required: the live "Sync now" egress can't run.
  // Swap it for an import-from-file route so the action stays honest.
  const egressBlocked = airGap && (entry.requires_network ?? false);

  return (
    <div className="p-5 space-y-5">
      {/* Update banner */}
      {hasUpdate && (
        <div className="flex items-start justify-between gap-3 p-2.5 bg-primary/10 rounded-lg border border-primary/30">
          <div className="min-w-0">
            <p className="text-[12px] font-medium text-primary">Update available</p>
            <p className="text-[11px] text-primary/80 font-mono mt-0.5">
              v{entry.installed_version ?? 0} → v{entry.manifest_version}
            </p>
            {entry.changelog && (
              <p className="text-[11px] text-muted-foreground mt-1" style={{ textWrap: 'pretty' }}>{entry.changelog}</p>
            )}
          </div>
          <Button size="sm" className="h-7 rounded-md flex-shrink-0" onClick={handleUpdate} disabled={updating}>
            {updating ? <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5 mr-1" />}
            Update
          </Button>
        </div>
      )}

      {/* Enable toggle */}
      {entry.installed && (
        <div className="flex items-center justify-between rounded-md border border-border/60 bg-card px-3 py-2">
          <div>
            <Label className="text-[12px] text-foreground">Enabled</Label>
            <div className="text-[11px] text-muted-foreground">When off, the enrichment is installed but not invoked.</div>
          </div>
          <Switch checked={entry.enabled} onCheckedChange={handleToggleEnabled} />
        </div>
      )}

      {/* Status + record_count + last_sync + last_error */}
      {entry.installed && (isDataFeed(entry) || entry.last_sync_at || entry.last_error) && (
        <div className="rounded-md border border-border/60 bg-card divide-y divide-border/60">
          {isDataFeed(entry) && entry.record_count > 0 && (
            <div className="px-3 py-2.5 flex items-center justify-between">
              <span className="text-[12px] text-muted-foreground">Records</span>
              <span className="font-mono text-[12px] text-foreground">{formatNumber(entry.record_count)}</span>
            </div>
          )}
          {entry.last_sync_at && (
            <div className="px-3 py-2.5 flex items-center justify-between">
              <span className="text-[12px] text-muted-foreground">Last sync</span>
              <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-foreground">
                {entry.last_sync_status === 'success' && <CheckCircle className="w-3.5 h-3.5 text-emerald-500" />}
                {entry.last_sync_status === 'failed' && <AlertTriangle className="w-3.5 h-3.5 text-red-500" />}
                {formatUTCCompact(entry.last_sync_at)}
              </span>
            </div>
          )}
          {entry.last_error && (
            <div className="px-3 py-2.5 text-[11px] text-red-500 font-mono whitespace-pre-wrap break-words">
              {entry.last_error}
            </div>
          )}
        </div>
      )}

      {/* Credentials */}
      {entry.installed && needsCreds && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Lock className="w-[12px] h-[12px] text-muted-foreground" />
            <Eyebrow>
              Credentials {entry.has_credentials && (
                <span className="ml-1 inline-flex items-center gap-1 px-1.5 py-px rounded font-mono text-[9.5px] uppercase tracking-[0.1em] border bg-emerald-500/10 border-emerald-500/30 text-emerald-500">
                  configured
                </span>
              )}
            </Eyebrow>
          </div>
          <div className="rounded-md border border-border/60 bg-card overflow-hidden divide-y divide-border/60">
            {credentialFields.map(field => (
              <div key={field.name} className="px-3 py-2.5 flex items-center gap-3">
                <div className="w-[110px] shrink-0">
                  <div className="text-[12px] text-foreground">
                    {field.label}
                    {field.required && <span className="text-red-500 ml-1">*</span>}
                  </div>
                  <div className="font-mono text-[10px] text-muted-foreground uppercase tracking-[0.08em]">
                    {field.field_type}
                  </div>
                </div>
                <div className="flex-1 relative">
                  <Input
                    id={`cred-${field.name}`}
                    type={field.field_type === 'secret' && !showSecrets[field.name] ? 'password' : 'text'}
                    // Only a write-only secret gets the mask placeholder. A
                    // readable field that is empty is genuinely unset, and
                    // showing dots there is what let a missing/!malformed URL
                    // masquerade as "configured" (NAN-2343).
                    placeholder={
                      entry.has_credentials && field.field_type === 'secret'
                        ? '••••••••'
                        : (field.help || `Enter ${field.label}`)
                    }
                    value={credentials[field.name] || ''}
                    onChange={(e) => {
                      setCredentials(prev => ({ ...prev, [field.name]: e.target.value }));
                      markCredsDirty();
                    }}
                    className={cn(
                      'h-8 rounded-md font-mono text-[12px]',
                      field.field_type === 'secret' && 'pr-8',
                    )}
                  />
                  {field.field_type === 'secret' && (
                    <Button
                      variant="ghost"
                      size="icon"
                      className="absolute right-0.5 top-1/2 -translate-y-1/2 h-7 w-7"
                      onClick={() => setShowSecrets(prev => ({ ...prev, [field.name]: !prev[field.name] }))}
                    >
                      {showSecrets[field.name] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
          {credentialFields.find(f => f.name === 'collector_token') && (
            <div className="mt-2 flex items-center gap-2">
              <Button variant="outline" size="sm" className="h-7 rounded-md text-[11px]" onClick={generateToken}>
                <KeyRound className="w-3 h-3 mr-1" /> Generate token
              </Button>
              {credentials.collector_token && (
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 rounded-md text-[11px]"
                  onClick={() => navigator.clipboard.writeText(credentials.collector_token)}
                >
                  <Copy className="w-3 h-3 mr-1" /> Copy
                </Button>
              )}
            </div>
          )}
          {credentialFields.find(f => f.help) && (
            <p className="mt-2 text-[11px] text-muted-foreground">
              {credentialFields.find(f => f.help)?.help}
            </p>
          )}
          {credsDirty && (
            <Button size="sm" className="mt-3 h-8 rounded-md" onClick={handleSaveCredentials} disabled={savingCreds}>
              {savingCreds ? <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" /> : <Save className="w-3.5 h-3.5 mr-1" />}
              Save credentials
            </Button>
          )}
        </div>
      )}

      {/* Artifact types */}
      {entry.tags?.length > 0 && (
        <div>
          <Eyebrow className="mb-2">Artifact types</Eyebrow>
          <div className="flex flex-wrap gap-1.5">
            {entry.tags.map(a => (
              <span key={a} className="font-mono text-[11px] text-foreground px-2 py-1 rounded bg-muted/40 border border-border/60">
                {a}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Requires */}
      {entry.allowed_domains?.length > 0 && (
        <div>
          <Eyebrow className="mb-2">Requires</Eyebrow>
          <ul className="space-y-1.5">
            <li className="flex items-center gap-2 text-[12px] text-foreground">
              <Check className="w-[12px] h-[12px] text-emerald-500" /> outbound HTTPS
            </li>
            {entry.requires_credential === 'required' && (
              <li className="flex items-center gap-2 text-[12px] text-foreground">
                <Check className="w-[12px] h-[12px] text-emerald-500" /> API credentials
              </li>
            )}
          </ul>
        </div>
      )}

      {/* Action footer */}
      <div className="pt-2 border-t border-border/60 flex items-center gap-2">
        {!entry.installed ? (
          <p className="text-[12px] text-muted-foreground">
            {isCustomCollector
              ? 'This integration is uninstalled. Its retained connections can still be deleted.'
              : 'Install this enrichment to start using it.'}
          </p>
        ) : (
          <>
            {/*
              This slot carries "Activate" and nothing else.

              It was a bare enable/disable toggle *labelled* "Apply changes"
              while enabled, so the obvious button to press after editing a
              credential discarded the edit and deactivated the integration
              (NAN-2343). Making it save instead removed the trap but left two
              buttons for one action — and since the inline "Save credentials"
              only renders while dirty, the one still on screen after a save
              was the permanently greyed-out one, reading as unfinished work
              (NAN-2345).

              Saving belongs to the button beside the fields: it is adjacent to
              what it acts on, it works whether or not the integration is
              enabled, and it appears only when there is something to save.
              Enable/disable belongs to the Switch above. Nothing is left for
              an enabled entry to "apply" here.
            */}
            {!entry.enabled && (
              <Button
                size="sm"
                className="h-8 rounded-md"
                onClick={() => handleToggleEnabled(true)}
                disabled={entry.requires_credential === 'required' && !entry.has_credentials}
              >
                <Zap className="w-[12px] h-[12px] mr-1" />
                Activate
              </Button>
            )}
            {isDataFeed(entry) && (
              egressBlocked ? (
                <Link to="/settings/airgap-import">
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8 rounded-md"
                    title="Live sync needs outbound internet. Import a signed data bundle instead."
                  >
                    <FileDown className="w-3.5 h-3.5 mr-1" /> Import bundle
                  </Button>
                </Link>
              ) : (
                <Button variant="outline" size="sm" className="h-8 rounded-md" onClick={handleSync} disabled={syncing}>
                  {syncing ? <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5 mr-1" />}
                  Sync now
                </Button>
              )
            )}
          </>
        )}
        <div className="flex-1" />
        {isCustomCollector ? (
          <Button
            variant="ghost"
            size="sm"
            className="h-8 rounded-md text-muted-foreground hover:text-red-500"
            onClick={() => void prepareCustomCollectorDelete()}
            disabled={!canDeleteCustomCollector || checkingDelete}
            title={
              canDeleteCustomCollector
                ? 'Permanently delete this custom integration'
                : 'Requires permissions to delete Log Sources and view integration code'
            }
          >
            {checkingDelete
              ? <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" />
              : <Trash2 className="w-3.5 h-3.5 mr-1" />}
            Delete integration
          </Button>
        ) : entry.installed && !isSystem ? (
          <Button
            variant="ghost"
            size="sm"
            className="h-8 rounded-md text-muted-foreground hover:text-red-500"
            onClick={handleUninstall}
          >
            <Trash2 className="w-3.5 h-3.5 mr-1" /> Uninstall
          </Button>
        ) : null}
      </div>
    </div>
  );
}

interface CodeTabProps {
  entry: MarketplaceCatalogEntry;
  handleExport: () => Promise<void>;
  exporting: boolean;
}

function CodeTab({ entry, handleExport, exporting }: CodeTabProps) {
  const code = entry.code || `// ${entry.name} enrichment\n// configure & activate to start using it\n\ninterface AgentEnrichmentResult {\n  raw: string;\n  enrich_type: "domain" | "hash" | "ip";\n  risk_score: number;\n  tags?: string[];\n  cache?: "warming" | "ready";\n}\n\nasync function enrich(\n  ev: EnrichEvent,\n  ctx: EnrichCtx\n): Promise<AgentEnrichmentResult>`;

  return (
    <div className="p-0">
      <div className="px-5 py-2 border-b border-border flex items-center gap-2 bg-muted/20">
        <span className="font-mono text-[11px] text-muted-foreground">
          {entry.execution_backend === 'collector' ? 'collector.ts' : 'enrich.ts'}
        </span>
        <div className="flex-1" />
        {entry.execution_backend === 'deno' && entry.custom_enrichment_id && (
          <Link
            to={`/enrichments/custom/${entry.custom_enrichment_id}`}
            className="text-[11px] text-primary hover:underline font-mono"
          >
            edit in wizard →
          </Link>
        )}
        {entry.execution_backend === 'collector' && entry.source_type === 'custom' && (
          <Link
            to={`/integrations/custom/${entry.id}`}
            className="text-[11px] text-primary hover:underline font-mono"
          >
            edit in wizard →
          </Link>
        )}
        {entry.execution_backend === 'deno' && (
          <Button
            variant="ghost"
            size="sm"
            className="h-7 rounded-md text-[11px]"
            onClick={handleExport}
            disabled={exporting}
          >
            {exporting ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Download className="w-3 h-3 mr-1" />}
            export
          </Button>
        )}
        <button
          className="h-7 w-7 rounded-md hover:bg-muted/40 text-muted-foreground hover:text-foreground inline-flex items-center justify-center"
          onClick={() => navigator.clipboard.writeText(code)}
          title="Copy code"
        >
          <Copy className="w-[11px] h-[11px]" />
        </button>
      </div>
      <pre className="px-5 py-4 font-mono text-[12px] text-foreground/90 leading-[1.6] overflow-x-auto whitespace-pre">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function PermissionsTab({ entry }: { entry: MarketplaceCatalogEntry }) {
  return (
    <div className="p-5 space-y-4">
      <div>
        <Eyebrow className="mb-2">Network egress</Eyebrow>
        {entry.allowed_domains?.length > 0 ? (
          <div className="rounded-md border border-border/60 bg-card divide-y divide-border/60">
            {entry.allowed_domains.map(d => (
              <div key={d} className="px-3 py-2.5 text-[12px] text-foreground font-mono">{d}</div>
            ))}
          </div>
        ) : (
          <div className="rounded-md border border-border/60 bg-card px-3 py-2.5 text-[12px] text-muted-foreground font-mono">
            No outbound network access required
          </div>
        )}
      </div>

      <div>
        <Eyebrow className="mb-2">Secrets read</Eyebrow>
        {entry.requires_credential !== 'none' ? (
          <div className="rounded-md border border-border/60 bg-card px-3 py-2.5 text-[12px] text-foreground font-mono">
            vault://providers/{entry.slug}/credentials
          </div>
        ) : (
          <div className="rounded-md border border-border/60 bg-card px-3 py-2.5 text-[12px] text-muted-foreground font-mono">
            No secrets required
          </div>
        )}
      </div>

      <div>
        <Eyebrow className="mb-2">Data scopes</Eyebrow>
        <div className="space-y-1.5">
          {[
            'read events.artifacts.*',
            isDataFeed(entry) ? 'write enrichments.cache.*' : null,
            entry.category === 'identity' ? 'write identity.users.*' : null,
            !isDataFeed(entry) && entry.category !== 'identity' ? 'invoke detection-rule.context.*' : null,
          ].filter((p): p is string => !!p).map(p => (
            <div key={p} className="flex items-center gap-2 text-[12px] text-foreground">
              <Check className="w-[12px] h-[12px] text-emerald-500" /> <span className="font-mono">{p}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
