// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-526 — redesigned /ingestion/log-sources/repositories.
//
// Three-pane port of design-ref/repositories.html (sidebar / table / preview)
// modeled on the already-shipped Rule Repositories page (NAN-504). Preserves
// every legacy behavior:
//
//   • 3s sync polling while any repo is `syncing`
//   • per-repo manual sync, delete (with confirm), upstream-updates banner
//   • Update & Deploy All orchestration (apply-all → deploy each updated source)
//   • Per-parser upstream diff modal
//   • Routing-rule auto-creation on import success
//   • Batch import (delegated to the existing BatchImportParsersModal)
//
// New from the mock and built out where the backend already supports it:
//
//   • Status set: AVAILABLE / UPDATED / IMPORTED / DRIFT (DELETED hidden until
//     backend tracks upstream removals)
//   • Filter pills, three-pane responsive layout, syntax-highlighted VRL, schema
//     extraction from VRL
//   • Sidebar stats grid (total / used / upd / drift)

import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSyncCompleteEffect } from '@/hooks/use-sync-complete';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, ArrowUpRight, ChevronDown, Eye, Loader2, Rocket } from 'lucide-react';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { TooltipProvider } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type {
  CreateParserRepositoryRequest,
  ParserImportPreview,
  ParserRepository,
} from '@/lib/api/parser-repositories';
import type { SourceConfiguration } from '@/lib/api/types';
import { ParserUpstreamDiffModal } from '@/components/repositories/ParserUpstreamDiffModal';
import { BatchImportParsersModal } from '@/components/parser-repositories/BatchImportParsersModal';
import { ParserRepoSidebar } from '@/components/parser-repositories/ParserRepoSidebar';
import {
  FilterRow,
  ReposHeader,
  ReposTable,
  ReposToolbar,
} from '@/components/parser-repositories/ParserReposTable';
import { ParserRepoPreview } from '@/components/parser-repositories/ParserRepoPreview';
import { SyncHistoryDrawer } from '@/components/parser-repositories/ParserRepoDrawers';
import {
  buildParserView,
  buildRepoView,
  categoryCounts,
  type CategoryCount,
  type ParserRepoView,
  type RepoParserView,
} from '@/components/parser-repositories/helpers';

// Maps a SourceConfiguration.config_type to the source_type / ingestion_method
// values the parser-import endpoint expects. Mirrors the legacy SOURCE_TYPE_MAP.
const SOURCE_TYPE_MAP: Record<string, { sourceType: string; label: string }> = {
  http: { sourceType: 'routed', label: 'HTTP (Routed)' },
  vector: { sourceType: 'vector', label: 'Vector' },
  splunk_hec: { sourceType: 'splunk_hec', label: 'Splunk HEC' },
  kafka: { sourceType: 'kafka', label: 'Kafka' },
  aws_s3: { sourceType: 'aws_s3', label: 'AWS S3' },
  gcp_pubsub: { sourceType: 'gcp_pubsub', label: 'GCP Pub/Sub' },
};

export function ParserRepositories() {
  useDocumentTitle('Parser Repositories');
  const { toast } = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [activeRepoId, setActiveRepoId] = useState<string | null>(null);
  const [activeCat, setActiveCat] = useState<CategoryCount['id']>('all');
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [selectedParserId, setSelectedParserId] = useState<string | null>(null);

  const [historyOpen, setHistoryOpen] = useState(false);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [deleteRepoId, setDeleteRepoId] = useState<string | null>(null);
  const [diffModalLogSourceId, setDiffModalLogSourceId] = useState<string | null>(null);

  // Per-parser preview state
  const [importMode, setImportMode] = useState<'linked' | 'forked'>('linked');
  const [selectedConfigId, setSelectedConfigId] = useState<string | null>(null);
  const [sourceTypeInput, setSourceTypeInput] = useState('');
  const [importPreview, setImportPreview] = useState<ParserImportPreview | null>(null);

  const [showUpstreamList, setShowUpstreamList] = useState(false);
  const [updateDeployProgress, setUpdateDeployProgress] = useState<string | null>(null);

  // ----------------------------------------------------------------
  // Queries
  // ----------------------------------------------------------------

  const { data: reposData, isLoading: reposLoading } = useQuery({
    queryKey: ['parser-repositories'],
    queryFn: () => api.parserRepositories.listRepositories(),
    refetchInterval: (q) => {
      const repos = q.state.data?.repositories ?? [];
      return repos.some((r) => r.last_sync_status === 'syncing') ? 1500 : false;
    },
  });

  const repositories = useMemo(() => reposData?.repositories ?? [], [reposData]);

  // Auto-select first repo on initial load.
  useEffect(() => {
    if (!activeRepoId && repositories.length > 0) {
      setActiveRepoId(repositories[0].id);
    }
    if (activeRepoId && !repositories.find((r) => r.id === activeRepoId)) {
      setActiveRepoId(repositories[0]?.id ?? null);
    }
  }, [repositories, activeRepoId]);

  const {
    data: parsersData = [],
    isLoading: parsersLoading,
    refetch: refetchParsers,
  } = useQuery({
    queryKey: ['parser-repository-parsers', activeRepoId],
    queryFn: () =>
      activeRepoId
        ? api.parserRepositories.listParsers(activeRepoId)
        : Promise.resolve([]),
    enabled: !!activeRepoId,
  });

  const { data: upstreamData, refetch: refetchUpstream } = useQuery({
    queryKey: ['parser-upstream-updates', activeRepoId],
    queryFn: () =>
      activeRepoId
        ? api.parserRepositories.getUpstreamUpdates(activeRepoId)
        : Promise.resolve({ updates: [] }),
    enabled: !!activeRepoId,
  });

  const { data: deployedConfigs = [] } = useQuery<SourceConfiguration[]>({
    queryKey: ['source-configs-deployed'],
    queryFn: () => api.listSourceConfigs({ deployed: true }),
    staleTime: 60_000,
  });

  // When the active repo finishes syncing, refresh parser list + upstream
  // updates and show a result toast (count of pending upstream changes if any).
  useSyncCompleteEffect(repositories, activeRepoId, (repo) => {
    refetchParsers();
    refetchUpstream().then((result) => {
      const count = result.data?.updates?.length ?? 0;
      if (repo.last_sync_status === 'failed') {
        toast({
          title: 'Sync failed',
          description: repo.last_sync_error || 'See sync history for details.',
          variant: 'destructive',
        });
      } else if (count > 0) {
        setShowUpstreamList(true);
        toast({
          title: 'Sync complete',
          description: `${count} parser${count !== 1 ? 's have' : ' has'} upstream changes available.`,
        });
      } else {
        toast({ title: 'Sync complete', description: 'All parsers are up to date.' });
      }
    });
  });

  // ----------------------------------------------------------------
  // View models
  // ----------------------------------------------------------------

  const upstreamByPath = useMemo(() => {
    const m = new Map<string, NonNullable<typeof upstreamData>['updates'][number]>();
    (upstreamData?.updates ?? []).forEach((u) => m.set(u.file_path, u));
    return m;
  }, [upstreamData]);

  const repoViews: ParserRepoView[] = useMemo(() => {
    return repositories.map((r) => {
      const isActive = r.id === activeRepoId;
      const parsers = isActive ? parsersData : [];
      const upstream = isActive ? (upstreamData?.updates ?? []) : [];
      return buildRepoView(r, parsers, upstream);
    });
  }, [repositories, parsersData, upstreamData, activeRepoId]);

  const activeRepo = repoViews.find((r) => r.id === activeRepoId) ?? null;

  const parserViews: RepoParserView[] = useMemo(() => {
    const fallbackCommit = activeRepo?.lastCommit.sha ?? '';
    return parsersData.map((p) => buildParserView(p, upstreamByPath, fallbackCommit));
  }, [parsersData, upstreamByPath, activeRepo]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return parserViews.filter((p) => {
      if (activeCat === 'updated' && p.status !== 'UPDATED') return false;
      if (activeCat === 'available' && p.status !== 'AVAILABLE') return false;
      if (activeCat === 'imported' && p.status !== 'IMPORTED') return false;
      if (activeCat === 'drift' && p.status !== 'DRIFT') return false;
      if (activeCat === 'deleted' && p.status !== 'DELETED') return false;
      if (!needle) return true;
      const hay = [
        p.name,
        p.desc,
        p.sourceType,
        p.vendor ?? '',
        p.product ?? '',
        p.category ?? '',
      ]
        .join(' ')
        .toLowerCase();
      return hay.includes(needle);
    });
  }, [parserViews, activeCat, query]);

  const selectedParser = parserViews.find((p) => p.id === selectedParserId) ?? null;
  const selectedRawParsers = useMemo(
    () => parsersData.filter((p) => selected.has(p.id)),
    [parsersData, selected],
  );
  const categories = categoryCounts(parserViews);

  // ----------------------------------------------------------------
  // Preview state — reset when a different parser is selected
  // ----------------------------------------------------------------

  useEffect(() => {
    if (!selectedParser) {
      setImportPreview(null);
      return;
    }
    setImportMode(selectedParser.importMode === 'forked' ? 'forked' : 'linked');
    setImportPreview(null);
    if (deployedConfigs.length > 0 && !selectedConfigId) {
      setSelectedConfigId(deployedConfigs[0].id);
    }
  }, [selectedParserId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Lazy-load preview metadata the first time the user wants to import this row.
  const previewMutation = useMutation({
    mutationFn: ({ repoId, path }: { repoId: string; path: string }) =>
      api.parserRepositories.previewImport(repoId, path),
    onSuccess: (preview) => {
      setImportPreview(preview);
      // Default the source-type input from the proposed name; user can override.
      if (!sourceTypeInput) {
        setSourceTypeInput(preview.repository_parser.name ?? '');
      }
    },
    onError: (err: Error) => {
      toast({ title: 'Preview failed', description: err.message, variant: 'destructive' });
    },
  });

  // Fetch preview when the Import tab is opened or the user clicks Import.
  // We trigger preview on selection so the metadata is ready by the time the
  // user opens the Import tab — saves a click. Cheap on the backend.
  useEffect(() => {
    if (!activeRepoId || !selectedParser) return;
    if (selectedParser.status === 'IMPORTED' || selectedParser.status === 'DELETED') return;
    previewMutation.mutate({ repoId: activeRepoId, path: selectedParser.raw.file_path });
  }, [selectedParserId, activeRepoId]); // eslint-disable-line react-hooks/exhaustive-deps

  // ----------------------------------------------------------------
  // Mutations
  // ----------------------------------------------------------------

  const createMutation = useMutation({
    mutationFn: (req: CreateParserRepositoryRequest) =>
      api.parserRepositories.createRepository(req),
    onSuccess: (repo: ParserRepository) => {
      queryClient.invalidateQueries({ queryKey: ['parser-repositories'] });
      setActiveRepoId(repo.id);
      toast({ title: `${repo.name} added — syncing…` });
      // Kick off the first sync immediately so the parser list populates.
      api.parserRepositories
        .syncRepository(repo.id)
        .then(() => queryClient.invalidateQueries({ queryKey: ['parser-repositories'] }))
        .catch(() => {});
    },
    onError: (err: Error) => {
      toast({
        title: 'Failed to add repository',
        description: err.message,
        variant: 'destructive',
      });
    },
  });

  const syncMutation = useMutation({
    mutationFn: (id: string) => api.parserRepositories.syncRepository(id),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['parser-repositories'] });
      toast({ title: 'Sync started', description: result.message });
    },
    onError: (err: Error) => {
      toast({ title: 'Sync failed to start', description: err.message, variant: 'destructive' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.parserRepositories.deleteRepository(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['parser-repositories'] });
      const wasActive = deleteRepoId === activeRepoId;
      setDeleteRepoId(null);
      if (wasActive) setActiveRepoId(null);
      toast({ title: 'Repository deleted' });
    },
    onError: (err: Error) => {
      toast({
        title: 'Failed to delete repository',
        description: err.message,
        variant: 'destructive',
      });
    },
  });

  const importMutation = useMutation({
    mutationFn: async ({
      repoId,
      path,
      configId,
      sourceType,
      mode,
    }: {
      repoId: string;
      path: string;
      configId: string | null;
      sourceType: string;
      mode: 'linked' | 'forked';
    }) => {
      const selectedConfig = deployedConfigs.find((c) => c.id === configId);
      const ingestionMethod = selectedConfig
        ? (SOURCE_TYPE_MAP[selectedConfig.config_type]?.sourceType ?? 'routed')
        : 'routed';

      const result = await api.parserRepositories.importParser(repoId, path, {
        import_type: mode,
        source_type: sourceType || undefined,
        ingestion_method: ingestionMethod,
      });

      // Routing-rule create-on-import — non-fatal if it fails.
      if (configId && sourceType) {
        try {
          await api.createRoutingRule(configId, {
            match_field: 'source_type',
            match_type: 'exact',
            match_value: sourceType,
            target_source_type: sourceType,
          });
        } catch {
          // Ignore — log source was created, routing can be configured manually.
        }
      }

      return result;
    },
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['parser-repository-parsers', activeRepoId] });
      queryClient.invalidateQueries({ queryKey: ['parser-upstream-updates', activeRepoId] });
      queryClient.invalidateQueries({ queryKey: ['log-sources'] });
      setSelectedParserId(null);
      setImportPreview(null);
      navigate(`/ingestion/log-sources/${result.log_source_id}`);
    },
    onError: (err: Error) => {
      toast({ title: 'Import failed', description: err.message, variant: 'destructive' });
    },
  });

  const updateAndDeployAllMutation = useMutation({
    mutationFn: async () => {
      if (!activeRepoId) throw new Error('No active repository');
      setUpdateDeployProgress('Applying updates…');
      const result = await api.parserRepositories.applyAllUpstreamUpdates(activeRepoId);

      const toPublish = result.results.filter((r) => r.updated);
      if (toPublish.length > 0) {
        setUpdateDeployProgress(
          `Publishing ${toPublish.length} source${toPublish.length !== 1 ? 's' : ''}…`,
        );
        // Publish (not deploy): publish creates a new active version from the
        // working copy AND deploys. Plain deploy reads from the active version,
        // so it would push the unchanged v1 VRL and leave the working copy diverged.
        const publishResults = await Promise.allSettled(
          toPublish.map((r) => api.publishLogSource(r.log_source_id)),
        );
        // Backend returns 200 with success=false on VRL validation failures,
        // so allSettled status alone undercounts failures.
        const deployed = publishResults.filter(
          (r) => r.status === 'fulfilled' && r.value.success === true,
        ).length;
        const deployFailed = toPublish.length - deployed;
        return { ...result, deployed, deployFailed };
      }
      return { ...result, deployed: 0, deployFailed: 0 };
    },
    onSuccess: (result) => {
      setUpdateDeployProgress(null);
      queryClient.invalidateQueries({ queryKey: ['parser-upstream-updates'] });
      queryClient.invalidateQueries({ queryKey: ['parser-repository-parsers', activeRepoId] });
      queryClient.invalidateQueries({ queryKey: ['log-sources'] });
      const parts: string[] = [];
      if (result.updated > 0) parts.push(`${result.updated} updated`);
      if (result.deployed > 0) parts.push(`${result.deployed} deployed`);
      if (result.failed > 0) parts.push(`${result.failed} failed to update`);
      if (result.deployFailed > 0) parts.push(`${result.deployFailed} failed to deploy`);
      toast({
        title: 'Update & deploy complete',
        description: parts.join(', ') || 'No updates pending.',
        variant: result.failed > 0 || result.deployFailed > 0 ? 'destructive' : 'default',
      });
    },
    onError: (err: Error) => {
      setUpdateDeployProgress(null);
      toast({ title: 'Update & deploy failed', description: err.message, variant: 'destructive' });
    },
  });

  // ----------------------------------------------------------------
  // Handlers
  // ----------------------------------------------------------------

  const toggleSelect = (id: string) => {
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  };

  const toggleSelectAll = (sel: boolean) => {
    if (sel) {
      setSelected(
        new Set(
          filtered
            .filter((p) => p.status !== 'DELETED' && p.status !== 'IMPORTED')
            .map((p) => p.id),
        ),
      );
    } else {
      setSelected(new Set());
    }
  };

  const handleRowAction = (parser: RepoParserView) => {
    if (parser.status === 'IMPORTED') {
      const id = parser.raw.linked_log_source_id;
      if (id) navigate(`/ingestion/log-sources/${id}`);
      return;
    }
    if (parser.status === 'DRIFT' && parser.raw.linked_log_source_id) {
      setDiffModalLogSourceId(parser.raw.linked_log_source_id);
      return;
    }
    if (parser.status === 'UPDATED' && parser.raw.linked_log_source_id) {
      // Apply + publish: applyUpstreamUpdate writes to the working copy only.
      // Without publish, the source ends up showing an "Unpublished changes"
      // banner and Vector keeps parsing with the old VRL.
      const logSourceId = parser.raw.linked_log_source_id;
      api.parserRepositories
        .applyUpstreamUpdate(logSourceId)
        .then(() => api.publishLogSource(logSourceId))
        .then((res) => {
          // Publish returns 200 with success=false on validation failures.
          if (!res.success) {
            throw new Error(res.message || 'Publish failed');
          }
          queryClient.invalidateQueries({ queryKey: ['parser-upstream-updates', activeRepoId] });
          queryClient.invalidateQueries({ queryKey: ['parser-repository-parsers', activeRepoId] });
          queryClient.invalidateQueries({ queryKey: ['log-sources'] });
          toast({ title: 'Updated & deployed' });
        })
        .catch((err: Error) => {
          toast({ title: 'Update failed', description: err.message, variant: 'destructive' });
        });
      return;
    }
    // AVAILABLE → open the preview pane and select the row.
    setSelectedParserId(parser.id);
  };

  const handleImport = () => {
    if (!activeRepoId || !selectedParser) return;
    importMutation.mutate({
      repoId: activeRepoId,
      path: selectedParser.raw.file_path,
      configId: selectedConfigId,
      sourceType: sourceTypeInput,
      mode: importMode,
    });
  };

  // ----------------------------------------------------------------
  // Render
  // ----------------------------------------------------------------

  const isPageLoading = reposLoading && repositories.length === 0;
  const showPreview = !!selectedParser;
  const upstreamCount = upstreamData?.updates.length ?? 0;

  if (isPageLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground text-[12px]">
        Loading repositories…
      </div>
    );
  }

  // Empty state — first-run with no repos.
  if (!activeRepo) {
    return (
      <TooltipProvider>
        <div className="-m-3 flex h-[calc(100%+1.5rem)] min-h-0 flex-col overflow-hidden [contain:layout]">
          <div className="border-b border-border bg-card/30 px-5 py-3.5 flex items-start gap-4">
            <div className="flex-1 min-w-0">
              <div className="text-[16.5px] font-semibold tracking-[-0.01em] text-foreground">
                Parser repositories
              </div>
              <div className="text-[11.5px] text-muted-foreground mt-0.5 leading-relaxed max-w-[740px]">
                Sync VRL parsers from Git. Preview the source, inspect the normalized schema, and
                import as draft log sources.
              </div>
            </div>
          </div>
          <div className="flex-1 flex items-center justify-center p-8 text-center">
            <div className="max-w-md">
              <div className="text-[14px] font-medium text-foreground mb-2">
                No repositories connected
              </div>
              <div className="text-[12px] text-muted-foreground leading-relaxed mb-4">
                Sync the official{' '}
                <code className="font-mono text-foreground/80">nano-sh/parsers</code> library to
                pull in pre-built parsers for common log sources.
              </div>
              <button
                type="button"
                onClick={() =>
                  createMutation.mutate({
                    name: 'nano parsers',
                    url: 'https://github.com/nanos-sh/parsers',
                    description: 'Official nano parsers for common log sources',
                    branch: 'main',
                    parsers_path: 'parsers/',
                    auto_sync_enabled: false,
                  })
                }
                disabled={createMutation.isPending}
                className="h-[28px] px-3 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-[11.5px] font-medium"
              >
                {createMutation.isPending ? 'Adding…' : 'Add nano parsers'}
              </button>
            </div>
          </div>
        </div>
      </TooltipProvider>
    );
  }

  return (
    <TooltipProvider>
      <div className="-m-3 flex h-[calc(100%+1.5rem)] min-h-0 flex-col overflow-hidden [contain:layout]">
        <ReposHeader
          repo={activeRepo}
          onSyncNow={() => syncMutation.mutate(activeRepo.id)}
          onOpenHistory={() => setHistoryOpen(true)}
          syncing={
            (syncMutation.isPending && syncMutation.variables === activeRepo.id) ||
            activeRepo.raw.last_sync_status === 'syncing'
          }
        />

        <div
          className="flex-1 min-h-0 grid"
          style={{
            gridTemplateColumns: showPreview ? '240px 1fr 440px' : '240px 1fr',
          }}
        >
          <ParserRepoSidebar
            repos={repoViews}
            activeRepoId={activeRepoId}
            onActivate={(id) => {
              setActiveRepoId(id);
              setSelectedParserId(null);
              setSelected(new Set());
            }}
            onSyncNow={(id) => syncMutation.mutate(id)}
            onOpenHistory={(id) => {
              setActiveRepoId(id);
              setHistoryOpen(true);
            }}
            onDelete={(id) => setDeleteRepoId(id)}
            syncingId={syncMutation.isPending ? (syncMutation.variables as string) : null}
          />

          <div className="flex flex-col min-h-0 min-w-0">
            <ReposToolbar
              selectedCount={selected.size}
              totalShown={filtered.length}
              query={query}
              onQueryChange={setQuery}
              onBulkImport={() => setBulkOpen(true)}
              onBulkClear={() => setSelected(new Set())}
            />
            <FilterRow categories={categories} activeId={activeCat} onActivate={setActiveCat} />
            {upstreamCount > 0 && activeCat !== 'updated' && (
              <UpstreamBanner
                count={upstreamCount}
                expanded={showUpstreamList}
                onToggleExpanded={() => setShowUpstreamList((v) => !v)}
                onUpdateAll={() => updateAndDeployAllMutation.mutate()}
                onReview={() => setActiveCat('updated')}
                running={updateAndDeployAllMutation.isPending}
                progress={updateDeployProgress}
              />
            )}
            {showUpstreamList && upstreamData && upstreamData.updates.length > 0 && (
              <UpstreamList
                updates={upstreamData.updates}
                onViewDiff={(id) => setDiffModalLogSourceId(id)}
              />
            )}
            {parsersLoading ? (
              <div className="flex-1 flex items-center justify-center text-[12px] text-muted-foreground">
                Loading parsers…
              </div>
            ) : (
              <ReposTable
                parsers={filtered}
                selected={selected}
                selectedParserId={selectedParserId}
                onToggleSelect={toggleSelect}
                onToggleSelectAll={toggleSelectAll}
                onSelectParser={setSelectedParserId}
                onAction={handleRowAction}
              />
            )}
          </div>

          {showPreview && selectedParser && (
            <ParserRepoPreview
              parser={selectedParser}
              preview={importPreview}
              previewLoading={previewMutation.isPending}
              importMode={importMode}
              onChangeImportMode={setImportMode}
              selectedConfigId={selectedConfigId}
              onChangeConfigId={setSelectedConfigId}
              sourceTypeInput={sourceTypeInput}
              onChangeSourceType={setSourceTypeInput}
              configs={deployedConfigs}
              importing={importMutation.isPending}
              onImport={handleImport}
              onClose={() => setSelectedParserId(null)}
              onViewDiff={(id) => setDiffModalLogSourceId(id)}
              onOpenLogSource={(id) => navigate(`/ingestion/log-sources/${id}`)}
            />
          )}
        </div>

        <SyncHistoryDrawer
          open={historyOpen}
          onClose={() => setHistoryOpen(false)}
          repo={activeRepo}
          syncing={syncMutation.isPending && syncMutation.variables === activeRepo.id}
          onSyncNow={(id) => syncMutation.mutate(id)}
        />

        <BatchImportParsersModal
          repositoryId={activeRepoId ?? ''}
          parsers={selectedRawParsers.length > 0 ? selectedRawParsers : parsersData.filter((p) => !p.is_imported)}
          open={bulkOpen}
          onOpenChange={setBulkOpen}
          onSuccess={() => {
            setBulkOpen(false);
            setSelected(new Set());
            queryClient.invalidateQueries({ queryKey: ['parser-repository-parsers', activeRepoId] });
            queryClient.invalidateQueries({ queryKey: ['log-sources'] });
          }}
        />

        {diffModalLogSourceId && (
          <ParserUpstreamDiffModal
            logSourceId={diffModalLogSourceId}
            open={!!diffModalLogSourceId}
            onOpenChange={(open) => {
              if (!open) setDiffModalLogSourceId(null);
            }}
          />
        )}

        <AlertDialog open={!!deleteRepoId} onOpenChange={() => setDeleteRepoId(null)}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Remove repository</AlertDialogTitle>
              <AlertDialogDescription>
                The repository and its cached parsers will be removed. Imported log sources keep
                running locally — they will only stop tracking upstream changes.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction
                onClick={() => deleteRepoId && deleteMutation.mutate(deleteRepoId)}
                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              >
                Remove
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>
    </TooltipProvider>
  );
}

// ------------------------------------------------------------------
// Upstream-update banner + expandable list (preserves legacy behavior)
// ------------------------------------------------------------------

function UpstreamBanner({
  count,
  expanded,
  onToggleExpanded,
  onUpdateAll,
  onReview,
  running,
  progress,
}: {
  count: number;
  expanded: boolean;
  onToggleExpanded: () => void;
  onUpdateAll: () => void;
  onReview: () => void;
  running: boolean;
  progress: string | null;
}) {
  return (
    <div className="border-b border-warning/30 bg-warning/5 px-3.5 py-2 flex items-center gap-2">
      <AlertTriangle className="w-[12px] h-[12px] text-warning shrink-0" strokeWidth={2} />
      <span className="text-[11.5px] text-warning font-medium">
        <span className="font-mono tabular-nums">{count}</span> imported{' '}
        {count === 1 ? 'parser has' : 'parsers have'} upstream updates
      </span>
      <button
        type="button"
        onClick={onToggleExpanded}
        className="text-[10.5px] text-warning/80 font-mono hover:text-warning flex items-center gap-1 ml-2"
      >
        {expanded ? 'Hide' : 'Review'}
        <ChevronDown
          className={`w-[10px] h-[10px] transition-transform ${expanded ? 'rotate-180' : ''}`}
          strokeWidth={1.5}
        />
      </button>
      <button
        type="button"
        onClick={onReview}
        className="text-[10.5px] text-warning/80 font-mono hover:text-warning flex items-center gap-1 ml-1"
      >
        Filter <ArrowUpRight className="w-[10px] h-[10px]" strokeWidth={1.5} />
      </button>
      <span className="flex-1" />
      <button
        type="button"
        onClick={onUpdateAll}
        disabled={running}
        className={cn(
          'h-[26px] px-2.5 rounded-md text-[11.5px] font-medium flex items-center gap-1.5',
          running
            ? 'bg-primary/60 text-primary-foreground cursor-not-allowed'
            : 'bg-primary text-primary-foreground hover:bg-primary/90',
        )}
      >
        {running ? (
          <>
            <Loader2 className="w-[11px] h-[11px] animate-spin" strokeWidth={1.5} />
            {progress ?? 'Working…'}
          </>
        ) : (
          <>
            <Rocket className="w-[11px] h-[11px]" strokeWidth={1.5} />
            Update & Deploy All
          </>
        )}
      </button>
    </div>
  );
}

function UpstreamList({
  updates,
  onViewDiff,
}: {
  updates: NonNullable<Awaited<ReturnType<typeof api.parserRepositories.getUpstreamUpdates>>>['updates'];
  onViewDiff: (logSourceId: string) => void;
}) {
  return (
    <div className="border-b border-border bg-card/30 px-3.5 py-2 max-h-[260px] overflow-y-auto space-y-1.5">
      {updates.map((u) => (
        <div
          key={u.log_source_id}
          className="flex items-center justify-between rounded-md border border-border bg-card px-2.5 py-1.5"
        >
          <div className="flex-1 min-w-0">
            <div className="text-[11.5px] font-medium truncate">
              {u.display_name || u.file_path.split('/').pop()}
            </div>
            <div className="text-[10px] text-muted-foreground font-mono truncate">{u.file_path}</div>
          </div>
          <span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground border border-border rounded px-1 py-px ml-2">
            {u.import_type}
          </span>
          <button
            type="button"
            onClick={() => onViewDiff(u.log_source_id)}
            className="ml-2 h-[24px] px-2 rounded-md border border-border bg-card hover:bg-muted text-[10.5px] font-mono text-foreground/70 inline-flex items-center gap-1"
          >
            <Eye className="w-[10px] h-[10px]" strokeWidth={1.5} />
            View diff
          </button>
        </div>
      ))}
    </div>
  );
}

export default ParserRepositories;
