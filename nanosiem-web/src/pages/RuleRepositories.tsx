// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-504 — redesigned /rules/repositories.
//
// Three-pane port of design-ref/rule-repositories.html (sidebar / table /
// preview). API surfaces that aren't backed yet (per-run sync history, drift
// detection, test-run sparkline, NEW vs AVAILABLE distinction) are stubbed or
// hidden — see issue NAN-504 for the full carve-out.

import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, ArrowUpRight } from 'lucide-react';
import { useSyncCompleteEffect } from '@/hooks/use-sync-complete';
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
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type {
  CreateRepositoryRequest,
  ImportRequest,
  RuleRepository,
} from '@/lib/api/rule-repositories';
import { RepoSidebar } from '@/components/repositories/RepoSidebar';
import { RepoPreview } from '@/components/repositories/RepoPreview';
import {
  ReposHeader,
  ReposTable,
  ReposToolbar,
  FilterRow,
} from '@/components/repositories/ReposTable';
import {
  AddRepoDrawer,
  BulkImportDrawer,
  FolderSelectionDrawer,
  SyncHistoryDrawer,
} from '@/components/repositories/RepoDrawers';
import {
  buildRepoView,
  buildRuleView,
  categoryCounts,
  type CategoryCount,
  type RepoRuleView,
  type RepoView,
} from '@/components/repositories/helpers';

export function RuleRepositories() {
  useDocumentTitle('Rule Repositories');
  const { toast } = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [activeRepoId, setActiveRepoId] = useState<string | null>(null);
  const [activeCat, setActiveCat] = useState<CategoryCount['id']>('all');
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);

  const [historyOpen, setHistoryOpen] = useState(false);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [foldersRepoId, setFoldersRepoId] = useState<string | null>(null);
  const [deleteRepoId, setDeleteRepoId] = useState<string | null>(null);

  // ----------------------------------------------------------------
  // Queries
  // ----------------------------------------------------------------

  const { data: reposData, isLoading: reposLoading } = useQuery({
    queryKey: ['rule-repositories'],
    queryFn: () => api.ruleRepositories.listRepositories(),
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

  const { data: rulesData = [], isLoading: rulesLoading, refetch: refetchRules } = useQuery({
    queryKey: ['rule-repository-rules', activeRepoId],
    queryFn: () => (activeRepoId ? api.ruleRepositories.listRules(activeRepoId, { limit: 500 }) : Promise.resolve([])),
    enabled: !!activeRepoId,
  });

  // When the active repo finishes syncing, refetch its rule list and surface a
  // toast so the user sees fresh data + completion confirmation without reload.
  useSyncCompleteEffect(repositories, activeRepoId, (repo) => {
    refetchRules();
    queryClient.invalidateQueries({ queryKey: ['rule-repository-upstream', repo.id] });
    if (repo.last_sync_status === 'failed') {
      toast({
        title: 'Sync failed',
        description: repo.last_sync_error || 'See sync history for details.',
        variant: 'destructive',
      });
    } else {
      toast({
        title: 'Sync complete',
        description: `${repo.name} is up to date.`,
      });
    }
  });

  const { data: upstreamData } = useQuery({
    queryKey: ['rule-repository-upstream', activeRepoId],
    queryFn: () =>
      activeRepoId
        ? api.ruleRepositories.getUpstreamUpdates(activeRepoId)
        : Promise.resolve({ updates: [], total_count: 0 }),
    enabled: !!activeRepoId,
  });

  const { data: sourceTypeRows = [] } = useQuery({
    queryKey: ['source-types'],
    queryFn: () => api.getSourceTypes(),
    staleTime: 5 * 60 * 1000,
  });

  const availableSourceTypes = useMemo(
    () => sourceTypeRows.map(([s]) => s).sort(),
    [sourceTypeRows],
  );

  // ----------------------------------------------------------------
  // View models
  // ----------------------------------------------------------------

  const upstreamByPath = useMemo(() => {
    const m = new Map<string, NonNullable<typeof upstreamData>['updates'][number]>();
    (upstreamData?.updates ?? []).forEach((u) => m.set(u.file_path, u));
    return m;
  }, [upstreamData]);

  const repoViews: RepoView[] = useMemo(() => {
    return repositories.map((r) => {
      const isActive = r.id === activeRepoId;
      const rules = isActive ? rulesData : [];
      const upstream = isActive ? upstreamData?.updates ?? [] : [];
      return buildRepoView(r, rules, upstream);
    });
  }, [repositories, rulesData, upstreamData, activeRepoId]);

  const activeRepo = repoViews.find((r) => r.id === activeRepoId) ?? null;

  const ruleViews: RepoRuleView[] = useMemo(() => {
    const fallbackCommit = activeRepo?.lastCommit.sha ?? '';
    return rulesData.map((r) => buildRuleView(r, upstreamByPath, fallbackCommit));
  }, [rulesData, upstreamByPath, activeRepo]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return ruleViews.filter((r) => {
      if (activeCat === 'new' && r.status !== 'NEW') return false;
      if (activeCat === 'updated' && r.status !== 'UPDATED') return false;
      if (activeCat === 'imported' && r.status !== 'IMPORTED') return false;
      if (activeCat === 'drift' && r.status !== 'DRIFT') return false;
      if (activeCat === 'deleted' && r.status !== 'DELETED') return false;
      if (!needle) return true;
      const hay = [r.name, r.desc, r.source, ...r.mitre].join(' ').toLowerCase();
      return hay.includes(needle);
    });
  }, [ruleViews, activeCat, query]);

  const selectedRule = ruleViews.find((r) => r.id === selectedRuleId) ?? null;
  const selectedRules = ruleViews.filter((r) => selected.has(r.id));
  const categories = categoryCounts(ruleViews);

  // ----------------------------------------------------------------
  // Mutations
  // ----------------------------------------------------------------

  const createMutation = useMutation({
    mutationFn: (req: CreateRepositoryRequest) => api.ruleRepositories.createRepository(req),
    onSuccess: (repo: RuleRepository) => {
      queryClient.invalidateQueries({ queryKey: ['rule-repositories'] });
      setActiveRepoId(repo.id);
      setAddOpen(false);
      toast({ title: `${repo.name} added — syncing…` });
      // Kick off the first sync immediately so the rule list populates.
      api.ruleRepositories
        .syncRepository(repo.id)
        .then(() => queryClient.invalidateQueries({ queryKey: ['rule-repositories'] }))
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
    mutationFn: (id: string) => api.ruleRepositories.syncRepository(id),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['rule-repositories'] });
      toast({ title: 'Sync started', description: result.message });
    },
    onError: (err: Error) => {
      toast({ title: 'Sync failed to start', description: err.message, variant: 'destructive' });
    },
  });

  const importMutation = useMutation({
    mutationFn: ({ repoId, path, req }: { repoId: string; path: string; req: ImportRequest }) =>
      api.ruleRepositories.importRule(repoId, path, req),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['rule-repository-rules', activeRepoId] });
      queryClient.invalidateQueries({ queryKey: ['rule-repositories'] });
      queryClient.invalidateQueries({ queryKey: ['detection-rules'] });
      toast({ title: 'Rule imported', description: 'Opening editor…' });
      // Auto-nav to the new rule (matches old ImportRuleModal behavior).
      if (result.detection_rule_id) {
        navigate(`/rules/editor/${result.detection_rule_id}`);
      }
    },
    onError: (err: Error) => {
      toast({ title: 'Import failed', description: err.message, variant: 'destructive' });
    },
  });

  const batchImportMutation = useMutation({
    mutationFn: async ({
      repoId,
      items,
    }: {
      repoId: string;
      items: {
        path: string;
        severity?: string;
        mode?: string;
        merge_to_single_source_type?: string;
      }[];
    }) => api.ruleRepositories.batchImport(repoId, items),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['rule-repository-rules', activeRepoId] });
      queryClient.invalidateQueries({ queryKey: ['rule-repository-upstream', activeRepoId] });
      queryClient.invalidateQueries({ queryKey: ['rule-repositories'] });
      const parts: string[] = [];
      if (result.imported > 0) parts.push(`${result.imported} imported`);
      if (result.updated > 0) parts.push(`${result.updated} updated`);
      if (result.skipped > 0) parts.push(`${result.skipped} skipped`);
      if (result.failed.length > 0) parts.push(`${result.failed.length} failed`);
      toast({
        title: 'Bulk import complete',
        description: parts.join(' · ') || 'No changes',
        variant: result.failed.length > 0 ? 'destructive' : 'default',
      });
      setBulkOpen(false);
      setSelected(new Set());
    },
    onError: (err: Error) => {
      toast({ title: 'Bulk import failed', description: err.message, variant: 'destructive' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.ruleRepositories.deleteRepository(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rule-repositories'] });
      setDeleteRepoId(null);
      if (deleteRepoId === activeRepoId) setActiveRepoId(null);
      toast({ title: 'Repository deleted' });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to delete repository', description: err.message, variant: 'destructive' });
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
      setSelected(new Set(filtered.filter((r) => r.status !== 'DELETED').map((r) => r.id)));
    } else {
      setSelected(new Set());
    }
  };

  // For non-import statuses (IMPORTED / UPDATED / DRIFT / DELETED): open the
  // linked detection rule. Note: typeid prefixes differ — `rule_*` for the
  // detection rule, `rrule_*` for the repository_rule cache row.
  const openOrAct = (rule: RepoRuleView) => {
    const detectionRuleId = rule.raw.linked_detection_rule_id;
    if (detectionRuleId) {
      navigate(`/rules/editor/${detectionRuleId}`);
    } else {
      toast({
        title: 'Cannot open rule',
        description:
          'This rule is marked imported but has no linked detection rule. Try syncing again.',
        variant: 'destructive',
      });
    }
  };

  const handleRowAction = (rule: RepoRuleView) => {
    // UPDATED rules go through the same import endpoint as a single-item batch
    // so the backend's overwrite-with-newer-upstream path runs (NAN-673). The
    // result toast tells the user whether the rule was actually updated or
    // already current. Other terminal statuses still open the editor for review.
    if (rule.status === 'UPDATED') {
      if (!activeRepoId) return;
      batchImportMutation.mutate({
        repoId: activeRepoId,
        items: [{ path: rule.raw.file_path }],
      });
      return;
    }
    if (
      rule.status === 'IMPORTED' ||
      rule.status === 'DELETED' ||
      rule.status === 'DRIFT'
    ) {
      openOrAct(rule);
      return;
    }
    if (!activeRepoId) return;
    // Quick row-import: defaults only, no source-type rewrites. Rich import
    // happens through the preview pane via handlePreviewImport.
    importMutation.mutate({
      repoId: activeRepoId,
      path: rule.raw.file_path,
      req: {},
    });
  };

  const handlePreviewImport = (req: ImportRequest) => {
    if (!activeRepoId || !selectedRule) return;
    importMutation.mutate({
      repoId: activeRepoId,
      path: selectedRule.raw.file_path,
      req,
    });
  };

  const handleBulkConfirm = (
    items: {
      path: string;
      severity?: string;
      mode?: string;
      merge_to_single_source_type?: string;
    }[],
  ) => {
    if (!activeRepoId) return;
    batchImportMutation.mutate({ repoId: activeRepoId, items });
  };

  // ----------------------------------------------------------------
  // Render
  // ----------------------------------------------------------------

  const isPageLoading = reposLoading && repositories.length === 0;
  const showPreview = !!selectedRule;

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
        <div className="-m-3 flex h-[calc(100%+1.5rem)] overflow-hidden min-h-0 flex-col">
        <div className="border-b border-border bg-card/30 px-5 py-3.5 flex items-start gap-4">
          <div className="flex-1 min-w-0">
            <div className="text-[16.5px] font-semibold tracking-[-0.01em] text-foreground">
              Rule repositories
            </div>
            <div className="text-[11.5px] text-muted-foreground mt-0.5 leading-relaxed max-w-[740px]">
              Track detections from Git. Sync upstream rules, preview diffs, remap sources, and
              import — bulk or one-by-one.
            </div>
          </div>
          <button
            type="button"
            onClick={() => setAddOpen(true)}
            className="h-[28px] px-3 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-[11.5px] font-medium"
          >
            Connect a repo
          </button>
        </div>
        <div className="flex-1 flex items-center justify-center p-8 text-center">
          <div className="max-w-md">
            <div className="text-[14px] font-medium text-foreground mb-2">No repositories connected</div>
            <div className="text-[12px] text-muted-foreground leading-relaxed mb-4">
              Connect a Git repository to sync detection rules. Start with the official{' '}
              <code className="font-mono text-foreground/80">nano-sh/rules</code> repo or bring your own.
            </div>
            <div className="flex items-center justify-center gap-2">
              <button
                type="button"
                onClick={() =>
                  createMutation.mutate({
                    name: 'nano rules',
                    url: 'https://github.com/nanos-sh/rules',
                    description: 'Official nano detection rules in native nPL format',
                    branch: 'main',
                    rules_path: '',
                    rule_format: 'nanosiem',
                    auto_sync_enabled: false,
                  })
                }
                disabled={createMutation.isPending}
                className="h-[28px] px-3 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-[11.5px] font-medium"
              >
                {createMutation.isPending ? 'Adding…' : 'Add nano rules'}
              </button>
              <button
                type="button"
                onClick={() => setAddOpen(true)}
                className="h-[28px] px-3 rounded-md border border-border bg-card hover:bg-muted text-[11.5px] font-medium text-foreground/80"
              >
                Connect custom repo
              </button>
            </div>
          </div>
        </div>

        <AddRepoDrawer
          open={addOpen}
          onClose={() => setAddOpen(false)}
          submitting={createMutation.isPending}
          onSubmit={async (req) => {
            await createMutation.mutateAsync({
              name: req.name,
              url: req.url,
              branch: req.branch,
              rules_path: req.rules_path || undefined,
              rule_format: req.rule_format,
              auto_sync_enabled: req.auto_sync_enabled,
              sync_interval_hours: req.sync_interval_hours,
            });
          }}
        />
        </div>
      </TooltipProvider>
    );
  }

  return (
    <TooltipProvider>
      <div className="-m-3 flex h-[calc(100%+1.5rem)] overflow-hidden min-h-0 flex-col">
        <ReposHeader
        repo={activeRepo}
        onSyncNow={() => syncMutation.mutate(activeRepo.id)}
        onOpenHistory={() => setHistoryOpen(true)}
        syncing={syncMutation.isPending && syncMutation.variables === activeRepo.id}
      />

      <div
        className="flex-1 min-h-0 grid"
        style={{
          gridTemplateColumns: showPreview ? '240px 1fr 420px' : '240px 1fr',
        }}
      >
        <RepoSidebar
          repos={repoViews}
          activeRepoId={activeRepoId}
          onActivate={(id) => {
            setActiveRepoId(id);
            setSelectedRuleId(null);
            setSelected(new Set());
          }}
          onSyncNow={(id) => syncMutation.mutate(id)}
          onOpenHistory={(id) => {
            setActiveRepoId(id);
            setHistoryOpen(true);
          }}
          onConfigureFolders={(id) => {
            setActiveRepoId(id);
            setFoldersRepoId(id);
          }}
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
          {(upstreamData?.total_count ?? 0) > 0 && activeCat !== 'updated' && (
            <button
              type="button"
              onClick={() => setActiveCat('updated')}
              className="border-b border-warning/30 bg-warning/5 px-3.5 py-2 flex items-center gap-2 text-left hover:bg-warning/10 transition"
            >
              <AlertTriangle className="w-[12px] h-[12px] text-warning shrink-0" strokeWidth={2} />
              <span className="text-[11.5px] text-warning font-medium">
                <span className="font-mono tabular-nums">{upstreamData?.total_count}</span>{' '}
                imported {upstreamData?.total_count === 1 ? 'rule has' : 'rules have'} upstream
                updates
              </span>
              <span className="ml-auto text-[10.5px] text-warning/80 font-mono flex items-center gap-1">
                Review <ArrowUpRight className="w-[10px] h-[10px]" strokeWidth={2} />
              </span>
            </button>
          )}
          {rulesLoading ? (
            <div className="flex-1 flex items-center justify-center text-[12px] text-muted-foreground">
              Loading rules…
            </div>
          ) : (
            <ReposTable
              rules={filtered}
              selected={selected}
              selectedRuleId={selectedRuleId}
              onToggleSelect={toggleSelect}
              onToggleSelectAll={toggleSelectAll}
              onSelectRule={setSelectedRuleId}
              onAction={handleRowAction}
            />
          )}
        </div>

        {showPreview && (
          <RepoPreview
            rule={selectedRule}
            repositoryId={activeRepoId}
            ruleFormat={activeRepo?.raw.rule_format ?? 'nanosiem'}
            availableSourceTypes={availableSourceTypes}
            onClose={() => setSelectedRuleId(null)}
            onImport={handlePreviewImport}
            onAction={openOrAct}
            importing={importMutation.isPending}
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

      <BulkImportDrawer
        open={bulkOpen}
        onClose={() => setBulkOpen(false)}
        rules={selectedRules}
        availableSourceTypes={availableSourceTypes}
        onConfirm={handleBulkConfirm}
        progress={
          batchImportMutation.isPending
            ? { running: true, total: selectedRules.length }
            : undefined
        }
      />

      <FolderSelectionDrawer
        repository={repositories.find((r) => r.id === foldersRepoId) ?? null}
        open={!!foldersRepoId}
        onClose={() => setFoldersRepoId(null)}
        onSyncStarted={() => {
          queryClient.invalidateQueries({ queryKey: ['rule-repositories'] });
          setFoldersRepoId(null);
        }}
      />

      <AddRepoDrawer
        open={addOpen}
        onClose={() => setAddOpen(false)}
        submitting={createMutation.isPending}
        onSubmit={async (req) => {
          await createMutation.mutateAsync({
            name: req.name,
            url: req.url,
            branch: req.branch,
            rules_path: req.rules_path || undefined,
            rule_format: req.rule_format,
            auto_sync_enabled: req.auto_sync_enabled,
            sync_interval_hours: req.sync_interval_hours,
          });
        }}
      />

      <AlertDialog open={!!deleteRepoId} onOpenChange={() => setDeleteRepoId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove repository</AlertDialogTitle>
            <AlertDialogDescription>
              All cached rules will be deleted. You can re-add it later to sync again.
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

export default RuleRepositories;
