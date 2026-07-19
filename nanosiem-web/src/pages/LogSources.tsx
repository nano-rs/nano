// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  Check,
  Eye,
  EyeOff,
  Globe,
  Loader2,
  MoreHorizontal,
  Network,
  Pencil,
  Plus,
  Power,
  RefreshCw,
  Rocket,
  Rss,
  Search,
  Trash2,
} from 'lucide-react';

import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import {
  useDeleteLogSource,
  useDeployLogSource,
  useIngestionHistory,
  useLogSources,
  useToggleLogSource,
  useUndeployLogSource,
} from '@/hooks/use-api';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import type { LogSource } from '@/lib/api';
import { logSourceTransportLabel } from '@/lib/log-source-transports';
import { cn } from '@/lib/utils';

type DerivedStatus = 'deployed' | 'ready' | 'paused' | 'draft';
type FilterId = 'all' | 'deployed' | 'ready' | 'warn' | 'draft';

const CHART_PALETTE = [
  'oklch(72% 0.15 200)', // cyan
  'oklch(70% 0.17 250)', // blue
  'oklch(72% 0.15 160)', // teal
  'oklch(74% 0.14 110)', // lime
  'oklch(76% 0.14 80)', // gold
  'oklch(72% 0.16 40)', // orange
  'oklch(70% 0.16 10)', // coral
  'oklch(68% 0.17 320)', // magenta
  'oklch(68% 0.16 280)', // violet
];

function deriveStatus(ls: LogSource): DerivedStatus {
  // NAN-1920: a wizard draft (never deployed, still being built) is the most
  // fundamental state — it takes precedence over enabled/deployed derivation.
  if (ls.lifecycle_status === 'draft') return 'draft';
  if (!ls.enabled) return 'paused';
  if (ls.deployed) return 'deployed';
  return 'ready';
}

function derivePendingDeploy(ls: LogSource): boolean {
  if (!ls.deployed || !ls.deployed_at || !ls.updated_at) return false;
  return new Date(ls.updated_at) > new Date(ls.deployed_at);
}

const TRANSPORT_COLOR = 'oklch(72% 0.15 200)';

function fmtRate(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return Math.round(n).toString();
}

export function LogSources() {
  useDocumentTitle('Log Sources');
  const { toast } = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { hasPermission } = useAuth();

  const { data: logSources, loading, refetch } = useLogSources();
  const { data: ingestionHistory } = useIngestionHistory(24);
  const { mutate: deleteLogSource } = useDeleteLogSource();
  const { mutate: toggleLogSource } = useToggleLogSource();
  const { mutate: deployLogSource } = useDeployLogSource();
  const { mutate: undeployLogSource } = useUndeployLogSource();

  const canCreate = hasPermission('log_sources:create');
  const canEdit = hasPermission('log_sources:edit');
  const canDelete = hasPermission('log_sources:delete');
  const canDeploy = hasPermission('log_sources:deploy');

  // Per-source RBAC scoping (NAN-1802): mark feeds whose `source_type` is in the
  // restricted registry. Only fetched for admins who can view scopes — others
  // never see the badge (and don't fire a 403). An empty registry = allow-all.
  const canViewScopes = hasPermission('source_scopes:view');
  const { data: restrictedResp } = useQuery({
    queryKey: ['source-scopes-restricted'],
    queryFn: () => api.sourceScopes.listRestricted(),
    enabled: canViewScopes,
    staleTime: 5 * 60 * 1000,
  });
  const restrictedSet = useMemo(
    () => new Set((restrictedResp?.restricted ?? []).map((r) => r.source_type)),
    [restrictedResp],
  );

  const [searchQuery, setSearchQuery] = useState('');
  const [filter, setFilter] = useState<FilterId>('all');

  // Confirmation dialog state — preserved from prior implementation. Toggling a feed
  // is treated as a meaningful operational change (a disabled feed is a real outage
  // signal); deploy / undeploy / delete carry obvious destructive risk.
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deployDialogOpen, setDeployDialogOpen] = useState(false);
  const [undeployDialogOpen, setUndeployDialogOpen] = useState(false);
  const [toggleDialogOpen, setToggleDialogOpen] = useState(false);
  const [logSourceToDelete, setLogSourceToDelete] = useState<LogSource | null>(null);
  const [logSourceToAction, setLogSourceToAction] = useState<LogSource | null>(null);

  // Routing-rule guard before delete
  const [associatedRoutingRules, setAssociatedRoutingRules] = useState<
    Array<{ configId: string; configName: string; ruleId: string; matchValue: string }>
  >([]);
  const [checkingAssociatedRules, setCheckingAssociatedRules] = useState(false);

  const sources = logSources ?? [];

  const stats = useMemo(() => {
    let deployed = 0;
    let ready = 0;
    let warn = 0;
    let draft = 0;
    for (const ls of sources) {
      const status = deriveStatus(ls);
      if (status === 'deployed') deployed += 1;
      else if (status === 'ready') ready += 1;
      else if (status === 'draft') draft += 1;
      if (derivePendingDeploy(ls)) warn += 1;
    }
    return { total: sources.length, deployed, ready, warn, draft };
  }, [sources]);

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return sources.filter((ls) => {
      const status = deriveStatus(ls);
      if (filter === 'deployed' && status !== 'deployed') return false;
      if (filter === 'ready' && status !== 'ready') return false;
      if (filter === 'draft' && status !== 'draft') return false;
      if (filter === 'warn' && !derivePendingDeploy(ls)) return false;
      if (!q) return true;
      const hay = [ls.name, ls.description, ls.vendor, ls.product, ls.source_type, ls.namespace]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return hay.includes(q);
    });
  }, [sources, searchQuery, filter]);

  // ----- mutations -----

  const handleOpenToggle = (ls: LogSource) => {
    setLogSourceToAction(ls);
    setToggleDialogOpen(true);
  };

  const handleToggle = async () => {
    if (!logSourceToAction) return;
    try {
      await toggleLogSource({ id: logSourceToAction.id, enabled: !logSourceToAction.enabled });
      toast({
        title: logSourceToAction.enabled ? 'Log source disabled' : 'Log source enabled',
        description: `"${logSourceToAction.name}" has been ${
          logSourceToAction.enabled ? 'disabled' : 'enabled'
        }.`,
      });
      setToggleDialogOpen(false);
      setLogSourceToAction(null);
      refetch();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to toggle log source',
        variant: 'destructive',
      });
    }
  };

  const handleOpenDeploy = (ls: LogSource) => {
    setLogSourceToAction(ls);
    setDeployDialogOpen(true);
  };

  const handleDeploy = async () => {
    if (!logSourceToAction) return;
    try {
      await deployLogSource(logSourceToAction.id);
      toast({
        title: 'Deployed',
        description: `"${logSourceToAction.name}" has been deployed to Vector.`,
      });
      setDeployDialogOpen(false);
      setLogSourceToAction(null);
      refetch();
    } catch (err) {
      toast({
        title: 'Deployment failed',
        description: err instanceof Error ? err.message : 'Failed to deploy',
        variant: 'destructive',
      });
    }
  };

  const handleOpenUndeploy = (ls: LogSource) => {
    setLogSourceToAction(ls);
    setUndeployDialogOpen(true);
  };

  const handleUndeploy = async () => {
    if (!logSourceToAction) return;
    try {
      await undeployLogSource(logSourceToAction.id);
      toast({
        title: 'Undeployed',
        description: `"${logSourceToAction.name}" has been removed from Vector.`,
      });
      setUndeployDialogOpen(false);
      setLogSourceToAction(null);
      refetch();
    } catch (err) {
      toast({
        title: 'Undeploy failed',
        description: err instanceof Error ? err.message : 'Failed to undeploy',
        variant: 'destructive',
      });
    }
  };

  const handleDelete = async () => {
    if (!logSourceToDelete) return;
    try {
      await deleteLogSource(logSourceToDelete.id);
      toast({
        title: 'Deleted',
        description: `"${logSourceToDelete.name}" has been deleted.`,
      });
      setDeleteDialogOpen(false);
      setLogSourceToDelete(null);
      setAssociatedRoutingRules([]);
      refetch();
      queryClient.invalidateQueries({ queryKey: ['parser-repository-parsers'] });
    } catch (err) {
      toast({
        title: 'Delete failed',
        description: err instanceof Error ? err.message : 'Failed to delete',
        variant: 'destructive',
      });
    }
  };

  // Routing-rule guard: a delete must surface any source-config rules that route events
  // to this log source's match_values, so the user can clear them up first.
  const checkAssociatedRoutingRules = async (logSource: LogSource) => {
    if (!logSource.match_values?.length) {
      setAssociatedRoutingRules([]);
      return;
    }
    setCheckingAssociatedRules(true);
    try {
      const configs = await api.listSourceConfigs({ enabled: true });
      const matchValues = new Set(logSource.match_values ?? []);
      const perConfig = await Promise.all(
        configs.map(async (config) => {
          try {
            const full = await api.getSourceConfigWithRules(config.id);
            return full.routing_rules
              .filter((rule) => matchValues.has(rule.target_source_type))
              .map((rule) => ({
                configId: config.id,
                configName: config.name,
                ruleId: rule.id,
                matchValue: rule.match_value || '(default)',
              }));
          } catch (err) {
            console.error(`Failed to fetch rules for ${config.name}:`, err);
            return [];
          }
        }),
      );
      setAssociatedRoutingRules(perConfig.flat());
    } catch (err) {
      console.error('Failed to check associated routing rules:', err);
      setAssociatedRoutingRules([]);
    } finally {
      setCheckingAssociatedRules(false);
    }
  };

  const handleDeleteClick = async (logSource: LogSource) => {
    setLogSourceToDelete(logSource);
    setDeleteDialogOpen(true);
    await checkAssociatedRoutingRules(logSource);
  };

  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex flex-col h-full min-h-0 -m-3 bg-background">
        <HeroStrip stats={stats} />

        <div className="shrink-0 border-b border-border bg-background px-4 pt-3 pb-3">
          <IngestionActivityCard history={ingestionHistory ?? []} />
        </div>

        <Toolbar
          query={searchQuery}
          onQueryChange={setSearchQuery}
          filter={filter}
          onFilterChange={setFilter}
          stats={stats}
          onRefresh={refetch}
          canCreate={canCreate}
          onNew={() => navigate('/ingestion/log-sources/new')}
        />

        <div className="flex-1 min-h-0 overflow-auto">
          {loading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
            </div>
          ) : filtered.length === 0 ? (
            <EmptyState
              hasQuery={!!searchQuery || filter !== 'all'}
              canCreate={canCreate}
              onNew={() => navigate('/ingestion/log-sources/new')}
              onBrowse={() => navigate('/ingestion/log-sources/repositories')}
            />
          ) : (
            <LogSourceTable
              rows={filtered}
              restrictedSet={restrictedSet}
              canEdit={canEdit}
              canDeploy={canDeploy}
              canDelete={canDelete}
              onToggle={handleOpenToggle}
              onDeploy={handleOpenDeploy}
              onUndeploy={handleOpenUndeploy}
              onDelete={handleDeleteClick}
            />
          )}
        </div>

        <DeleteDialog
          open={deleteDialogOpen}
          onOpenChange={(open) => {
            setDeleteDialogOpen(open);
            if (!open) {
              setLogSourceToDelete(null);
              setAssociatedRoutingRules([]);
            }
          }}
          logSource={logSourceToDelete}
          checking={checkingAssociatedRules}
          associatedRules={associatedRoutingRules}
          onConfirm={handleDelete}
        />

        <ConfirmDialog
          open={deployDialogOpen}
          onOpenChange={setDeployDialogOpen}
          title="Deploy Log Source"
          description={
            logSourceToAction
              ? `Deploy "${logSourceToAction.name}"? Vector will start ingesting from this source immediately.`
              : ''
          }
          confirmLabel="Deploy"
          onConfirm={handleDeploy}
        />

        <ConfirmDialog
          open={undeployDialogOpen}
          onOpenChange={setUndeployDialogOpen}
          title="Undeploy Log Source"
          description={
            logSourceToAction
              ? `Undeploy "${logSourceToAction.name}"? Ingestion stops immediately.`
              : ''
          }
          confirmLabel="Undeploy"
          confirmTone="warn"
          onConfirm={handleUndeploy}
        />

        <ConfirmDialog
          open={toggleDialogOpen}
          onOpenChange={setToggleDialogOpen}
          title={logSourceToAction?.enabled ? 'Disable Log Source' : 'Enable Log Source'}
          description={
            logSourceToAction
              ? logSourceToAction.enabled
                ? `Disable "${logSourceToAction.name}"? ${
                    logSourceToAction.deployed
                      ? 'Vector keeps the parser running until you undeploy.'
                      : ''
                  }`.trim()
                : `Enable "${logSourceToAction.name}"?`
              : ''
          }
          confirmLabel={logSourceToAction?.enabled ? 'Disable' : 'Enable'}
          confirmTone={logSourceToAction?.enabled ? 'warn' : 'default'}
          onConfirm={handleToggle}
        />
      </div>
    </TooltipProvider>
  );
}

// ----- Hero strip -----

function HeroStrip({ stats }: { stats: { total: number; deployed: number; ready: number; warn: number } }) {
  return (
    <div className="shrink-0 border-b border-border bg-card/40 px-5 py-4 flex items-start gap-4">
      <div className="w-[38px] h-[38px] rounded-lg border border-border bg-card flex items-center justify-center shrink-0">
        <Rss className="w-[18px] h-[18px] text-muted-foreground" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2.5 flex-wrap">
          <div className="text-[16.5px] font-semibold tracking-[-0.01em] text-foreground">Log sources</div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground border border-border rounded px-1.5 py-px whitespace-nowrap">
            Feed index
          </span>
        </div>
        <div className="text-[11.5px] text-muted-foreground mt-0.5 leading-relaxed max-w-[740px]">
          Parsers that normalize incoming events into a structured source type and route them to a repository. Each log
          source owns its VRL code, validation tests, deploy history, and version log.
        </div>
      </div>
      <div className="hidden md:flex items-center gap-4 shrink-0">
        <HeroStat value={stats.deployed} label="Deployed" />
        <div className="w-px h-8 bg-border" />
        <HeroStat value={stats.ready} label="Ready" />
        <div className="w-px h-8 bg-border" />
        <HeroStat value={stats.total} label="Sources" />
        <div className="w-px h-8 bg-border" />
        <HeroStat value={stats.warn} label="Pending deploy" warn={stats.warn > 0} />
      </div>
    </div>
  );
}

function HeroStat({ value, label, warn }: { value: number | string; label: string; warn?: boolean }) {
  return (
    <div className="flex flex-col items-end">
      <div
        className={cn(
          'font-mono text-[14px] tabular-nums',
          warn ? 'text-amber-500' : 'text-foreground',
        )}
      >
        {value}
      </div>
      <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">{label}</div>
    </div>
  );
}

// ----- Toolbar -----

function Toolbar({
  query,
  onQueryChange,
  filter,
  onFilterChange,
  stats,
  onRefresh,
  canCreate,
  onNew,
}: {
  query: string;
  onQueryChange: (v: string) => void;
  filter: FilterId;
  onFilterChange: (id: FilterId) => void;
  stats: { total: number; deployed: number; ready: number; warn: number; draft: number };
  onRefresh: () => void;
  canCreate: boolean;
  onNew: () => void;
}) {
  const items: Array<{ id: FilterId; label: string; count: number }> = [
    { id: 'all', label: 'All', count: stats.total },
    { id: 'deployed', label: 'Deployed', count: stats.deployed },
    { id: 'ready', label: 'Ready', count: stats.ready },
    { id: 'draft', label: 'Draft', count: stats.draft },
    { id: 'warn', label: 'Pending deploy', count: stats.warn },
  ];
  return (
    <div className="shrink-0 flex items-center gap-2 px-4 py-2.5 border-b border-border bg-card/40">
      <div className="relative">
        <Search className="w-3.5 h-3.5 text-muted-foreground absolute left-2.5 top-1/2 -translate-y-1/2" />
        <Input
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          placeholder="Search log sources, vendors, products…"
          className="h-8 pl-8 w-[340px] text-[12px] bg-card"
        />
      </div>
      <div className="flex items-center gap-0.5 bg-card rounded-md p-0.5 border border-border">
        {items.map((it) => (
          <button
            key={it.id}
            type="button"
            onClick={() => onFilterChange(it.id)}
            className={cn(
              'h-[26px] px-2.5 rounded-[4px] text-[11px] font-medium flex items-center gap-1.5 transition-colors',
              filter === it.id
                ? 'bg-primary/15 text-primary'
                : 'text-foreground/80 hover:text-foreground hover:bg-foreground/5',
            )}
          >
            {it.label}
            <span
              className={cn(
                'font-mono text-[10px] tabular-nums',
                filter === it.id ? 'text-primary/80' : 'text-muted-foreground/70',
              )}
            >
              {it.count}
            </span>
          </button>
        ))}
      </div>
      <div className="flex-1" />
      <Button variant="outline" size="sm" className="h-8 gap-1.5" onClick={onRefresh}>
        <RefreshCw className="w-3.5 h-3.5" />
      </Button>
      {canCreate && (
        <Button size="sm" className="h-8 gap-1.5" onClick={onNew}>
          <Plus className="w-3.5 h-3.5" />
          New log source
        </Button>
      )}
    </div>
  );
}

// ----- Activity chart -----

type IngestionPoint = { source_type: string; timestamp: string; count: number };

function IngestionActivityCard({ history }: { history: IngestionPoint[] }) {
  // Stack ingestion-history points by source_type. Real history is coarse (per-bucket
  // counts from ClickHouse) — we render it directly without smoothing. If the backend
  // returns nothing, we still show the chrome with a flat line so the chart slot stays
  // legible while the user reads the rest of the page.
  const { stacked, sourceTypes, maxY, bucketSeconds } = useMemo(() => {
    if (!history.length) return { stacked: [], sourceTypes: [] as string[], maxY: 0, bucketSeconds: 0 };
    const types = Array.from(new Set(history.map((p) => p.source_type)));
    const byTime = new Map<string, Map<string, number>>();
    for (const p of history) {
      let row = byTime.get(p.timestamp);
      if (!row) {
        row = new Map();
        byTime.set(p.timestamp, row);
      }
      row.set(p.source_type, (row.get(p.source_type) ?? 0) + p.count);
    }
    const timestamps = Array.from(byTime.keys()).sort();
    const series = types.map((t, i) => ({
      id: t,
      label: t,
      color: CHART_PALETTE[i % CHART_PALETTE.length],
      points: timestamps.map((ts) => byTime.get(ts)?.get(t) ?? 0),
    }));
    const N = timestamps.length;
    const running = new Array(N).fill(0) as number[];
    const out = series.map((s) => {
      const lower = [...running];
      for (let i = 0; i < N; i++) running[i] += s.points[i];
      const upper = [...running];
      return { ...s, lower, upper };
    });
    const maxYv = Math.max(1, ...out.flatMap((l) => l.upper));
    let bucket = 0;
    if (timestamps.length >= 2) {
      bucket =
        (new Date(timestamps[1]).getTime() - new Date(timestamps[0]).getTime()) / 1000;
    }
    return { stacked: out, sourceTypes: types, maxY: maxYv, bucketSeconds: bucket };
  }, [history]);

  const N = stacked[0]?.upper.length ?? 0;
  const W = 1360;
  const H = 150;
  const PAD_L = 44;
  const PAD_R = 12;
  const PAD_T = 6;
  const PAD_B = 24;
  const innerW = W - PAD_L - PAD_R;
  const innerH = H - PAD_T - PAD_B;

  const xAt = (i: number) => (N <= 1 ? PAD_L : PAD_L + (i / (N - 1)) * innerW);
  const yAt = (v: number) => PAD_T + innerH - (v / Math.max(maxY, 1)) * innerH;

  const pathFor = (layer: { lower: number[]; upper: number[] }) => {
    const top = layer.upper.map((v, i) => `${i === 0 ? 'M' : 'L'}${xAt(i).toFixed(1)},${yAt(v).toFixed(1)}`).join(' ');
    const bot = layer.lower
      .map((_, i) => `L${xAt(N - 1 - i).toFixed(1)},${yAt(layer.lower[N - 1 - i]).toFixed(1)}`)
      .join(' ');
    return `${top} ${bot} Z`;
  };

  // Estimate evt/min for the peak label. If we can compute the bucket size from the
  // timestamps, normalize per-bucket counts to per-minute. Otherwise leave the peak
  // label blank rather than mislead the analyst.
  const peakPerMin = bucketSeconds > 0 ? (maxY * 60) / bucketSeconds : 0;

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border">
        <Rss className="w-3.5 h-3.5 text-muted-foreground" />
        <div className="text-[11.5px] font-medium text-foreground whitespace-nowrap">Ingestion activity</div>
        <span className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground whitespace-nowrap">
          24h · stacked by source type
        </span>
        <div className="flex-1" />
        {peakPerMin > 0 && (
          <div className="text-[10.5px] font-mono text-muted-foreground tabular-nums whitespace-nowrap">
            Peak ≈ <span className="text-foreground">{fmtRate(peakPerMin)}</span>{' '}
            <span className="text-muted-foreground/70">evt/min</span>
          </div>
        )}
      </div>
      <div className="p-2">
        {stacked.length === 0 ? (
          <div className="h-[150px] flex items-center justify-center text-[11px] text-muted-foreground">
            No ingestion activity in the last 24 hours.
          </div>
        ) : (
          <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-[150px]" preserveAspectRatio="none">
            {[0, 0.25, 0.5, 0.75, 1].map((f, i) => {
              const y = PAD_T + innerH - f * innerH;
              return (
                <line
                  key={i}
                  x1={PAD_L}
                  x2={W - PAD_R}
                  y1={y}
                  y2={y}
                  stroke="var(--border)"
                  strokeWidth="1"
                  strokeDasharray={i === 0 ? '' : '2,3'}
                />
              );
            })}
            {[0, 0.5, 1].map((f, i) => {
              const y = PAD_T + innerH - f * innerH;
              const v = peakPerMin > 0 ? f * peakPerMin : f * maxY;
              return (
                <text
                  key={i}
                  x={PAD_L - 6}
                  y={y + 3}
                  textAnchor="end"
                  fontFamily="var(--font-mono, ui-monospace)"
                  fontSize="9"
                  fill="var(--muted-foreground)"
                >
                  {fmtRate(v)}
                </text>
              );
            })}
            {[0, 0.25, 0.5, 0.75, 1].map((f, i) => {
              const x = PAD_L + f * innerW;
              const h = Math.round(24 - f * 24);
              return (
                <text
                  key={i}
                  x={x}
                  y={H - 8}
                  textAnchor="middle"
                  fontFamily="var(--font-mono, ui-monospace)"
                  fontSize="9"
                  fill="var(--muted-foreground)"
                >
                  {h === 0 ? 'now' : `-${h}h`}
                </text>
              );
            })}
            {stacked.map((layer) => (
              <path
                key={layer.id}
                d={pathFor(layer)}
                fill={layer.color}
                fillOpacity="0.72"
                stroke={layer.color}
                strokeWidth="0.75"
                strokeOpacity="0.9"
              />
            ))}
          </svg>
        )}
        {sourceTypes.length > 0 && (
          <div className="flex items-center gap-3 flex-wrap px-2 pt-1.5 pb-1">
            {stacked.map((s) => (
              <div key={s.id} className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-sm" style={{ background: s.color }} />
                <span className="text-[10.5px] text-foreground/80">{s.label}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ----- Table -----

function LogSourceTable({
  rows,
  restrictedSet,
  canEdit,
  canDeploy,
  canDelete,
  onToggle,
  onDeploy,
  onUndeploy,
  onDelete,
}: {
  rows: LogSource[];
  restrictedSet: Set<string>;
  canEdit: boolean;
  canDeploy: boolean;
  canDelete: boolean;
  onToggle: (ls: LogSource) => void;
  onDeploy: (ls: LogSource) => void;
  onUndeploy: (ls: LogSource) => void;
  onDelete: (ls: LogSource) => void;
}) {
  return (
    <div className="@container/table">
      <table className="w-full text-[12px]">
        <thead>
          <tr className="border-b border-border bg-card/40">
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground pl-4 py-2">
              Feed
            </th>
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground py-2 w-[120px] @max-[900px]/table:hidden">
              Type
            </th>
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground py-2 w-[200px] @max-[1100px]/table:hidden">
              Vendor / Product
            </th>
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground py-2 w-[140px]">
              Status
            </th>
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground py-2 w-[130px] @max-[640px]/table:w-[60px]">
              Enabled
            </th>
            <th className="w-[44px] py-2"></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((ls) => (
            <LogSourceRow
              key={ls.id}
              source={ls}
              restricted={restrictedSet.has(ls.source_type)}
              canEdit={canEdit}
              canDeploy={canDeploy}
              canDelete={canDelete}
              onToggle={onToggle}
              onDeploy={onDeploy}
              onUndeploy={onUndeploy}
              onDelete={onDelete}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function LogSourceRow({
  source,
  restricted,
  canEdit,
  canDeploy,
  canDelete,
  onToggle,
  onDeploy,
  onUndeploy,
  onDelete,
}: {
  source: LogSource;
  restricted: boolean;
  canEdit: boolean;
  canDeploy: boolean;
  canDelete: boolean;
  onToggle: (ls: LogSource) => void;
  onDeploy: (ls: LogSource) => void;
  onUndeploy: (ls: LogSource) => void;
  onDelete: (ls: LogSource) => void;
}) {
  const navigate = useNavigate();
  const status = deriveStatus(source);
  const pending = derivePendingDeploy(source);
  const warn = pending; // single warn signal until backend ships richer health data
  const transportLabel = logSourceTransportLabel(source);

  return (
    <tr
      className="border-b border-border cursor-pointer group hover:bg-foreground/[0.03]"
      onClick={() => navigate(`/ingestion/log-sources/${source.id}`)}
    >
      {/* Feed */}
      <td className="pl-4 py-3 align-top">
        <div className="flex items-start gap-3">
          <div className="w-[30px] h-[30px] rounded-md border border-border bg-foreground/[0.03] flex items-center justify-center shrink-0 mt-0.5">
            <Rss className="w-[13px] h-[13px] text-muted-foreground" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[12.5px] font-medium text-foreground truncate group-hover:text-primary transition-colors">
                {source.name}
              </span>
              {warn && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <button
                      type="button"
                      onClick={(e) => e.stopPropagation()}
                      className="shrink-0 inline-flex items-center text-amber-500"
                    >
                      <AlertTriangle className="w-3 h-3" />
                    </button>
                  </TooltipTrigger>
                  <TooltipContent side="top" sideOffset={6} collisionPadding={8} className="text-[11px]">
                    Edits since the last deploy haven't been applied to Vector yet.
                  </TooltipContent>
                </Tooltip>
              )}
              {/* Inline transport surfaces when Type col hidden */}
              <span className="hidden @max-[900px]/table:inline-flex items-center gap-1 h-[15px] px-1 rounded-[3px] border border-border bg-foreground/[0.03]">
                <Globe className="w-[8px] h-[8px]" style={{ color: TRANSPORT_COLOR }} />
                <span className="text-[9.5px] font-mono uppercase tracking-wider text-foreground/80">{transportLabel}</span>
              </span>
            </div>
            {source.description && (
              <div className="text-[11px] text-muted-foreground truncate mt-0.5 leading-relaxed max-w-[620px]">
                {source.description}
              </div>
            )}
            <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
              <span className="text-[10px] font-mono text-muted-foreground">{source.source_type}</span>
              {restricted && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <button
                      type="button"
                      onClick={(e) => e.stopPropagation()}
                      className="shrink-0 inline-flex items-center gap-1 h-[15px] px-1 rounded-[3px] bg-amber-500/12 text-amber-500 font-mono text-[9px] uppercase tracking-wider"
                    >
                      <EyeOff className="w-[9px] h-[9px]" />
                      Restricted
                    </button>
                  </TooltipTrigger>
                  <TooltipContent side="top" sideOffset={6} collisionPadding={8} className="text-[11px] max-w-[280px]">
                    This source type is visibility-scoped — only granted groups can see its events.
                    Manage in Settings → Source Visibility.
                  </TooltipContent>
                </Tooltip>
              )}
              {source.namespace && source.namespace !== 'default' && (
                <>
                  <span className="w-px h-2.5 bg-border" />
                  <span className="text-[10px] font-mono text-muted-foreground">{source.namespace}</span>
                </>
              )}
              {/* Vendor/product inline when that column is hidden */}
              {(source.vendor || source.product) && (
                <span className="hidden @max-[1100px]/table:flex items-center gap-1.5">
                  <span className="w-px h-2.5 bg-border" />
                  <span className="text-[10px] font-mono text-muted-foreground">{source.vendor}</span>
                  {source.product && (
                    <span className="text-[10px] font-mono text-muted-foreground/70">· {source.product}</span>
                  )}
                </span>
              )}
            </div>
          </div>
        </div>
      </td>

      {/* Type */}
      <td className="py-3 align-top @max-[900px]/table:hidden">
        <div className="inline-flex items-center gap-1.5 h-[22px] px-1.5 rounded-[4px] border border-border bg-foreground/[0.03]">
          <Globe className="w-3 h-3" style={{ color: TRANSPORT_COLOR }} />
          <span className="text-[10.5px] font-mono text-foreground/80">{transportLabel}</span>
        </div>
      </td>

      {/* Vendor / Product */}
      <td className="py-3 align-top @max-[1100px]/table:hidden">
        {source.vendor || source.product ? (
          <>
            <div className="text-[11.5px] text-foreground">{source.vendor || '—'}</div>
            <div className="text-[10.5px] text-muted-foreground">{source.product || ''}</div>
          </>
        ) : (
          <div className="text-[10.5px] text-muted-foreground/70">—</div>
        )}
      </td>

      {/* Status */}
      <td className="py-3 align-top">
        <StatusBadge status={status} validated={source.validated} validationError={source.validation_error} />
      </td>

      {/* Enabled */}
      <td className="py-3 align-top">
        <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
          <EnabledToggle
            checked={source.enabled}
            disabled={!canEdit}
            warn={warn}
            onClick={() => onToggle(source)}
          />
          <span
            className={cn(
              'text-[10px] font-mono uppercase tracking-wider @max-[640px]/table:hidden',
              source.enabled
                ? warn
                  ? 'text-amber-500'
                  : 'text-foreground/80'
                : 'text-muted-foreground',
            )}
          >
            {source.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
      </td>

      {/* Overflow */}
      <td className="pr-3 py-3 align-top">
        <div onClick={(e) => e.stopPropagation()}>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                className="w-7 h-7 rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/5 transition-colors"
              >
                <MoreHorizontal className="w-4 h-4" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="bg-card border-border">
              <Link to={`/ingestion/log-sources/${source.id}`}>
                <DropdownMenuItem className="cursor-pointer text-[11.5px]">
                  <Eye className="w-3.5 h-3.5 mr-2" />
                  View details
                </DropdownMenuItem>
              </Link>
              {canEdit && (
                <Link to={`/ingestion/log-sources/${source.id}`}>
                  <DropdownMenuItem className="cursor-pointer text-[11.5px]">
                    <Pencil className="w-3.5 h-3.5 mr-2" />
                    Edit
                  </DropdownMenuItem>
                </Link>
              )}
              {canDeploy && (
                <>
                  <DropdownMenuSeparator />
                  {source.deployed ? (
                    <DropdownMenuItem
                      className="cursor-pointer text-[11.5px] text-amber-600 focus:text-amber-700 focus:bg-amber-500/10 dark:text-amber-400"
                      onClick={() => onUndeploy(source)}
                    >
                      <Power className="w-3.5 h-3.5 mr-2" />
                      Undeploy
                    </DropdownMenuItem>
                  ) : (
                    <DropdownMenuItem
                      className="cursor-pointer text-[11.5px]"
                      disabled={!source.validated}
                      onClick={() => onDeploy(source)}
                    >
                      <Rocket className="w-3.5 h-3.5 mr-2" />
                      Deploy
                    </DropdownMenuItem>
                  )}
                </>
              )}
              {canDelete && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    className="cursor-pointer text-[11.5px] text-red-500 focus:text-red-500 focus:bg-red-500/10"
                    onClick={() => onDelete(source)}
                  >
                    <Trash2 className="w-3.5 h-3.5 mr-2" />
                    Delete
                  </DropdownMenuItem>
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </td>
    </tr>
  );
}

function StatusBadge({
  status,
  validated,
  validationError,
}: {
  status: DerivedStatus;
  validated: boolean;
  validationError?: string;
}) {
  // NAN-1920: a wizard draft (onboarded, not yet deployed) is its own first-
  // class state and wins over every other badge — a draft is typically also
  // unvalidated, but we surface the more meaningful "in progress" signal.
  if (status === 'draft') {
    return (
      <span className="inline-flex items-center gap-1.5 h-[22px] px-2 rounded-[4px] bg-foreground/[0.04] text-foreground/70 text-[10.5px] font-medium border border-dashed border-border">
        <Pencil className="w-3 h-3" />
        Draft
      </span>
    );
  }
  // Non-draft feed whose VRL hasn't passed validation. Relabeled from "Draft"
  // (NAN-1920) so it no longer collides with the lifecycle Draft badge above.
  if (!validated) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            onClick={(e) => e.stopPropagation()}
            className="inline-flex items-center gap-1.5 h-[22px] px-2 rounded-[4px] bg-amber-500/15 text-amber-500 text-[10.5px] font-medium"
          >
            <AlertTriangle className="w-3 h-3" />
            Unvalidated
          </button>
        </TooltipTrigger>
        {validationError && (
          <TooltipContent side="top" sideOffset={6} collisionPadding={8} className="text-[11px] max-w-[320px]">
            {validationError}
          </TooltipContent>
        )}
      </Tooltip>
    );
  }
  if (status === 'deployed') {
    return (
      <span className="inline-flex items-center gap-1.5 h-[22px] px-2 rounded-[4px] bg-emerald-500/15 text-emerald-500 text-[10.5px] font-medium">
        <Check className="w-3 h-3" />
        Deployed
      </span>
    );
  }
  if (status === 'paused') {
    return (
      <span className="inline-flex items-center gap-1.5 h-[22px] px-2 rounded-[4px] bg-foreground/[0.05] text-muted-foreground text-[10.5px] font-medium border border-border">
        Paused
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 h-[22px] px-2 rounded-[4px] bg-foreground/[0.03] text-foreground/80 text-[10.5px] font-medium border border-border">
      Ready
    </span>
  );
}

function EnabledToggle({
  checked,
  warn,
  disabled,
  onClick,
}: {
  checked: boolean;
  warn?: boolean;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-pressed={checked}
      className={cn(
        'w-[30px] h-[17px] rounded-full flex items-center transition-colors relative shrink-0',
        checked ? (warn ? 'bg-amber-500' : 'bg-primary') : 'bg-foreground/[0.05] border border-border',
        disabled && 'opacity-50 cursor-not-allowed',
      )}
    >
      <span
        className={cn(
          'absolute w-[13px] h-[13px] rounded-full bg-white shadow transition-all',
          checked ? 'left-[15px]' : 'left-[2px]',
        )}
      />
    </button>
  );
}

// ----- Empty state -----

function EmptyState({
  hasQuery,
  canCreate,
  onNew,
  onBrowse,
}: {
  hasQuery: boolean;
  canCreate: boolean;
  onNew: () => void;
  onBrowse: () => void;
}) {
  if (hasQuery) {
    return (
      <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
        <Rss className="w-10 h-10 text-muted-foreground/50 mb-3" />
        <div className="text-[12.5px] font-medium text-foreground">No matching log sources</div>
        <div className="text-[11px] text-muted-foreground mt-1">Try a different search or filter.</div>
      </div>
    );
  }
  return (
    <div className="flex flex-col items-center justify-center py-20 px-4 text-center">
      <Rss className="w-10 h-10 text-muted-foreground/50 mb-3" />
      <div className="text-[13px] font-medium text-foreground">No log sources yet</div>
      <div className="text-[11.5px] text-muted-foreground mt-1 max-w-[420px]">
        Import a pre-built parser from a repository or build a new feed from sample logs.
      </div>
      <div className="flex items-center gap-2 mt-4">
        <Button variant="outline" size="sm" className="h-8" onClick={onBrowse}>
          Browse repositories
        </Button>
        {canCreate && (
          <Button size="sm" className="h-8 gap-1.5" onClick={onNew}>
            <Plus className="w-3.5 h-3.5" />
            New log source
          </Button>
        )}
      </div>
    </div>
  );
}

// ----- Confirmation dialogs -----

function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  confirmTone = 'default',
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel: string;
  confirmTone?: 'default' | 'warn' | 'danger';
  onConfirm: () => void;
}) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="max-w-md gap-0 p-0 bg-card border-border text-foreground">
        <AlertDialogHeader className="border-b border-border px-5 py-4">
          <AlertDialogTitle className="text-[14px] font-semibold">{title}</AlertDialogTitle>
          <AlertDialogDescription className="font-mono text-[11px] text-muted-foreground">
            {description}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter className="border-t border-border px-5 py-3">
          <AlertDialogCancel className="h-8 text-[11.5px]">Cancel</AlertDialogCancel>
          <AlertDialogAction
            className={cn(
              'h-8 text-[11.5px]',
              confirmTone === 'warn' && 'bg-amber-600 hover:bg-amber-700 text-white',
              confirmTone === 'danger' && 'bg-red-600 hover:bg-red-700 text-white',
            )}
            onClick={onConfirm}
          >
            {confirmLabel}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

function DeleteDialog({
  open,
  onOpenChange,
  logSource,
  checking,
  associatedRules,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  logSource: LogSource | null;
  checking: boolean;
  associatedRules: Array<{ configId: string; configName: string; ruleId: string; matchValue: string }>;
  onConfirm: () => void;
}) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="max-w-lg gap-0 p-0 bg-card border-border text-foreground">
        <AlertDialogHeader className="border-b border-border px-5 py-4">
          <AlertDialogTitle className="text-[14px] font-semibold">Delete log source</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="font-mono text-[11px] text-muted-foreground">
              Delete "{logSource?.name}"? This action cannot be undone.
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="px-5 py-4 space-y-3">
          {logSource?.deployed && (
            <div className="text-[11.5px] text-amber-500">
              This log source is currently deployed. It will be undeployed first.
            </div>
          )}
          {checking ? (
            <div className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Checking for associated routing rules…
            </div>
          ) : associatedRules.length > 0 ? (
            <div className="rounded-md border border-primary/30 bg-primary/[0.06] p-3">
              <div className="flex items-start gap-2">
                <Network className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                <div className="min-w-0">
                  <div className="text-[11.5px] font-medium text-primary">
                    {associatedRules.length} routing rule{associatedRules.length > 1 ? 's' : ''} route to this log source
                  </div>
                  <ul className="mt-1.5 text-[11px] text-foreground/80 list-disc list-inside space-y-0.5">
                    {associatedRules.slice(0, 5).map((rule, idx) => (
                      <li key={`${rule.ruleId}-${idx}`} className="font-mono">
                        {rule.configName}: {rule.matchValue}
                      </li>
                    ))}
                    {associatedRules.length > 5 && (
                      <li className="text-muted-foreground">…and {associatedRules.length - 5} more</li>
                    )}
                  </ul>
                  <div className="mt-2 text-[11px] text-muted-foreground">
                    These routing rules continue to exist but logs will have no parser.
                  </div>
                </div>
              </div>
            </div>
          ) : null}
        </div>
        <AlertDialogFooter className="border-t border-border px-5 py-3">
          <AlertDialogCancel className="h-8 text-[11.5px]">Cancel</AlertDialogCancel>
          <AlertDialogAction
            disabled={checking}
            onClick={onConfirm}
            className="h-8 text-[11.5px] bg-red-600 hover:bg-red-700 text-white"
          >
            Delete
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export default LogSources;
