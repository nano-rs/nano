// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  Box,
  Cloud,
  Database,
  Eye,
  Globe,
  MoreHorizontal,
  Pencil,
  Plug,
  Plus,
  Power,
  Radio,
  RefreshCw,
  Rocket,
  Search,
  Trash2,
  Zap,
} from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
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
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { TooltipProvider } from '@/components/ui/tooltip';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import type {
  NewSourceConfiguration,
  SourceConfigType,
  SourceConfiguration,
} from '@/lib/api';
import { cn } from '@/lib/utils';
import { sourceConfigPath } from '@/lib/ingestion-paths';
import { credentialProviderFor } from '@/components/log-sources/CredentialPicker';
import { SourceConfigForm } from '@/components/log-sources/SourceConfigForm';

type FilterId = 'all' | 'deployed' | 'ready' | 'enabled';
type DerivedStatus = 'deployed' | 'ready' | 'failed';

interface TransportSpec {
  value: SourceConfigType;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  popular?: boolean;
}

// NAN-883: HEC is served by the OOTB `splunk_hec_ingest` listener with one
// shared `${VECTOR_AUTH_TOKEN}`. A user HEC source config is just a routing
// profile — two of them would emit colliding `splunk_hec_route` transforms.
// Gate the picker (and the backend rejects duplicates with 409).
// NAN-1572: OTLP is also single-instance — the OOTB :4317/:4318 listener is
// shared, so a second otlp config would emit colliding `otlp_route` transforms.
const SINGLE_INSTANCE_TYPES: SourceConfigType[] = ['splunk_hec', 'otlp'];

const TRANSPORTS: TransportSpec[] = [
  { value: 'http', label: 'HTTP', icon: Globe, description: 'Generic HTTP POST endpoint with X-Source-Type header routing.', popular: true },
  { value: 'vector', label: 'Vector', icon: Radio, description: 'Upstream Vector forwarders over the native Vector protocol.', popular: true },
  { value: 'otlp', label: 'OpenTelemetry (OTLP)', icon: Plug, description: 'OTLP logs over gRPC (:4317) / HTTP (:4318).', popular: true },
  { value: 'aws_s3', label: 'AWS S3', icon: Cloud, description: 'Ingest objects from S3 via SQS notifications.', popular: true },
  { value: 'aws_sqs', label: 'AWS SQS', icon: Cloud, description: 'Consume an SQS queue directly, where the message body is the log.', popular: false },
  { value: 'gcp_pubsub', label: 'GCP Pub/Sub', icon: Cloud, description: 'Subscribe to a Google Cloud Pub/Sub topic.' },
  { value: 'azure_event_hubs', label: 'Azure Event Hubs', icon: Cloud, description: 'Consume an Event Hub with a consumer group, checkpointed in Blob Storage.' },
  { value: 'kafka', label: 'Kafka', icon: Database, description: 'Consume events from one or more Kafka topics.' },
  { value: 'splunk_hec', label: 'Splunk HEC', icon: Zap, description: 'Splunk HTTP Event Collector compatibility endpoint.' },
];

const TRANSPORT_BY_VALUE = new Map(TRANSPORTS.map((t) => [t.value, t]));

const transportOf = (configType: string): TransportSpec => {
  return (
    TRANSPORT_BY_VALUE.get(configType as SourceConfigType) ?? {
      value: configType as SourceConfigType,
      label: configType,
      icon: Box,
      description: '',
    }
  );
};

// NAN-4936: a deploy Vector refused (quarantined) or never confirmed is shown
// as failed with its reason, even when an earlier version is still deployed.
const FAILED_DEPLOY_STATUSES = new Set(['quarantined', 'quarantine_unconfirmed', 'failure', 'unconfirmed']);

const deployFailure = (config: SourceConfiguration): string | null => {
  const last = config.last_deployment;
  if (!last || last.action !== 'deploy' || !FAILED_DEPLOY_STATUSES.has(last.status)) return null;
  return last.error_message || last.status;
};

const deriveStatus = (config: SourceConfiguration): DerivedStatus =>
  deployFailure(config) ? 'failed' : config.deployed ? 'deployed' : 'ready';

const fmtCount = (n: number): string => {
  if (!Number.isFinite(n) || n <= 0) return '0';
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(2).replace(/\.?0+$/, '')}B`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1).replace(/\.0$/, '')}k`;
  return Math.round(n).toString();
};

const computeEps = (events24h: number | null | undefined): number => {
  if (!events24h || events24h <= 0) return 0;
  return events24h / 86_400;
};

/**
 * NAN-4941: the source-configuration list as a section of a Log Sources tab.
 * Cloud pull shows the pull transports (S3/SQS, SQS, Pub/Sub, Event Hubs,
 * Kafka); Credentials shows the push listeners (HTTP, Vector, OTLP, HEC).
 * Rows keep the toggle / deploy / undeploy / delete actions of the retired
 * Source Configs page and open the detail at /ingestion/log-sources/inputs/:id.
 */
export function SourceConfigsPanel({
  types,
  title,
  description,
  addLabel = 'Add source',
  testId,
}: {
  types: readonly SourceConfigType[];
  title: string;
  description: string;
  addLabel?: string;
  testId: string;
}) {

  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { hasPermission } = useAuth();

  const canCreate = hasPermission('source_configs:create');
  const canEdit = hasPermission('source_configs:edit');
  const canDelete = hasPermission('source_configs:delete');
  const canDeploy = hasPermission('source_configs:deploy');

  const [searchQuery, setSearchQuery] = useState('');
  const [filter, setFilter] = useState<FilterId>('all');

  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<SourceConfiguration | null>(null);
  const [undeployTarget, setUndeployTarget] = useState<SourceConfiguration | null>(null);
  const [deployTarget, setDeployTarget] = useState<SourceConfiguration | null>(null);

  const { data: allConfigs = [], isLoading, refetch } = useQuery({
    queryKey: ['sourceConfigs'],
    queryFn: () => api.listSourceConfigs(),
  });
  const sourceConfigs = useMemo(
    () => allConfigs.filter((c) => types.includes(c.config_type)),
    [allConfigs, types],
  );
  const transports = useMemo(() => TRANSPORTS.filter((t) => types.includes(t.value)), [types]);

  const createMutation = useMutation({
    mutationFn: (request: NewSourceConfiguration) => api.createSourceConfig(request),
    onSuccess: (config) => {
      queryClient.invalidateQueries({ queryKey: ['sourceConfigs'] });
      toast({ title: 'Source created', description: `${config.name} is ready to configure.` });
      setCreateDialogOpen(false);
      navigate(sourceConfigPath(config.id));
    },
    onError: (error) => {
      toast({ title: 'Failed to create', description: String(error), variant: 'destructive' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteSourceConfig(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sourceConfigs'] });
      toast({ title: 'Deleted' });
      setDeleteTarget(null);
    },
    onError: (error) => {
      toast({ title: 'Failed to delete', description: String(error), variant: 'destructive' });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.toggleSourceConfig(id, enabled),
    onSuccess: (config) => {
      queryClient.invalidateQueries({ queryKey: ['sourceConfigs'] });
      toast({
        title: config.enabled ? 'Enabled' : 'Disabled',
        description: `${config.name} has been ${config.enabled ? 'enabled' : 'disabled'}.`,
      });
    },
    onError: (error) => {
      toast({ title: 'Failed to toggle', description: String(error), variant: 'destructive' });
    },
  });

  const deployMutation = useMutation({
    mutationFn: (id: string) => api.deploySourceConfig(id),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['sourceConfigs'] });
      toast({
        title: result.success ? 'Deployed' : 'Deploy failed',
        description: result.message,
        variant: result.success ? 'default' : 'destructive',
      });
      setDeployTarget(null);
    },
    onError: (error) => {
      toast({ title: 'Failed to deploy', description: String(error), variant: 'destructive' });
    },
  });

  const undeployMutation = useMutation({
    mutationFn: (id: string) => api.undeploySourceConfig(id),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['sourceConfigs'] });
      toast({
        title: result.success ? 'Undeployed' : 'Undeploy failed',
        description: result.message,
        variant: result.success ? 'default' : 'destructive',
      });
      setUndeployTarget(null);
    },
    onError: (error) => {
      toast({ title: 'Failed to undeploy', description: String(error), variant: 'destructive' });
    },
  });

  const stats = useMemo(() => {
    let deployed = 0;
    let ready = 0;
    let enabled = 0;
    let totalEvents24h = 0;
    for (const c of sourceConfigs) {
      const status = deriveStatus(c);
      if (status === 'deployed') deployed += 1;
      else ready += 1;
      if (c.enabled) enabled += 1;
      if (c.events_24h && c.events_24h > 0) totalEvents24h += c.events_24h;
    }
    return {
      total: sourceConfigs.length,
      deployed,
      ready,
      enabled,
      totalEps: computeEps(totalEvents24h),
    };
  }, [sourceConfigs]);

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return sourceConfigs.filter((c) => {
      const status = deriveStatus(c);
      if (filter === 'deployed' && status !== 'deployed') return false;
      if (filter === 'ready' && status !== 'ready') return false;
      if (filter === 'enabled' && !c.enabled) return false;
      if (!q) return true;
      const transport = transportOf(c.config_type);
      const hay = [c.name, c.description, c.config_type, transport.label]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return hay.includes(q);
    });
  }, [sourceConfigs, searchQuery, filter]);

  return (
    <TooltipProvider delayDuration={200}>
      <section className="rounded-md border border-border bg-card" data-testid={testId} aria-label={title}>
        <HeroStrip stats={stats} title={title} description={description} />

        <Toolbar
          query={searchQuery}
          onQueryChange={setSearchQuery}
          filter={filter}
          onFilterChange={setFilter}
          stats={stats}
          onRefresh={refetch}
          canCreate={canCreate}
          addLabel={addLabel}
          onNew={() => setCreateDialogOpen(true)}
        />

        <div className="overflow-x-auto">
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <LoadingIcon className="w-6 h-6 text-muted-foreground" />
            </div>
          ) : filtered.length === 0 ? (
            <EmptyState
              hasQuery={!!searchQuery || filter !== 'all'}
              canCreate={canCreate}
              addLabel={addLabel}
              onNew={() => setCreateDialogOpen(true)}
            />
          ) : (
            <SourceConfigTable
              rows={filtered}
              canEdit={canEdit}
              canDeploy={canDeploy}
              canDelete={canDelete}
              onRowClick={(config) =>
                navigate(sourceConfigPath(config.id))
              }
              onToggle={(config) =>
                toggleMutation.mutate({ id: config.id, enabled: !config.enabled })
              }
              onDeploy={(config) => setDeployTarget(config)}
              onUndeploy={(config) => setUndeployTarget(config)}
              onDelete={(config) => setDeleteTarget(config)}
            />
          )}
        </div>

        <AddSourceSheet
          open={createDialogOpen}
          onOpenChange={setCreateDialogOpen}
          submitting={createMutation.isPending}
          onSubmit={(request) => createMutation.mutate(request)}
          transports={transports}
          existingTypes={new Set(allConfigs.map((c) => c.config_type as SourceConfigType))}
        />

        <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
          <AlertDialogContent className="max-w-md gap-0 p-0 bg-card border-border text-foreground">
            <AlertDialogHeader className="border-b border-border px-5 py-4">
              <AlertDialogTitle className="text-[14px] font-semibold">
                Delete source config
              </AlertDialogTitle>
              <AlertDialogDescription className="font-mono text-[11px] text-muted-foreground">
                Delete &ldquo;{deleteTarget?.name}&rdquo;? This action cannot be undone.
                {deleteTarget?.deployed && ' The config will be undeployed first.'}
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter className="border-t border-border px-5 py-3">
              <AlertDialogCancel className="h-8 text-[11.5px]">Cancel</AlertDialogCancel>
              <AlertDialogAction
                className="h-8 text-[11.5px] bg-red-600 hover:bg-red-700 text-white"
                onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
              >
                Delete
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

        <AlertDialog open={!!deployTarget} onOpenChange={() => setDeployTarget(null)}>
          <AlertDialogContent className="max-w-md gap-0 p-0 bg-card border-border text-foreground">
            <AlertDialogHeader className="border-b border-border px-5 py-4">
              <AlertDialogTitle className="text-[14px] font-semibold">
                Deploy source config
              </AlertDialogTitle>
              <AlertDialogDescription className="font-mono text-[11px] text-muted-foreground">
                Push &ldquo;{deployTarget?.name}&rdquo; to Vector. Ingestion starts immediately
                and routing rules become live.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter className="border-t border-border px-5 py-3">
              <AlertDialogCancel className="h-8 text-[11.5px]">Cancel</AlertDialogCancel>
              <AlertDialogAction
                className="h-8 text-[11.5px]"
                onClick={() => deployTarget && deployMutation.mutate(deployTarget.id)}
              >
                <Rocket className="h-3.5 w-3.5" />
                Deploy
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

        <AlertDialog open={!!undeployTarget} onOpenChange={() => setUndeployTarget(null)}>
          <AlertDialogContent className="max-w-md gap-0 p-0 bg-card border-border text-foreground">
            <AlertDialogHeader className="border-b border-border px-5 py-4">
              <AlertDialogTitle className="text-[14px] font-semibold">
                Undeploy source config
              </AlertDialogTitle>
              <AlertDialogDescription className="font-mono text-[11px] text-muted-foreground">
                Remove &ldquo;{undeployTarget?.name}&rdquo; from Vector. Ingestion stops
                immediately. You can re-deploy at any time.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter className="border-t border-border px-5 py-3">
              <AlertDialogCancel className="h-8 text-[11.5px]">Cancel</AlertDialogCancel>
              <AlertDialogAction
                className="h-8 text-[11.5px] bg-amber-600 hover:bg-amber-700 text-white"
                onClick={() => undeployTarget && undeployMutation.mutate(undeployTarget.id)}
              >
                <Power className="h-3.5 w-3.5" />
                Undeploy
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </section>
    </TooltipProvider>
  );
}

// ----- Hero strip -----

interface HeroStats {
  total: number;
  deployed: number;
  ready: number;
  enabled: number;
  totalEps: number;
}

function HeroStrip({ stats, title, description }: { stats: HeroStats; title: string; description: string }) {
  return (
    <div className="border-b border-border px-4 py-2.5 flex items-start gap-3">
      <Plug className="w-3.5 h-3.5 mt-0.5 text-muted-foreground shrink-0" strokeWidth={1.5} />
      <div className="flex-1 min-w-0">
        <div className="text-[13px] font-semibold text-foreground">{title}</div>
        <div className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed max-w-[740px]">{description}</div>
      </div>
      <div className="hidden md:flex items-center gap-4 shrink-0">
        <HeroStat value={stats.deployed} label="Deployed" />
        <HeroStat value={stats.ready} label="Ready" />
        <HeroStat value={fmtCount(stats.totalEps)} label="Events / sec" />
      </div>
    </div>
  );
}

function HeroStat({ value, label }: { value: number | string; label: string }) {
  return (
    <div className="flex flex-col items-end">
      <div className="font-mono text-[14px] tabular-nums text-foreground">{value}</div>
      <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
        {label}
      </div>
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
  addLabel,
  onNew,
}: {
  addLabel: string;
  query: string;
  onQueryChange: (v: string) => void;
  filter: FilterId;
  onFilterChange: (id: FilterId) => void;
  stats: HeroStats;
  onRefresh: () => void;
  canCreate: boolean;
  onNew: () => void;
}) {
  const items: Array<{ id: FilterId; label: string; count: number }> = [
    { id: 'all', label: 'All', count: stats.total },
    { id: 'deployed', label: 'Deployed', count: stats.deployed },
    { id: 'ready', label: 'Ready', count: stats.ready },
    { id: 'enabled', label: 'Enabled', count: stats.enabled },
  ];
  return (
    <div className="flex items-center gap-2 px-4 py-2 border-b border-border flex-wrap">
      <div className="relative">
        <Search className="w-3.5 h-3.5 text-muted-foreground absolute left-2.5 top-1/2 -translate-y-1/2" />
        <Input
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          placeholder="Search…"
          aria-label="Search sources"
          className="h-7 pl-8 w-[260px] text-[12px] bg-card"
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
        <Button size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={onNew}>
          <Plus className="w-3.5 h-3.5" />
          {addLabel}
        </Button>
      )}
    </div>
  );
}

// ----- Table -----

function SourceConfigTable({
  rows,
  canEdit,
  canDeploy,
  canDelete,
  onRowClick,
  onToggle,
  onDeploy,
  onUndeploy,
  onDelete,
}: {
  rows: SourceConfiguration[];
  canEdit: boolean;
  canDeploy: boolean;
  canDelete: boolean;
  onRowClick: (config: SourceConfiguration) => void;
  onToggle: (config: SourceConfiguration) => void;
  onDeploy: (config: SourceConfiguration) => void;
  onUndeploy: (config: SourceConfiguration) => void;
  onDelete: (config: SourceConfiguration) => void;
}) {
  return (
    <div className="@container/table">
      <table className="w-full text-[12px]">
        <thead>
          <tr className="border-b border-border bg-card/40">
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground pl-4 py-2">
              Source
            </th>
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground py-2 w-[110px] @max-[900px]/table:hidden">
              Type
            </th>
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground py-2 w-[110px]">
              Status
            </th>
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground py-2 w-[170px] @max-[1100px]/table:hidden">
              Volume (24h)
            </th>
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground py-2 w-[120px] @max-[640px]/table:w-[60px]">
              Enabled
            </th>
            <th className="w-[44px] py-2"></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((config) => (
            <SourceConfigRow
              key={config.id}
              config={config}
              canEdit={canEdit}
              canDeploy={canDeploy}
              canDelete={canDelete}
              onRowClick={() => onRowClick(config)}
              onToggle={() => onToggle(config)}
              onDeploy={() => onDeploy(config)}
              onUndeploy={() => onUndeploy(config)}
              onDelete={() => onDelete(config)}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SourceConfigRow({
  config,
  canEdit,
  canDeploy,
  canDelete,
  onRowClick,
  onToggle,
  onDeploy,
  onUndeploy,
  onDelete,
}: {
  config: SourceConfiguration;
  canEdit: boolean;
  canDeploy: boolean;
  canDelete: boolean;
  onRowClick: () => void;
  onToggle: () => void;
  onDeploy: () => void;
  onUndeploy: () => void;
  onDelete: () => void;
}) {
  const transport = transportOf(config.config_type);
  const Icon = transport.icon;
  const status = deriveStatus(config);
  const eps = computeEps(config.events_24h);

  return (
    <tr
      className="border-b border-border cursor-pointer group hover:bg-foreground/[0.03]"
      onClick={onRowClick}
    >
      <td className="pl-4 py-3 align-top">
        <div className="flex items-start gap-3 min-w-0">
          <div className="w-8 h-8 rounded-md border border-border bg-foreground/[0.03] flex items-center justify-center shrink-0 mt-0.5">
            <Icon className="w-[14px] h-[14px] text-muted-foreground" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[12.5px] font-medium text-foreground truncate group-hover:text-primary transition-colors">
                {config.name}
              </span>
              <span className="hidden @max-[900px]/table:inline-flex items-center gap-1 h-[15px] px-1 rounded-[3px] border border-border bg-foreground/[0.03]">
                <span className="text-[9.5px] font-mono uppercase tracking-wider text-foreground/80">
                  {transport.label}
                </span>
              </span>
            </div>
            {config.description && (
              <div className="text-[11px] text-muted-foreground line-clamp-2 mt-0.5 leading-relaxed max-w-[520px]">
                {config.description}
              </div>
            )}
            {status === 'deployed' && eps > 0 && (
              <div className="hidden @max-[1100px]/table:flex mt-1 items-center gap-2 font-mono text-[10.5px] text-muted-foreground tabular-nums">
                <span className="text-foreground/80">{fmtCount(config.events_24h ?? 0)}</span>
                <span className="text-muted-foreground/60">·</span>
                <span>{fmtCount(eps)} EPS</span>
              </div>
            )}
          </div>
        </div>
      </td>

      <td className="py-3 align-top @max-[900px]/table:hidden">
        <span className="inline-flex items-center gap-1.5 h-[22px] px-1.5 rounded-[4px] border border-border bg-foreground/[0.03]">
          <Icon className="w-3 h-3 text-muted-foreground" />
          <span className="text-[10.5px] font-mono text-foreground/80">{transport.label}</span>
        </span>
      </td>

      <td className="py-3 align-top">
        <StatusBadge status={status} />
        {status === 'failed' && (
          <div
            className="mt-1 max-w-[260px] font-mono text-[10.5px] leading-snug text-red-500 line-clamp-3 break-words"
            title={deployFailure(config) ?? undefined}
            data-testid="source-config-deploy-failure"
          >
            {config.last_deployment?.status?.startsWith('quarantine') ? 'Quarantined: ' : ''}
            {deployFailure(config)}
          </div>
        )}
      </td>

      <td className="py-3 align-top @max-[1100px]/table:hidden">
        {status === 'deployed' && (config.events_24h ?? 0) > 0 ? (
          <div className="flex flex-col">
            <div className="font-mono text-[12px] text-foreground tabular-nums">
              {fmtCount(config.events_24h ?? 0)}
            </div>
            <div className="font-mono text-[10px] text-muted-foreground tabular-nums">
              {fmtCount(eps)} EPS
            </div>
          </div>
        ) : (
          <span className="font-mono text-[11px] text-muted-foreground/70">—</span>
        )}
      </td>

      <td className="py-3 align-top">
        <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
          <EnabledToggle
            checked={config.enabled}
            disabled={!canEdit}
            onClick={onToggle}
          />
          <span
            className={cn(
              'text-[10px] font-mono uppercase tracking-wider @max-[640px]/table:hidden',
              config.enabled ? 'text-foreground/80' : 'text-muted-foreground',
            )}
          >
            {config.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
      </td>

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
              <DropdownMenuItem className="cursor-pointer text-[11.5px]" onClick={onRowClick}>
                <Eye className="w-3.5 h-3.5 mr-2" />
                View details
              </DropdownMenuItem>
              {canEdit && (
                <DropdownMenuItem className="cursor-pointer text-[11.5px]" onClick={onRowClick}>
                  <Pencil className="w-3.5 h-3.5 mr-2" />
                  Edit
                </DropdownMenuItem>
              )}
              {canDeploy && (
                <>
                  <DropdownMenuSeparator />
                  {config.deployed ? (
                    <DropdownMenuItem
                      className="cursor-pointer text-[11.5px] text-amber-600 focus:text-amber-700 focus:bg-amber-500/10 dark:text-amber-400"
                      onClick={onUndeploy}
                    >
                      <Power className="w-3.5 h-3.5 mr-2" />
                      Undeploy
                    </DropdownMenuItem>
                  ) : (
                    <DropdownMenuItem className="cursor-pointer text-[11.5px]" onClick={onDeploy}>
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
                    onClick={onDelete}
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

function StatusBadge({ status }: { status: DerivedStatus }) {
  if (status === 'failed') {
    return (
      <span className="inline-flex items-center gap-1.5 h-[22px] px-2 rounded-[4px] bg-red-500/15 text-red-500 text-[10.5px] font-medium">
        <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
        Failed
      </span>
    );
  }
  if (status === 'deployed') {
    return (
      <span className="inline-flex items-center gap-1.5 h-[22px] px-2 rounded-[4px] bg-emerald-500/15 text-emerald-500 text-[10.5px] font-medium">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
        Deployed
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
  disabled,
  onClick,
}: {
  checked: boolean;
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
        checked ? 'bg-primary' : 'bg-foreground/[0.05] border border-border',
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
  addLabel,
  onNew,
}: {
  hasQuery: boolean;
  canCreate: boolean;
  addLabel: string;
  onNew: () => void;
}) {
  if (hasQuery) {
    return (
      <div className="flex flex-col items-center justify-center py-8 px-4 text-center">
        <Plug className="w-5 h-5 text-muted-foreground/60 mb-2" strokeWidth={1.5} />
        <div className="text-[12.5px] font-medium text-foreground">
          Nothing matches the filter
        </div>
        <div className="text-[11px] text-muted-foreground mt-1">
          Try a different search or filter.
        </div>
      </div>
    );
  }
  return (
    <div className="flex flex-col items-center justify-center py-8 px-4 text-center" data-testid="source-configs-empty">
      <Plug className="w-5 h-5 text-muted-foreground/60 mb-2" strokeWidth={1.5} />
      <div className="text-[12.5px] font-medium text-foreground">None yet</div>
      <div className="text-[11.5px] text-muted-foreground mt-1 max-w-[420px]">
        Each one owns routing rules that decide which log source an event goes to.
      </div>
      {canCreate && (
        <div className="mt-3">
          <Button size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={onNew}>
            <Plus className="w-3.5 h-3.5" />
            {addLabel}
          </Button>
        </div>
      )}
    </div>
  );
}

// ----- Add source sheet (two-step pick → name → create) -----

function AddSourceSheet({
  open,
  onOpenChange,
  submitting,
  onSubmit,
  transports,
  existingTypes,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  submitting: boolean;
  onSubmit: (request: NewSourceConfiguration) => void;
  transports: TransportSpec[];
  existingTypes: Set<SourceConfigType>;
}) {
  const [step, setStep] = useState<'pick' | 'name'>('pick');
  const [picked, setPicked] = useState<SourceConfigType | null>(null);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  // NAN-4941: a pull transport picks a stored credential or takes a new
  // secret inline (the picker's "Enter new" sheet), so setup never leaves the tab.
  const [credentialId, setCredentialId] = useState<string | undefined>(undefined);
  const [connectionConfig, setConnectionConfig] = useState<Record<string, unknown>>({});

  const reset = () => {
    setStep('pick');
    setPicked(null);
    setName('');
    setDescription('');
    setCredentialId(undefined);
    setConnectionConfig({});
  };

  const handleOpenChange = (next: boolean) => {
    if (!next) reset();
    onOpenChange(next);
  };

  const transport = picked ? TRANSPORT_BY_VALUE.get(picked) : null;

  const submit = () => {
    if (!picked || !name.trim()) return;
    onSubmit({
      name: name.trim(),
      description: description.trim() || undefined,
      config_type: picked,
      connection_config: credentialProviderFor(picked) ? connectionConfig : {},
      credential_id: credentialProviderFor(picked) ? credentialId : undefined,
    });
  };

  return (
    <Sheet open={open} onOpenChange={handleOpenChange}>
      <SheetContent
        side="right"
        className="w-[520px] sm:max-w-[520px] gap-0 p-0 bg-card border-l border-border text-foreground flex flex-col"
      >
        <SheetHeader className="border-b border-border px-5 py-4 space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-md border border-border bg-foreground/[0.03] flex items-center justify-center">
              <Plus className="w-[14px] h-[14px] text-muted-foreground" />
            </div>
            <div className="flex-1 min-w-0">
              <SheetTitle className="text-[14px] font-semibold leading-tight">
                {transports.length === 1 ? `Add ${transports[0].label}` : 'Add source'}
              </SheetTitle>
              <SheetDescription className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
                {step === 'pick' ? 'Step 1 of 2 · Pick transport' : 'Step 2 of 2 · Name & create'}
              </SheetDescription>
            </div>
          </div>
        </SheetHeader>

        <div className="flex-1 min-h-0 overflow-y-auto px-5 py-4">
          {step === 'pick' ? (
            <PickTransport
              transports={transports}
              selected={picked}
              onSelect={(t) => {
                setPicked(t);
                setCredentialId(undefined);
                // NAN-4936: new S3 sources start with a 60s SQS visibility timeout
                // (an in-flight notification comes back 60s after a Vector restart,
                // not Vector's 300s). Existing sources keep whatever they saved.
                setConnectionConfig(t === 'aws_s3' ? { visibility_timeout_secs: 60 } : {});
              }}
              existingTypes={existingTypes}
            />
          ) : transport ? (
            <NameTransport
              transport={transport}
              name={name}
              description={description}
              onNameChange={setName}
              onDescriptionChange={setDescription}
              credentialId={credentialId}
              onCredentialChange={setCredentialId}
              connectionConfig={connectionConfig}
              onConnectionConfigChange={setConnectionConfig}
            />
          ) : null}
        </div>

        <SheetFooter className="border-t border-border px-5 py-3 flex-row sm:justify-between sm:space-x-0">
          <Button
            variant="ghost"
            size="sm"
            className="h-8 text-[11.5px]"
            onClick={() => (step === 'name' ? setStep('pick') : handleOpenChange(false))}
          >
            {step === 'name' ? 'Back' : 'Cancel'}
          </Button>
          {step === 'pick' ? (
            <Button
              size="sm"
              className="h-8 text-[11.5px]"
              disabled={!picked}
              onClick={() => setStep('name')}
            >
              Continue
            </Button>
          ) : (
            <Button
              size="sm"
              className="h-8 text-[11.5px]"
              disabled={submitting || !name.trim()}
              onClick={submit}
            >
              {submitting && <LoadingIcon className="h-3.5 w-3.5" />}
              Create &amp; configure
            </Button>
          )}
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}

function PickTransport({
  transports,
  selected,
  onSelect,
  existingTypes,
}: {
  transports: TransportSpec[];
  selected: SourceConfigType | null;
  onSelect: (value: SourceConfigType) => void;
  existingTypes: Set<SourceConfigType>;
}) {
  const popular = transports.filter((t) => t.popular);
  const rest = transports.filter((t) => !t.popular);

  // NAN-883: HEC is single-instance — disable if one already exists.
  const isDisabled = (t: TransportSpec): boolean =>
    SINGLE_INSTANCE_TYPES.includes(t.value) && existingTypes.has(t.value);
  const disabledReason = (t: TransportSpec): string | null =>
    t.value === 'splunk_hec' && existingTypes.has('splunk_hec')
      ? 'Only one Splunk HEC routing config is supported. Edit the existing one to add routing rules.'
      : null;

  const renderCard = (t: TransportSpec) => (
    <TransportCard
      key={t.value}
      transport={t}
      active={selected === t.value}
      disabled={isDisabled(t)}
      disabledReason={disabledReason(t)}
      onSelect={() => onSelect(t.value)}
    />
  );

  return (
    <div className="space-y-4">
      {popular.length > 0 && (
        <div>
          <div className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground mb-2">
            Popular
          </div>
          <div className="grid grid-cols-2 gap-2">{popular.map(renderCard)}</div>
        </div>
      )}
      {rest.length > 0 && (
        <div>
          <div className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground mb-2">
            {popular.length > 0 ? 'More' : 'Transports'}
          </div>
          <div className="grid grid-cols-2 gap-2">{rest.map(renderCard)}</div>
        </div>
      )}
      <div className="rounded-md border border-border bg-foreground/[0.02] p-3 text-[11px] text-muted-foreground leading-relaxed">
        After creating the source, you&rsquo;ll configure connection settings (auth, endpoints,
        topics) and routing rules in the workspace.
      </div>
    </div>
  );
}

function TransportCard({
  transport,
  active,
  disabled,
  disabledReason,
  onSelect,
}: {
  transport: TransportSpec;
  active: boolean;
  disabled?: boolean;
  disabledReason?: string | null;
  onSelect: () => void;
}) {
  const Icon = transport.icon;
  return (
    <button
      type="button"
      onClick={onSelect}
      disabled={disabled}
      title={disabled ? disabledReason ?? undefined : undefined}
      aria-disabled={disabled}
      className={cn(
        'flex flex-col items-start gap-1.5 p-3 rounded-md border text-left transition-all',
        disabled
          ? 'border-border bg-foreground/[0.01] opacity-55 cursor-not-allowed'
          : active
            ? 'border-primary/60 bg-primary/8'
            : 'border-border bg-foreground/[0.02] hover:border-border/80 hover:bg-foreground/[0.04]',
      )}
    >
      <div
        className={cn(
          'w-7 h-7 rounded-md flex items-center justify-center',
          active && !disabled
            ? 'bg-primary/15 text-primary'
            : 'bg-card border border-border text-muted-foreground',
        )}
      >
        <Icon className="w-[14px] h-[14px]" />
      </div>
      <div className="text-[12.5px] font-medium text-foreground">{transport.label}</div>
      <div className="text-[10.5px] text-muted-foreground leading-[1.45]">
        {disabled && disabledReason ? disabledReason : transport.description}
      </div>
    </button>
  );
}

function NameTransport({
  transport,
  name,
  description,
  onNameChange,
  onDescriptionChange,
  credentialId,
  onCredentialChange,
  connectionConfig,
  onConnectionConfigChange,
}: {
  connectionConfig: Record<string, unknown>;
  onConnectionConfigChange: (v: Record<string, unknown>) => void;
  transport: TransportSpec;
  name: string;
  description: string;
  onNameChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  credentialId: string | undefined;
  onCredentialChange: (id: string | undefined) => void;
}) {
  const Icon = transport.icon;
  const credentialProvider = credentialProviderFor(transport.value);
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 p-3 rounded-md border border-border bg-foreground/[0.02]">
        <div className="w-9 h-9 rounded-md bg-primary/15 text-primary flex items-center justify-center">
          <Icon className="w-[16px] h-[16px]" />
        </div>
        <div className="min-w-0">
          <div className="text-[12.5px] font-medium text-foreground">{transport.label}</div>
          <div className="text-[11px] text-muted-foreground">{transport.description}</div>
        </div>
      </div>
      <div className="space-y-1.5">
        <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
          Name
        </Label>
        <Input
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder={`${transport.label} ingest`}
          className="h-8 text-[12px] bg-card"
        />
      </div>
      <div className="space-y-1.5">
        <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
          Description
        </Label>
        <Textarea
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          placeholder="Optional — what feeds flow through this transport?"
          className="text-[12px] bg-card min-h-[72px]"
        />
      </div>
      {credentialProvider && (
        <div className="space-y-1.5 border-t border-border pt-3" data-testid="add-source-connection">
          <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
            Connection
          </Label>
          <SourceConfigForm
            sourceType={transport.value}
            config={connectionConfig}
            onConfigChange={onConnectionConfigChange}
            credentialId={credentialId}
            onCredentialChange={onCredentialChange}
          />
        </div>
      )}
      <div className="rounded-md border border-amber-500/20 bg-amber-500/5 p-3 text-[11px] text-amber-700 dark:text-amber-300 leading-relaxed flex items-start gap-2">
        <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
        <span>
          The source will be created in <span className="font-mono">Ready</span> state.{' '}
          {credentialProvider
            ? 'Next you pick which log source its events route to, then deploy.'
            : 'You\u2019ll configure connection settings and routing rules on the next page, then deploy when ready.'}
        </span>
      </div>
    </div>
  );
}

