// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-2192 — collector connections, rendered as a tab inside the marketplace
 * drawer.
 *
 * Was a standalone /integrations page in NAN-2189. That split one lifecycle
 * across two surfaces: the marketplace already installs, configures, stores
 * credentials for and enables its entries, so "browse here, operate there" was
 * a seam with nothing behind it.
 *
 * The one thing genuinely different about collectors is cardinality —
 * marketplace entries are 1:1 with their config, a collector is 1:N (one
 * integration, many vendor tenants). That justifies this section, not a page.
 *
 * Each enabled stream is materialized as a log source, so the ongoing "is data
 * arriving?" question is answered in Ingestion → Log Sources alongside every
 * other feed. Streams that could not get one are surfaced here, because the
 * alternative is a collector that appears healthy while collecting into
 * nothing.
 */

import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle, CheckCircle2, Clock, Loader2, Play, Plus,
  RefreshCw, Trash2, XCircle,
} from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { api, collectorManifest } from '@/lib/api';
import type {
  IntegrationInstance, MarketplaceCatalogEntry, StreamProvisionReport, StreamStatus,
} from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatUTCCompact } from '@/lib/date-utils';
import { cn } from '@/lib/utils';

// =============================================================================
// Presentation helpers
// =============================================================================

/**
 * Staleness thresholds.
 *
 * Iterator APIs drop undelivered events after a retention window (Netskope: 7
 * days on some streams), so a stalled stream is silent data loss, not a
 * backlog. Warn well before the shortest vendor window rather than at it.
 */
const STALE_WARN_SECS = 3 * 3600;
const STALE_ERROR_SECS = 24 * 3600;

function staleTone(secs: number | undefined): 'ok' | 'warn' | 'error' | 'none' {
  if (secs === undefined) return 'none';
  if (secs >= STALE_ERROR_SECS) return 'error';
  if (secs >= STALE_WARN_SECS) return 'warn';
  return 'ok';
}

function formatDuration(secs: number | undefined): string {
  if (secs === undefined) return '—';
  if (secs < 60) return `${Math.max(0, Math.round(secs))}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  if (secs < 86_400) return `${Math.round(secs / 3600)}h`;
  return `${Math.round(secs / 86_400)}d`;
}

function RunStatusBadge({ instance }: { instance: IntegrationInstance }) {
  if (instance.running) {
    return (
      <span className="inline-flex items-center gap-1 font-mono text-[10.5px] text-blue-600 dark:text-blue-400">
        <Loader2 className="h-3 w-3 animate-spin" /> running
      </span>
    );
  }
  if (!instance.enabled) {
    return <span className="font-mono text-[10.5px] text-muted-foreground">disabled</span>;
  }
  switch (instance.last_run_status) {
    case 'success':
      return (
        <span className="inline-flex items-center gap-1 font-mono text-[10.5px] text-emerald-600 dark:text-emerald-400">
          <CheckCircle2 className="h-3 w-3" /> ok
        </span>
      );
    case 'partial':
      return (
        <span className="inline-flex items-center gap-1 font-mono text-[10.5px] text-amber-600 dark:text-amber-400">
          <AlertTriangle className="h-3 w-3" /> partial
        </span>
      );
    case 'failed':
      return (
        <span className="inline-flex items-center gap-1 font-mono text-[10.5px] text-red-600 dark:text-red-400">
          <XCircle className="h-3 w-3" /> failed
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 font-mono text-[10.5px] text-muted-foreground">
          <Clock className="h-3 w-3" /> never run
        </span>
      );
  }
}

function StreamRow({ stream }: { stream: StreamStatus }) {
  const tone = staleTone(stream.staleness_secs);
  return (
    <div className="flex items-center gap-3 border-b border-border/60 px-3 py-1 last:border-b-0">
      <span
        className={cn(
          'h-1.5 w-1.5 shrink-0 rounded-full',
          !stream.enabled && 'bg-muted-foreground/30',
          stream.enabled && tone === 'ok' && 'bg-emerald-500',
          stream.enabled && tone === 'warn' && 'bg-amber-500',
          stream.enabled && tone === 'error' && 'bg-red-500',
          stream.enabled && tone === 'none' && 'bg-muted-foreground/50',
        )}
      />
      <span className="w-40 shrink-0 truncate text-[12px]">{stream.label ?? stream.stream_id}</span>
      <span className="w-52 shrink-0 truncate font-mono text-[10.5px] text-muted-foreground">
        {stream.source_type}
      </span>
      <span className="w-24 shrink-0 text-right font-mono text-[10.5px] tabular-nums text-muted-foreground">
        {stream.events_fetched.toLocaleString()}
      </span>
      <span
        className={cn(
          'w-20 shrink-0 text-right font-mono text-[10.5px] tabular-nums',
          tone === 'error' ? 'text-red-600 dark:text-red-400'
            : tone === 'warn' ? 'text-amber-600 dark:text-amber-400'
            : 'text-muted-foreground',
        )}
        title={stream.last_success_at ? `Last delivered ${formatUTCCompact(stream.last_success_at)}` : 'Never delivered'}
      >
        {stream.enabled ? formatDuration(stream.staleness_secs) : '—'}
      </span>
      {stream.last_error && (
        <span className="min-w-0 flex-1 truncate text-[11px] text-red-600 dark:text-red-400" title={stream.last_error}>
          {stream.last_error}
        </span>
      )}
    </div>
  );
}

// =============================================================================
// Instance dialog
// =============================================================================

interface InstanceDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  integration: MarketplaceCatalogEntry;
  /** Editing an existing instance, or undefined to create one. */
  instance?: IntegrationInstance;
  canWriteCredentials: boolean;
  /** Lets the tab surface which streams failed to get a log source. */
  onSaved?: (saved: IntegrationInstance) => void;
}

function InstanceDialog({
  open, onOpenChange, integration, instance, canWriteCredentials, onSaved,
}: InstanceDialogProps) {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const manifest = useMemo(() => collectorManifest(integration.config), [integration.config]);
  const isEdit = Boolean(instance);

  const [name, setName] = useState(instance?.name ?? integration.name);
  const [config, setConfig] = useState<Record<string, string>>(() => {
    const initial: Record<string, string> = {};
    for (const field of manifest.configFields) {
      const value = instance?.config?.[field.name];
      initial[field.name] = typeof value === 'string' ? value : '';
    }
    return initial;
  });
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [streams, setStreams] = useState<string[]>(
    instance?.enabled_streams ?? manifest.streams.filter((s) => s.default).map((s) => s.id),
  );
  const [schedule, setSchedule] = useState(instance?.schedule ?? '');
  const [enabled, setEnabled] = useState(instance?.enabled ?? true);

  const save = useMutation({
    mutationFn: async () => {
      // Only send credentials the operator actually typed. On edit, an empty
      // map must not overwrite the stored secret — the API never returned it,
      // so there is nothing to send back.
      const typedCredentials = Object.fromEntries(
        Object.entries(credentials).filter(([, v]) => v.trim() !== ''),
      );
      const payload = {
        name,
        config,
        enabled_streams: streams,
        schedule: schedule.trim() === '' ? null : schedule.trim(),
        ...(Object.keys(typedCredentials).length > 0 ? { credentials: typedCredentials } : {}),
      };
      if (instance) {
        return api.integrations.updateInstance(instance.id, { ...payload, enabled });
      }
      return api.integrations.createInstance({
        slug: integration.slug,
        ...payload,
        schedule: payload.schedule ?? undefined,
        enabled,
      });
    },
    onSuccess: (saved) => {
      queryClient.invalidateQueries({ queryKey: ['integration-instances'] });
      toast({ title: isEdit ? 'Connection updated' : 'Connection created' });
      onSaved?.(saved);
      onOpenChange(false);
    },
    onError: (error: Error) => {
      toast({ title: 'Save failed', description: error.message, variant: 'destructive' });
    },
  });

  const missingRequiredConfig = manifest.configFields.some(
    (f) => f.required && (config[f.name] ?? '').trim() === '',
  );
  // Credentials are required to create, but on edit the stored ones stand.
  const missingCredentials =
    integration.requires_credential === 'required' &&
    !isEdit &&
    integration.credential_fields.some((f) => f.required && (credentials[f.name] ?? '').trim() === '');

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="text-[15px]">
            {isEdit ? 'Edit' : 'Connect'} {integration.name}
          </DialogTitle>
          <DialogDescription className="text-[12px]">
            One instance per vendor tenant. Credentials are encrypted at rest and never returned by the API.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label className="text-[11px]">Name</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Netskope — EU production"
              className="h-8 text-[12px]"
            />
          </div>

          {manifest.configFields.map((field) => (
            <div key={field.name} className="space-y-1.5">
              <Label className="text-[11px]">
                {field.label}
                {field.required && <span className="ml-1 text-red-500">*</span>}
              </Label>
              <Input
                value={config[field.name] ?? ''}
                onChange={(e) => setConfig((c) => ({ ...c, [field.name]: e.target.value }))}
                placeholder={field.placeholder}
                className="h-8 font-mono text-[12px]"
              />
              {field.help && <p className="text-[11px] text-muted-foreground">{field.help}</p>}
            </div>
          ))}

          {integration.credential_fields.length > 0 && (
            <div className="space-y-3 rounded border border-border p-3">
              <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                Credentials
                {isEdit && instance?.has_credentials && (
                  <span className="ml-2 normal-case tracking-normal text-muted-foreground/80">
                    · stored — leave blank to keep
                  </span>
                )}
              </div>
              {!canWriteCredentials && (
                <p className="text-[11px] text-amber-600 dark:text-amber-400">
                  You do not have the <span className="font-mono">credentials:use</span> permission,
                  so credential fields are read-only.
                </p>
              )}
              {integration.credential_fields.map((field) => (
                <div key={field.name} className="space-y-1.5">
                  <Label className="text-[11px]">
                    {field.label}
                    {field.required && !isEdit && <span className="ml-1 text-red-500">*</span>}
                  </Label>
                  <Input
                    type="password"
                    autoComplete="new-password"
                    disabled={!canWriteCredentials}
                    value={credentials[field.name] ?? ''}
                    onChange={(e) =>
                      setCredentials((c) => ({ ...c, [field.name]: e.target.value }))
                    }
                    className="h-8 font-mono text-[12px]"
                  />
                  {field.help && <p className="text-[11px] text-muted-foreground">{field.help}</p>}
                </div>
              ))}
            </div>
          )}

          <div className="space-y-2">
            <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Streams
            </div>
            {manifest.streams.map((stream) => (
              <label key={stream.id} className="flex items-start gap-2 text-[12px]">
                <Checkbox
                  checked={streams.includes(stream.id)}
                  onCheckedChange={(checked) =>
                    setStreams((s) =>
                      checked ? [...s, stream.id] : s.filter((id) => id !== stream.id),
                    )
                  }
                  className="mt-0.5"
                />
                <span className="min-w-0">
                  <span className="font-medium">{stream.label}</span>
                  <span className="ml-2 font-mono text-[10.5px] text-muted-foreground">
                    {stream.source_type}
                  </span>
                  {stream.description && (
                    <span className="block text-[11px] text-muted-foreground">
                      {stream.description}
                    </span>
                  )}
                </span>
              </label>
            ))}
          </div>

          <div className="space-y-1.5">
            <Label className="text-[11px]">Schedule</Label>
            <Input
              value={schedule}
              onChange={(e) => setSchedule(e.target.value)}
              placeholder={manifest.pollSchedule ?? '*/15 * * * *'}
              className="h-8 font-mono text-[12px]"
            />
            <p className="text-[11px] text-muted-foreground">
              Cron. Blank uses the integration default
              {manifest.pollSchedule && (
                <span className="font-mono"> ({manifest.pollSchedule})</span>
              )}
              .
            </p>
          </div>

          <div className="flex items-center justify-between rounded border border-border px-3 py-2">
            <div>
              <div className="text-[12px] font-medium">Enabled</div>
              <p className="text-[11px] text-muted-foreground">
                A disabled instance keeps its cursors and stops pulling.
              </p>
            </div>
            <Switch checked={enabled} onCheckedChange={setEnabled} />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            size="sm"
            disabled={
              save.isPending || name.trim() === '' || missingRequiredConfig || missingCredentials
            }
            onClick={() => save.mutate()}
          >
            {save.isPending && <Loader2 className="mr-1.5 h-3 w-3 animate-spin" />}
            {isEdit ? 'Save' : 'Connect'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// =============================================================================
// Provisioning warnings
// =============================================================================

/**
 * Surface streams that have no log source.
 *
 * A collector whose streams silently collect into nothing looks identical to a
 * healthy one — same "ok" run status, same rising event count — which is the
 * failure this whole section exists to make impossible.
 */
function ProvisioningNotice({ reports }: { reports: StreamProvisionReport[] }) {
  const problems = reports.filter((r) => r.status !== 'linked');
  if (problems.length === 0) return null;

  return (
    <div className="mx-3 mb-2 rounded border border-amber-500/40 bg-amber-500/5 px-3 py-2">
      <div className="flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-amber-600 dark:text-amber-400">
        <AlertTriangle className="h-[11px] w-[11px]" />
        {problems.length} {problems.length === 1 ? 'stream has' : 'streams have'} no log source
      </div>
      <ul className="mt-1.5 space-y-1">
        {problems.map((p) => (
          <li key={p.stream_id} className="text-[11.5px] text-muted-foreground">
            <span className="font-mono text-foreground">{p.source_type}</span>
            {p.status === 'no_parser' && p.declared_parser && (
              <>
                {' — needs parser '}
                <span className="font-mono text-foreground">{p.declared_parser}</span>
                {', which no synced repository provides. Events will arrive unparsed. '}
                <Link to="/ingestion/log-sources/repositories" className="text-primary hover:underline">
                  Sync a repository
                </Link>
              </>
            )}
            {p.status === 'no_parser' && !p.declared_parser && (
              <>
                {' — no parser claims this source type. Events will arrive unparsed. '}
                <Link to="/ingestion/log-sources/repositories" className="text-primary hover:underline">
                  Import one
                </Link>
              </>
            )}
            {p.status === 'not_permitted' && (
              <> — {p.missing}. Ask an administrator to import the parser.</>
            )}
            {p.status === 'failed' && <> — {p.error}</>}
          </li>
        ))}
      </ul>
    </div>
  );
}

// =============================================================================
// Tab
// =============================================================================

interface ConnectionsTabProps {
  /** The collector whose connections these are. */
  entry: MarketplaceCatalogEntry;
}

export function ConnectionsTab({ entry }: ConnectionsTabProps) {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { hasPermission } = useAuth();

  const canEdit = hasPermission('log_sources:edit');
  const canDelete = hasPermission('log_sources:delete');
  const canWriteCredentials = hasPermission('credentials:use');

  const [dialogInstance, setDialogInstance] = useState<IntegrationInstance | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<IntegrationInstance | null>(null);
  const [provisioning, setProvisioning] = useState<StreamProvisionReport[]>([]);

  const instancesQuery = useQuery({
    queryKey: ['integration-instances', entry.slug],
    // Instances change while a run is in flight, so poll rather than making the
    // operator refresh to find out whether their trigger did anything.
    refetchInterval: 15_000,
    queryFn: () => api.integrations.listInstances(entry.slug),
  });

  const triggerRun = useMutation({
    mutationFn: (id: string) => api.integrations.triggerRun(id),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['integration-instances'] });
      toast({ title: 'Run queued', description: result.message });
    },
    onError: (error: Error) =>
      toast({ title: 'Could not queue run', description: error.message, variant: 'destructive' }),
  });

  const toggleEnabled = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.integrations.updateInstance(id, { enabled }),
    onSuccess: (updated) => {
      queryClient.invalidateQueries({ queryKey: ['integration-instances'] });
      setProvisioning(updated.provisioning ?? []);
    },
    onError: (error: Error) =>
      toast({ title: 'Update failed', description: error.message, variant: 'destructive' }),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.integrations.deleteInstance(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integration-instances'] });
      // Deliberate wording: the log sources survive. They hold the operator's
      // parser and config, so deleting an instance unlinks rather than destroys.
      toast({
        title: 'Connection deleted',
        description: 'Its log sources were kept and will stop receiving events.',
      });
      setDeleteTarget(null);
    },
    onError: (error: Error) =>
      toast({ title: 'Delete failed', description: error.message, variant: 'destructive' }),
  });

  const instances = instancesQuery.data?.instances ?? [];

  return (
    <div className="py-3">
      <div className="flex items-center justify-between px-3 pb-2">
        <div>
          <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
            Connections
          </div>
          <p className="mt-0.5 text-[11.5px] text-muted-foreground">
            One per vendor tenant. Each enabled stream becomes a log source.
          </p>
        </div>
        {canEdit && entry.installed && (
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              setDialogInstance(null);
              setDialogOpen(true);
            }}
          >
            <Plus className="mr-1.5 h-3.5 w-3.5" />
            Connect tenant
          </Button>
        )}
      </div>

      <ProvisioningNotice reports={provisioning} />

      {!entry.installed ? (
        <p className="px-3 py-4 text-[12px] text-muted-foreground">
          Install this integration before connecting a tenant.
        </p>
      ) : instancesQuery.isLoading ? (
        <div className="flex items-center gap-2 px-3 py-4 text-[12px] text-muted-foreground">
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading…
        </div>
      ) : instances.length === 0 ? (
        <p className="px-3 py-4 text-[12px] text-muted-foreground">
          Not connected to a tenant yet.
        </p>
      ) : (
        <div className="border-t border-border">
          {instances.map((instance) => (
            <div key={instance.id} className="border-b border-border last:border-b-0">
              <div className="flex items-center gap-3 px-3 py-2">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-[12.5px] font-medium">{instance.name}</span>
                    <RunStatusBadge instance={instance} />
                  </div>
                  <div className="mt-0.5 font-mono text-[10.5px] text-muted-foreground">
                    {instance.events_fetched.toLocaleString()} events
                    {instance.last_run_at && <> · last run {formatUTCCompact(instance.last_run_at)}</>}
                    {instance.schedule && <> · {instance.schedule}</>}
                  </div>
                  {instance.last_error && (
                    <div
                      className="mt-0.5 truncate text-[11px] text-red-600 dark:text-red-400"
                      title={instance.last_error}
                    >
                      {instance.last_error}
                    </div>
                  )}
                </div>

                <div className="flex shrink-0 items-center gap-1.5">
                  <Switch
                    checked={instance.enabled}
                    disabled={!canEdit || toggleEnabled.isPending}
                    onCheckedChange={(enabled) => toggleEnabled.mutate({ id: instance.id, enabled })}
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={!canEdit || !instance.enabled || instance.running}
                    title={
                      instance.running
                        ? 'A run is already in flight'
                        : 'Queue a run on the next scheduler tick'
                    }
                    onClick={() => triggerRun.mutate(instance.id)}
                  >
                    <Play className="h-3.5 w-3.5" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={!canEdit}
                    onClick={() => {
                      setDialogInstance(instance);
                      setDialogOpen(true);
                    }}
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={!canDelete}
                    onClick={() => setDeleteTarget(instance)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>

              {instance.streams.length > 0 && (
                <div className="bg-muted/30">
                  {instance.streams
                    .filter((s) => s.enabled)
                    .map((stream) => (
                      <StreamRow key={stream.stream_id} stream={stream} />
                    ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {dialogOpen && (
        <InstanceDialog
          open
          onOpenChange={(open) => {
            setDialogOpen(open);
            if (!open) setDialogInstance(null);
          }}
          integration={entry}
          instance={dialogInstance ?? undefined}
          canWriteCredentials={canWriteCredentials}
          onSaved={(saved) => setProvisioning(saved.provisioning ?? [])}
        />
      )}

      <ConfirmDialog
        open={Boolean(deleteTarget)}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        title="Delete this connection?"
        description={
          <>
            <span className="font-medium text-foreground">{deleteTarget?.name}</span> stops
            collecting and its cursors are discarded. Its log sources are kept — reconnecting
            starts from now, so anything the vendor drops in between is lost.
          </>
        }
        confirmLabel="Delete"
        variant="danger"
        loading={remove.isPending}
        onConfirm={() => deleteTarget && remove.mutate(deleteTarget.id)}
      />
    </div>
  );
}

export default ConnectionsTab;
