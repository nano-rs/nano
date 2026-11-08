// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Pull feeds (NAN-4914): bundled connector specs (Okta System Log, Google
 * Workspace, Slack, Netskope) run on a schedule by the nano-connector-runner
 * service. Events land in the local Vector through HEC and the cursor moves
 * only after Vector acknowledged them. New feeds start at current activity.
 *
 * NAN-4941: a Log Sources tab (/ingestion/log-sources/pull-feeds). The vendor
 * secret is entered with the feed, rotated from its row, and the connector
 * credentials are managed (masked, versions, rollback, delete) below the list.
 */

import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowUpCircle, CloudDownload, KeyRound, Pause, Play, Plus, RefreshCw, RotateCcw, Trash2 } from 'lucide-react';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type {
  ConnectorFeed,
  ConnectorSpecInfo,
  CreateConnectorFeedRequest,
} from '@/lib/api/connector-feeds';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { cn } from '@/lib/utils';
import type { CloudCredential } from '@/lib/api/types';
import { LogSourcesPageHeader, LogSourcesPageShell } from '@/components/add-data/LogSourcesPageShell';
import {
  CredentialInspectorSheet,
  CredentialsManager,
  useCredentialUsage,
} from '@/components/credentials/CredentialsManager';
import { CONNECTOR_CREDENTIAL_PROVIDERS } from '@/components/credentials/connector-credentials';
import {
  AllowShrinkField,
  hasAllowShrink,
  textConfigFields as textFieldsOf,
  withAllowShrink,
} from '@/components/connector-feeds/AllowShrinkField';

const FIELD_LABEL = 'text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground';
const HELP_TEXT = 'text-[10.5px] text-muted-foreground leading-relaxed';
const NEW_CREDENTIAL = '__new__';

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function relative(iso: string | null): string {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  const abs = Math.abs(diff);
  const unit = abs < 60_000 ? `${Math.round(abs / 1000)}s` : abs < 3_600_000 ? `${Math.round(abs / 60_000)}m` : abs < 86_400_000 ? `${Math.round(abs / 3_600_000)}h` : `${Math.round(abs / 86_400_000)}d`;
  return diff >= 0 ? `${unit} ago` : `in ${unit}`;
}

function StatusPill({ feed }: { feed: ConnectorFeed }) {
  const [label, cls] = !feed.enabled
    ? ['paused', 'text-muted-foreground border-border']
    : feed.running
      ? ['running', 'text-sky-600 border-sky-600/40']
      : feed.last_status === 'success'
        ? ['healthy', 'text-emerald-600 border-emerald-600/40']
        : feed.last_status
          ? [feed.last_status, 'text-red-600 border-red-600/40']
          : ['pending', 'text-muted-foreground border-border'];
  return (
    <span className={cn('inline-flex items-center rounded border px-1.5 py-px font-mono text-[10.5px] uppercase tracking-wider', cls)}>
      {label}
    </span>
  );
}

export function ConnectorFeeds() {
  useDocumentTitle('Pull feeds');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  // NAN-4941 review: the tab is reachable with log_sources:view OR credentials:view.
  // The feed list and its actions need log_sources:*; the connector credential
  // store below needs credentials:*, so a credentials-only role still rotates here.
  const canViewFeeds = hasPermission('log_sources:view');
  const canCreate = canViewFeeds && hasPermission('log_sources:create') && hasPermission('log_sources:deploy');
  const canEdit = hasPermission('log_sources:edit');
  const canDeploy = hasPermission('log_sources:deploy');
  const canDelete = hasPermission('log_sources:delete');

  const [createOpen, setCreateOpen] = useState(false);
  const [removeTarget, setRemoveTarget] = useState<ConnectorFeed | null>(null);
  const [adoptTarget, setAdoptTarget] = useState<ConnectorFeed | null>(null);
  const [resetTarget, setResetTarget] = useState<ConnectorFeed | null>(null);
  const [rotateTarget, setRotateTarget] = useState<CloudCredential | null>(null);
  const canViewCredentials = hasPermission('credentials:view');
  const canRotate = hasPermission('credentials:rotate');
  const credentialsList = useQuery({
    queryKey: ['credentials'],
    queryFn: () => api.listCredentials().then((r) => r.credentials),
    enabled: canViewCredentials,
  });
  const credentialById = useMemo(
    () => new Map((credentialsList.data ?? []).map((c) => [c.id, c])),
    [credentialsList.data],
  );
  const credentialUsage = useCredentialUsage();

  const feedsQuery = useQuery({
    queryKey: ['connectorFeeds'],
    queryFn: () => api.connectorFeeds.list(),
    refetchInterval: 15_000,
    enabled: canViewFeeds,
  });
  const specsQuery = useQuery({
    queryKey: ['connectorSpecs'],
    queryFn: () => api.connectorFeeds.listSpecs(),
    enabled: canViewFeeds,
  });
  const feeds = feedsQuery.data ?? [];
  const specs = specsQuery.data ?? [];
  const specByName = useMemo(() => new Map(specs.map((s) => [s.name, s])), [specs]);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['connectorFeeds'] });

  const toggle = useMutation({
    mutationFn: (feed: ConnectorFeed) => api.connectorFeeds.setEnabled(feed.id, !feed.enabled),
    onSuccess: (feed) => {
      invalidate();
      toast({ title: feed.enabled ? 'Feed resumed' : 'Feed paused', description: feed.name });
    },
    onError: (e) => toast({ title: 'Could not change the feed', description: errorText(e), variant: 'destructive' }),
  });
  const remove = useMutation({
    mutationFn: (feed: ConnectorFeed) => api.connectorFeeds.remove(feed.id),
    onSuccess: () => {
      invalidate();
      setRemoveTarget(null);
      toast({ title: 'Feed removed' });
    },
    onError: (e) => toast({ title: 'Could not remove the feed', description: errorText(e), variant: 'destructive' }),
  });
  const reset = useMutation({
    mutationFn: ({ feed, stream }: { feed: ConnectorFeed; stream: string }) => api.connectorFeeds.resetStream(feed.id, stream),
    onSuccess: (r) => {
      invalidate();
      setResetTarget(null);
      toast({ title: 'Stream re-anchored', description: `${r.stream} resumes at ${new Date(r.anchor).toLocaleString()}` });
    },
    onError: (e) => toast({ title: 'Could not reset the stream', description: errorText(e), variant: 'destructive' }),
  });

  const adopt = useMutation({
    mutationFn: (feed: ConnectorFeed) => api.connectorFeeds.adoptSpec(feed.id),
    onSuccess: (r) => {
      invalidate();
      setAdoptTarget(null);
      toast({ title: r.adopted ? 'Spec update adopted' : 'Already on the current spec', description: r.adopted ? `${r.checkpoints_reset} stream cursor(s) reset` : undefined });
    },
    onError: (e) => toast({ title: 'Could not adopt the spec update', description: errorText(e), variant: 'destructive' }),
  });

  const failing = feeds.filter((f) => f.enabled && f.last_status && f.last_status !== 'success').length;

  return (
    <LogSourcesPageShell active="pull-feeds" testId="pull-feeds-page">
      <LogSourcesPageHeader
        icon={CloudDownload}
        title="Pull feeds"
        actions={canViewFeeds ? <>
          <Button size="sm" variant="outline" className="h-7 gap-1.5 text-[11.5px]" onClick={() => feedsQuery.refetch()}>
            <RefreshCw className="h-3 w-3" strokeWidth={1.5} /> Refresh
          </Button>
          {canCreate && (
            <Button size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={() => setCreateOpen(true)} disabled={specs.length === 0}>
              <Plus className="h-3 w-3" strokeWidth={1.5} /> New pull feed
            </Button>
          )}
        </> : undefined}
        meta={canViewFeeds ? <>
          <span>{feeds.length} feeds</span>
          <span className={cn(failing > 0 && 'text-red-600')}>{failing} failing</span>
        </> : undefined}
      />

      <div className="px-5 py-4 space-y-4">
      <div className="text-[11.5px] text-muted-foreground leading-relaxed max-w-[740px]">
        SaaS audit logs pulled on a schedule by the connector runner and delivered through HEC. A new
        feed starts at current activity; its cursor moves only after Vector acknowledged the events.
      </div>
      {canViewFeeds && (
      <div className="rounded-md border border-border bg-card overflow-x-auto" data-testid="pull-feeds-region">

        {feedsQuery.isLoading ? (
          <div className="p-5 text-[12px] text-muted-foreground">Loading…</div>
        ) : feedsQuery.isError ? (
          <div className="p-5 text-[12px] text-red-600">{errorText(feedsQuery.error)}</div>
        ) : feeds.length === 0 ? (
          <div className="p-5 text-[12px] text-muted-foreground">
            No pull feeds yet. Deploy the HEC log source for the vendor first, then add a feed.
          </div>
        ) : (
          <table className="w-full text-[12px]">
            <thead className="sticky top-0 bg-card">
              <tr className="border-b border-border text-left">
                {['Name', 'Connector', 'Lane', 'Status', 'Credential', 'Schedule', 'Last success', 'Next run', ''].map((h) => (
                  <th key={h} className={cn(FIELD_LABEL, 'px-3 py-1.5 font-normal')}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {feeds.map((feed) => (
                <tr key={feed.id} className="h-7 border-b border-border align-middle hover:bg-muted/30">
                  <td className="px-3">
                    <div className="text-foreground">
                      {feed.name}
                      {feed.spec_update_available && (
                        <span
                          className="ml-2 rounded-sm border border-amber-500/40 px-1 font-mono text-[10px] text-amber-600 dark:text-amber-400"
                          data-testid="feed-spec-update"
                          title="This build bundles a newer connector spec. Adopting it resets the feed's cursors."
                        >
                          update available
                        </span>
                      )}
                    </div>
                    {feed.last_error && feed.enabled && (
                      <div className="font-mono text-[10.5px] text-red-600 truncate max-w-[420px]" title={feed.last_error}>
                        {feed.last_error}
                      </div>
                    )}
                  </td>
                  <td className="px-3 font-mono text-[11px]">{specByName.get(feed.connector)?.display_name ?? feed.connector}</td>
                  <td className="px-3 font-mono text-[11px]">{feed.source_type}</td>
                  <td className="px-3"><StatusPill feed={feed} /></td>
                  <td className="px-3 font-mono text-[11px]">
                    {feed.credential_id ? (
                      <span className="inline-flex items-center gap-1.5">
                        <KeyRound className="h-3 w-3 text-muted-foreground" strokeWidth={1.5} />
                        <span className="truncate max-w-[160px]" title={feed.credential_id}>
                          {credentialById.get(feed.credential_id)?.name ?? feed.credential_id}
                        </span>
                        <span className="text-muted-foreground" aria-label="Secret hidden">••••</span>
                        {canRotate && credentialById.get(feed.credential_id) && (
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-5 px-1.5 text-[10.5px]"
                            onClick={() => setRotateTarget(credentialById.get(feed.credential_id!) ?? null)}
                          >
                            Rotate
                          </Button>
                        )}
                      </span>
                    ) : '—'}
                  </td>
                  <td className="px-3 font-mono text-[11px]">{feed.effective_schedule}</td>
                  <td className="px-3 font-mono text-[11px]">{relative(feed.last_success_at)}</td>
                  <td className="px-3 font-mono text-[11px]">{feed.enabled ? relative(feed.next_run_at) : '—'}</td>
                  <td className="px-3 text-right whitespace-nowrap">
                    {canEdit && (!feed.enabled ? canDeploy : true) && (
                      <Button size="sm" variant="ghost" className="h-6 px-2 text-[11px]" onClick={() => toggle.mutate(feed)} disabled={toggle.isPending}>
                        {feed.enabled ? <><Pause className="h-3 w-3 mr-1" />Pause</> : <><Play className="h-3 w-3 mr-1" />Resume</>}
                      </Button>
                    )}
                    {canEdit && canDeploy && feed.spec_update_available && (
                      <Button size="sm" variant="ghost" className="h-6 px-2 text-[11px]" onClick={() => setAdoptTarget(feed)}>
                        <ArrowUpCircle className="h-3 w-3 mr-1" />Adopt update
                      </Button>
                    )}
                    {canEdit && (
                      <Button size="sm" variant="ghost" className="h-6 px-2 text-[11px]" onClick={() => setResetTarget(feed)}>
                        <RotateCcw className="h-3 w-3 mr-1" />Reset
                      </Button>
                    )}
                    {canDelete && (
                      <Button size="sm" variant="ghost" className="h-6 px-2 text-[11px] text-red-600" onClick={() => setRemoveTarget(feed)}>
                        <Trash2 className="h-3 w-3 mr-1" />Remove
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      )}

      {canViewCredentials && (
        <CredentialsManager
          providers={CONNECTOR_CREDENTIAL_PROVIDERS}
          title="Connector credentials"
          description="Vendor secrets for pull feeds. Entered with the feed, encrypted at rest and never returned by the API. Rotate to replace one; prior versions stay for rollback."
        />
      )}
      </div>

      <CredentialInspectorSheet
        cred={rotateTarget}
        usage={rotateTarget ? credentialUsage.get(rotateTarget.id) ?? [] : []}
        rotateOnOpen
        onClose={() => setRotateTarget(null)}
      />

      {createOpen && (
        <CreateFeedSheet
          specs={specs}
          onClose={() => setCreateOpen(false)}
          onCreated={() => {
            invalidate();
            // A feed created with a new secret adds a connector credential.
            void queryClient.invalidateQueries({ queryKey: ['credentials'] });
            setCreateOpen(false);
          }}
        />
      )}

      <ConfirmDialog
        open={removeTarget !== null}
        onOpenChange={(open) => !open && setRemoveTarget(null)}
        title="Remove pull feed"
        description={
          <>
            Remove <span className="text-foreground font-medium">{removeTarget?.name}</span> with its cursors and run
            history. The bound credential stays under Connector credentials.
          </>
        }
        confirmLabel="Remove"
        variant="danger"
        loading={remove.isPending}
        onConfirm={() => removeTarget && remove.mutate(removeTarget)}
      />

      <ConfirmDialog
        open={!!adoptTarget}
        onOpenChange={(open) => !open && setAdoptTarget(null)}
        title="Adopt connector spec update"
        description={
          <>
            Move <span className="text-foreground font-medium">{adoptTarget?.name}</span> to the connector spec bundled
            with this build. Its stream cursors are reset, so the next run starts fresh (an identity feed runs a full,
            shrink-guarded directory sync).
          </>
        }
        confirmLabel="Adopt"
        loading={adopt.isPending}
        onConfirm={() => adoptTarget && adopt.mutate(adoptTarget)}
      />

      {resetTarget && (
        <ResetDialog
          feed={resetTarget}
          loading={reset.isPending}
          onClose={() => setResetTarget(null)}
          onReset={(stream) => reset.mutate({ feed: resetTarget, stream })}
        />
      )}
    </LogSourcesPageShell>
  );
}

function ResetDialog({
  feed,
  loading,
  onClose,
  onReset,
}: {
  feed: ConnectorFeed;
  loading: boolean;
  onClose: () => void;
  onReset: (stream: string) => void;
}) {
  const detail = useQuery({ queryKey: ['connectorFeed', feed.id], queryFn: () => api.connectorFeeds.get(feed.id) });
  const streams = detail.data?.checkpoints ?? [];
  const [stream, setStream] = useState('');
  return (
    <ConfirmDialog
      open
      onOpenChange={(open) => !open && onClose()}
      title="Re-anchor a stream"
      description="The stream resumes five minutes before now. A reset never reads older history. Only time-window streams can be reset."
      confirmLabel="Reset"
      variant="warning"
      loading={loading}
      confirmDisabled={!stream}
      onConfirm={() => onReset(stream)}
    >
      <div className="space-y-1.5">
        <Label className={FIELD_LABEL}>Stream</Label>
        <Select value={stream} onValueChange={setStream}>
          <SelectTrigger className="h-8 text-[12px] font-mono"><SelectValue placeholder={streams.length ? 'Pick a stream' : 'No checkpoints yet'} /></SelectTrigger>
          <SelectContent>
            {streams.map((s) => (
              <SelectItem key={s.stream_id} value={s.stream_id} className="text-[12px] font-mono">
                {s.stream_id} · {s.kind} · {s.commits} commits
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </ConfirmDialog>
  );
}

function CreateFeedSheet({
  specs,
  onClose,
  onCreated,
}: {
  specs: ConnectorSpecInfo[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canCreateCredential = hasPermission('credentials:create');
  const [connector, setConnector] = useState(specs[0]?.name ?? '');
  const spec = specs.find((s) => s.name === connector);
  const [name, setName] = useState('');
  const [config, setConfig] = useState<Record<string, string>>({});
  const [credentialChoice, setCredentialChoice] = useState<string>(NEW_CREDENTIAL);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [schedule, setSchedule] = useState('');
  const [allowShrink, setAllowShrink] = useState(false);
  const textConfigFields = textFieldsOf(spec?.config_fields ?? []);
  const hasShrinkGuard = hasAllowShrink(spec?.config_fields ?? []);

  const credentialsQuery = useQuery({
    queryKey: ['credentials'],
    queryFn: () => api.listCredentials().then((r) => r.credentials),
    enabled: hasPermission('credentials:view'),
  });
  const matching = (credentialsQuery.data ?? []).filter((c) => c.provider === spec?.credential_provider);
  // Without credentials:create the only option is an existing credential.
  const effectiveChoice =
    credentialChoice === NEW_CREDENTIAL && !canCreateCredential ? (matching[0]?.id ?? '') : credentialChoice;

  const create = useMutation({
    mutationFn: (request: CreateConnectorFeedRequest) => api.connectorFeeds.create(request),
    onSuccess: () => {
      toast({ title: 'Pull feed created', description: 'It starts at current activity on its next tick.' });
      onCreated();
    },
    onError: (e) => toast({ title: 'Could not create the feed', description: errorText(e), variant: 'destructive' }),
  });

  const submit = () => {
    if (!spec) return;
    let cfg: CreateConnectorFeedRequest['config'] = {};
    for (const f of textConfigFields) {
      const v = (config[f] ?? '').trim();
      if (v || !spec.optional_config_fields.includes(f)) cfg[f] = v;
    }
    cfg = withAllowShrink(cfg, spec.config_fields, allowShrink);
    const request: CreateConnectorFeedRequest = { name: name.trim(), connector: spec.name, config: cfg };
    if (spec.credential_fields.length > 0) {
      if (effectiveChoice === NEW_CREDENTIAL) request.credentials = secrets;
      else if (effectiveChoice) request.credential_id = effectiveChoice;
    }
    if (schedule.trim()) request.schedule = schedule.trim();
    create.mutate(request);
  };

  return (
    <Sheet open onOpenChange={(open) => !open && onClose()}>
      <SheetContent
        side="right"
        data-testid="new-pull-feed-sheet"
        className="w-[520px] sm:max-w-[520px] gap-0 p-0 bg-card border-l border-border text-foreground flex flex-col"
      >
        <SheetHeader className="border-b border-border px-5 py-4 space-y-1 text-left">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-md border border-border bg-foreground/[0.03] flex items-center justify-center">
              <CloudDownload className="w-[14px] h-[14px] text-muted-foreground" strokeWidth={1.5} />
            </div>
            <div className="flex-1 min-w-0">
              <SheetTitle className="text-[14px] font-semibold leading-tight">New pull feed</SheetTitle>
              <SheetDescription className="text-[11.5px] leading-relaxed text-muted-foreground">
                {spec?.kind === 'identity'
                  ? 'Directory feeds sync users and group memberships into the user directory; no log source is needed.'
                  : 'The vendor lane needs a deployed HEC log source first; the feed is refused otherwise.'}
              </SheetDescription>
            </div>
          </div>
        </SheetHeader>
        <div className="flex-1 min-h-0 overflow-y-auto px-5 py-4">
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label className={FIELD_LABEL}>Connector</Label>
              <Select
                value={connector}
                onValueChange={(v) => {
                  setConnector(v);
                  setConfig({});
                  setSecrets({});
                  setCredentialChoice(NEW_CREDENTIAL);
                  setAllowShrink(false);
                }}
              >
                <SelectTrigger className="h-8 text-[12px]"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {specs.map((s) => (
                    <SelectItem key={s.name} value={s.name} className="text-[12px]">{s.display_name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {spec && (
                <p className={HELP_TEXT}>
                  {spec.kind === 'identity' ? (
                    <>Into <span className="font-mono">user_registry</span></>
                  ) : (
                    <>Lane <span className="font-mono">{spec.source_type}</span></>
                  )}
                  {spec.schedule && <> · runs at most <span className="font-mono">{spec.schedule}</span></>}
                </p>
              )}
            </div>
            <div className="space-y-1.5">
              <Label className={FIELD_LABEL}>Name</Label>
              <Input className="h-8 text-[12px]" value={name} onChange={(e) => setName(e.target.value)} placeholder="Okta production" />
            </div>
            {spec && textConfigFields.map((f) => (
              <div key={f} className="space-y-1.5">
                <Label className={FIELD_LABEL}>
                  {f}
                  {spec.optional_config_fields.includes(f) && <span className="normal-case tracking-normal"> (optional)</span>}
                </Label>
                <Input
                  className="h-8 text-[12px] font-mono"
                  value={config[f] ?? ''}
                  onChange={(e) => setConfig({ ...config, [f]: e.target.value })}
                />
              </div>
            ))}
            {spec && spec.credential_fields.length > 0 && (
              <div className="space-y-2 border-l border-border pl-3">
                <div className="space-y-1.5">
                  <Label className={FIELD_LABEL}>Credential ({spec.credential_provider})</Label>
                  <Select value={effectiveChoice} onValueChange={setCredentialChoice}>
                    <SelectTrigger className="h-8 text-[12px]"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {canCreateCredential && <SelectItem value={NEW_CREDENTIAL} className="text-[12px]">Enter a new credential</SelectItem>}
                      {matching.map((c) => (
                        <SelectItem key={c.id} value={c.id} className="text-[12px]">
                          {c.name} <span className="font-mono text-muted-foreground">v{c.active_version}</span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                {effectiveChoice === NEW_CREDENTIAL && spec.credential_provider === 'google_workspace' && (
                  <div className="space-y-1.5">
                    <Label className={FIELD_LABEL}>Service account key (JSON)</Label>
                    <Textarea
                      className="min-h-[96px] text-[11px] font-mono"
                      value={secrets.credentials_json ?? ''}
                      onChange={(e) => setSecrets({ credentials_json: e.target.value })}
                      placeholder='{"type": "service_account", "client_email": "...", "private_key": "..."}'
                    />
                    <p className={HELP_TEXT}>
                      The key of a service account with domain-wide delegation for the reports audit scope. Only its
                      client email and private key are stored.
                    </p>
                  </div>
                )}
                {effectiveChoice === NEW_CREDENTIAL && spec.credential_provider !== 'google_workspace' &&
                  spec.credential_fields.map((f) => (
                    <div key={f} className="space-y-1.5">
                      <Label className={FIELD_LABEL}>{f}</Label>
                      <Input
                        type="password"
                        autoComplete="off"
                        className="h-8 text-[12px] font-mono"
                        value={secrets[f] ?? ''}
                        onChange={(e) => setSecrets({ ...secrets, [f]: e.target.value })}
                      />
                    </div>
                  ))}
                <p className={HELP_TEXT}>Stored encrypted under Connector credentials, with versions and rotation. Never shown again.</p>
              </div>
            )}
            {hasShrinkGuard && (
              <AllowShrinkField id="pull-feed-allow-shrink" checked={allowShrink} onCheckedChange={setAllowShrink} />
            )}
            <div className="space-y-1.5">
              <Label className={FIELD_LABEL}>Schedule override (cron, optional)</Label>
              <Input className="h-8 text-[12px] font-mono" value={schedule} onChange={(e) => setSchedule(e.target.value)} placeholder={spec?.schedule ?? '*/5 * * * *'} />
            </div>
          </div>
        </div>
        <SheetFooter className="border-t border-border px-5 py-3">
          <Button variant="outline" size="sm" className="h-8 text-[11.5px]" onClick={onClose} disabled={create.isPending}>
            Cancel
          </Button>
          <Button
            size="sm"
            className="h-8 text-[11.5px] gap-1.5"
            onClick={submit}
            disabled={!spec || !name.trim() || create.isPending}
          >
            <Plus className="w-[12px] h-[12px]" strokeWidth={1.5} />
            Create feed
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
