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

import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowUpCircle, CloudDownload, KeyRound, Pause, Play, Plus, RefreshCw, RotateCcw, Trash2 } from 'lucide-react';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { api, ApiClientError } from '@/lib/api';
import { LOG_SOURCES_MISSING } from '@/components/connector-feeds/pull-links';
import type {
  ConnectorFeed,
  ConnectorSpecInfo,
  CreateConnectorFeedRequest,
} from '@/lib/api/connector-feeds';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { InfoTip } from '@/components/ui/info-tip';
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
import { Term } from '@/components/ui/term';
import {
  ConfigField,
  FieldLabel,
  feedConfig,
  useLaneSetup,
  credentialFieldInfo,
  defaultConfig,
  fieldLabel,
  setupSummary,
  useFeedSubmit,
} from '@/components/connector-feeds/ConnectorFields';
import { scheduleDefaultText } from '@/components/connector-feeds/schedule';

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

  // NAN-5903: resuming and adopting a spec update start the feed. The API
  // refuses a start whose lanes have no log source (LOG_SOURCES_MISSING);
  // Fix setup then repeats it with consent, through the same setup confirm
  // as New pull feed (one server path: the lane setup in the API).
  const laneSetup = useLaneSetup();
  const [fix, setFix] = useState<{ feed: ConnectorFeed; kind: 'resume' | 'adopt'; message: string } | null>(null);
  const refusedForMissingSources = (feed: ConnectorFeed, kind: 'resume' | 'adopt', e: unknown) => {
    if (e instanceof ApiClientError && e.code === LOG_SOURCES_MISSING) {
      setFix({ feed, kind, message: e.message });
      return true;
    }
    return false;
  };
  const toggle = useMutation({
    mutationFn: (feed: ConnectorFeed) => api.connectorFeeds.setEnabled(feed.id, !feed.enabled),
    onSuccess: (feed) => {
      invalidate();
      setFix(null);
      toast({ title: feed.enabled ? 'Feed resumed' : 'Feed paused', description: feed.name });
    },
    onError: (e, feed) => {
      if (!refusedForMissingSources(feed, 'resume', e)) {
        toast({ title: 'Could not change the feed', description: errorText(e), variant: 'destructive' });
      }
    },
  });
  const runFix = (target: { feed: ConnectorFeed; kind: 'resume' | 'adopt' }) =>
    void laneSetup.start({
      plan: () => api.connectorFeeds.plan(target.feed.connector, feedConfig(target.feed)),
      run: (setUp) =>
        target.kind === 'resume'
          ? api.connectorFeeds.setEnabled(target.feed.id, true, setUp).then(() => undefined)
          : api.connectorFeeds.adoptSpec(target.feed.id, setUp).then(() => undefined),
      onDone: (_r, plan) => {
        invalidate();
        setFix(null);
        toast({
          title: target.kind === 'resume' ? 'Feed resumed' : 'Spec update adopted',
          description: [target.feed.name, plan?.changes_log_sources ? setupSummary({ id: target.feed.id, credential_id: null, log_sources: plan.log_sources }) : undefined]
            .filter(Boolean)
            .join('. '),
        });
      },
      onError: (e) => toast({ title: 'Could not fix the setup', description: errorText(e), variant: 'destructive' }),
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
    onError: (e, feed) => {
      setAdoptTarget(null);
      if (!refusedForMissingSources(feed, 'adopt', e)) {
        toast({ title: 'Could not adopt the spec update', description: errorText(e), variant: 'destructive' });
      }
    },
  });

  // Deep links from other pages (NAN-5903): `?new=<connector>` opens New pull
  // feed with it preselected; `?fix=<feed id>` offers Fix setup for that feed.
  const [searchParams, setSearchParams] = useSearchParams();
  const [newConnector, setNewConnector] = useState<string | null>(null);
  useEffect(() => {
    const wanted = searchParams.get('new');
    const fixId = searchParams.get('fix');
    if (wanted && specs.length > 0 && canCreate) {
      setNewConnector(specs.some((s) => s.name === wanted) ? wanted : null);
      setCreateOpen(true);
    }
    const fixFeed = fixId ? feeds.find((f) => f.id === fixId) : undefined;
    if (fixFeed) {
      const kind = searchParams.get('action') === 'adopt' ? 'adopt' : 'resume';
      setFix({ feed: fixFeed, kind, message: 'Some log sources this feed needs are missing.' });
    }
    if ((wanted && specs.length > 0) || fixFeed) {
      const next = new URLSearchParams(searchParams);
      next.delete('new');
      if (fixFeed) {
        next.delete('fix');
        next.delete('action');
      }
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, setSearchParams, specs, feeds, canCreate]);

  const failing = feeds.filter((f) => f.enabled && f.last_status && f.last_status !== 'success').length;

  return (
    <LogSourcesPageShell active="pull-feeds" testId="pull-feeds-page">
      <LogSourcesPageHeader
        icon={CloudDownload}
        title={<Term id="pull-feed">Pull feeds</Term>}
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
          <InfoTip label="About pull feeds" side="bottom" contentClassName="max-w-[300px]">
            Each feed fetches one SaaS app&apos;s audit logs on a schedule. A new feed starts at current activity, and it
            only moves forward once nano has safely received the events.
          </InfoTip>
        </> : undefined}
      />

      <div className="px-5 py-4 space-y-4">
      {fix && (
        <div
          role="alert"
          data-testid="feed-fix-setup"
          className="flex items-center gap-3 rounded-md border border-red-600/40 px-3 py-2 text-[12px]"
        >
          <div className="min-w-0 flex-1">
            <div className="font-medium text-foreground">Some log sources this feed needs are missing</div>
            <div className="text-[11px] text-muted-foreground">
              <span className="font-mono">{fix.feed.name}</span>: {fix.message}
            </div>
          </div>
          {canEdit && canDeploy && (
            <Button size="sm" className="h-7 text-[11.5px]" disabled={laneSetup.isPending} onClick={() => runFix(fix)}>
              Fix setup
            </Button>
          )}
          <Button size="sm" variant="ghost" className="h-7 text-[11.5px]" onClick={() => setFix(null)}>
            Dismiss
          </Button>
        </div>
      )}
      {canViewFeeds && (
      <div className="rounded-md border border-border bg-card overflow-x-auto" data-testid="pull-feeds-region">

        {feedsQuery.isLoading ? (
          <div className="p-5 text-[12px] text-muted-foreground">Loading…</div>
        ) : feedsQuery.isError ? (
          <div className="p-5 text-[12px] text-red-600">{errorText(feedsQuery.error)}</div>
        ) : feeds.length === 0 ? (
          <div className="p-5 text-[12px] text-muted-foreground">
            No pull feeds yet. Create one with New pull feed; nano sets up the log sources it needs.
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
                          title="This version of nano has a newer recipe for this feed. Adopting it resets where the feed left off."
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
          description="Encrypted at rest and never returned by the API. Rotation keeps prior versions."
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
          initialConnector={newConnector}
          onClose={() => { setCreateOpen(false); setNewConnector(null); }}
          onCreated={() => {
            invalidate();
            // A feed created with a new secret adds a connector credential.
            void queryClient.invalidateQueries({ queryKey: ['credentials'] });
            setCreateOpen(false);
          }}
        />
      )}

      {laneSetup.confirm}

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
            Move <span className="text-foreground font-medium">{adoptTarget?.name}</span> to the <Term id="connector-spec">connector spec</Term> bundled
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
      description="Resumes five minutes before now; older history is never read. Time-window streams only."
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
  initialConnector,
  onClose,
  onCreated,
}: {
  specs: ConnectorSpecInfo[];
  /** Preselected by a deep link (`?new=<connector>`). */
  initialConnector?: string | null;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canCreateCredential = hasPermission('credentials:create');
  const first = specs.find((s) => s.name === initialConnector) ?? specs[0];
  const [connector, setConnector] = useState(first?.name ?? '');
  const spec = specs.find((s) => s.name === connector);
  const [name, setName] = useState('');
  const [config, setConfig] = useState<Record<string, string>>(() => defaultConfig(first));
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

  const create = useFeedSubmit({
    onCreated: (created) => {
      const setUp = setupSummary(created);
      toast({
        title: 'Pull feed created',
        description: [setUp, 'It starts with new activity on its next run.'].filter(Boolean).join(' '),
      });
      onCreated();
    },
    onError: (e) => toast({ title: 'Could not create the feed', description: errorText(e), variant: 'destructive' }),
  });

  // A list field (which apps to collect) needs at least one value ticked.
  const emptyList = !!spec?.config_field_info?.some(
    (f) => f.choices.length > 0 && !spec.optional_config_fields.includes(f.key) && !(config[f.key] ?? '').trim(),
  );

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
    create.submit(request);
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
                  ? 'Directory feeds copy users and group memberships into the user directory. They need no log source.'
                  : 'Collects the app\'s audit logs on a schedule. If the logs need a log source that is not set up yet, nano sets it up too, and asks you first.'}
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
                  setConfig(defaultConfig(specs.find((s) => s.name === v)));
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
                    <>Into the user directory</>
                  ) : (
                    <>Sends events as <span className="font-mono">{spec.source_type.replace('{{item}}', '<item>')}</span></>
                  )}
                  {spec.schedule && <> · {scheduleDefaultText(spec.schedule).toLowerCase()}</>}
                </p>
              )}
            </div>
            <div className="space-y-1.5">
              <Label className={FIELD_LABEL}>Name</Label>
              <Input className="h-8 text-[12px]" value={name} onChange={(e) => setName(e.target.value)} placeholder="Okta production" />
            </div>
            {spec && textConfigFields.map((f) => (
              <ConfigField
                key={f}
                spec={spec}
                fieldKey={f}
                id={`pull-feed-${spec.name}-${f}`}
                value={config[f] ?? ''}
                onChange={(v) => setConfig({ ...config, [f]: v })}
                labelClassName="text-[12px] font-medium"
              />
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
                      <FieldLabel
                        htmlFor={`pull-feed-${spec.name}-cred-${f}`}
                        info={credentialFieldInfo(spec, f)}
                        fieldKey={f}
                        className="text-[12px] font-medium"
                      />
                      <Input
                        id={`pull-feed-${spec.name}-cred-${f}`}
                        data-credential-key={f}
                        aria-label={fieldLabel(credentialFieldInfo(spec, f), f)}
                        type="password"
                        autoComplete="off"
                        className="h-8 text-[12px] font-mono"
                        value={secrets[f] ?? ''}
                        onChange={(e) => setSecrets({ ...secrets, [f]: e.target.value })}
                      />
                    </div>
                  ))}
                <p className={HELP_TEXT}>Stored encrypted under Connector credentials. Never shown again.</p>
              </div>
            )}
            {hasShrinkGuard && (
              <AllowShrinkField id="pull-feed-allow-shrink" checked={allowShrink} onCheckedChange={setAllowShrink} />
            )}
            <div className="space-y-1.5">
              <div className="flex items-center gap-1">
                <Label htmlFor="pull-feed-schedule" className="text-[12px] font-medium">
                  How often to run <span className="font-normal text-muted-foreground">(optional)</span>
                </Label>
                <InfoTip label="About the schedule" side="top" contentClassName="max-w-[280px]">
                  A cron expression, such as */15 * * * * for every 15 minutes. Leave it blank to use the default. It
                  cannot run more often than the default.
                </InfoTip>
              </div>
              <Input
                id="pull-feed-schedule"
                className="h-8 text-[12px] font-mono placeholder:font-sans placeholder:text-muted-foreground/70"
                value={schedule}
                onChange={(e) => setSchedule(e.target.value)}
                placeholder={scheduleDefaultText(spec?.schedule ?? null)}
              />
            </div>
          </div>
        </div>
        <SheetFooter className="border-t border-border px-5 py-3">
          {create.confirm}
          <Button variant="outline" size="sm" className="h-8 text-[11.5px]" onClick={onClose} disabled={create.isPending}>
            Cancel
          </Button>
          <Button
            size="sm"
            className="h-8 text-[11.5px] gap-1.5"
            onClick={submit}
            disabled={!spec || !name.trim() || create.isPending || emptyList}
          >
            <Plus className="w-[12px] h-[12px]" strokeWidth={1.5} />
            Create feed
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
