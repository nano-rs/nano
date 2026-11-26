// SPDX-License-Identifier: AGPL-3.0-or-later
// Pull collectors as ordinary Marketplace cards (main NAN-3590), re-backed on
// connector pull feeds (NAN-4914) for NAN-4946. State comes from
// `useConnectorCollectors`.
//
// NAN-5903: Pull feeds is the ONE place a feed is set up (its form owns the
// plain-English fields and the log source setup confirm). The card shows a
// collector's feeds and health, enables, disables and rotates them, and hops
// to Pull feeds to set one up (`Set up in Pull`) or to fix one whose log
// sources are missing (`Fix setup`).
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api, ApiClientError } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { DetailSheet } from '@/components/ui/detail-sheet';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import type { ConnectorFeed } from '@/lib/api/connector-feeds';
import type { RotateCredentialRequest } from '@/lib/api/types';
import { connectorSecretFields, connectorSecretsPayload, connectorSecretsValid } from '@/components/credentials/connector-credentials';
import { collectorDeliveryLabel, feedRunStatusLabel, humanizeEnum } from '@/lib/marketplace-labels';
import { formatUTCCompact } from '@/lib/date-utils';
import { CatalogCard, MetaBadge } from './InventoryCard';
import { CONNECTOR_FEEDS_KEY, collectorState, isDirectoryCollector, type CollectorPermissions, type CollectorRow } from './useConnectorCollectors';
import { Term } from '@/components/ui/term';
import { LOG_SOURCES_MISSING, PULL_FEEDS_PATH, pullFixSetupPath, pullNewFeedPath, type FixSetupKind } from '@/components/connector-feeds/pull-links';

const sectionLabel = 'font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground';
const labelCls = 'text-[12px] font-medium';
const inputCls = 'h-8 font-mono text-[12px]';
const helpCls = 'text-[11px] leading-[1.45] text-muted-foreground';
const textAction = 'text-primary underline-offset-2 hover:underline focus-visible:underline focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring rounded-sm disabled:pointer-events-none disabled:opacity-50';
// Multi-line secrets keep newlines (PEM), so they can't use <input type=password>.
const textSecurity = typeof CSS !== 'undefined' && typeof CSS.supports === 'function' && CSS.supports('-webkit-text-security', 'disc');
const maskedText = textSecurity ? '[-webkit-text-security:disc]' : 'text-transparent caret-foreground selection:bg-transparent';

function relative(iso: string | null): string {
  return iso ? formatUTCCompact(iso) : '—';
}

function FeedRow({ feed, onAdopt }: { feed: ConnectorFeed; onAdopt?: () => void }) {
  return <div className="border-b border-border/60 px-3 py-1.5 last:border-b-0 font-mono text-[10.5px]" data-testid={`collector-feed-${feed.id}`}>
    <div className="flex items-center justify-between gap-3">
      <span className="truncate text-[11px] text-foreground">{feed.name}</span>
      <span className="flex items-center gap-2 text-muted-foreground">
        {feed.spec_update_available && <span className="text-foreground" data-testid="collector-spec-update">update available</span>}
        {feed.spec_update_available && onAdopt && <button type="button" className={`font-sans text-[11px] ${textAction}`}
          aria-label={`Adopt spec update for ${feed.name}`} onClick={onAdopt}>Adopt update</button>}
        {!feed.enabled ? 'disabled' : feed.running ? 'running' : feedRunStatusLabel(feed.last_status)}
      </span>
    </div>
    <div className="mt-0.5 grid grid-cols-2 gap-x-3 text-muted-foreground tabular-nums">
      <span>lane {feed.source_type} · {feed.effective_schedule}</span>
      <span className="text-right">next {feed.enabled ? relative(feed.next_run_at) : '—'}</span>
      <span>last success {relative(feed.last_success_at)}</span>
      <span className="text-right">{feed.consecutive_failures > 0 ? `${feed.consecutive_failures} failed runs` : ''}</span>
    </div>
    {feed.last_error && <p className="mt-0.5 text-[11px] font-sans text-destructive">{feed.last_error}</p>}
  </div>;
}

export function CollectorCard({ spec, feeds, feedStatus, permissions }: CollectorRow & {
  feedStatus: { isError: boolean; isPending: boolean };
  permissions: CollectorPermissions;
}) {
  const { toggle: canToggle, remove: canRemove, rotate: canRotate } = permissions;
  const client = useQueryClient();
  const navigate = useNavigate();
  const [manage, setManage] = useState(false);
  const [remove, setRemove] = useState(false);
  const needsCredential = spec.credential_fields.length > 0;
  const canOpenInstall = permissions.installExisting || permissions.installNew;
  const refresh = () => client.invalidateQueries({ queryKey: CONNECTOR_FEEDS_KEY });
  // A start refused because a lane's log source is missing names the feed,
  // so the error can offer Fix setup on Pull feeds.
  const [failure, setFailure] = useState<{ message: string; fix?: { feedId: string; kind: FixSetupKind } } | null>(null);
  const failed = (feed: ConnectorFeed, kind: FixSetupKind) => (e: unknown) => {
    const missing = e instanceof ApiClientError && e.code === LOG_SOURCES_MISSING;
    setFailure({ message: e instanceof Error ? e.message : String(e), fix: missing ? { feedId: feed.id, kind } : undefined });
  };
  const toggle = useMutation({
    mutationFn: async (enable: boolean) => {
      setFailure(null);
      for (const feed of feeds) {
        if (feed.enabled === enable) continue;
        try { await api.connectorFeeds.setEnabled(feed.id, enable); } catch (e) { failed(feed, 'resume')(e); return; }
      }
    },
    onSettled: refresh,
  });
  // NAN-4931: this build bundles a newer connector spec; adopting it resets the feed's cursors.
  const [adoptTarget, setAdoptTarget] = useState<ConnectorFeed | null>(null);
  const adopt = useMutation({
    mutationFn: async (feed: ConnectorFeed) => {
      setFailure(null);
      try { await api.connectorFeeds.adoptSpec(feed.id); } catch (e) { failed(feed, 'adopt')(e); }
    },
    onSuccess: () => setAdoptTarget(null),
    onSettled: refresh,
  });
  const updateAvailable = feeds.some(feed => feed.spec_update_available);
  const uninstall = useMutation({
    mutationFn: async () => { for (const feed of feeds) await api.connectorFeeds.remove(feed.id); },
    onSuccess: () => { setRemove(false); setManage(false); },
    onSettled: refresh,
  });

  // Rotate the vendor credential the installed feeds are bound to (one
  // credential may back several feeds; each is rotated once).
  const boundCredentials = [...new Set(feeds.map(f => f.credential_id).filter((id): id is string => !!id))];
  const rotationFields = connectorSecretFields(spec.credential_provider, [spec]);
  const [rotating, setRotating] = useState(false);
  const [rotationSecrets, setRotationSecrets] = useState<Record<string, string>>({});
  const rotation = useMutation({
    mutationFn: async () => {
      const request = { credentials: connectorSecretsPayload(rotationFields, rotationSecrets) } as unknown as RotateCredentialRequest;
      for (const id of boundCredentials) await api.rotateCredential(id, request);
    },
    onSuccess: () => { setRotating(false); setRotationSecrets({}); void refresh(); },
    onError: () => { setRotationSecrets({}); },
  });
  const changeRotating = (value: boolean) => {
    if (rotation.isPending) return;
    setRotating(value); setRotationSecrets({}); rotation.reset();
  };

  const { installed, enabled, health } = collectorState(feeds, feedStatus);
  const installBlocked = !canOpenInstall || feedStatus.isError;
  const actionError = failure?.message ?? uninstall.error?.message;
  const kind = isDirectoryCollector(spec) ? 'directory' : 'pull';
  return <>
    <CatalogCard id={`collector:${spec.name}`} name={spec.display_name}
      meta={<><MetaBadge>{kind}</MetaBadge> · {health}{updateAvailable && <> · <span className="text-foreground">update available</span></>}</>}
      body={feedStatus.isError ? <span role="alert" className="text-destructive">Could not load feed status</span>
        : isDirectoryCollector(spec) ? `Syncs users and groups from ${spec.display_name} into the identity directory on a schedule.`
        : `Pulls ${spec.display_name} audit events on a schedule into the ${spec.source_type} lane. A new feed starts at current activity.`}
      footerLabel={collectorDeliveryLabel({ slug: spec.name, name: spec.display_name })}
      footerAction={<span className={installed || !installBlocked ? 'text-primary' : 'text-muted-foreground'}>{installed ? `Installed · ${enabled ? 'On' : 'Off'}` : 'Set up in Pull'}</span>}
      footerActionDisabled={!installed && installBlocked}
      disabled={!installed && installBlocked}
      onOpen={() => installed ? setManage(true) : navigate(pullNewFeedPath(spec.name))} />
    <DetailSheet open={manage && installed} onOpenChange={setManage} size="md" breadcrumb={['Marketplace', 'Pull collectors']}
      title={spec.display_name} description={`Connector ${spec.name} · lane ${spec.source_type}`} meta={<span className="font-mono">{spec.name} · {health}</span>}
      footer={<>
        {canRemove && <Button size="sm" variant="outline" className="h-7 text-[11.5px] mr-auto" disabled={uninstall.isPending || toggle.isPending} onClick={() => setRemove(true)}>Uninstall</Button>}
        {canRotate && needsCredential && boundCredentials.length > 0 && <Button size="sm" variant="outline" className="h-7 text-[11.5px]" disabled={toggle.isPending || uninstall.isPending} onClick={() => changeRotating(true)}>Rotate credential</Button>}
        {canOpenInstall && <Button asChild size="sm" variant="outline" className="h-7 text-[11.5px]"><Link to={pullNewFeedPath(spec.name)}>Set up in Pull</Link></Button>}
        {canToggle && <Button size="sm" variant="outline" className="h-7 text-[11.5px]" disabled={toggle.isPending || uninstall.isPending} onClick={() => toggle.mutate(!enabled)}>{enabled ? 'Disable' : 'Enable'}</Button>}
      </>}>
      <div className="space-y-2">
        <div className={sectionLabel}>Feeds · {feeds.length}</div>
        <div className="rounded border border-border">{feeds.map(feed => <FeedRow key={feed.id} feed={feed}
          onAdopt={canToggle && !adopt.isPending ? () => setAdoptTarget(feed) : undefined} />)}</div>
        <p className="font-mono text-[10.5px] text-muted-foreground">{collectorDeliveryLabel({ slug: spec.name, name: spec.display_name })} → <Term id="hec">HEC</Term> → <Term id="vector">Vector</Term></p>
        <p className={helpCls}>Stream resets and run history live on <Link to={PULL_FEEDS_PATH} className={textAction}><Term nested id="pull-feed">Pull feeds</Term></Link>.</p>
        {(feedStatus.isError || actionError) && <p role="alert" className="text-[11px] text-destructive">{actionError ?? 'Could not load feed status'}</p>}
        {failure?.fix && <Button asChild size="sm" variant="outline" className="h-7 text-[11.5px]"><Link to={pullFixSetupPath(failure.fix.feedId, failure.fix.kind)}>Fix setup</Link></Button>}
      </div>
    </DetailSheet>
    <Dialog open={rotating && installed} onOpenChange={changeRotating}>
      <DialogContent className="max-w-sm p-4 shadow-none">
        <DialogHeader>
          <DialogTitle>Rotate credential · {spec.display_name}</DialogTitle>
          <span className="font-mono text-[10.5px] text-muted-foreground">{spec.credential_provider} · {boundCredentials.length} bound</span>
          <DialogDescription>Feeds keep their checkpoints and use the new secret on their next run.</DialogDescription>
        </DialogHeader>
        <form onSubmit={event => { event.preventDefault(); if (canRotate && connectorSecretsValid(rotationFields, rotationSecrets) && !rotation.isPending) rotation.mutate(); }}>
          <div className="space-y-3">
            {rotationFields.map(key => <div key={key} className="space-y-1">
              <Label htmlFor={`rotate-${spec.name}-${key}`} className={labelCls}>{key === 'credentials_json' ? 'Service account key JSON' : humanizeEnum(key.toLowerCase())}</Label>
              {key === 'credentials_json' || /PRIVATE_KEY/.test(key)
                ? <Textarea id={`rotate-${spec.name}-${key}`} rows={4} spellCheck={false} autoComplete="off" className={`min-h-0 font-mono text-[11px] ${maskedText}`}
                    value={rotationSecrets[key] ?? ''} disabled={rotation.isPending} required
                    onChange={event => setRotationSecrets(current => ({ ...current, [key]: event.target.value }))} />
                : <Input id={`rotate-${spec.name}-${key}`} type="password" autoComplete="new-password" spellCheck={false} className={inputCls}
                    value={rotationSecrets[key] ?? ''} disabled={rotation.isPending} required
                    onChange={event => setRotationSecrets(current => ({ ...current, [key]: event.target.value }))} />}
            </div>)}
            {rotation.isError && <p role="alert" className="text-[11px] text-destructive">Could not rotate the credential. Check provider access and enter it again to retry.</p>}
          </div>
          <DialogFooter className="mt-4">
            <Button type="button" variant="outline" size="sm" disabled={rotation.isPending} onClick={() => changeRotating(false)}>Cancel</Button>
            <Button type="submit" size="sm" disabled={!canRotate || !connectorSecretsValid(rotationFields, rotationSecrets) || rotation.isPending}>{rotation.isPending ? 'Rotating…' : 'Save credential'}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
    <ConfirmDialog open={!!adoptTarget} onOpenChange={open => { if (!open && !adopt.isPending) setAdoptTarget(null); }}
      title="Adopt connector spec update"
      description={<>Move <span className="text-foreground font-medium">{adoptTarget?.name}</span> to the <Term id="connector-spec">connector spec</Term> bundled with this build.
        Its stream cursors are reset, so the next run starts fresh (an identity feed runs a full, shrink-guarded directory sync).</>}
      confirmLabel="Adopt" loading={adopt.isPending} onConfirm={() => { if (adoptTarget) adopt.mutate(adoptTarget); }} />
    <ConfirmDialog open={remove} onOpenChange={setRemove} title={`Uninstall ${spec.display_name}?`}
      description="Stops collection and removes this connector's feeds with their cursors and run history. Bound credentials stay in Credentials."
      variant="danger" confirmLabel="Uninstall" onConfirm={() => uninstall.mutate()} loading={uninstall.isPending} />
  </>;
}
