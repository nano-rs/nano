// SPDX-License-Identifier: AGPL-3.0-or-later
// Pull collectors as ordinary Marketplace cards (main NAN-3590), re-backed on
// connector pull feeds (NAN-4914) for NAN-4946. Each card owns its install /
// manage sheets and mutations; state comes from `useConnectorCollectors`.
import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { DetailSheet, FormSheet } from '@/components/ui/detail-sheet';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import type { ConnectorFeed, CreateConnectorFeedRequest } from '@/lib/api/connector-feeds';
import type { RotateCredentialRequest } from '@/lib/api/types';
import { connectorSecretFields, connectorSecretsPayload, connectorSecretsValid } from '@/components/credentials/connector-credentials';
import { collectorDeliveryLabel, feedRunStatusLabel, humanizeEnum } from '@/lib/marketplace-labels';
import { formatUTCCompact } from '@/lib/date-utils';
import { AllowShrinkField, hasAllowShrink, textConfigFields, withAllowShrink } from '@/components/connector-feeds/AllowShrinkField';
import { CatalogCard, MetaBadge } from './InventoryCard';
import { CONNECTOR_FEEDS_KEY, collectorState, isDirectoryCollector, type CollectorPermissions, type CollectorRow } from './useConnectorCollectors';

const sectionLabel = 'font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground';
const labelCls = 'text-[12px] font-medium';
const inputCls = 'h-8 font-mono text-[12px]';
const helpCls = 'text-[11px] leading-[1.45] text-muted-foreground';
const textAction = 'text-primary underline-offset-2 hover:underline focus-visible:underline focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring rounded-sm disabled:pointer-events-none disabled:opacity-50';
// Multi-line secrets keep newlines (PEM), so they can't use <input type=password>.
const textSecurity = typeof CSS !== 'undefined' && typeof CSS.supports === 'function' && CSS.supports('-webkit-text-security', 'disc');
const maskedText = textSecurity ? '[-webkit-text-security:disc]' : 'text-transparent caret-foreground selection:bg-transparent';
/** Credential fields that identify rather than authenticate; shown as plain mono text. */
const PUBLIC_CREDENTIAL_FIELDS = ['CLIENT_EMAIL'];
const NEW_CREDENTIAL = '__new__';

function Code({ children }: { children: ReactNode }) {
  return <code className="rounded-sm bg-muted/50 px-1 font-mono text-[10.5px] text-foreground">{children}</code>;
}

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
  const { hasPermission } = useAuth();
  const [open, setOpen] = useState(false);
  const [manage, setManage] = useState(false);
  const [remove, setRemove] = useState(false);
  const [name, setName] = useState(spec.display_name);
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [config, setConfig] = useState<Record<string, string>>({});
  const [schedule, setSchedule] = useState('');
  const [allowShrink, setAllowShrink] = useState(false);
  const [credentialChoice, setCredentialChoice] = useState(NEW_CREDENTIAL);
  const [revealKey, setRevealKey] = useState(false);
  // Google Workspace: a service-account JSON key fills CLIENT_EMAIL and
  // PRIVATE_KEY locally (main NAN-3590); the file never leaves the browser.
  const googleKey = spec.credential_fields.includes('CLIENT_EMAIL') && spec.credential_fields.includes('PRIVATE_KEY');
  const [keyFile, setKeyFile] = useState<{ name: string; email: string } | null>(null);
  const [keyError, setKeyError] = useState<string | null>(null);
  const loadKey = async (file: File | undefined) => {
    setKeyError(null); setKeyFile(null);
    if (!file) return;
    try {
      if (file.size > 65536) throw new Error();
      const key = JSON.parse(await file.text());
      if (typeof key.private_key !== 'string' || !key.private_key.trim() || typeof key.client_email !== 'string' || !key.client_email.trim()) throw new Error();
      setCredentials(current => ({ ...current, PRIVATE_KEY: key.private_key, CLIENT_EMAIL: key.client_email }));
      setKeyFile({ name: file.name || 'key.json', email: key.client_email });
    } catch { setKeyError('Choose a valid Google service account JSON key file.'); }
  };
  const needsCredential = spec.credential_fields.length > 0;
  const canCreateCredential = permissions.installNew;
  const existing = useQuery({
    queryKey: ['credentials'],
    queryFn: () => api.listCredentials(),
    enabled: open && needsCredential && hasPermission('credentials:view'),
  });
  const matching = (existing.data?.credentials ?? []).filter(c => c.provider === spec.credential_provider);
  const choice = credentialChoice === NEW_CREDENTIAL && !canCreateCredential ? (matching[0]?.id ?? '') : credentialChoice;
  // The install action needs the permission for the credential path chosen.
  const canInstall = needsCredential ? (choice === NEW_CREDENTIAL ? permissions.installNew : permissions.installExisting) : permissions.installExisting;
  const canOpenInstall = permissions.installExisting || permissions.installNew;
  const refresh = () => client.invalidateQueries({ queryKey: CONNECTOR_FEEDS_KEY });

  const install = useMutation({
    mutationFn: () => {
      const cfg: CreateConnectorFeedRequest['config'] = {};
      for (const field of textConfigFields(spec.config_fields)) {
        const value = (config[field] ?? '').trim();
        if (value || !spec.optional_config_fields.includes(field)) cfg[field] = value;
      }
      const request: CreateConnectorFeedRequest = {
        name: name.trim(), connector: spec.name, config: withAllowShrink(cfg, spec.config_fields, allowShrink),
      };
      if (needsCredential) {
        if (choice === NEW_CREDENTIAL) request.credentials = Object.fromEntries(spec.credential_fields.map(f => [f, f === 'PRIVATE_KEY' ? credentials[f] ?? '' : (credentials[f] ?? '').trim()]));
        else if (choice) request.credential_id = choice;
      }
      if (schedule.trim()) request.schedule = schedule.trim();
      return api.connectorFeeds.create(request);
    },
    onSuccess: () => { setOpen(false); setCredentials({}); setConfig({}); void refresh(); },
    onError: () => { setCredentials({}); },
  });
  const toggle = useMutation({
    mutationFn: async (enabled: boolean) => {
      for (const feed of feeds) if (feed.enabled !== enabled) await api.connectorFeeds.setEnabled(feed.id, enabled);
    },
    onSettled: refresh,
  });
  // NAN-4931: this build bundles a newer connector spec; adopting it resets the feed's cursors.
  const [adoptTarget, setAdoptTarget] = useState<ConnectorFeed | null>(null);
  const adopt = useMutation({
    mutationFn: (feed: ConnectorFeed) => api.connectorFeeds.adoptSpec(feed.id),
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
  const changeOpen = (value: boolean) => {
    if (install.isPending) return;
    setKeyFile(null); setKeyError(null);
    setOpen(value); setName(spec.display_name); setCredentials({}); setConfig({}); setSchedule(''); setAllowShrink(false); setCredentialChoice(NEW_CREDENTIAL); setRevealKey(false); install.reset();
  };
  const busy = install.isPending || !canOpenInstall;
  const credentialReady = !needsCredential || (choice === NEW_CREDENTIAL ? spec.credential_fields.every(f => credentials[f]?.trim()) : !!choice);
  const ready = !!name.trim() && credentialReady
    && textConfigFields(spec.config_fields).filter(f => !spec.optional_config_fields.includes(f)).every(f => config[f]?.trim());
  const installBlocked = !canOpenInstall || feedStatus.isError;
  const actionError = toggle.error?.message ?? uninstall.error?.message ?? adopt.error?.message;
  const kind = isDirectoryCollector(spec) ? 'directory' : 'pull';
  return <>
    <CatalogCard id={`collector:${spec.name}`} name={spec.display_name}
      meta={<><MetaBadge>{kind}</MetaBadge> · {health}{updateAvailable && <> · <span className="text-foreground">update available</span></>}</>}
      body={feedStatus.isError ? <span role="alert" className="text-destructive">Could not load feed status</span>
        : isDirectoryCollector(spec) ? `Syncs users and groups from ${spec.display_name} into the identity directory on a schedule.`
        : `Pulls ${spec.display_name} audit events on a schedule into the ${spec.source_type} lane. A new feed starts at current activity.`}
      footerLabel={collectorDeliveryLabel({ slug: spec.name, name: spec.display_name })}
      footerAction={<span className={installed || !installBlocked ? 'text-primary' : 'text-muted-foreground'}>{installed ? `Installed · ${enabled ? 'On' : 'Off'}` : 'Install'}</span>}
      footerActionDisabled={!installed && installBlocked}
      disabled={!installed && installBlocked}
      onOpen={() => installed ? setManage(true) : changeOpen(true)} />
    <DetailSheet open={manage && installed} onOpenChange={setManage} size="md" breadcrumb={['Marketplace', 'Pull collectors']}
      title={spec.display_name} description={`Connector ${spec.name} · lane ${spec.source_type}`} meta={<span className="font-mono">{spec.name} · {health}</span>}
      footer={<>
        {canRemove && <Button size="sm" variant="outline" className="h-7 text-[11.5px] mr-auto" disabled={uninstall.isPending || toggle.isPending} onClick={() => setRemove(true)}>Uninstall</Button>}
        {canRotate && needsCredential && boundCredentials.length > 0 && <Button size="sm" variant="outline" className="h-7 text-[11.5px]" disabled={toggle.isPending || uninstall.isPending} onClick={() => changeRotating(true)}>Rotate credential</Button>}
        {canOpenInstall && <Button size="sm" variant="outline" className="h-7 text-[11.5px]" onClick={() => { setManage(false); changeOpen(true); }}>Add feed</Button>}
        {canToggle && <Button size="sm" variant="outline" className="h-7 text-[11.5px]" disabled={toggle.isPending || uninstall.isPending} onClick={() => toggle.mutate(!enabled)}>{enabled ? 'Disable' : 'Enable'}</Button>}
      </>}>
      <div className="space-y-2">
        <div className={sectionLabel}>Feeds · {feeds.length}</div>
        <div className="rounded border border-border">{feeds.map(feed => <FeedRow key={feed.id} feed={feed}
          onAdopt={canToggle && !adopt.isPending ? () => setAdoptTarget(feed) : undefined} />)}</div>
        <p className="font-mono text-[10.5px] text-muted-foreground">{collectorDeliveryLabel({ slug: spec.name, name: spec.display_name })} → HEC → Vector</p>
        <p className={helpCls}>Stream resets and run history live on <Link to="/ingestion/pull-feeds" className={textAction}>Pull feeds</Link>.</p>
        {(feedStatus.isError || actionError) && <p role="alert" className="text-[11px] text-destructive">{actionError ?? 'Could not load feed status'}</p>}
      </div>
    </DetailSheet>
    <FormSheet open={open} onOpenChange={changeOpen} title={`Install ${spec.display_name}`} size="md" breadcrumb={['Marketplace', 'Pull collectors']}
      meta={<span className="font-mono">{spec.name} · lane {spec.source_type}</span>}
      description="Credentials are stored in the credentials store and are never shown again."
      onSubmit={() => install.mutate()} pending={install.isPending} submitDisabled={!ready || !canInstall} submitLabel={install.isPending ? 'Installing…' : 'Install'}>
      <div className="space-y-3">
        <div className="space-y-1">
          <Label htmlFor={`collector-name-${spec.name}`} className={labelCls}>Feed name</Label>
          <Input id={`collector-name-${spec.name}`} className={inputCls} value={name} disabled={busy} onChange={event => setName(event.target.value)} />
        </div>
        {needsCredential && (matching.length > 0 || !canCreateCredential) && <div className="space-y-1">
          <Label htmlFor={`collector-credential-${spec.name}`} className={labelCls}>Credential</Label>
          <select id={`collector-credential-${spec.name}`} className="h-8 w-full rounded-md border border-input bg-background px-2 font-mono text-[12px]" value={choice} disabled={busy}
            onChange={event => setCredentialChoice(event.target.value)}>
            {canCreateCredential && <option value={NEW_CREDENTIAL}>Enter a new credential</option>}
            {matching.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </div>}
        {needsCredential && choice === NEW_CREDENTIAL && googleKey && <div className="space-y-1">
          <Label htmlFor={`collector-key-${spec.name}`} className={labelCls}>Service account JSON key</Label>
          <input id={`collector-key-${spec.name}`} type="file" accept=".json,application/json" disabled={busy}
            className="block w-full font-mono text-[11px] file:mr-2 file:h-7 file:rounded-md file:border file:border-border file:bg-transparent file:px-2 file:text-[11.5px] file:text-foreground"
            onChange={event => { void loadKey(event.target.files?.[0]); }} />
          {keyFile ? <p className="font-mono text-[10.5px] text-muted-foreground" data-testid="collector-key-loaded">{keyFile.email} · key loaded from {keyFile.name}</p>
            : <p className={helpCls}>Read locally; fills <Code>client_email</Code> and <Code>private_key</Code> below. Or paste them by hand.</p>}
          {keyError && <p role="alert" className="text-[11px] text-destructive">{keyError}</p>}
        </div>}
        {needsCredential && choice === NEW_CREDENTIAL && spec.credential_fields.map(field => <div key={field} className="space-y-1">
          <div className="flex items-center justify-between gap-2">
            <Label htmlFor={`collector-${spec.name}-${field}`} className={labelCls}>{humanizeEnum(field.toLowerCase())}<span aria-hidden className="ml-0.5 text-muted-foreground">*</span></Label>
            {/PRIVATE_KEY/.test(field) && <button type="button" className={`font-mono text-[10.5px] ${textAction}`} aria-pressed={revealKey}
              aria-label={revealKey ? `Hide ${field}` : `Show ${field}`} onClick={() => setRevealKey(value => !value)}>{revealKey ? 'hide' : 'show'}</button>}
          </div>
          {/PRIVATE_KEY/.test(field)
            ? <Textarea id={`collector-${spec.name}-${field}`} rows={4} spellCheck={false} autoComplete="off" data-masked={!revealKey} value={credentials[field] ?? ''} disabled={busy}
                className={`min-h-0 resize-y px-2.5 py-1.5 font-mono text-[11px] leading-[1.45] ${revealKey ? '' : maskedText}`} placeholder="-----BEGIN PRIVATE KEY-----"
                onChange={event => setCredentials(current => ({ ...current, [field]: event.target.value }))} />
            : <Input id={`collector-${spec.name}-${field}`} className={inputCls} type={PUBLIC_CREDENTIAL_FIELDS.includes(field) ? 'text' : 'password'}
                autoComplete={PUBLIC_CREDENTIAL_FIELDS.includes(field) ? 'off' : 'new-password'} spellCheck={false} value={credentials[field] ?? ''} disabled={busy}
                onChange={event => setCredentials(current => ({ ...current, [field]: event.target.value }))} />}
        </div>)}
        {textConfigFields(spec.config_fields).map(field => {
          const optional = spec.optional_config_fields.includes(field);
          return <div key={field} className="space-y-1">
            <Label htmlFor={`collector-${spec.name}-${field}`} className={labelCls}>{humanizeEnum(field.toLowerCase())}{!optional && <span aria-hidden className="ml-0.5 text-muted-foreground">*</span>}</Label>
            <Input id={`collector-${spec.name}-${field}`} className={inputCls} value={config[field] ?? ''} disabled={busy} placeholder={optional ? 'optional' : undefined}
              onChange={event => setConfig(current => ({ ...current, [field]: event.target.value }))} />
          </div>;
        })}
        {hasAllowShrink(spec.config_fields) && <AllowShrinkField id={`collector-allow-shrink-${spec.name}`} checked={allowShrink}
          disabled={busy} onCheckedChange={setAllowShrink} />}
        <div className="space-y-1">
          <Label htmlFor={`collector-schedule-${spec.name}`} className={labelCls}>Schedule</Label>
          <Input id={`collector-schedule-${spec.name}`} className={inputCls} value={schedule} disabled={busy} placeholder={spec.schedule ?? 'connector default'}
            onChange={event => setSchedule(event.target.value)} />
          <p className={helpCls}>Cron; blank keeps the connector default{spec.schedule && <> (<Code>{spec.schedule}</Code>)</>}.</p>
        </div>
        {!isDirectoryCollector(spec) && <p className={helpCls}>
          Events post to the local HEC listener into lane <Code>{spec.source_type}</Code>. A deployed HEC
          log source for that lane is required; <Link to="/ingestion/log-sources" className={textAction}>Log Sources</Link> deploys one.
        </p>}
        {install.isError && <p role="alert" className="text-[11px] text-destructive">{install.error.message} Enter credentials again to retry.</p>}
      </div>
    </FormSheet>
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
      description={<>Move <span className="text-foreground font-medium">{adoptTarget?.name}</span> to the connector spec bundled with this build.
        Its stream cursors are reset, so the next run starts fresh (an identity feed runs a full, shrink-guarded directory sync).</>}
      confirmLabel="Adopt" loading={adopt.isPending} onConfirm={() => { if (adoptTarget) adopt.mutate(adoptTarget); }} />
    <ConfirmDialog open={remove} onOpenChange={setRemove} title={`Uninstall ${spec.display_name}?`}
      description="Stops collection and removes this connector's feeds with their cursors and run history. Bound credentials stay in Credentials."
      variant="danger" confirmLabel="Uninstall" onConfirm={() => uninstall.mutate()} loading={uninstall.isPending} />
  </>;
}
