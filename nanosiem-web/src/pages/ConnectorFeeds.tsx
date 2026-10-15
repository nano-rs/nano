// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { ConnectorFeed, CreateConnectorFeed } from '@/lib/api/connector-feeds';
import { useAuth } from '@/contexts/AuthContext';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useSharedTenant } from '@/hooks/use-shared-tenant';
import { useIngestGate } from '@/hooks/use-capabilities';
import { TenzirOnlyNote } from '@/components/add-data/TenzirOnlyNote';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { FormSheet } from '@/components/ui/detail-sheet';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';

const emptyForm = (): CreateConnectorFeed => ({ name: '', connector: '', config: {}, vendor_credentials: {}, ingest_token: '' });
const IDENTITY_LABEL = 'Directory sync (identity)';
// Identity feeds write the identity directory: never send an ingest token.
const createInput = (form: CreateConnectorFeed, identity: boolean): CreateConnectorFeed => {
  if (!identity) return form;
  const rest = { ...form };
  delete rest.ingest_token;
  return rest;
};

export function ConnectorFeeds() {
  useDocumentTitle('Pull feeds');
  const shared = useSharedTenant();
  const { hasPermission } = useAuth();
  const cache = useQueryClient();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [removing, setRemoving] = useState<ConnectorFeed | null>(null);
  const feeds = useQuery({ queryKey: ['connector-feeds'], queryFn: () => api.connectorFeeds.list(), enabled: !shared, refetchInterval: 30_000 });
  const specs = useQuery({ queryKey: ['connector-specs'], queryFn: () => api.connectorFeeds.specs(), enabled: !shared });
  const selected = specs.data?.find(spec => spec.name === form.connector);
  const identity = selected?.kind === 'identity';
  const refresh = () => { void cache.invalidateQueries({ queryKey: ['connector-feeds'] }); };
  const create = useMutation({ gcTime: 0, mutationFn: (input: CreateConnectorFeed) => api.connectorFeeds.create(input), onSuccess: () => { setOpen(false); setForm(emptyForm()); create.reset(); refresh(); } });
  const toggle = useMutation({ mutationFn: (feed: ConnectorFeed) => api.connectorFeeds.setEnabled(feed.id, !feed.enabled), onSuccess: refresh });
  const remove = useMutation({ mutationFn: (id: string) => api.connectorFeeds.delete(id), onSuccess: refresh });
  const error = feeds.error || specs.error || create.error || toggle.error || remove.error;
  // NAN-3844: pull feeds deliver through Vector; an `install.sh --tenzir`
  // install has none. Existing feeds stay visible so they can be paused or deleted.
  const { tenzirOnly, blocked } = useIngestGate();
  const canCreate = hasPermission('log_sources:create') && hasPermission('log_sources:deploy') && !blocked;
  if (shared) return <p className="p-4 text-xs">Pull feeds are managed through Integrations on this edition.</p>;

  return <div className="space-y-3 p-4 text-xs">
    <nav className="font-mono text-[10.5px] text-muted-foreground"><Link to="/">Home</Link> / Ingestion / Pull feeds</nav>
    <div className="flex items-center justify-between"><h1 className="text-xl font-semibold">Pull feeds</h1>{canCreate && <Button size="sm" onClick={() => { setForm(emptyForm()); create.reset(); setOpen(true); }}>Create feed</Button>}</div>
    <p className="font-mono text-[10.5px] text-muted-foreground">{feeds.data?.length ?? 0} feeds · New feeds start from now. A running pull finishes before a pause takes effect.</p>
    {tenzirOnly && <TenzirOnlyNote />}
    {error && <p role="alert" className="text-destructive">{error instanceof Error ? error.message : 'Feed operation failed'}</p>}
    {feeds.isLoading ? <p>Loading feeds…</p> : <table className="w-full border text-left">
      <thead><tr className="h-7 border-b"><th className="px-2">Name</th><th>Connector</th><th>Kind</th><th>Status</th><th>Last success</th><th className="px-2 text-right">Actions</th></tr></thead>
      <tbody>{feeds.data?.map(feed => <tr key={feed.id} className="h-7 border-b">
        <td className="px-2">{feed.name}</td><td className="font-mono">{feed.connector}</td><td className="font-mono text-[10.5px]" title={feed.kind === 'identity' ? IDENTITY_LABEL : 'Event collector'}>{feed.kind}</td><td>{feed.enabled ? feed.last_status ?? 'Waiting' : 'Paused'}{feed.last_error && <span className="block max-w-[28rem] truncate font-mono text-[10.5px] text-destructive" title={feed.last_error}>{feed.last_error}</span>}</td><td className="font-mono text-[10.5px]">{feed.last_success_at ? new Date(feed.last_success_at).toLocaleString() : '—'}</td>
        <td className="space-x-2 px-2 text-right">{hasPermission('log_sources:edit') && <button disabled={toggle.isPending || (!feed.enabled && (blocked || !hasPermission('log_sources:deploy')))} onClick={() => toggle.mutate(feed)}>{feed.enabled ? 'Pause' : 'Resume'}</button>}{hasPermission('log_sources:delete') && <button onClick={() => setRemoving(feed)}>Delete</button>}</td>
      </tr>)}</tbody>
    </table>}
    {!feeds.isLoading && !feeds.data?.length && <p>No pull feeds configured.</p>}
    <FormSheet open={open} onOpenChange={value => { setOpen(value); if (!value) setForm(emptyForm()); }} title="Create pull feed" breadcrumb={['Ingestion', 'Pull feeds']} description={identity ? `${IDENTITY_LABEL}: users and group memberships go to the identity directory. Enter the vendor credential; it is stored encrypted.` : 'Enter the vendor credential and your local HEC ingest token. Credentials are stored encrypted.'} pending={create.isPending} submitLabel="Create feed" submitDisabled={!selected} onSubmit={() => create.mutate(createInput(form, identity))}>
      <div className="space-y-3">
        <label className="block">Name<Input required maxLength={100} value={form.name} onChange={event => setForm({ ...form, name: event.target.value })} /></label>
        <label className="block">Connector<select className="mt-1 h-8 w-full border bg-background px-2 font-mono text-xs" required value={form.connector} onChange={event => setForm({ ...form, connector: event.target.value, config: {}, vendor_credentials: {} })}><option value="">Select connector</option>{specs.data?.map(spec => <option key={spec.name} value={spec.name}>{spec.kind === 'identity' ? `${spec.name} · directory sync` : spec.name}</option>)}</select></label>
        {identity && <p className="text-xs text-muted-foreground"><span className="font-mono">{IDENTITY_LABEL}</span> · no ingest token or parser needed. Synced users appear on the Identity page.</p>}
        {selected && !identity && <p className="text-xs text-muted-foreground">Deploy an enabled HEC parser with a match value for lane <span className="font-mono">{selected.source_slug}</span> in <Link className="underline" to="/ingestion/log-sources">Log Sources</Link> before starting this feed.</p>}
        {selected?.config_fields.map(field => <label key={field} className="block font-mono">{field}<Input required value={form.config[field] ?? ''} onChange={event => setForm({ ...form, config: { ...form.config, [field]: event.target.value } })} /></label>)}
        {selected?.credential_fields.map(field => <label key={field} className="block font-mono">{field}<Input type="password" autoComplete="new-password" required value={form.vendor_credentials[field] ?? ''} onChange={event => setForm({ ...form, vendor_credentials: { ...form.vendor_credentials, [field]: event.target.value } })} /></label>)}
        {!identity && <label className="block">Local HEC ingest token<Input type="password" autoComplete="new-password" required maxLength={2048} value={form.ingest_token ?? ''} onChange={event => setForm({ ...form, ingest_token: event.target.value })} /></label>}
      </div>
    </FormSheet>
    <ConfirmDialog open={removing !== null} onOpenChange={value => { if (!value) setRemoving(null); }} title="Delete pull feed?" description={`Delete ${removing?.name ?? 'this feed'} and its saved cursor?`} variant="danger" confirmLabel="Delete" onConfirm={() => { if (removing) remove.mutate(removing.id); }} />
  </div>;
}
