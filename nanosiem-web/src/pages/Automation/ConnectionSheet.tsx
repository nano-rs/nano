// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — Capabilities → Connections (mock soar-connections.jsx): list,
 * detail sheet with the stored test result, the generated connection form,
 * and delete with the server dependency check.
 *
 * Credentials are write-only: the server never returns them, the form never
 * prefills them, and an untouched credential is omitted from an update so
 * the stored value is kept. Entered secrets live only in component state.
 */
import { useState, type ReactNode } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Ban, Check, ChevronRight, KeyRound, Pencil, Play, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { api } from '@/lib/api';
import type { SoarCatalog, SoarCatalogPack, SoarConnection, SoarTestResult } from '@/lib/api/soar';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { cn } from '@/lib/utils';
import { packState } from './soar-model';
import { Banner, DetailSheet, Field, H, KV, ListState, Mono, Spinner, StatusPill, inputCls } from './soar-kit';
import { effectErrorMessage, errorStatus, invalidateSoar, type useConnections } from './soar-queries';
import { connectablePacks, relAgo, testState } from './cap-model';
import { Gated, Row, SearchBox, TabHeader, TD, TH, type CapAccess } from './CapShared';
import { StaleBanner } from './PackCatalog';

type Connections = ReturnType<typeof useConnections>;

export interface ConnFormInit {
  /** Edit this connection. */
  id?: string;
  /** New connection for this pack. */
  pack?: string;
}

function configString(value: unknown): string {
  return typeof value === 'string' ? value : value === null || value === undefined ? '' : String(value);
}

export function ConnectionsTab({ catalog, connections, access, tenant, selected, onSelect, onForm, onRun, now = Date.now() }: {
  catalog: SoarCatalog | undefined;
  connections: Connections;
  access: CapAccess;
  tenant: string;
  selected: string | null;
  onSelect: (id: string | null) => void;
  onForm: (init: ConnFormInit) => void;
  onRun: (pack: string) => void;
  now?: number;
}) {
  const client = useQueryClient();
  const [q, setQ] = useState('');
  const [del, setDel] = useState<SoarConnection | null>(null);
  const [ack, setAck] = useState(false);
  const remove = useMutation({
    mutationFn: (c: SoarConnection) => api.soar.deleteConnection(c.id),
    onSuccess: () => onSelect(null),
    onSettled: () => void invalidateSoar(client, tenant),
  });
  const list = connections.data?.connections ?? [];
  const packFor = (name: string) => catalog?.packs.find((p) => p.name === name);
  const rows = list.filter((c) => !q || `${c.label} ${packFor(c.pack_name)?.vendor ?? c.pack_name}`.toLowerCase().includes(q.toLowerCase()));
  const c = selected ? list.find((x) => x.id === selected) : undefined;
  const failed = list.filter((x) => testState(x.last_test_status) === 'testfailed').length;
  const never = list.filter((x) => !x.last_test_at).length;
  const forbidden = connections.isError && errorStatus(connections.error) === 403;

  return (
    <div className="relative flex h-full min-h-0 flex-col">
      <TabHeader
        title="Connections"
        meta={connections.data && (
          <>
            <span>{list.length} connections</span>
            <span className="text-destructive">{failed} last test failed</span>
            <span>{never} never tested</span>
          </>
        )}
        actions={<Gated perm="soar:manage" access={access} size="sm" onClick={() => onForm({})}><Plus className="h-3.5 w-3.5" strokeWidth={1.5} />New connection</Gated>}
      />
      <div className="flex items-center gap-2 px-5 pb-2.5"><SearchBox value={q} onChange={setQ} placeholder="Search connections" /></div>
      {remove.isError && <Banner tone="danger" title="Delete failed" className="mx-5 mb-2.5">{effectErrorMessage(remove.error, 'The connection could not be deleted.')}</Banner>}
      <div className="min-h-0 flex-1 overflow-auto border-t border-border">
        {connections.isPending ? <ListState state="loading" cols={[200, 160, 80, 120]} />
          : forbidden ? <ListState state="forbidden" title="You can't view connections" body="Viewing requires soar:view on this tenant. Ask a tenant admin to grant a role that includes it." />
          : connections.isError && !connections.data ? <ListState state="error" title="Could not load connections" body="Your filters are kept." onRetry={() => void connections.refetch()} />
          : list.length === 0 ? (
            <ListState
              state="empty"
              title="No connections"
              body="A connection stores this tenant’s settings and credentials for an installed pack."
              action={<Gated perm="soar:manage" access={access} size="sm" onClick={() => onForm({})}>New connection</Gated>}
            />
          )
          : rows.length === 0 ? <ListState state="filtered" title="No connections match these filters" action={<button type="button" onClick={() => setQ('')} className="h-7 rounded-md border border-border-2 px-2.5 text-[11.5px] text-foreground">Clear filters</button>} />
          : (
            <>
              <StaleBanner query={connections} what="Connections" />
              <table className="w-full min-w-[680px]">
                <thead className="border-b border-border">
                  <tr><TH className="w-[28%]">Label</TH><TH>Vendor · pack</TH><TH>Credentials</TH><TH>Last test</TH><TH className="w-[60px]" /></tr>
                </thead>
                <tbody>
                  {rows.map((x) => {
                    const p = packFor(x.pack_name);
                    const ts = testState(x.last_test_status);
                    return (
                      <Row key={x.id} onClick={() => onSelect(x.id)} active={selected === x.id} testId="connection-row">
                        <TD><div className="font-medium text-foreground">{x.label}</div><Mono className="text-[10.5px] text-fg-4">{x.id.slice(0, 8)}</Mono></TD>
                        <TD className="text-fg-2">
                          {p ? `${p.vendor} · ${p.display_name}` : x.pack_name}
                          {p?.installed_version && <Mono className="ml-1 text-muted-foreground">{p.installed_version}</Mono>}
                          {p && packState(p) === 'withdrawn' && <span className="ml-2"><StatusPill s="withdrawn" /></span>}
                        </TD>
                        <TD><CredState c={x} /></TD>
                        <TD><StatusPill s={ts} />{x.last_test_at && <Mono className="ml-2 text-[10.5px] text-muted-foreground">{relAgo(x.last_test_at, now)}</Mono>}</TD>
                        <TD className="text-right"><ChevronRight className="inline h-3.5 w-3.5 text-fg-4" strokeWidth={1.5} /></TD>
                      </Row>
                    );
                  })}
                </tbody>
              </table>
            </>
          )}
      </div>

      {c && (
        <DetailSheet
          open
          onClose={() => onSelect(null)}
          label="connection"
          eyebrow="Connection"
          title={c.label}
          meta={<><Mono>{c.id.slice(0, 8)}</Mono><span>{packFor(c.pack_name) ? `${packFor(c.pack_name)!.vendor} · ${packFor(c.pack_name)!.display_name}` : c.pack_name}</span></>}
          footer={(
            <>
              <Gated perm="soar:manage" access={access} size="sm" variant="outline" className="text-destructive" onClick={() => { setAck(false); setDel(c); }}><Trash2 className="h-3 w-3" strokeWidth={1.5} />Delete</Gated>
              <span className="flex-1" />
              <Gated perm="soar:manage" access={access} size="sm" variant="outline" onClick={() => onForm({ id: c.id })}><Pencil className="h-3 w-3" strokeWidth={1.5} />Edit</Gated>
              <Gated
                perm="soar:run"
                access={access}
                size="sm"
                disabled={!!packFor(c.pack_name) && packState(packFor(c.pack_name)!) === 'withdrawn'}
                reason="Pack release withdrawn"
                onClick={() => onRun(c.pack_name)}
              >
                <Play className="h-3 w-3" strokeWidth={1.5} />Run action
              </Gated>
            </>
          )}
        >
          <ConnDetail c={c} pack={packFor(c.pack_name)} access={access} tenant={tenant} now={now} />
        </DetailSheet>
      )}

      <ConfirmDialog
        open={del !== null}
        onOpenChange={(o) => !o && setDel(null)}
        variant="danger"
        title={`Delete “${del?.label ?? 'connection'}”?`}
        description="Stored credentials are destroyed. This cannot be undone."
        confirmLabel={del && !del.can_delete ? 'Deletion blocked' : 'Delete connection'}
        confirmDisabled={!del || !del.can_delete || !ack}
        onConfirm={() => del && del.can_delete && remove.mutate(del)}
      >
        {del && (
          <div className="flex flex-col gap-3">
            <div className={cn('rounded-md border px-2.5 py-2 text-[11.5px]', del.can_delete ? 'border-border text-fg-2' : 'border-warning/35 bg-warning/[0.06] text-foreground')} data-testid="delete-deps">
              <div className="mb-1 font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">Server dependency check</div>
              {del.can_delete
                ? del.active_runs > 0 ? `${del.active_runs} active run${del.active_runs > 1 ? 's' : ''} on this connection.` : 'No flows or active runs block deleting this connection.'
                : `Referenced by live flows or active runs${del.active_runs > 0 ? ` (${del.active_runs} active run${del.active_runs > 1 ? 's' : ''})` : ''}. Archive or edit those flows before deleting.`}
            </div>
            {del.can_delete && (
              <label className="flex cursor-pointer items-start gap-2 rounded-md border border-border-2 px-2.5 py-2 text-[12px] text-foreground">
                <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} className="mt-0.5 accent-[var(--destructive)]" aria-label="Acknowledge connection delete" />
                <span>Delete {del.label} and its stored credentials</span>
              </label>
            )}
          </div>
        )}
      </ConfirmDialog>
    </div>
  );
}

function CredState({ c }: { c: SoarConnection }) {
  const ok = c.ready && c.credential_fields.every((f) => !f.required || f.configured);
  return (
    <span className={cn('inline-flex items-center gap-1.5 text-[12px]', ok ? 'text-fg-2' : 'text-warn')}>
      <KeyRound className="h-3 w-3 text-muted-foreground" strokeWidth={1.5} />
      {ok ? 'Configured' : 'Incomplete'}
    </span>
  );
}

function ConnDetail({ c, pack, access, tenant, now }: { c: SoarConnection; pack: SoarCatalogPack | undefined; access: CapAccess; tenant: string; now: number }) {
  const client = useQueryClient();
  const [result, setResult] = useState<SoarTestResult | null>(null);
  const test = useMutation({
    mutationFn: () => api.soar.testConnection(c.id),
    onSuccess: (r) => setResult(r),
    onSettled: () => void invalidateSoar(client, tenant),
  });
  const withdrawn = !!pack && packState(pack) === 'withdrawn';
  const labelFor = (k: string) => pack?.config_fields?.find((f) => f.name === k)?.label ?? k.replace(/_/g, ' ');
  const stored = result
    ? { status: result.status, at: result.tested_at, message: result.message }
    : { status: c.last_test_status, at: c.last_test_at, message: null };
  return (
    <>
      {withdrawn && (
        <Banner tone="danger" icon={<Ban strokeWidth={1.5} />} title={`Pack release ${pack?.installed_version ?? ''} withdrawn`}>
          New runs on this connection are blocked. {pack?.change_summary}
        </Banner>
      )}
      <KV rows={[
        ['Pack', <span>{pack?.display_name ?? c.pack_name} <Mono className="text-muted-foreground">{pack?.installed_version}</Mono></span>],
        ...Object.entries(c.config ?? {}).map(([k, v]) => [labelFor(k), <Mono>{configString(v)}</Mono>] as [string, ReactNode]),
        ['Credentials', <CredState c={c} />],
        ['Active runs', <Mono>{c.active_runs}</Mono>],
      ]} />
      <div className="flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <H className="flex-1">Connection test</H>
          <Gated perm="soar:manage" access={access} variant="outline" disabled={test.isPending || !pack?.test_action} reason={!pack?.test_action ? 'This pack declares no read-only test action' : undefined} onClick={() => test.mutate()}>
            {test.isPending ? <><Spinner />Testing…</> : <><RefreshCw className="h-3 w-3" strokeWidth={1.5} />Test connection</>}
          </Gated>
        </div>
        {test.isError
          ? <Banner tone="danger" title="Test could not run">{effectErrorMessage(test.error, 'The test request failed.')}</Banner>
          : <TestResult status={stored.status} at={stored.at} message={stored.message} testing={test.isPending} now={now} />}
      </div>
    </>
  );
}

export function TestResult({ status, at, message, testing, now = Date.now() }: { status: string | null | undefined; at: string | null | undefined; message?: string | null; testing?: boolean; now?: number }) {
  if (testing) {
    return <div className="flex items-center gap-2 rounded-md border border-border px-3 py-2.5 text-[12px] text-fg-2"><Spinner />Running read-only test action against the vendor…</div>;
  }
  if (!at && !status) {
    return <div className="rounded-md border border-dashed border-border px-3 py-2.5 text-[12px] text-muted-foreground">Not tested yet. Tests run a read-only action and store the result.</div>;
  }
  if (testState(status) === 'passed') {
    return (
      <Banner tone="good" icon={<Check strokeWidth={1.5} />} title={`Test passed · ${relAgo(at, now)}`}>
        {message || 'Authenticated and completed the read-only test action.'} Stored result, not live health.
      </Banner>
    );
  }
  return (
    <Banner tone="danger" title={`Test failed · ${status} · ${relAgo(at, now)}`}>
      {message || 'The read-only test action did not complete. Check the settings and credentials, then test again.'}
    </Banner>
  );
}

/** Generated form sheet (mock ConnForm): label → settings → write-only credentials. */
export function ConnectionForm({ init, catalog, connections, tenant, onClose, now = Date.now() }: {
  init: ConnFormInit;
  catalog: SoarCatalog | undefined;
  connections: SoarConnection[];
  tenant: string;
  onClose: () => void;
  now?: number;
}) {
  const client = useQueryClient();
  const editing = init.id ? connections.find((c) => c.id === init.id) : undefined;
  const installable = connectablePacks(catalog);
  const [packName, setPackName] = useState(editing?.pack_name ?? init.pack ?? installable[0]?.name ?? '');
  const pack = catalog?.packs.find((p) => p.name === packName);
  const configFields = pack?.config_fields ?? [];
  const credentialFields = pack?.credential_fields ?? [];
  const [label, setLabel] = useState(editing?.label ?? '');
  const [config, setConfig] = useState<Record<string, string>>(() => {
    const out: Record<string, string> = {};
    for (const f of pack?.config_fields ?? []) out[f.name] = editing ? configString(editing.config?.[f.name]) : f.default ?? '';
    return out;
  });
  const [secret, setSecret] = useState<Record<string, string>>({});
  const [replace, setReplace] = useState<Record<string, boolean>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [result, setResult] = useState<SoarTestResult | null>(null);
  const stored = new Map((editing?.credential_fields ?? []).map((f) => [f.name, f.configured]));
  const editingCred = (name: string) => !editing || !stored.get(name) || !!replace[name];

  const choosePack = (name: string) => {
    setPackName(name);
    const p = catalog?.packs.find((x) => x.name === name);
    setConfig(Object.fromEntries((p?.config_fields ?? []).map((f) => [f.name, f.default ?? ''])));
    setSecret({});
    setErrors({});
    setResult(null);
  };

  const validate = () => {
    const e: Record<string, string> = {};
    if (!label.trim()) e.label = 'Label is required.';
    for (const f of configFields) if (f.required && !config[f.name]?.trim()) e[f.name] = f.one_of.length ? `Choose ${f.label.toLowerCase()}.` : `${f.label} is required.`;
    for (const f of credentialFields) if (f.required && editingCred(f.name) && !secret[f.name]) e[`cred:${f.name}`] = `${f.label} is required.`;
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const save = useMutation({
    mutationFn: () => {
      const cleanConfig = Object.fromEntries(configFields.filter((f) => config[f.name]?.trim()).map((f) => [f.name, config[f.name].trim()]));
      const creds = Object.fromEntries(credentialFields.filter((f) => editingCred(f.name) && secret[f.name] !== undefined).map((f) => [f.name, secret[f.name]]));
      return editing
        ? api.soar.updateConnection(editing.id, { label: label.trim(), config: cleanConfig, ...(Object.keys(creds).length ? { credentials: creds } : {}) })
        : api.soar.createConnection({ pack_name: packName, label: label.trim(), config: cleanConfig, credentials: creds });
    },
    onSuccess: () => {
      setSecret({});
      void invalidateSoar(client, tenant);
      onClose();
    },
  });
  const test = useMutation({
    mutationFn: () => api.soar.testConnection(editing!.id),
    onSuccess: (r) => setResult(r),
    onSettled: () => void invalidateSoar(client, tenant),
  });
  const busy = save.isPending || test.isPending;
  const nErr = Object.keys(errors).length;

  return (
    <DetailSheet
      open
      onClose={busy ? () => {} : onClose}
      label="connection-form"
      width={540}
      eyebrow={editing ? 'Edit connection' : 'New connection'}
      title={editing ? editing.label : 'Set up connection'}
      meta={pack && <span>{pack.vendor} · {pack.display_name} <Mono>{pack.installed_version}</Mono></span>}
      footer={(
        <>
          <span title={editing ? 'Tests the saved settings and credentials' : 'Save the connection first to test it'} className="inline-flex">
            <Button size="sm" variant="outline" className="h-8 px-3 text-[12px] shadow-none" disabled={busy || !editing} onClick={() => test.mutate()}>
              {test.isPending ? <><Spinner />Testing…</> : 'Test connection'}
            </Button>
          </span>
          <span className="flex-1" />
          <Button size="sm" variant="ghost" className="h-8 px-3 text-[12px] shadow-none" disabled={busy} onClick={onClose}>Cancel</Button>
          <Button size="sm" className="h-8 px-3 text-[12px] shadow-none" disabled={busy || !pack} onClick={() => validate() && save.mutate()}>
            {save.isPending ? <><Spinner />Saving…</> : editing ? 'Save changes' : 'Create connection'}
          </Button>
        </>
      )}
    >
      <form className="flex flex-col gap-4" autoComplete="off" onSubmit={(e) => { e.preventDefault(); if (validate()) save.mutate(); }} data-testid="connection-form">
        {nErr > 0 && (
          <Banner tone="danger" title={`${nErr} field${nErr > 1 ? 's' : ''} need attention`}>Non-secret values are kept. Re-enter any credential that was cleared.</Banner>
        )}
        {save.isError && <Banner tone="danger" title="Save failed">{effectErrorMessage(save.error, 'The connection could not be saved.')}</Banner>}
        {!editing && (
          <Field label="Pack" required hint="Only installed, enabled packs with connection settings are listed.">
            <Select value={packName} onValueChange={choosePack}>
              <SelectTrigger aria-label="Pack" className={cn(inputCls(), 'bg-background shadow-none')}><SelectValue placeholder="Install a pack first" /></SelectTrigger>
              <SelectContent>
                {installable.map((p) => <SelectItem key={p.name} value={p.name} className="text-[12px]">{p.vendor} · {p.display_name} ({p.installed_version})</SelectItem>)}
              </SelectContent>
            </Select>
          </Field>
        )}
        <Field label="Label" required error={errors.label} hint="Shown in Run action, approvals and the case wall.">
          <input aria-label="Label" className={inputCls(!!errors.label)} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. CrowdStrike · US-1 prod" />
        </Field>
        {configFields.map((f) => (
          <Field key={f.name} label={f.label} required={f.required} error={errors[f.name]}>
            {f.one_of.length > 0 ? (
              <Select value={config[f.name] ?? ''} onValueChange={(v) => setConfig((p) => ({ ...p, [f.name]: v }))}>
                <SelectTrigger aria-label={f.label} className={cn(inputCls(!!errors[f.name]), 'bg-background font-mono text-[12px] shadow-none')}><SelectValue placeholder={`Select ${f.label.toLowerCase()}`} /></SelectTrigger>
                <SelectContent>
                  {f.one_of.map((o) => <SelectItem key={o} value={o} className="font-mono text-[12px]">{o}</SelectItem>)}
                </SelectContent>
              </Select>
            ) : (
              <input aria-label={f.label} className={cn(inputCls(!!errors[f.name]), 'font-mono text-[12px]')} value={config[f.name] ?? ''} onChange={(e) => setConfig((p) => ({ ...p, [f.name]: e.target.value }))} />
            )}
          </Field>
        ))}
        <div className="flex flex-col gap-3 border-t border-border pt-3">
          <H>Credentials · write-only</H>
          {credentialFields.length === 0 && <div className="text-[11.5px] text-muted-foreground">This pack needs no credentials.</div>}
          {credentialFields.map((f) => (!editingCred(f.name) ? (
            <Field key={f.name} label={f.label} required={f.required}>
              <div className="flex h-8 items-center gap-2 rounded-md border border-border-2 px-2.5 text-[12.5px]">
                <KeyRound className="h-3 w-3 text-muted-foreground" strokeWidth={1.5} />
                <span className="flex-1 text-fg-2">Configured</span>
                <button type="button" onClick={() => setReplace((r) => ({ ...r, [f.name]: true }))} className="text-[11.5px] text-primary hover:underline">Replace</button>
              </div>
            </Field>
          ) : (
            <Field key={f.name} label={f.label} required={f.required} error={errors[`cred:${f.name}`]} hint={editing ? 'The current value is not shown. Saving replaces it.' : 'Stored encrypted. Never shown again after saving.'}>
              <div className="flex gap-2">
                <input
                  type="password"
                  autoComplete="new-password"
                  aria-label={f.label}
                  className={cn(inputCls(!!errors[`cred:${f.name}`]), 'font-mono text-[12px]')}
                  value={secret[f.name] ?? ''}
                  onChange={(e) => setSecret((s) => ({ ...s, [f.name]: e.target.value }))}
                  placeholder="••••••••••••"
                />
                {editing && stored.get(f.name) && (
                  <Button type="button" size="sm" variant="ghost" className="h-8 px-2.5 text-[12px] shadow-none" onClick={() => { setReplace((r) => ({ ...r, [f.name]: false })); setSecret((s) => { const n = { ...s }; delete n[f.name]; return n; }); }}>
                    Keep current
                  </Button>
                )}
              </div>
            </Field>
          )))}
        </div>
        {(test.isPending || result || test.isError) && (
          <div className="flex flex-col gap-1.5">
            <H>Test result</H>
            {test.isError
              ? <Banner tone="danger" title="Test could not run">{effectErrorMessage(test.error, 'The test request failed.')}</Banner>
              : <TestResult status={result?.status} at={result?.tested_at} message={result?.message} testing={test.isPending} now={now} />}
          </div>
        )}
        <button type="submit" hidden aria-hidden />
      </form>
    </DetailSheet>
  );
}
