// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — Capabilities (mock soar3-cap.jsx): entity × verb map with vendor
 * badges and a detail panel, the connections wiring diagram, and the Packs
 * and Connections tabs (soar-catalog.jsx, soar-connections.jsx).
 *
 * Demo principals see the map and packs only (connections are fenced) and
 * never see effect controls.
 */
import { Fragment, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Play, Plus, X } from 'lucide-react';
import type { SoarCatalog, SoarConnection } from '@/lib/api/soar';
import { cn } from '@/lib/utils';
import { ENT, ActionChip, EffMark, H, Inv, KV, ListState, PAGE_TITLE, Spinner, StatusPill, Vendor, FilterSeg } from './soar-kit';
import { packState, type EntityKind } from './soar-model';
import { useCatalog, useConnections } from './soar-queries';
import { useSoarGate } from './soar-gate';
import { RunActionDialog, type RunActionPreset } from './RunActionDialog';
import {
  CAP_ROWS, CAP_VERBS, approvalText, availableVersion, capSummary, cellProviders, inverseLabel, isGap, relAgo, testState,
  type CapVerb, type Provider,
} from './cap-model';
import { Gated, PackChangeDialog, useCapAccess, type CapAccess, type PackChange } from './CapShared';
import { PacksTab, StaleBanner, catalogListState, usePackChange } from './PackCatalog';
import { ConnectionForm, ConnectionsTab, type ConnFormInit } from './ConnectionSheet';

type Tab = 'map' | 'packs' | 'connections';

export function CapabilitiesPage() {
  const gate = useSoarGate();
  const access = useCapAccess(gate.demo);
  const [params, setParams] = useSearchParams();
  const raw = params.get('tab');
  const tab: Tab = raw === 'packs' || (raw === 'connections' && !gate.demo) ? raw : 'map';
  const enabled = gate.state === 'enabled';
  const catalog = useCatalog(gate.tenant, enabled);
  const connections = useConnections(gate.tenant, enabled && !gate.demo);
  const conns = gate.demo ? undefined : connections.data?.connections;
  const [form, setForm] = useState<ConnFormInit | null>(null);
  const [run, setRun] = useState<RunActionPreset | null>(null);

  const go = (t: Tab, extra: Record<string, string> = {}) => setParams(t === 'map' ? extra : { tab: t, ...extra }, { replace: true });
  const selectedConn = tab === 'connections' ? params.get('conn') : null;

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden bg-background">
      <div className="flex shrink-0 flex-wrap items-end gap-4 border-b border-border px-5 pb-3 pt-4">
        <div className="min-w-0">
          <h1 className={PAGE_TITLE}>Capabilities</h1>
          <div className="mt-1.5 font-mono text-[11px] text-muted-foreground">
            SOAR catalog · packs, connections and what they let automation do{gate.demo && ' · read-only demo'}
          </div>
        </div>
        <span className="flex-1" />
        <FilterSeg
          label="Capabilities view"
          value={tab}
          onChange={(t) => go(t)}
          options={[['map', 'Capabilities'], ['packs', 'Packs'], ...(gate.demo ? [] : [['connections', 'Connections'] as [Tab, string]])]}
        />
      </div>
      <div className="relative min-h-0 flex-1">
        {tab === 'map' && (
          <CapMap
            catalog={catalog}
            connections={conns}
            access={access}
            tenant={gate.tenant}
            onConnect={(pack) => setForm({ pack })}
            onNewConnection={() => setForm({})}
            onOpenConnection={(id) => go('connections', { conn: id })}
            onRun={setRun}
          />
        )}
        {tab === 'packs' && (
          <PacksTab
            catalog={catalog}
            connections={conns}
            access={access}
            tenant={gate.tenant}
            onConnect={(pack) => setForm({ pack })}
            onRun={(pack) => setRun({ pack })}
          />
        )}
        {tab === 'connections' && (
          <ConnectionsTab
            catalog={catalog.data}
            connections={connections}
            access={access}
            tenant={gate.tenant}
            selected={selectedConn}
            onSelect={(id) => go('connections', id ? { conn: id } : {})}
            onForm={setForm}
            onRun={(pack) => setRun({ pack })}
          />
        )}
      </div>
      {form && !gate.demo && (
        <ConnectionForm
          key={`${form.id ?? ''}:${form.pack ?? ''}`}
          init={form}
          catalog={catalog.data}
          connections={conns ?? []}
          tenant={gate.tenant}
          onClose={() => setForm(null)}
        />
      )}
      {!gate.demo && (
        <RunActionDialog
          open={run !== null}
          onOpenChange={(o) => !o && setRun(null)}
          tenant={gate.tenant}
          catalog={catalog.data}
          connections={conns ?? []}
          preset={run ?? undefined}
        />
      )}
    </div>
  );
}

const LEGEND_PACKS: Array<[string, string, Partial<{ ghost: boolean; struck: boolean }>, string]> = [
  ['falcon', 'installed + connected', {}, ''],
  ['okta', 'installed, no connection', {}, 'opacity-60'],
  ['defender', 'available', { ghost: true }, ''],
  ['panos', 'disabled', { ghost: true }, 'opacity-40'],
  ['urlscan', 'withdrawn', { struck: true }, ''],
];

function CapMap({ catalog, connections, access, tenant, onConnect, onNewConnection, onOpenConnection, onRun }: {
  catalog: ReturnType<typeof useCatalog>;
  connections: SoarConnection[] | undefined;
  access: CapAccess;
  tenant: string;
  onConnect: (pack: string) => void;
  onNewConnection: () => void;
  onOpenConnection: (id: string) => void;
  onRun: (preset: RunActionPreset) => void;
}) {
  const [sel, setSel] = useState<[EntityKind, CapVerb] | null>(null);
  const [change, setChange] = useState<PackChange | null>(null);
  const mutate = usePackChange(tenant);
  const rootRef = useRef<HTMLDivElement>(null);
  const [rw, setRw] = useState(1400);
  useEffect(() => {
    const el = rootRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const ob = new ResizeObserver(() => setRw(el.clientWidth));
    ob.observe(el);
    return () => ob.disconnect();
  });
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !(e.target as HTMLElement | null)?.closest?.('input,textarea')) setSel(null);
    };
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, []);
  const overlay = rw < 1000;

  const state = catalogListState(catalog);
  if (state === 'loading') return <ListState state="loading" cols={[100, 140, 140, 140, 140]} />;
  if (state === 'error') return <ListState state="error" title="Could not load the catalog" onRetry={() => void catalog.refetch()} />;
  if (state === 'forbidden') return <ListState state="forbidden" title="You can't view capabilities" body="Viewing requires soar:view on this tenant." />;
  const data = catalog.data as SoarCatalog;
  if (data.packs.length === 0) {
    return <ListState state="empty" title="No packs are entitled for this tenant" body="The catalog lists packs included in your plan. Contact your nano account team if you expected packs here." />;
  }
  const sum = capSummary(data, connections);
  const prov = sel ? cellProviders(sel[0], sel[1], data, connections) : [];
  const gapSel = !!sel && isGap(sel[0], sel[1], prov);

  return (
    <div ref={rootRef} className="relative grid h-full" style={{ gridTemplateColumns: sel && !overlay ? 'minmax(0,1fr) 340px' : 'minmax(0,1fr)' }}>
      <div className="flex min-h-0 flex-col overflow-auto">
        <StaleBanner query={catalog} what="Capabilities" />
        <div className="px-5 pb-1 pt-3 font-mono text-[11px] text-muted-foreground" data-testid="cap-summary">
          {sum.live} capabilities live · {sum.gaps} gaps · {sum.installed} packs installed{connections && ` · ${connections.length} connections`}
        </div>
        <div className="shrink-0 overflow-x-auto px-5">
          <div className="grid min-w-[640px]" style={{ gridTemplateColumns: `minmax(60px,100px) repeat(${CAP_VERBS.length}, minmax(0,1fr))` }} data-testid="capability-map" aria-label="Capability map">
            <span />
            {CAP_VERBS.map((v) => (
              <div key={v} title={v} className="flex h-9 min-w-0 items-end break-words px-1.5 pb-1.5 text-[11px] font-medium leading-[1.15] text-fg-2">{v}</div>
            ))}
            {CAP_ROWS.map(([t, l]) => {
              const I = ENT[t];
              return (
                <Fragment key={t}>
                  <div className="flex h-[54px] min-w-0 items-center gap-2 overflow-hidden whitespace-nowrap border-t border-border text-[12px] text-foreground">
                    <I className="h-3.5 w-3.5 text-muted-foreground" strokeWidth={1.5} />{l}
                  </div>
                  {CAP_VERBS.map((v) => {
                    const c = cellProviders(t, v, data, connections);
                    const on = !!sel && sel[0] === t && sel[1] === v;
                    const gap = isGap(t, v, c);
                    return (
                      <button
                        key={v}
                        type="button"
                        aria-label={`${l} × ${v}`}
                        aria-pressed={on}
                        data-testid="cap-cell"
                        onClick={() => setSel(on ? null : [t, v])}
                        className="h-[54px] min-w-0 border-l border-t border-border p-1 text-left"
                      >
                        {gap ? (
                          <div className={cn('flex h-full items-center justify-center rounded-md border border-dashed text-[10px]', on ? 'border-primary text-primary' : 'border-fg-4/70 text-fg-4')}>gap</div>
                        ) : c.length ? (
                          <div className={cn('flex h-full min-w-0 flex-wrap content-center items-center gap-1 overflow-hidden rounded-md px-1.5', on ? 'bg-primary/[0.06] ring-2 ring-primary' : 'bg-foreground/[0.025] hover:bg-foreground/[0.05]')}>
                            {c.map((x, i) => (
                              <span
                                key={`${x.pack.name}.${x.action.name}`}
                                title={`${x.pack.display_name} · ${x.action.display_name} · ${x.st}`}
                                className={cn('flex items-center gap-1', (x.st === 'available' || x.st === 'noconn') && 'opacity-60', x.st === 'disabled' && 'opacity-35')}
                              >
                                <EffMark e={x.effect} size={8} />
                                <Vendor p={x.pack.name} label={x.pack.vendor} size={18} ghost={x.st === 'available' || x.st === 'disabled'} struck={x.st === 'withdrawn'} />
                                {x.inverse && i === 0 && <Inv className="text-[10px]" />}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <div className={cn('flex h-full items-center justify-center rounded-md', on && 'ring-1 ring-border-2')}><span className="h-1 w-1 rounded-full bg-fg-4/50" /></div>
                        )}
                      </button>
                    );
                  })}
                </Fragment>
              );
            })}
          </div>
          <div className="flex flex-wrap gap-4 border-t border-border py-2.5 text-[10.5px] text-muted-foreground">
            {LEGEND_PACKS.map(([p, label, o, cls]) => (
              <span key={p} className={cn('flex items-center gap-1.5', cls)}><Vendor p={p} size={14} {...o} />{label}</span>
            ))}
            <span className="flex items-center gap-1.5"><span className="h-3 w-5 rounded border border-dashed border-fg-4" />gap</span>
          </div>
        </div>

        {connections && (
          <Wiring catalog={data} connections={connections} access={access} onNew={onNewConnection} onOpen={onOpenConnection} />
        )}
      </div>

      {sel && (
        <div
          className={cn('flex min-h-0 flex-col overflow-auto border-l border-border bg-card', overlay && 'absolute bottom-0 right-0 top-0 z-20 w-[340px] max-w-[92%] shadow-[-12px_0_32px_rgba(0,0,0,0.35)]')}
          data-testid="cap-detail"
          role="region"
          aria-label="Capability detail"
        >
          <div className="relative border-b border-border px-4 py-3">
            <button type="button" onClick={() => setSel(null)} title="Close (esc)" aria-label="Close capability detail" className="absolute right-2.5 top-2.5 flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-foreground/[0.05] hover:text-foreground">
              <X className="h-3.5 w-3.5" strokeWidth={1.5} />
            </button>
            <H>{CAP_ROWS.find((r) => r[0] === sel[0])?.[1]} × {sel[1]}</H>
            {prov[0] && <div className="mt-2"><ActionChip e={prov[0].effect} verb={sel[1]} t={sel[0]} v={`any ${sel[0]}`} inv={!!prov[0].inverse} /></div>}
          </div>
          <div className="flex flex-col gap-3 p-4">
            {gapSel && <div className="rounded-md border border-dashed border-border-2 p-3 text-[11.5px] leading-[1.5] text-fg-2">No installed or available pack provides this. Ask your nano account team about pack coverage.</div>}
            {!gapSel && prov.length === 0 && <div className="text-[11.5px] text-muted-foreground">Not a supported combination.</div>}
            {prov.map((x) => (
              <ProviderCard
                key={`${x.pack.name}.${x.action.name}`}
                x={x}
                entity={sel[0]}
                connections={connections}
                access={access}
                pending={mutate.isPending}
                onRun={onRun}
                onConnect={onConnect}
                onChange={setChange}
              />
            ))}
            <div className="text-[10.5px] leading-[1.5] text-muted-foreground">Validation shows schema checks and recorded fixture replays. It is not a test against the live vendor.</div>
          </div>
        </div>
      )}
      <PackChangeDialog change={change} onClose={() => setChange(null)} pending={mutate.isPending} onConfirm={(c) => { mutate.mutate(c); setChange(null); }} />
    </div>
  );
}

function ProviderCard({ x, entity, connections, access, pending, onRun, onConnect, onChange }: {
  x: Provider;
  entity: EntityKind;
  connections: SoarConnection[] | undefined;
  access: CapAccess;
  pending: boolean;
  onRun: (preset: RunActionPreset) => void;
  onConnect: (pack: string) => void;
  onChange: (c: PackChange) => void;
}) {
  const conn = connections?.find((c) => c.pack_name === x.pack.name);
  const s = packState(x.pack);
  const avail = availableVersion(x.pack);
  const ts = conn ? testState(conn.last_test_status) : null;
  const inv = inverseLabel(x.inverse);
  return (
    <div className={cn('flex flex-col gap-2.5 rounded-md border p-3', x.st === 'live' ? 'border-border' : 'border-dashed border-border-2')} data-testid="cap-provider">
      <div className="flex items-center gap-2">
        <Vendor p={x.pack.name} label={x.pack.vendor} size={20} ghost={x.st === 'available' || x.st === 'disabled'} struck={x.st === 'withdrawn'} />
        <div className="min-w-0 flex-1">
          <div className="text-[12.5px] font-medium text-foreground">{x.pack.display_name}</div>
          <div className="font-mono text-[10px] text-muted-foreground">
            {x.pack.installed_version ? `${x.pack.installed_version}${s === 'update' ? ' · ' : ''}` : `${avail ?? x.pack.version} · not installed`}
            {s === 'update' && <span className="text-primary">{avail} available</span>}
          </div>
        </div>
        <StatusPill s={s} className="text-[10.5px]" />
      </div>
      {x.st === 'withdrawn' && <div className="text-[11px] text-destructive">Release withdrawn. New runs blocked. {x.pack.change_summary}</div>}
      {x.st === 'disabled' && <div className="text-[11px] text-muted-foreground">Disabled for this tenant by an admin.</div>}
      <KV rows={[
        ['Action', <span className="flex items-center gap-1.5"><EffMark e={x.effect} size={9} />{x.action.display_name}</span>],
        ['Connection', conn
          ? <span>{conn.label}{conn.last_test_at && <span className={ts === 'passed' ? 'text-muted-foreground' : 'text-destructive'}> · test {ts === 'passed' ? 'passed' : 'failed'} {relAgo(conn.last_test_at)}</span>}</span>
          : <span className="text-muted-foreground">{connections ? 'none' : '—'}</span>],
        ['Approval', approvalText(x.action)],
        ['Retry', x.action.idempotent ? 'Safe to retry' : <span className="text-warn">Not safe to retry</span>],
        inv ? ['Inverse', `${inv} ↺`] : null,
      ]} />
      <div className="flex flex-wrap gap-2">
        {x.st === 'live' && <Gated perm="soar:run" access={access} onClick={() => onRun({ pack: x.pack.name, action: x.action.name })}><Play className="h-3 w-3" strokeWidth={1.5} />Run on a {entity}</Gated>}
        {x.st === 'noconn' && connections && <Gated perm="soar:manage" access={access} onClick={() => onConnect(x.pack.name)}>Set up connection</Gated>}
        {x.st === 'available' && (
          <Gated perm="soar:manage" access={access} variant="outline" disabled={pending} onClick={() => onChange({ pack: x.pack, kind: 'install' })}>
            {pending ? <><Spinner />Installing…</> : `Install ${avail ?? x.pack.version}`}
          </Gated>
        )}
        {s === 'update' && <Gated perm="soar:manage" access={access} variant="outline" onClick={() => onChange({ pack: x.pack, kind: 'upgrade' })}>Upgrade…</Gated>}
      </div>
    </div>
  );
}

/** Patch bay: every connection wired to nano, line style = stored test result. */
function Wiring({ catalog, connections, access, onNew, onOpen }: {
  catalog: SoarCatalog;
  connections: SoarConnection[];
  access: CapAccess;
  onNew: () => void;
  onOpen: (id: string) => void;
}) {
  return (
    <div className="mt-auto shrink-0 border-t border-border px-5 py-4" data-testid="cap-wiring">
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <H>Connections</H>
        <div className="flex items-center gap-3 whitespace-nowrap font-mono text-[10px] text-muted-foreground">
          <span className="flex items-center gap-1.5"><span className="h-px w-5 bg-muted-foreground" />passing</span>
          <span className="flex items-center gap-1.5"><span className="w-5 border-t border-dashed border-destructive" />failing</span>
          <span className="flex items-center gap-1.5"><span className="w-5 border-t border-dotted border-fg-4" />never tested</span>
        </div>
        <span className="flex-1" />
        <Gated perm="soar:manage" access={access} variant="outline" onClick={onNew}><Plus className="h-3 w-3" strokeWidth={1.5} />Connection</Gated>
      </div>
      {connections.length === 0 ? (
        <div className="rounded-md border border-dashed border-border px-3 py-2.5 text-[12px] text-muted-foreground">No connections yet. A connection stores this tenant’s settings and credentials for an installed pack.</div>
      ) : (
        <div className="flex items-stretch">
          <div className="flex w-[64px] shrink-0 flex-col items-center justify-center rounded-md border border-primary/50 bg-primary/[0.06] py-3">
            <span className="text-[13px] font-semibold text-foreground">nano</span>
            <span className="font-mono text-[9.5px] text-muted-foreground">soar</span>
          </div>
          <div className="relative w-5 shrink-0"><span className="absolute left-0 right-0 top-1/2 h-px bg-border-2" /></div>
          <div className="relative flex min-w-0 flex-1 flex-col py-1">
            <span className="absolute bottom-[18px] left-0 top-[18px] w-px bg-border-2" />
            {connections.map((c) => {
              const pack = catalog.packs.find((p) => p.name === c.pack_name);
              const res = testState(c.last_test_status);
              const wd = !!pack && packState(pack) === 'withdrawn';
              return (
                <button
                  key={c.id}
                  type="button"
                  onClick={() => onOpen(c.id)}
                  title={res === 'testfailed' ? `Last test: ${c.last_test_status}` : undefined}
                  className="group relative flex h-9 min-w-0 items-center pl-5 text-left"
                  data-testid="wiring-row"
                >
                  <span className="absolute left-0 top-1/2 h-px w-5 bg-border-2" />
                  <span className="flex min-w-0 max-w-[220px] shrink items-center gap-2 pr-2">
                    <Vendor p={c.pack_name} label={pack?.vendor} size={18} struck={wd} />
                    <span className="truncate text-[12px] text-foreground group-hover:underline">{c.label}</span>
                    {c.active_runs > 0 && <span className="shrink-0 whitespace-nowrap font-mono text-[10px] text-primary" title="Active runs on this connection">⟜{c.active_runs}</span>}
                  </span>
                  <span className="relative flex h-full min-w-[16px] flex-1 items-center">
                    <span className={cn('w-full', res === 'passed' ? 'h-px bg-muted-foreground' : res === 'testfailed' ? 'border-t border-dashed border-destructive' : 'border-t border-dotted border-fg-4')} />
                  </span>
                  <span className="flex shrink-0 items-center gap-2 whitespace-nowrap pl-2">
                    <span className={cn('h-2 w-2 shrink-0 rounded-full', res === 'passed' ? 'bg-success' : res === 'testfailed' ? 'bg-destructive' : 'border border-fg-4')} />
                    <span className={cn('text-[11px]', res === 'testfailed' ? 'text-destructive' : res === 'passed' ? 'text-fg-2' : 'text-muted-foreground')}>
                      {res === 'passed' ? `passed ${relAgo(c.last_test_at)}` : res === 'testfailed' ? `failed ${relAgo(c.last_test_at)}` : 'never tested'}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

export default CapabilitiesPage;
