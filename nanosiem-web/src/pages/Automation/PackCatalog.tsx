// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — Capabilities → Packs (mock soar-catalog.jsx): the SOAR catalog
 * table, pack detail sheet and the install / upgrade confirm.
 */
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Ban, ChevronRight, Play } from 'lucide-react';
import { api } from '@/lib/api';
import type { SoarCatalogPack, SoarConnection } from '@/lib/api/soar';
import { cn } from '@/lib/utils';
import { asEffect, packState } from './soar-model';
import { Banner, DetailSheet, EffectBadge, FilterSelect, FilterSeg, H, KV, ListState, Mono, StatusPill } from './soar-kit';
import { effectErrorMessage, errorStatus, invalidateSoar, type useCatalog } from './soar-queries';
import { approvalText, availableVersion, inverseLabel, inverseOf, packCategories, packConnectable } from './cap-model';
import { Disclosure, Gated, PackChangeDialog, Row, SearchBox, TabHeader, TD, TH, type CapAccess, type PackChange } from './CapShared';

type Catalog = ReturnType<typeof useCatalog>;

export function usePackChange(tenant: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ pack, kind }: PackChange): Promise<unknown> =>
      kind === 'install'
        ? api.soar.installPack(pack.name, pack.version)
        : kind === 'remove'
          ? api.soar.removePack(pack.name)
          : api.soar.applyUpstreamUpdate(pack.name, pack.upstream_version ?? pack.version),
    onSettled: () => void invalidateSoar(client, tenant),
  });
}

export function catalogListState(catalog: Catalog): 'loading' | 'error' | 'forbidden' | null {
  if (catalog.isPending) return 'loading';
  if (catalog.isError && !catalog.data) return errorStatus(catalog.error) === 403 ? 'forbidden' : 'error';
  return null;
}

/** Live refresh failed but older data is still shown (mock ListShell "stale"). */
export function StaleBanner({ query, what }: { query: { isError: boolean; data: unknown; dataUpdatedAt: number; refetch: () => unknown }; what: string }) {
  if (!query.isError || !query.data) return null;
  const at = new Date(query.dataUpdatedAt).toISOString().slice(11, 16);
  return (
    <div className="px-3 py-2">
      <Banner
        tone="warn"
        title={`Showing data from ${at} UTC`}
        action={<button type="button" onClick={() => void query.refetch()} className="h-6 rounded-md border border-border-2 px-2 text-[11px] text-foreground hover:bg-foreground/[0.04]">Refresh</button>}
      >
        Live refresh failed. {what} may not reflect recent changes.
      </Banner>
    </div>
  );
}

export function PacksTab({ catalog, connections, access, tenant, onConnect, onRun }: {
  catalog: Catalog;
  connections: SoarConnection[] | undefined;
  access: CapAccess;
  tenant: string;
  onConnect: (pack: string) => void;
  onRun: (pack: string) => void;
}) {
  const [q, setQ] = useState('');
  const [cat, setCat] = useState('all');
  const [inst, setInst] = useState<'all' | 'installed' | 'not'>('all');
  const [sel, setSel] = useState<string | null>(null);
  const [change, setChange] = useState<PackChange | null>(null);
  const mutate = usePackChange(tenant);

  const state = catalogListState(catalog);
  const packs = catalog.data?.packs ?? [];
  const rows = packs.filter((p) => {
    const hay = `${p.vendor} ${p.display_name} ${p.name} ${p.actions.map((a) => a.display_name).join(' ')}`.toLowerCase();
    if (q && !hay.includes(q.toLowerCase())) return false;
    if (cat !== 'all' && !p.categories.includes(cat)) return false;
    if (inst === 'installed' && !p.installed) return false;
    if (inst === 'not' && p.installed) return false;
    return true;
  });
  const pack = sel ? packs.find((p) => p.name === sel) : undefined;
  const count = (s: string) => packs.filter((p) => packState(p) === s).length;
  const hasConn = (p: SoarCatalogPack) => !!connections?.some((c) => c.pack_name === p.name);

  return (
    <div className="relative flex h-full min-h-0 flex-col">
      <TabHeader
        title="SOAR catalog"
        meta={catalog.data && (
          <>
            <span>{packs.length} packs</span>
            <span>{packs.filter((p) => p.installed).length} installed</span>
            <span className="text-primary">{count('update')} update available</span>
            <span className="text-destructive">{count('withdrawn')} withdrawn</span>
          </>
        )}
      />
      <div className="flex flex-wrap items-center gap-2 px-5 pb-2.5">
        <SearchBox value={q} onChange={setQ} placeholder="Search vendors, packs, actions" />
        <FilterSelect label="Category" value={cat} onChange={setCat} options={packCategories(catalog.data)} />
        <FilterSeg value={inst} onChange={setInst} label="Installed filter" options={[['all', 'All'], ['installed', 'Installed'], ['not', 'Not installed']]} />
      </div>
      {mutate.isError && (
        <Banner tone="danger" title="Pack change failed" className="mx-5 mb-2.5">{effectErrorMessage(mutate.error, 'The pack could not be changed.')}</Banner>
      )}
      <div className="min-h-0 flex-1 overflow-auto border-t border-border">
        {state === 'loading' ? <ListState state="loading" cols={[160, 200, 70, 70, 90]} />
          : state === 'error' ? <ListState state="error" title="Could not load the catalog" body="Your filters are kept." onRetry={() => void catalog.refetch()} />
          : state === 'forbidden' ? <ListState state="forbidden" title="You can't view packs" body="Viewing requires soar:view on this tenant. Ask a tenant admin to grant a role that includes it." />
          : packs.length === 0 ? <ListState state="empty" title="No packs are entitled for this tenant" body="The catalog lists packs included in your plan. Contact your nano account team if you expected packs here." />
          : rows.length === 0 ? <ListState state="filtered" title="No packs match these filters" action={<ClearButton onClick={() => { setQ(''); setCat('all'); setInst('all'); }} />} />
          : (
            <>
              <StaleBanner query={catalog} what="Packs" />
              <table className="w-full min-w-[760px]">
                <thead className="border-b border-border">
                  <tr><TH className="w-[22%]">Vendor</TH><TH>Pack</TH><TH>Category</TH><TH>Actions</TH><TH>Available</TH><TH>Installed</TH><TH>State</TH><TH className="w-[150px]" /></tr>
                </thead>
                <tbody>
                  {rows.map((p) => {
                    const s = packState(p);
                    return (
                      <Row key={p.name} onClick={() => setSel(p.name)} active={sel === p.name} testId="pack-row">
                        <TD className="text-fg-2">{p.vendor}</TD>
                        <TD className="font-medium text-foreground">{p.display_name}</TD>
                        <TD className="text-[12px] text-fg-2">{p.categories.join(', ')}</TD>
                        <TD><Mono className="text-fg-2">{p.actions.length}</Mono></TD>
                        <TD><Mono className="text-fg-2">{availableVersion(p) ?? '—'}</Mono></TD>
                        <TD><Mono className={p.installed_version ? 'text-foreground' : 'text-fg-4'}>{p.installed_version ?? '—'}</Mono></TD>
                        <TD><StatusPill s={s} /></TD>
                        <TD className="text-right">
                          <span onClick={(e) => e.stopPropagation()} className="inline-flex">
                            {s === 'available' && <Gated perm="soar:manage" access={access} variant="outline" disabled={mutate.isPending} onClick={() => setChange({ pack: p, kind: 'install' })}>Install</Gated>}
                            {s === 'update' && <Gated perm="soar:manage" access={access} variant="outline" onClick={() => setChange({ pack: p, kind: 'upgrade' })}>Upgrade</Gated>}
                            {s === 'installed' && !hasConn(p) && packConnectable(p) && connections && (
                              <Gated perm="soar:manage" access={access} variant="outline" onClick={() => onConnect(p.name)}>Set up connection</Gated>
                            )}
                          </span>
                        </TD>
                      </Row>
                    );
                  })}
                </tbody>
              </table>
            </>
          )}
      </div>

      <PackSheet
        pack={pack}
        onClose={() => setSel(null)}
        access={access}
        connections={connections}
        pending={mutate.isPending}
        onChange={setChange}
        onConnect={onConnect}
        onRun={onRun}
      />
      <PackChangeDialog change={change} onClose={() => setChange(null)} pending={mutate.isPending} onConfirm={(c) => { mutate.mutate(c); setChange(null); }} />
    </div>
  );
}

function ClearButton({ onClick }: { onClick: () => void }) {
  return <button type="button" onClick={onClick} className="h-7 rounded-md border border-border-2 px-2.5 text-[11.5px] text-foreground hover:bg-foreground/[0.04]">Clear filters</button>;
}

export function PackSheet({ pack, onClose, access, connections, pending, onChange, onConnect, onRun }: {
  pack: SoarCatalogPack | undefined;
  onClose: () => void;
  access: CapAccess;
  connections: SoarConnection[] | undefined;
  pending: boolean;
  onChange: (c: PackChange) => void;
  onConnect: (pack: string) => void;
  onRun: (pack: string) => void;
}) {
  if (!pack) return null;
  const s = packState(pack);
  const avail = availableVersion(pack);
  const conn = connections?.find((c) => c.pack_name === pack.name);
  return (
    <DetailSheet
      open
      onClose={onClose}
      label="pack"
      width={600}
      eyebrow={`Pack · ${pack.vendor}`}
      title={pack.display_name}
      meta={(
        <>
          <StatusPill s={s} />
          <Mono>{pack.installed_version ? `installed ${pack.installed_version}` : 'not installed'}</Mono>
          {avail && <Mono>available {avail}</Mono>}
          <span>{pack.categories.join(', ')}</span>
        </>
      )}
      footer={
        s === 'withdrawn' ? (
          <>
            <span className="flex-1 text-[11.5px] text-muted-foreground">New runs are blocked for this release.</span>
            <Gated perm="soar:manage" access={access} size="sm" variant="outline" disabled={pending} onClick={() => onChange({ pack, kind: 'remove' })}>Remove pack</Gated>
          </>
        ) : (
          <>
            <span className="flex-1" />
            {s === 'available' && <Gated perm="soar:manage" access={access} size="sm" disabled={pending} onClick={() => onChange({ pack, kind: 'install' })}>{`Install ${avail ?? pack.version}`}</Gated>}
            {s === 'update' && <Gated perm="soar:manage" access={access} size="sm" variant="outline" onClick={() => onChange({ pack, kind: 'upgrade' })}>Upgrade to {avail}</Gated>}
            {pack.installed && s !== 'disabled' && packConnectable(pack) && connections && (
              <Gated perm="soar:manage" access={access} size="sm" variant={conn ? 'outline' : 'default'} onClick={() => onConnect(pack.name)}>Set up connection</Gated>
            )}
            {conn && s !== 'disabled' && <Gated perm="soar:run" access={access} size="sm" onClick={() => onRun(pack.name)}><Play className="h-3 w-3" strokeWidth={1.5} />Run action</Gated>}
          </>
        )
      }
    >
      <PackBody pack={pack} />
    </DetailSheet>
  );
}

function PackBody({ pack }: { pack: SoarCatalogPack }) {
  const [open, setOpen] = useState<string | null>(null);
  const s = packState(pack);
  return (
    <>
      {s === 'withdrawn' && (
        <Banner tone="danger" icon={<Ban strokeWidth={1.5} />} title={`Release ${pack.installed_version ?? pack.version} withdrawn`}>
          {pack.change_summary || 'This release was withdrawn upstream.'} New runs cannot start. Historical runs stay viewable in Runs.
        </Banner>
      )}
      {s === 'disabled' && (
        <Banner tone="neutral" icon={<Ban strokeWidth={1.5} />} title="Disabled for this tenant">
          A tenant admin disabled this pack. Actions are hidden from Run action and flows until it is re-enabled.
        </Banner>
      )}
      <div className="text-[12.5px] leading-[1.55] text-fg-2">{pack.description}</div>
      <div>
        <H className="mb-2">Actions · {pack.actions.length}</H>
        <div className="divide-y divide-border rounded-md border border-border" data-testid="pack-actions">
          {pack.actions.map((a) => {
            const inv = inverseLabel(inverseOf(pack, a));
            const oneOf = new Set(a.require_one_of.flat());
            return (
              <div key={a.name}>
                <button type="button" aria-expanded={open === a.name} onClick={() => setOpen(open === a.name ? null : a.name)} className="flex w-full items-center gap-2.5 px-3 py-2.5 text-left hover:bg-foreground/[0.03]">
                  <ChevronRight className={cn('h-3 w-3 text-muted-foreground transition-transform', open === a.name && 'rotate-90')} strokeWidth={1.5} />
                  <span className="flex-1 text-[12.5px] font-medium text-foreground">{a.display_name}</span>
                  <EffectBadge effect={asEffect(a.effect)} />
                </button>
                {open === a.name && (
                  <div className="flex flex-col gap-2.5 px-3 pb-3 pl-[34px]">
                    {a.description && <div className="text-[12px] text-fg-2">{a.description}</div>}
                    <KV rows={[
                      ['Inputs', (
                        <div className="flex flex-col gap-0.5">
                          {a.inputs.map((i) => (
                            <span key={i.name}>
                              <Mono className="text-foreground">{i.name}</Mono>{' '}
                              <span className="font-mono text-[10.5px] text-muted-foreground">{i.type}{oneOf.has(i.name) ? ' · one of target' : i.required ? ' · required' : ' · optional'}</span>
                            </span>
                          ))}
                        </div>
                      )],
                      ['Approval default', approvalText(a)],
                      ['Retry safety', a.idempotent ? <span className="text-good">Safe to retry (idempotent)</span> : <span className="text-warn">Not safe to retry automatically</span>],
                      inv ? ['Inverse action', <span>{inv} <span className="text-muted-foreground">· runs separately, with its own approval</span></span>] : null,
                    ]} />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
      <Disclosure title="Technical details" meta={pack.installed_version ?? pack.version}>
        <KV rows={[
          ['Version', <Mono>{pack.installed_version ?? pack.version}</Mono>],
          ['Origin', <Mono className="text-[11px]">{pack.origin} · {pack.name}</Mono>],
          ['Provenance', <span className="text-muted-foreground">—</span>],
          ['License', <span className="text-muted-foreground">—</span>],
          ['Validation', <span className="text-muted-foreground">—</span>],
          ['Rate limit', <Mono>{pack.per_minute}/min · {pack.per_day}/day</Mono>],
          ['Fixture replay', <span className="text-muted-foreground">Recorded vendor fixtures replayed offline. Not a test against the live vendor.</span>],
        ]} />
      </Disclosure>
    </>
  );
}
