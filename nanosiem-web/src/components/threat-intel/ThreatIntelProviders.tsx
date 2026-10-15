// SPDX-License-Identifier: AGPL-3.0-or-later
// Marketplace "Threat intel lookups" section (category agent): the official
// lookup providers, their install state, and a configure sheet for
// credentials, rate limits and cache TTL. Credentials are write-only: the
// API reports only whether each field is set.

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { ScanSearch } from 'lucide-react';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { FormSheet } from '@/components/ui/detail-sheet';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Section } from '@/components/marketplace/MarketplaceShell';
import { CatalogCard } from '@/components/marketplace/InventoryCard';
import type { ConfigureThreatIntelProvider, ThreatIntelProvider } from '@/lib/api/threat-intel';
import { matchesProvider, useThreatIntelEnabled, useThreatIntelKey, useThreatIntelProviders } from './use-threat-intel';

function providerState(p: ThreatIntelProvider): string {
  if (!p.installed) return 'not installed';
  if (!p.enabled) return 'disabled';
  return p.ready ? 'ready' : 'needs credentials';
}


export function ThreatIntelProvidersSection({ searchQuery = '', installedOnly = false }: { searchQuery?: string; installedOnly?: boolean }) {
  const enabled = useThreatIntelEnabled();
  const [open, setOpen] = useState<string | null>(null);
  const providers = useThreatIntelProviders();
  if (!enabled) return null;
  if (providers.isError) {
    return <p role="alert" className="mt-4 text-[12px] text-destructive">Could not load threat-intel providers.</p>;
  }
  const list = (providers.data?.providers ?? []).filter(
    (p) => matchesProvider(p, searchQuery) && (!installedOnly || p.installed),
  );
  if (list.length === 0) return null;
  const selected = providers.data?.providers.find((p) => p.provider === open) ?? null;
  return (
    <>
      <Section icon={<ScanSearch className="h-[12px] w-[12px] text-muted-foreground" strokeWidth={1.5} />} title="Threat intel lookups" count={list.length}>
        {list.map((p) => (
          <CatalogCard
            key={p.provider}
            id={`threat-intel:${p.provider}`}
            name={p.name}
            meta={<>agent · {providerState(p)}</>}
            body={p.description}
            footerLabel={p.artifact_types.join(' · ')}
            footerAction={p.installed ? `${p.usage.today}/${p.effective.per_day} today` : 'Install'}
            onOpen={() => setOpen(p.provider)}
          />
        ))}
      </Section>
      {selected && <ProviderSheet provider={selected} onClose={() => setOpen(null)} />}
    </>
  );
}

export function ProviderSheet({ provider, onClose }: { provider: ThreatIntelProvider; onClose: () => void }) {
  const key = useThreatIntelKey();
  const client = useQueryClient();
  const { hasAllPermissions } = useAuth();
  const canConfigure = hasAllPermissions(['enrichments:configure']);
  const [creds, setCreds] = useState<Record<string, string>>({});
  const [enabled, setEnabled] = useState(provider.installed ? provider.enabled : true);
  const [perMinute, setPerMinute] = useState(String(provider.effective.per_minute));
  const [perDay, setPerDay] = useState(String(provider.effective.per_day));
  const [ttl, setTtl] = useState(String(provider.effective.cache_ttl_secs));
  const [confirmRemove, setConfirmRemove] = useState(false);
  const invalidate = () => client.invalidateQueries({ queryKey: [...key, 'providers'] });

  const save = useMutation({
    mutationFn: (body: ConfigureThreatIntelProvider) => api.threatIntel.configureProvider(provider.provider, body),
    onSuccess: () => {
      void invalidate();
      onClose();
    },
  });
  const remove = useMutation({
    mutationFn: () => api.threatIntel.uninstallProvider(provider.provider),
    onSuccess: () => {
      void invalidate();
      onClose();
    },
  });

  // Send a limit only when it changed, so an untouched form never pins the
  // current default as a tenant override.
  const changed = (v: string, current: number) => {
    const n = Number(v);
    return v !== '' && Number.isFinite(n) && n >= 0 && Math.floor(n) !== current ? Math.floor(n) : undefined;
  };
  const credentials = Object.fromEntries(Object.entries(creds).filter(([, v]) => v !== ''));
  const dirty = Object.keys(credentials).length > 0;
  const missingRequired = provider.credential_fields.some((f) => f.required && !f.set && !credentials[f.name]?.trim());

  return (
    <>
      <FormSheet
        open
        onOpenChange={(o) => {
          if (!o) onClose();
        }}
        size="sm"
        breadcrumb={['Marketplace', 'Threat intel', provider.provider]}
        title={provider.name}
        icon={<ScanSearch className="h-4 w-4" strokeWidth={1.5} />}
        meta={
          <span>
            {provider.artifact_types.join(' · ')} · {providerState(provider)} · {provider.usage.this_minute}/{provider.effective.per_minute} min ·{' '}
            {provider.usage.today}/{provider.effective.per_day} day
          </span>
        }
        guardDirty={dirty}
        submitLabel={provider.installed ? 'Save' : 'Install'}
        pending={save.isPending}
        submitDisabled={!canConfigure || (enabled && missingRequired)}
        onSubmit={() =>
          save.mutate({
            enabled,
            credentials: Object.keys(credentials).length ? credentials : undefined,
            per_minute: changed(perMinute, provider.effective.per_minute),
            per_day: changed(perDay, provider.effective.per_day),
            cache_ttl_secs: changed(ttl, provider.effective.cache_ttl_secs),
          })
        }
        footerStart={
          provider.installed && canConfigure ? (
            <Button type="button" size="sm" variant="ghost" className="h-7 text-[11.5px] text-destructive" onClick={() => setConfirmRemove(true)}>
              Uninstall
            </Button>
          ) : undefined
        }
      >
        <div className="space-y-3 text-[12px]">
          <p className="text-muted-foreground">{provider.description}</p>
          <div className="flex items-center justify-between">
            <Label htmlFor="ti-enabled" className="text-[12px]">Enabled</Label>
            <Switch id="ti-enabled" checked={enabled} onCheckedChange={setEnabled} disabled={!canConfigure} />
          </div>
          {provider.credential_fields.map((f) => (
            <div key={f.name} className="space-y-1">
              <Label htmlFor={`ti-cred-${f.name}`} className="text-[12px]">
                {f.label}
                {!f.required && <span className="ml-1 text-muted-foreground">(optional)</span>}
              </Label>
              <Input
                id={`ti-cred-${f.name}`}
                type="password"
                autoComplete="off"
                className="h-7 font-mono text-[12px]"
                placeholder={f.set ? '•••••••• stored — type to replace' : 'not set'}
                value={creds[f.name] ?? ''}
                onChange={(e) => setCreds((c) => ({ ...c, [f.name]: e.target.value }))}
                disabled={!canConfigure}
              />
            </div>
          ))}
          <div className="grid grid-cols-3 gap-2">
            <LimitField id="ti-per-minute" label="per minute" value={perMinute} onChange={setPerMinute} hint={provider.defaults.per_minute} disabled={!canConfigure} />
            <LimitField id="ti-per-day" label="per day" value={perDay} onChange={setPerDay} hint={provider.defaults.per_day} disabled={!canConfigure} />
            <LimitField id="ti-ttl" label="cache ttl (s)" value={ttl} onChange={setTtl} hint={provider.defaults.cache_ttl_secs} disabled={!canConfigure} />
          </div>
          <p className="text-[11px] text-muted-foreground">
            Limits default to the provider&apos;s free tier; 0 resets to the default. Lookups beyond them return
            “quota exhausted” instead of calling the provider. Results are cached for this tenant only.
          </p>
          {save.isError && <p role="alert" className="text-destructive">{save.error.message}</p>}
          {remove.isError && <p role="alert" className="text-destructive">{remove.error.message}</p>}
        </div>
      </FormSheet>
      <ConfirmDialog
        open={confirmRemove}
        onOpenChange={setConfirmRemove}
        title={`Uninstall ${provider.name}?`}
        description="Removes the stored credentials, cached results and usage counters for this provider."
        onConfirm={() => {
          setConfirmRemove(false);
          remove.mutate();
        }}
        loading={remove.isPending}
      />
    </>
  );
}

function LimitField({ id, label, value, onChange, hint, disabled }: { id: string; label: string; value: string; onChange: (v: string) => void; hint: number; disabled?: boolean }) {
  return (
    <div className="space-y-1">
      <Label htmlFor={id} className="font-mono text-[10.5px] text-muted-foreground">{label}</Label>
      <Input
        id={id}
        inputMode="numeric"
        className="h-7 font-mono text-[12px] tabular-nums"
        value={value}
        onChange={(e) => onChange(e.target.value.replace(/[^0-9]/g, ''))}
        title={`default ${hint}`}
        disabled={disabled}
      />
    </div>
  );
}
