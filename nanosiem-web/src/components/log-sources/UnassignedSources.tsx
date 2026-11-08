// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Unassigned sources (NAN-4912 phase 2; main's NAN-4847 A on the ClickHouse
 * product). Two kinds of traffic with no log source:
 *
 *  - source keys arriving in the last 24 h that no source claims (typically
 *    senders multiplexing over the legacy install token, or the
 *    unauthenticated OTLP / Vector-native lanes). "Create source" makes a draft
 *    whose key is exactly that key: no token is issued, rotated or rebound, so
 *    the sender keeps working and its events now land in the new source;
 *  - unbound tokens (their source was deleted; Vector refuses them). "Assign"
 *    creates a draft source and binds the SAME token to it, so the sender's
 *    configuration stays valid.
 */

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, KeyRound, Radio } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import type { IngestToken } from '@/lib/api/ingest-tokens';
import { INGEST_TOKENS_QUERY_KEY } from '@/lib/api/ingest-tokens';
import {
  CONNECT_STATUS_QUERY_KEY,
  UNASSIGNED_SOURCES_QUERY_KEY,
  type UnassignedSource,
} from '@/lib/api/log-source-connect';

/** Mirrors nanosiem-api-lib SOURCE_INVENTORY_CAPS (live source inventory admission). */
const INVENTORY_CAPS = ['search:execute', 'log_sources:create', 'detections:view', 'source_scopes:view'];

/** The same alphabet the server accepts for a source key. */
export const SOURCE_KEY_RE = /^[a-z0-9][a-z0-9_.-]{0,99}$/;

function relative(iso?: string | null): string {
  if (!iso) return '—';
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function compact(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

type Target = { kind: 'key'; source: UnassignedSource } | { kind: 'token'; token: IngestToken };

function ConvertDialog({ target, onClose }: { target: Target | null; onClose: () => void }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const initialKey = target?.kind === 'key' ? target.source.route_key : '';
  const [key, setKey] = useState(initialKey);
  const [name, setName] = useState(initialKey);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!target) return null;
  const keyValid = SOURCE_KEY_RE.test(key);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await api.logSourceConnect.convert({
        route_key: key,
        name: name.trim() || undefined,
        credential_id: target.kind === 'token' ? target.token.credential_id : undefined,
      });
      void queryClient.invalidateQueries({ queryKey: UNASSIGNED_SOURCES_QUERY_KEY });
      void queryClient.invalidateQueries({ queryKey: CONNECT_STATUS_QUERY_KEY });
      void queryClient.invalidateQueries({ queryKey: INGEST_TOKENS_QUERY_KEY });
      void queryClient.invalidateQueries({ queryKey: ['log-sources'] });
      onClose();
      // Continue at Parse: the received events become the parser's samples.
      navigate(`/ingestion/log-sources/new?source_id=${encodeURIComponent(result.log_source.id)}&stage=parse`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the source');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="text-[14px]">
            {target.kind === 'key' ? 'Create source from unassigned data' : 'Assign token to a new source'}
          </DialogTitle>
          <DialogDescription className="text-[11.5px]">
            {target.kind === 'key'
              ? 'Creates a draft source with this key. No token changes: senders keep their configuration and their events land in the new source.'
              : `Creates a draft source and binds ${target.token.name} (${target.token.token_prefix}…) to it. Same token value: the sender's configuration stays valid.`}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <label className="block space-y-1">
            <span className="text-[10.5px] font-medium text-foreground/80">Source key</span>
            <Input
              value={key}
              disabled={target.kind === 'key'}
              onChange={(e) => setKey(e.target.value.toLowerCase())}
              className="h-8 font-mono text-[12px]"
              data-testid="convert-key"
            />
            {!keyValid && key && (
              <span className="text-[10.5px] text-destructive">Lowercase letters, digits, _ - . ; start with a letter or digit.</span>
            )}
          </label>
          <label className="block space-y-1">
            <span className="text-[10.5px] font-medium text-foreground/80">Name</span>
            <Input value={name} onChange={(e) => setName(e.target.value)} className="h-8 text-[12px]" data-testid="convert-name" />
          </label>
          {error && (
            <div role="alert" className="text-[11px] text-destructive" data-testid="convert-error">
              {error}
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" size="sm" className="h-7" onClick={onClose}>
            Cancel
          </Button>
          <Button size="sm" className="h-7" disabled={busy || !keyValid} onClick={() => void submit()} data-testid="convert-submit">
            {busy ? 'Creating…' : 'Create source'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function UnassignedSources() {
  const { hasPermission } = useAuth();
  const canCreate = hasPermission('log_sources:create');
  const canBind = canCreate && hasPermission('settings:system');
  // Unassigned keys are live source inventory: the server admits only
  // principals holding one of the inventory capabilities (as /api/source-types).
  const canSeeInventory = INVENTORY_CAPS.some((cap) => hasPermission(cap));
  const [target, setTarget] = useState<Target | null>(null);
  const query = useQuery({
    queryKey: UNASSIGNED_SOURCES_QUERY_KEY,
    queryFn: () => api.logSourceConnect.listUnassigned(),
    refetchInterval: 30_000,
    retry: 1,
    enabled: canSeeInventory,
  });
  if (!canSeeInventory) return null;

  if (query.isError) {
    return (
      <div role="alert" className="px-4 py-2 border-b border-border text-[11px] text-destructive" data-testid="unassigned-error">
        Could not load unassigned sources.{' '}
        <button type="button" className="text-primary hover:underline" onClick={() => void query.refetch()}>
          Retry
        </button>
      </div>
    );
  }
  const data = query.data;
  if (!data || (data.sources.length === 0 && data.unbound_tokens.length === 0)) return null;

  return (
    <section className="border-b border-border" data-testid="unassigned-sources">
      <div className="flex items-center gap-2 px-4 h-8 border-b border-border bg-card/40">
        <span className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
          Unassigned · {data.window_hours}h
        </span>
        <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums">
          {data.sources.length + data.unbound_tokens.length}
        </span>
        {data.install_token_mode === 'legacy_multiplex' && (
          <span className="text-[10.5px] text-muted-foreground truncate">
            · the install token is in legacy multiplex mode: senders choose their source key. Creating a source keeps them working.
          </span>
        )}
      </div>
      <table className="w-full text-[12px]">
        <tbody>
          {data.sources.map((s) => (
            <tr key={`key:${s.route_key}`} className="border-b border-border last:border-b-0 h-7" data-testid="unassigned-key">
              <td className="pl-4 pr-2 w-[24px]">
                <Radio className="w-3 h-3 text-muted-foreground" strokeWidth={1.5} />
              </td>
              <td className="py-1.5">
                <span className="font-mono text-[11.5px] text-foreground">{s.route_key}</span>
                <span className="ml-2 text-[10.5px] text-muted-foreground">arriving · no source</span>
              </td>
              <td className="py-1.5 w-[110px] font-mono text-[10.5px] text-muted-foreground tabular-nums">{compact(s.events_24h)} / 24h</td>
              <td className="py-1.5 w-[90px] font-mono text-[10.5px] text-muted-foreground">{relative(s.last_seen)}</td>
              <td className="py-1.5 pr-3 w-[150px] text-right">
                {!s.convertible ? (
                  <span className="inline-flex items-center gap-1 text-[10.5px] text-amber-500" title="Contains characters a source key cannot carry; fix the type at the sender">
                    <AlertTriangle className="w-3 h-3" strokeWidth={1.5} /> fix at sender
                  </span>
                ) : (
                  canCreate && (
                    <Button variant="outline" size="sm" className="h-6 px-2 text-[11px]" onClick={() => setTarget({ kind: 'key', source: s })}>
                      Create source
                    </Button>
                  )
                )}
              </td>
            </tr>
          ))}
          {data.unbound_tokens.map((t) => (
            <tr key={`token:${t.credential_id}`} className="border-b border-border last:border-b-0 h-7" data-testid="unassigned-token">
              <td className="pl-4 pr-2 w-[24px]">
                <KeyRound className="w-3 h-3 text-muted-foreground" strokeWidth={1.5} />
              </td>
              <td className="py-1.5">
                <span className="text-[11.5px] text-foreground">{t.name}</span>
                <span className="ml-2 font-mono text-[10.5px] text-muted-foreground">{t.token_prefix}…</span>
                <span className="ml-2 text-[10.5px] text-amber-500">refused · source deleted</span>
              </td>
              <td className="py-1.5 w-[110px] font-mono text-[10.5px] text-muted-foreground tabular-nums">
                {compact(t.request_count ?? 0)} req
              </td>
              <td className="py-1.5 w-[90px] font-mono text-[10.5px] text-muted-foreground">{relative(t.last_used_at)}</td>
              <td className="py-1.5 pr-3 w-[150px] text-right">
                {canBind && (
                  <Button variant="outline" size="sm" className="h-6 px-2 text-[11px]" onClick={() => setTarget({ kind: 'token', token: t })}>
                    Assign to new source
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <ConvertDialog key={target ? (target.kind === 'key' ? target.source.route_key : target.token.credential_id) : 'none'} target={target} onClose={() => setTarget(null)} />
    </section>
  );
}
