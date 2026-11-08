// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * "Credentials that can write this source" (main's NAN-2597 card, re-backed
 * for the ClickHouse product by NAN-4922). On this product a writer is an
 * ingest token bound to the source (NAN-4907): the token decides the source,
 * and a binding never changes, so main's collector rows and "Convert type"
 * dialog have no counterpart. Rows never carry a secret.
 *
 * "Add credential / ingest path" (NAN-2946) opens the issue form inline, with
 * the token, sender snippets and first-event checklist; `?action=add-credential`
 * (from Add source → Your sources) opens it on arrival.
 */

import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Plus, ShieldOff, X } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';

import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { useToast } from '@/hooks/use-toast';
import { api, ApiClientError } from '@/lib/api';
import { INGEST_TOKENS_QUERY_KEY, type IngestToken } from '@/lib/api/ingest-tokens';
import { CONNECT_STATUS_QUERY_KEY, connectDetailQueryKey } from '@/lib/api/log-source-connect';
import { DIRECT_PROTOCOLS, INGEST_ENDPOINT_QUERY_KEY, issuableSlugs, type AddDataSource } from '@/lib/add-data-sources';
import { formatRelativeCompact, formatUTC } from '@/lib/date-utils';
import { cn } from '@/lib/utils';
import { IssueCredentialPanel, ISSUE_TOKEN_PERMISSION } from './IssueCredentialPanel';

const STATE_TONE: Record<IngestToken['state'], string> = {
  active: 'text-emerald-500 border-emerald-500/40',
  unbound: 'text-amber-500 border-amber-500/40',
  revoked: 'text-muted-foreground border-border',
};

export function SourceWritersCard({
  logSourceId,
  canRevoke,
  canIssue = false,
  searchField,
}: {
  logSourceId: string;
  /** Revoke and issue are token-management actions (`settings:system`). */
  canRevoke: boolean;
  canIssue?: boolean;
  /** The field Search scopes a source by (`metadata.log_source` on OCSF). */
  searchField?: string;
}) {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [params, setParams] = useSearchParams();
  const [issuing, setIssuing] = useState(() => params.get('action') === 'add-credential');
  const [revokeTarget, setRevokeTarget] = useState<IngestToken | null>(null);

  // Clear the one-shot `?action=` so a reload does not reopen the form over a token.
  useEffect(() => {
    if (params.get('action') !== 'add-credential') return;
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete('action');
      return next;
    }, { replace: true });
  }, [params, setParams]);
  useEffect(() => {
    if (issuing) document.getElementById('source-credentials')?.scrollIntoView?.({ block: 'start' });
  }, [issuing]);

  const query = useQuery({
    queryKey: connectDetailQueryKey(logSourceId),
    queryFn: () => api.logSourceConnect.getStatus(logSourceId),
    refetchInterval: 30_000,
    retry: 1,
  });
  const endpoint = useQuery({
    queryKey: INGEST_ENDPOINT_QUERY_KEY,
    queryFn: () => api.getIngestEndpoint(),
    enabled: issuing,
    staleTime: 60 * 1000,
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.ingestTokens.revoke(id),
    onSuccess: (token) => {
      toast({ title: 'Token revoked', description: `${token.name} is refused within a few seconds.` });
      void queryClient.invalidateQueries({ queryKey: connectDetailQueryKey(logSourceId) });
      void queryClient.invalidateQueries({ queryKey: CONNECT_STATUS_QUERY_KEY });
      void queryClient.invalidateQueries({ queryKey: INGEST_TOKENS_QUERY_KEY });
    },
    onError: (err) => toast({ title: 'Could not revoke', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' }),
  });

  // Enrichment sources have no connect state (404): no ingest path to show.
  if (query.error instanceof ApiClientError && query.error.status === 404) return null;
  const detail = query.data;
  if (detail && !detail.push_capable) return null;
  const writers = (detail?.tokens ?? []).filter((t) => t.state !== 'revoked');
  const slug = detail?.route_key ?? '';
  const issuable = canIssue && issuableSlugs([slug]).length === 1;
  const source: AddDataSource | null = detail
    ? { slug, protocols: [...DIRECT_PROTOCOLS], enrolled: true, logSource: undefined, events24h: detail.events_24h, lastEventAt: detail.last_seen ?? null }
    : null;

  return (
    <div id="source-credentials" className="rounded-md border border-border bg-card" data-testid="source-writers">
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 px-4 py-2 border-b border-border">
        <span className="font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Credentials</span>
        <span className="text-[12px] font-semibold text-foreground">Can write this source</span>
        <span className="font-mono text-[11px] px-1.5 py-px rounded-[3px] bg-muted text-muted-foreground tabular-nums">
          {detail ? writers.length : '—'}
        </span>
        <span className="flex-1" />
        {slug && (
          <span className="font-mono text-[10.5px] text-muted-foreground truncate">
            source_type <span className="text-primary">{slug}</span>
          </span>
        )}
        {issuable && !issuing && (
          <button
            type="button"
            onClick={() => setIssuing(true)}
            data-testid="source-writers-issue"
            className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md border border-border text-[11.5px] font-medium text-foreground hover:bg-muted"
          >
            <Plus className="w-3.5 h-3.5" strokeWidth={1.5} /> Add credential / ingest path
          </button>
        )}
      </div>

      {issuing && source && (
        <div className="border-b border-border px-4 py-3 space-y-2" data-testid="source-writers-issue-panel">
          <div className="flex items-center gap-2">
            <span className="text-[12px] font-medium text-foreground">Issue an ingest token for this source</span>
            <span className="flex-1" />
            <Button variant="ghost" size="sm" className="h-6 px-1.5" aria-label="Close" onClick={() => setIssuing(false)}>
              <X className="w-3.5 h-3.5" strokeWidth={1.5} />
            </Button>
          </div>
          {endpoint.data ? (
            <IssueCredentialPanel endpoint={endpoint.data} source={source} logSourceId={logSourceId} searchField={searchField} />
          ) : endpoint.error ? (
            <div className="text-[11.5px] text-red-500" role="alert">Could not load the ingest endpoint: {endpoint.error.message}</div>
          ) : (
            <div className="flex items-center gap-2 text-[11.5px] text-muted-foreground"><LoadingIcon className="w-3.5 h-3.5" /> Loading your ingest endpoint…</div>
          )}
        </div>
      )}

      {query.isLoading ? (
        <div className="flex items-center gap-2 px-4 py-3 text-[11.5px] text-muted-foreground">
          <LoadingIcon className="w-3.5 h-3.5" /> Loading credentials…
        </div>
      ) : query.error ? (
        <div className="px-4 py-3 text-[11.5px] text-red-500" role="alert">Credentials unavailable: {query.error.message}</div>
      ) : writers.length === 0 ? (
        <div className="flex items-center gap-2 px-4 py-3 text-[11.5px] text-muted-foreground">
          <span>No active token can write this source.</span>
          {issuable && !issuing && (
            <button type="button" className="text-primary hover:underline" onClick={() => setIssuing(true)}>Issue one</button>
          )}
          {!canIssue && <span>Issuing needs <span className="font-mono">{ISSUE_TOKEN_PERMISSION}</span>.</span>}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left min-w-[720px]" data-testid="source-writers-table">
            <thead>
              <tr className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">
                <th className="px-4 py-2 font-semibold">Name</th>
                <th className="px-4 py-2 font-semibold">Token</th>
                <th className="px-4 py-2 font-semibold">State</th>
                <th className="px-4 py-2 font-semibold">Last used</th>
                <th className="px-4 py-2 font-semibold">Requests</th>
                <th className="px-4 py-2 font-semibold text-right" />
              </tr>
            </thead>
            <tbody>
              {writers.map((w) => (
                <tr key={w.credential_id} className="border-t border-border text-[11.5px] hover:bg-muted/30">
                  <td className="px-4 py-1.5 font-mono text-foreground truncate max-w-[260px]" title={w.name}>{w.name}</td>
                  <td className="px-4 py-1.5 font-mono text-[11px] text-muted-foreground">{w.token_prefix}…</td>
                  <td className="px-4 py-1.5">
                    <span className={cn('inline-flex items-center h-4 px-1.5 rounded-sm border font-mono text-[9.5px]', STATE_TONE[w.state])}>{w.state}</span>
                  </td>
                  <td className="px-4 py-1.5 font-mono text-[10.5px] text-muted-foreground" title={w.last_used_at ? formatUTC(w.last_used_at) : undefined}>
                    {w.last_used_at ? formatRelativeCompact(w.last_used_at) : 'never'}
                  </td>
                  <td className="px-4 py-1.5 font-mono text-[11px] tabular-nums text-foreground/80">{(w.request_count ?? 0).toLocaleString()}</td>
                  <td className="px-4 py-1.5 text-right">
                    {canRevoke && w.revocable && (
                      <button
                        type="button"
                        onClick={() => setRevokeTarget(w)}
                        className="inline-flex items-center gap-1.5 h-6 px-2 rounded-md border border-red-500/30 text-[11.5px] font-medium text-red-500 hover:bg-red-500/10"
                      >
                        <ShieldOff className="w-3.5 h-3.5" strokeWidth={1.5} /> Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ConfirmDialog
        open={!!revokeTarget}
        onOpenChange={(open) => { if (!open) setRevokeTarget(null); }}
        title={`Revoke ${revokeTarget?.name ?? 'token'}?`}
        description="Senders using this token are refused within a few seconds. This cannot be undone; issue a new token to reconnect them."
        confirmLabel="Revoke token"
        variant="danger"
        onConfirm={() => { if (revokeTarget) revoke.mutate(revokeTarget.credential_id); setRevokeTarget(null); }}
      />
    </div>
  );
}
