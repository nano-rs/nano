// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * "Credentials that can write this source" (NAN-2597, design §2.5 "after
 * issuance"). Source credentials routed to it, collectors that allowlist it
 * (with the names an event may declare) and, for the Unattributed labels
 * (`unknown` / `default`), every collector. Each row links to its revoke
 * dialog on Log Sources → Credentials. Rows never carry a secret.
 *
 * NAN-2946: with `canIssue`, the card also links to Add data with the source
 * preselected ("Issue credential"), so a source with no writer is not a dead end.
 */

import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { AssignSourcePanel } from './AssignSourcePanel';
import type { TenantIngestCredential } from '@/lib/api/types';
import { addDataSources, INGEST_ENDPOINT_QUERY_KEY } from '@/lib/add-data-sources';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Plus, ShieldOff } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';

import { api } from '@/lib/api';
import type { TenantSourceWriters } from '@/lib/api/types';
import { PROTOCOL_LABEL, addDataLink, issuableSlugs, revokeLink, sourceWritersQueryKey } from '@/lib/add-data-sources';
import { describeIngestCredentialError } from '@/lib/ingest-credential-errors';
import { cn } from '@/lib/utils';

export function SourceWritersCard({
  logSourceId,
  sourceSlug,
  canRevoke,
  canIssue = false,
  compact,
  onRenameSource,
}: {
  /** Registry entry (Log Source detail): all of its lake labels. */
  logSourceId?: string;
  /** One lake label (Source Visibility). */
  sourceSlug?: string;
  canRevoke: boolean;
  /** Offer "Issue credential" (the caller holds `log_sources:deploy`). */
  canIssue?: boolean;
  /** Drop the card header (embedded in another panel). */
  compact?: boolean;
  onRenameSource?: () => void;
}) {
  const [selected, setSelected] = useState<TenantIngestCredential | null>(null);
  const endpoint = useQuery({ queryKey: INGEST_ENDPOINT_QUERY_KEY, queryFn: () => api.getIngestEndpoint(), enabled: !!selected });
  const registry = useQuery({ queryKey: ['add-data', 'log-sources'], queryFn: () => api.listLogSources(), enabled: !!selected });
  const query = useQuery<TenantSourceWriters>({
    queryKey: sourceWritersQueryKey({ logSourceId, sourceSlug }),
    queryFn: () => (logSourceId ? api.getLogSourceCredentials(logSourceId) : api.getSourceWriters(sourceSlug ?? '')),
    enabled: !!logSourceId || !!sourceSlug,
    staleTime: 30 * 1000,
  });
  const writers = query.data?.writers ?? [];
  // A registry entry with one lake label preselects it; several labels open
  // Add data on the source picker. Unattributed labels cannot be issued for.
  const slugs = issuableSlugs(query.data?.source_slugs ?? (sourceSlug ? [sourceSlug] : []));
  const issueHref = canIssue && slugs.length > 0 ? (slugs.length === 1 ? addDataLink(slugs[0]) : `${addDataLink()}?sources=${encodeURIComponent(slugs.join(','))}`) : null;
  const issueLink = issueHref ? (
    <Link
      to={issueHref}
      data-testid="source-writers-issue"
      className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md border border-border text-[11.5px] font-medium text-foreground hover:bg-muted"
    >
      <Plus className="w-3.5 h-3.5" strokeWidth={1.5} /> Add credential / ingest path
    </Link>
  ) : null;

  return (
    <div id="source-credentials" className="rounded-md border border-border bg-card" data-testid="source-writers">
      {!compact && (
        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 px-4 py-2 border-b border-border">
          <span className="font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Credentials</span>
          <span className="text-[12px] font-semibold text-foreground">Can write this source</span>
          <span className="font-mono text-[11px] px-1.5 py-px rounded-[3px] bg-muted text-muted-foreground tabular-nums">
            {query.data ? writers.length : '—'}
          </span>
          <span className="flex-1" />
          {query.data && query.data.source_slugs.length > 0 && (
            <span className="font-mono text-[10.5px] text-muted-foreground truncate">
              slug <span className="text-primary">{query.data.source_slugs.join(' · ')}</span>
            </span>
          )}
          {onRenameSource && <Button variant="outline" size="sm" onClick={onRenameSource}>Rename source</Button>}
          {issueLink}
        </div>
      )}
      {query.isLoading ? (
        <div className="flex items-center gap-2 px-4 py-3 text-[11.5px] text-muted-foreground">
          <LoadingIcon className="w-3.5 h-3.5" /> Loading credentials…
        </div>
      ) : query.error ? (
        <div className="px-4 py-3 text-[11.5px] text-red-500" role="alert">
          {describeIngestCredentialError(query.error).detail}
        </div>
      ) : writers.length === 0 ? (
        <div className="flex items-center gap-2 px-4 py-3 text-[11.5px] text-muted-foreground">
          <span>No active credential can write this source.</span>
          {issueHref && (
            <Link to={issueHref} className="text-primary hover:underline">
              Issue one
            </Link>
          )}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className={cn('w-full text-left', !compact && 'min-w-[860px]')} data-testid="source-writers-table">
            <thead>
              <tr className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">
                <th className="px-4 py-2 font-semibold">Label</th>
                <th className="px-4 py-2 font-semibold">Type</th>
                <th className="px-4 py-2 font-semibold">Protocol</th>
                <th className="px-4 py-2 font-semibold">Declared as</th>
                <th className="px-4 py-2 font-semibold">Credential</th>
                <th className="px-4 py-2 font-semibold text-right" />
              </tr>
            </thead>
            <tbody>
              {writers.map((w) => (
                <tr key={w.credential_id} className="border-t border-border text-[11.5px] hover:bg-muted/30">
                  <td className="px-4 py-1.5 font-mono text-foreground truncate max-w-[260px]" title={w.label}>
                    {w.label}
                  </td>
                  <td className="px-4 py-1.5 font-mono text-muted-foreground">{w.kind}</td>
                  <td className="px-4 py-1.5 text-foreground">{PROTOCOL_LABEL[w.protocol] ?? w.protocol}</td>
                  <td className="px-4 py-1.5">
                    {w.implicit ? (
                      <span className="text-muted-foreground">undeclared events ({w.writes.join(', ')})</span>
                    ) : w.declared_names.length > 0 ? (
                      <span className="flex flex-wrap gap-1">
                        {w.declared_names.map((n) => (
                          <span key={n} className="font-mono text-[11px] px-1.5 h-5 inline-flex items-center rounded-[3px] border border-border text-foreground/80">
                            {n}
                          </span>
                        ))}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">fixed by the token</span>
                    )}
                  </td>
                  <td className="px-4 py-1.5 font-mono text-[11px] text-muted-foreground truncate max-w-[300px]" title={w.credential_id}>
                    {w.credential_id}
                  </td>
                  <td className="px-4 py-1.5 text-right">
                    {canIssue && w.kind === 'source' && <Button variant="outline" size="sm" className="mr-2 h-6 text-[11.5px]" onClick={() => setSelected(w)}>Convert type / rename</Button>}
                    {canRevoke && w.revocable ? (
                      <Link
                        to={revokeLink(w.credential_id)}
                        className="inline-flex items-center gap-1.5 h-6 px-2 rounded-md border border-red-500/30 text-[11.5px] font-medium text-red-500 hover:bg-red-500/10"
                      >
                        <ShieldOff className="w-3.5 h-3.5" strokeWidth={1.5} /> Revoke
                      </Link>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Dialog open={!!selected} onOpenChange={(open) => { if (!open) setSelected(null); }}>
        <DialogContent><DialogHeader><DialogTitle>Convert type / rename credential</DialogTitle></DialogHeader>
          {selected && <AssignSourcePanel credentialId={selected.credential_id} initialLabel={selected.label}
            sources={addDataSources(endpoint.data, registry.data).filter((s) => s.protocols.includes(selected.protocol as 'hec' | 'nano_https' | 'otlp_http'))}
            onAssigned={() => { setSelected(null); void query.refetch(); }} />}
        </DialogContent>
      </Dialog>
    </div>
  );
}
