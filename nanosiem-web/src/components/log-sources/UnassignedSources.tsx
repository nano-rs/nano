// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { Rss } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { LogSource, TenantIngestCredential } from '@/lib/api';
import { addDataSources, INGEST_CREDENTIALS_QUERY_KEY, INGEST_ENDPOINT_QUERY_KEY, PROTOCOL_LABEL } from '@/lib/add-data-sources';
import { logSourceSlugs } from '@/lib/log-source-lanes';
import { formatCompactNumber, formatRelativeCompact } from '@/lib/date-utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { AssignSourcePanel } from '@/components/add-data/AssignSourcePanel';

export function unassignedCredentials(credentials: TenantIngestCredential[], sources: LogSource[], query = '') {
  const claimed = new Set(sources.flatMap((s) => logSourceSlugs(s) ?? s.match_values ?? []));
  return credentials.filter((c) => c.state === 'active' && c.routes.some((r) => r.state === 'active' &&
    (r.source_slug === 'unknown' || r.source_slug === 'default' || !claimed.has(r.source_slug))))
    .filter((c) => `${c.label} ${c.source_slugs.join(' ')} unassigned needs a source type`.toLowerCase().includes(query.trim().toLowerCase()));
}

export function UnassignedSources({ sources, canAssign, query = '' }: { sources: LogSource[]; canAssign: boolean; query?: string }) {
  const credentials = useQuery({ queryKey: INGEST_CREDENTIALS_QUERY_KEY, queryFn: () => api.listIngestCredentials(), refetchInterval: 30_000 });
  const endpoint = useQuery({ queryKey: INGEST_ENDPOINT_QUERY_KEY, queryFn: () => api.getIngestEndpoint() });
  const [selected, setSelected] = useState<TenantIngestCredential | null>(null);
  const rows = unassignedCredentials(credentials.data?.credentials ?? [], sources, query);
  const targets = addDataSources(endpoint.data, sources);
  if (credentials.isError) return <tr><td colSpan={7} role="alert" className="px-4 py-2 text-destructive">Could not load unassigned sources. <Button variant="ghost" size="sm" onClick={() => void credentials.refetch()}>Retry</Button></td></tr>;
  if (!rows.length) return null;
  return <>
    {rows.map((c) => <tr key={c.credential_id} className="border-b border-border" data-testid="unassigned-sources">
      <td className="pl-4 py-3 align-top"><div className="flex items-start gap-3"><div className="w-[30px] h-[30px] rounded-md border border-border bg-foreground/[0.03] flex items-center justify-center shrink-0 mt-0.5"><Rss className="w-[13px] h-[13px] text-muted-foreground" /></div><div><div className="font-medium text-foreground">{c.label}</div><div className="font-mono text-muted-foreground">Needs a source type</div></div></div></td>
      <td className="py-3 align-top @max-[900px]/table:hidden"><span className="font-mono text-muted-foreground">{PROTOCOL_LABEL[c.protocol] ?? c.protocol}</span></td>
      <td className="py-3 align-top @max-[1100px]/table:hidden">—</td>
      <td className="py-3 align-top @max-[760px]/table:hidden"><div className="font-mono">{c.activity && !c.activity.redacted ? formatCompactNumber(c.activity.edge_events_24h ?? c.activity.lake_events_24h) : '—'}</div><div className="font-mono text-muted-foreground">{c.activity?.last_seen_at && !c.activity.redacted ? formatRelativeCompact(c.activity.last_seen_at) : '—'}</div></td>
      <td className="py-3 align-top"><Badge variant="outline">Unassigned</Badge></td>
      <td className="py-3 align-top"><span className="font-mono text-muted-foreground">Active</span></td>
      <td className="pr-3 py-3 align-top">{canAssign && c.kind === 'source' && <Button size="sm" variant="outline" onClick={() => setSelected(c)}>Assign source type</Button>}</td>
    </tr>)}
    <Dialog open={!!selected} onOpenChange={(open) => { if (!open) setSelected(null); }}>
      <DialogContent><DialogHeader><DialogTitle>Assign source type</DialogTitle></DialogHeader>
        {selected && <AssignSourcePanel key={selected.credential_id} credentialId={selected.credential_id} initialLabel={selected.label}
          sources={targets.filter((s) => !s.enrolled || s.protocols.includes(selected.protocol as 'hec' | 'nano_https' | 'otlp_http'))}
          onAssigned={() => setSelected(null)} />}
      </DialogContent>
    </Dialog>
  </>;
}
