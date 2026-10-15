// SPDX-License-Identifier: AGPL-3.0-or-later

import type { TenantIngestEndpoint } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { CopyButton } from './CopyButton';

const STATE_TONE: Record<string, string> = {
  ready: 'text-emerald-500 border-emerald-500/40',
  rolling: 'text-amber-500 border-amber-500/40',
  provisioning: 'text-amber-500 border-amber-500/40',
};

/** The tenant's real ingest endpoint (never a placeholder host). */
export function IngestEndpointCard({
  endpoint,
  highlight,
}: {
  endpoint: TenantIngestEndpoint;
  /** Emphasise the row for the chosen protocol. */
  highlight?: string;
}) {
  const rows: Array<{ key: string; protocol?: string; label: string; value: string }> = [
    { key: 'host', label: 'host', value: endpoint.hostname },
    { key: 'hec', protocol: 'hec', label: 'HEC', value: endpoint.hec_url },
    { key: 'nano_https', protocol: 'nano_https', label: 'HTTPS JSON', value: endpoint.nano_https_url },
    { key: 'otlp_http', protocol: 'otlp_http', label: 'OTLP logs', value: endpoint.otlp_logs_url },
  ];
  return (
    <div className="rounded-md border border-border bg-card" data-testid="ingest-endpoint-card">
      <div className="flex items-center gap-2 px-3 h-7 border-b border-border">
        <span className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/70">Your ingest endpoint</span>
        <span className="flex-1" />
        <span
          className={cn(
            'inline-flex items-center h-4 px-1.5 rounded-sm border font-mono text-[9.5px]',
            STATE_TONE[endpoint.endpoint_state] ?? 'text-muted-foreground border-border',
          )}
        >
          {endpoint.endpoint_state}
        </span>
      </div>
      <div className="divide-y divide-border/60">
        {rows.map((r) => (
          <div
            key={r.key}
            className={cn(
              'grid grid-cols-[88px_minmax(0,1fr)_auto] items-center gap-2 px-3 h-7',
              highlight && r.protocol === highlight && 'bg-primary/[0.06]',
            )}
          >
            <span className="text-[11px] text-muted-foreground">{r.label}</span>
            <span className="font-mono text-[11.5px] text-foreground truncate" title={r.value}>
              {r.value}
            </span>
            <CopyButton text={r.value} aria-label={`Copy ${r.label}`} />
          </div>
        ))}
      </div>
    </div>
  );
}
