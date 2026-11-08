// SPDX-License-Identifier: AGPL-3.0-or-later

import { AlertTriangle } from 'lucide-react';
import type { IngestEndpoint } from '@/lib/api/types';
import { INGEST_BASE_URL_ENV, isDevServerOrigin } from '@/lib/ingest-endpoint-origin';
import { cn } from '@/lib/utils';
import { CopyButton } from './CopyButton';

/**
 * This deployment's ingest endpoint (main's NAN-2593 card, re-backed for the
 * ClickHouse product by NAN-4922 on `GET /api/log-sources/ingest-endpoint`).
 * HTTP JSON and OTLP rows are the web edge (`<base>/ingest`, `<base>/otlp`);
 * the HEC row is Vector's HEC listener. `configured` is false when the origin
 * was inferred from this browser's address: the card says so, because a sender
 * elsewhere may need another name. A dev-server origin (Vite, NAN-4945) cannot
 * receive events at all, so the badge warns and names the variable to set.
 */
export function IngestEndpointCard({
  endpoint,
  highlight,
  protocol,
  signal = 'log',
}: {
  endpoint: IngestEndpoint;
  /** Emphasise the row for the chosen protocol. */
  highlight?: string;
  /** A linear onboarding step shows only the selected transport. */
  protocol?: string;
  signal?: string;
}) {
  const rows: Array<{ key: string; protocol?: string; label: string; value: string; title?: string }> = [
    { key: 'host', label: 'host', value: endpoint.hostname },
    { key: 'hec', protocol: 'hec', label: 'HEC', value: endpoint.hec_event_url, title: 'Vector HEC listener (authenticates the token itself)' },
    { key: 'nano_https', protocol: 'nano_https', label: 'HTTP JSON', value: endpoint.nano_https_url },
    {
      key: 'otlp_http',
      protocol: 'otlp_http',
      label: signal === 'metric' ? 'OTLP metrics' : signal === 'trace' ? 'OTLP traces' : 'OTLP logs',
      value: signal === 'metric' ? endpoint.otlp_metrics_url : signal === 'trace' ? endpoint.otlp_traces_url : endpoint.otlp_logs_url,
    },
  ];
  const devServer = isDevServerOrigin(endpoint.base_url);
  const badge = devServer ? 'dev server' : endpoint.configured ? 'configured' : 'inferred';
  const badgeTitle = devServer
    ? `${endpoint.base_url} is a dev server: it does not serve /ingest or /otlp. Set ${INGEST_BASE_URL_ENV} to the ingest edge.`
    : endpoint.configured
      ? `From ${INGEST_BASE_URL_ENV} / BASE_URL`
      : `Inferred from this browser address; set ${INGEST_BASE_URL_ENV} (or BASE_URL) for senders elsewhere`;
  return (
    <div className="rounded-md border border-border bg-card" data-testid="ingest-endpoint-card">
      <div className="flex items-center gap-2 px-3 h-7 border-b border-border">
        <span className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/70">Your ingest endpoint</span>
        <span className="flex-1" />
        <span
          className={cn(
            'inline-flex items-center h-4 px-1.5 rounded-sm border font-mono text-[9.5px]',
            endpoint.configured && !devServer ? 'text-emerald-500 border-emerald-500/40' : 'text-amber-500 border-amber-500/40',
          )}
          title={badgeTitle}
          data-testid="ingest-endpoint-state"
        >
          {badge}
        </span>
      </div>
      {devServer && (
        <div className="flex items-start gap-2 px-3 py-1.5 border-b border-amber-500/30 bg-amber-500/[0.04] text-[11px] leading-relaxed" role="alert" data-testid="ingest-endpoint-dev-server">
          <AlertTriangle className="w-3 h-3 mt-0.5 text-amber-500 shrink-0" strokeWidth={1.5} />
          <span className="text-foreground/80">
            <span className="font-mono">{endpoint.base_url}</span> is a dev server: it does not serve{' '}
            <span className="font-mono">/ingest</span> or <span className="font-mono">/otlp</span>, so senders get an empty 404.
            Set <span className="font-mono">{INGEST_BASE_URL_ENV}</span> to the ingest edge
            (<span className="font-mono">scripts/local-stack.sh</span>: <span className="font-mono">http://localhost:18090</span>).
          </span>
        </div>
      )}
      <div className="divide-y divide-border/60">
        {rows.filter((r) => !protocol || !r.protocol || r.protocol === protocol).filter((r) => !protocol || r.key !== 'host').map((r) => (
          <div
            key={r.key}
            className={cn(
              'grid grid-cols-[88px_minmax(0,1fr)_auto] items-center gap-2 px-3 h-7',
              highlight && r.protocol === highlight && 'bg-primary/[0.06]',
            )}
          >
            <span className="text-[11px] text-muted-foreground" title={r.title}>{r.label}</span>
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
