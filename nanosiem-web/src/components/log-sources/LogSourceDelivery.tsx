// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Log Source → Delivery (main's NAN-3661 panel, re-backed for the ClickHouse
 * product by NAN-4922).
 *
 * Main listed the hosted pull-broker sources and connector feeds feeding the
 * source's lake lane (`/api/log-sources/{id}/pipe-inputs`). Here a source is
 * fed by ingest tokens pushed to Vector (NAN-4907) or by the source
 * configuration it is dispatched from (Kafka, S3/SQS, Pub/Sub, Event Hubs), so
 * the panel shows, from APIs this product already serves:
 *
 * - push: the bound tokens (active count, last request accepted);
 * - pull: the source configuration, whether it is enabled and deployed;
 * - accepted: events in the last 1 h / 24 h and the newest event (`/health`);
 * - collector errors: what the collector reported failing (NAN-2196), with
 *   the hint `/health` attaches. Data that never arrived shows up here, not as
 *   a parse failure.
 *
 * Connector feeds (NAN-4914, pull lane) join this panel once that backend lands.
 *
 * NAN-4941: push listener configurations (HTTP, Vector, OTLP, HEC routing
 * profiles) with a routing rule into this source are listed too, so a
 * user-editable listener is one click from the source it feeds.
 */

import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';

import { api, ApiClientError } from '@/lib/api';
import type { LogSourceHealth } from '@/lib/api/types';
import { connectDetailQueryKey } from '@/lib/api/log-source-connect';
import { INGEST_CREDENTIALS_PATH } from '@/lib/add-data-sources';
import { CLOUD_PULL_PATH, PROVIDER_LABEL, pullState } from '@/lib/cloud-pull';
import { isListenerConfigType, sourceConfigPath } from '@/lib/ingestion-paths';
import { useAuth } from '@/contexts/AuthContext';
import { formatCompactNumber, formatRelativeCompact, formatUTC } from '@/lib/date-utils';
import { cn } from '@/lib/utils';

const EYEBROW = 'font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground';

const STATE_TONE: Record<string, string> = {
  active: 'text-emerald-500 border-emerald-500/40',
  receiving: 'text-emerald-500 border-emerald-500/40',
  pending: 'text-amber-500 border-amber-500/40',
  idle: 'text-muted-foreground border-border',
  paused: 'text-muted-foreground border-border',
  failing: 'text-red-500 border-red-500/40',
};

function When({ at, never = 'never', testId }: { at: string | null | undefined; never?: string; testId?: string }) {
  return at ? (
    <span className="font-mono text-[10.5px]" title={formatUTC(at)} data-testid={testId}>{formatRelativeCompact(at)}</span>
  ) : (
    <span className="font-mono text-[10.5px] text-muted-foreground" data-testid={testId}>{never}</span>
  );
}

function StateBadge({ state }: { state: string }) {
  return (
    <span className={cn('inline-flex items-center h-4 px-1.5 rounded-sm border font-mono text-[9.5px]', STATE_TONE[state] ?? 'text-muted-foreground border-border')}>
      {state}
    </span>
  );
}

const LISTENER_LABEL: Record<string, string> = {
  http: 'HTTP listener',
  vector: 'Vector listener',
  otlp: 'OTLP listener',
  splunk_hec: 'HEC listener',
};

export function LogSourceDelivery({
  logSourceId,
  dispatchSourceConfigId,
  matchValues = [],
  health,
}: {
  logSourceId: string;
  /** The source's routing keys; a listener rule targeting one of them feeds it. */
  matchValues?: string[];
  /** The source configuration the source is dispatched from (pull transports), if any. */
  dispatchSourceConfigId?: string | null;
  health: LogSourceHealth | null | undefined;
}) {
  const connect = useQuery({
    queryKey: connectDetailQueryKey(logSourceId),
    queryFn: () => api.logSourceConnect.getStatus(logSourceId),
    refetchInterval: 30_000,
    retry: 1,
  });
  const config = useQuery({
    queryKey: ['source-configs', dispatchSourceConfigId],
    queryFn: () => api.getSourceConfig(dispatchSourceConfigId as string),
    enabled: !!dispatchSourceConfigId,
    staleTime: 30_000,
    retry: 1,
  });
  const { hasPermission } = useAuth();
  const listeners = useQuery({
    queryKey: ['source-configs', 'listener-routes', logSourceId, matchValues],
    queryFn: async () => {
      const configs = (await api.listSourceConfigs()).filter((c) => isListenerConfigType(c.config_type));
      const withRules = await Promise.all(
        configs.map(async (config) => ({ config, rules: await api.listRoutingRules(config.id).catch(() => []) })),
      );
      return withRules
        .filter(({ rules }) => rules.some((r) => matchValues.includes(r.target_source_type)))
        .map(({ config }) => config);
    },
    enabled: hasPermission('source_configs:view') && matchValues.length > 0,
    staleTime: 30_000,
    retry: 1,
  });
  const listenerConfigs = listeners.data ?? [];
  const detail = connect.error instanceof ApiClientError && connect.error.status === 404 ? undefined : connect.data;
  const tokens = (detail?.tokens ?? []).filter((t) => t.state === 'active');
  // Token use is sampled from Vector's counters (seconds behind); the rollup's
  // newest event is the other proof of delivery, so either one counts.
  const lastUsed = [...tokens.map((t) => t.last_used_at), detail && detail.events_24h > 0 ? detail.last_seen : null]
    .filter((x): x is string => !!x).sort().at(-1) ?? null;
  const pushState = !detail?.push_capable ? null : tokens.length === 0 ? 'idle' : lastUsed ? 'receiving' : 'pending';
  const errors = health?.collector_errors ?? [];
  const errors24h = health?.collector_errors_24h ?? 0;

  return (
    <section className="rounded-md border border-border bg-card" data-testid="log-source-delivery" aria-label="Delivery">
      <div className="flex items-center gap-2.5 px-4 py-2 border-b border-border">
        <span className="font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Delivery</span>
        <span className="text-[12px] font-semibold text-foreground">How events reach this source</span>
        <span className="flex-1" />
        {errors24h > 0 && (
          <span className="font-mono text-[10.5px] text-red-500" data-testid="delivery-errors-24h">{errors24h} collector errors 24h</span>
        )}
      </div>

      <table className="w-full text-left text-[11.5px]" data-testid="delivery-table">
        <thead>
          <tr className={EYEBROW}>
            <th className="px-4 py-1.5 font-semibold">Path</th>
            <th className="px-4 py-1.5 font-semibold">State</th>
            <th className="px-4 py-1.5 font-semibold">Last success</th>
            <th className="px-4 py-1.5 font-semibold">Detail</th>
          </tr>
        </thead>
        <tbody>
          {pushState && (
            <tr className="border-t border-border h-7" data-testid="delivery-row-push">
              <td className="px-4 py-1.5 text-foreground">Push · ingest tokens</td>
              <td className="px-4 py-1.5"><StateBadge state={pushState} /></td>
              <td className="px-4 py-1.5"><When at={lastUsed} testId="delivery-push-last" /></td>
              <td className="px-4 py-1.5 text-muted-foreground">
                <span className="font-mono text-[10.5px]">{tokens.length} active</span>
                {' · '}HEC / HTTP JSON / OTLP as <span className="font-mono text-[10.5px] text-foreground/80">source_type={detail?.route_key}</span>
                {' · '}<Link className="text-primary hover:underline" to={INGEST_CREDENTIALS_PATH}>Credentials</Link>
              </td>
            </tr>
          )}
          {dispatchSourceConfigId && (
            <tr className="border-t border-border h-7" data-testid="delivery-row-pull">
              <td className="px-4 py-1.5 text-foreground">
                Pull · {config.data ? (PROVIDER_LABEL[config.data.config_type] ?? config.data.config_type) : 'source configuration'}
              </td>
              <td className="px-4 py-1.5">
                {config.data ? <StateBadge state={errors.length > 0 && config.data.enabled ? 'failing' : pullState(config.data)} /> : <span className="font-mono text-[10.5px] text-muted-foreground">—</span>}
              </td>
              <td className="px-4 py-1.5"><When at={config.data?.last_event_at ?? health?.last_event_at ?? null} /></td>
              <td className="px-4 py-1.5 text-muted-foreground">
                {config.data ? (
                  <Link className="text-primary hover:underline" to={sourceConfigPath(config.data.id)}>{config.data.name}</Link>
                ) : config.error ? 'unavailable' : 'loading…'}
                {config.data && !config.data.deployed && <span className="ml-2 text-amber-500">not deployed</span>}
                {' · '}<Link className="text-primary hover:underline" to={CLOUD_PULL_PATH}>Cloud pull</Link>
              </td>
            </tr>
          )}
          {listenerConfigs.map((c) => (
            <tr key={c.id} className="border-t border-border h-7" data-testid="delivery-row-listener">
              <td className="px-4 py-1.5 text-foreground">Push · {LISTENER_LABEL[c.config_type] ?? c.config_type}</td>
              <td className="px-4 py-1.5"><StateBadge state={pullState(c)} /></td>
              <td className="px-4 py-1.5"><When at={c.last_event_at ?? null} /></td>
              <td className="px-4 py-1.5 text-muted-foreground">
                <Link className="text-primary hover:underline" to={sourceConfigPath(c.id)}>{c.name}</Link>
                {!c.deployed && <span className="ml-2 text-amber-500">not deployed</span>}
                {' · routing rule into this source'}
              </td>
            </tr>
          ))}
          {!pushState && !dispatchSourceConfigId && listenerConfigs.length === 0 && (
            <tr className="border-t border-border h-7">
              <td colSpan={4} className="px-4 py-1.5 text-muted-foreground">
                No push path or source configuration feeds this source.
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <div className="border-t border-border px-4 py-2 flex flex-wrap items-baseline gap-x-6 gap-y-1" data-testid="delivery-accepted">
        <span className={EYEBROW}>Accepted</span>
        <span className="font-mono text-[11px] tabular-nums">
          <span className="text-foreground" data-testid="delivery-accepted-1h">{formatCompactNumber(health?.events_last_hour ?? 0)}</span>
          <span className="text-muted-foreground"> 1h</span>
        </span>
        <span className="font-mono text-[11px] tabular-nums">
          <span className="text-foreground" data-testid="delivery-accepted-24h">{formatCompactNumber(health?.events_last_24h ?? 0)}</span>
          <span className="text-muted-foreground"> 24h</span>
        </span>
        <span className="font-mono text-[11px] text-muted-foreground">
          last event <When at={health?.last_event_at ?? null} />
        </span>
        {(health?.parse_errors_24h ?? 0) > 0 && (
          <span className="font-mono text-[11px] text-amber-500">{formatCompactNumber(health!.parse_errors_24h)} parse errors 24h</span>
        )}
      </div>

      {errors.length > 0 && (
        <div className="border-t border-border px-4 py-2 space-y-1.5" data-testid="delivery-collector-errors">
          <div className={EYEBROW}>Collector errors</div>
          {health?.collector_error_hint && (
            <div className="text-[11.5px] text-foreground/90" data-testid="delivery-error-hint">{health.collector_error_hint}</div>
          )}
          <ul className="space-y-0.5">
            {errors.slice(0, 5).map((e, i) => (
              <li key={`${e.timestamp}-${i}`} className="grid grid-cols-[88px_minmax(0,1fr)] gap-2 text-[11px]">
                <When at={e.timestamp} />
                <span className="min-w-0">
                  {e.error_code && <span className="font-mono text-[10.5px] text-red-500 mr-2" data-testid="delivery-error-code">{e.error_code}</span>}
                  <span className="text-muted-foreground [overflow-wrap:anywhere]">{e.message}</span>
                  <span className="font-mono text-[10px] text-muted-foreground/70 ml-2">{e.component_type} · {e.stage}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
