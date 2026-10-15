// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3661: Log Source → Delivery. Every cloud pull source and connector feed
 * that delivers into this log source's lane (matched on its `source_slug`
 * labels by `GET /api/log-sources/{id}/pipe-inputs`), with its state, last
 * success, last error as a code plus an actionable hint, and the action that
 * fixes it: retry / resume in place (log_sources:edit), or a link to the Cloud
 * pull page or the Marketplace collector.
 *
 * Below the deliveries: rows accepted into the lake for this source in the
 * last 1 h / 24 h (the per-source counters behind `/health`), and (NAN-3680)
 * rows the lake refused at strict OCSF admission with the newest refusal's
 * reason and OCSF attribute. Refused rows are a delivery problem: the data
 * arrives and none of it is searchable. Lean lakes report them too (NAN-3662,
 * from the part log); a lake that does not report them is said so instead of
 * showing a zero.
 *
 * A pull that started point-forward (NAN-3604) skips the messages queued
 * before it was activated. That skip is intentional, so it is shown as a
 * neutral note on the pull row, never as an error or a refusal.
 */

import { Link } from 'react-router-dom';
import { Play, RotateCw } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { usePipeLaneInputs } from '@/hooks/use-pipe-inputs';
import { usePullSourceAction, usePullSourceAwsSetup, usePullSourceGcpSetup } from '@/hooks/use-pull-sources';
import { useToast } from '@/hooks/use-toast';
import { collectorPath, type PipeConnectorInput, type PipeLaneInputs, type PipePullInput } from '@/lib/api/pipelines';
import type { PullSourceProvider, PullSourceState } from '@/lib/api/pull-sources';
import { CLOUD_PULL_PATH, PROVIDER_LABEL, pullRowActions } from '@/lib/cloud-pull';
import { formatRelativeCompact, formatUTC } from '@/lib/date-utils';
import {
  attentionSummary,
  connectorAttention,
  hintNeedsAwsSetup,
  hintNeedsGcpSetup,
  pullAttention,
  pullErrorHint,
  worstAttention,
  type DeliveryAttention,
  type PullHintContext,
  type PullHintSetup,
} from '@/lib/delivery-health';
import { PullStateBadge } from '@/components/cloud-pull/CloudPullTable';
import type { LogSourceRefusalSample } from '@/lib/api/types';
import { hasRefusals, refusalCause, refusalSentence } from '@/lib/ingest-refusal';
import { cn } from '@/lib/utils';

const EYEBROW = 'font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground';
const ACTION_BTN = 'inline-flex items-center gap-1 h-6 px-2 rounded border border-border text-[11px] hover:bg-accent disabled:opacity-50';

const FEED_TONE: Record<string, string> = {
  success: 'text-emerald-500 border-emerald-500/40',
  pending: 'text-amber-500 border-amber-500/40',
  lease_lost: 'text-amber-500 border-amber-500/40',
  failed: 'text-red-500 border-red-500/40',
  timeout: 'text-red-500 border-red-500/40',
};

const LEVEL_TONE: Record<string, string> = {
  failed: 'text-red-500',
  blocked: 'text-orange-500',
  paused: 'text-muted-foreground',
};

export interface DeliveryHealth {
  events_last_hour?: number;
  events_last_24h?: number;
  last_event_at?: string | null;
  /** NAN-3680: rows refused at strict OCSF admission (24 h); null/absent = not recorded on this lake. */
  refused_events_24h?: number | null;
  last_refusal?: LogSourceRefusalSample | null;
}

function setupPath(setup: PullHintSetup): string | null {
  if (setup === 'aws' || setup === 'gcp' || setup === 'azure') return `${CLOUD_PULL_PATH}?provider=${setup}`;
  return null;
}

function When({ at, never = 'never', testId }: { at: string | null | undefined; never?: string; testId?: string }) {
  return at ? (
    <span className="font-mono text-[10.5px]" title={formatUTC(at)} data-testid={testId}>{formatRelativeCompact(at)}</span>
  ) : (
    <span className="font-mono text-[10.5px] text-muted-foreground" data-testid={testId}>{never}</span>
  );
}

function ErrorCell({ lastError, ctx }: { lastError: string | null | undefined; ctx: PullHintContext }) {
  if (!lastError) return <span className="font-mono text-[10.5px] text-muted-foreground">—</span>;
  const { code, hint, retriesAutomatically, setup } = pullErrorHint(lastError, ctx);
  const fix = setupPath(setup);
  return (
    <div className="min-w-0 py-1" data-testid="delivery-error">
      <div className="flex flex-wrap items-baseline gap-x-2">
        {code && <span className="font-mono text-[10.5px] text-red-500" data-testid="delivery-error-code">{code}</span>}
        {hint ? (
          <span className="text-[11.5px] text-foreground/90" data-testid="delivery-error-hint">{hint}</span>
        ) : (
          <span className="text-[11px] text-muted-foreground [overflow-wrap:anywhere]">{lastError}</span>
        )}
      </div>
      {hint && (
        <div className="mt-0.5 flex flex-wrap items-baseline gap-x-2 text-[10.5px] text-muted-foreground">
          {retriesAutomatically && <span>retrying automatically</span>}
          {fix && <Link className="text-primary hover:underline" to={fix}>Open {setup?.toUpperCase()} setup</Link>}
          <details className="inline">
            <summary className="cursor-pointer select-none">raw error</summary>
            <span className="font-mono [overflow-wrap:anywhere]" data-testid="delivery-error-raw">{lastError}</span>
          </details>
        </div>
      )}
    </div>
  );
}

/** "N pre-activation messages skipped (point-forward start)", or null when none (or not reported). */
export function skippedBacklogNote(count: number | null | undefined): string | null {
  if (typeof count !== 'number' || !(count > 0)) return null;
  return `${count.toLocaleString()} pre-activation ${count === 1 ? 'message' : 'messages'} skipped (point-forward start)`;
}

function PullRow({ source, ctx, canEdit }: { source: PipePullInput; ctx: PullHintContext; canEdit: boolean }) {
  const { toast } = useToast();
  const action = usePullSourceAction();
  const actions = pullRowActions(source.state as PullSourceState);
  const busy = action.isPending;
  const run = (kind: 'retry' | 'resume') =>
    action.mutate({ id: source.id, action: kind }, {
      onSuccess: () => toast({ title: kind === 'retry' ? 'Verification queued' : 'Pull resumed', description: `${source.name} is back in verification.` }),
      onError: (err) => toast({ title: `Could not ${kind === 'retry' ? 'retry verification for' : 'resume'} ${source.name}`, description: err.message, variant: 'destructive' }),
    });
  return (
    <tr className="border-b border-border/60 align-top text-[12px]" data-testid={`delivery-pull-${source.id}`}>
      <td className="py-1.5 pl-4 font-mono text-[10.5px] whitespace-nowrap">
        pull · {PROVIDER_LABEL[source.provider as PullSourceProvider] ?? source.provider}
      </td>
      <td className="truncate px-2 py-1.5">
        <Link className="hover:underline" to={CLOUD_PULL_PATH} title={source.id}>{source.name}</Link>
        <div className="font-mono text-[10px] text-muted-foreground">{source.source_slug}</div>
        {skippedBacklogNote(source.skipped_backlog) && (
          <div
            className="text-[10.5px] text-muted-foreground"
            data-testid="delivery-skipped-backlog"
            title="Messages already queued when this pull was activated were acknowledged without ingesting them. This is intentional, not loss."
          >
            {skippedBacklogNote(source.skipped_backlog)}
          </div>
        )}
      </td>
      <td className="px-2 py-1.5"><PullStateBadge state={source.state as PullSourceState} lastError={source.last_error} /></td>
      <td className="px-2 py-1.5" title="Last broker verification">
        <When at={source.verified_at} never="not verified" testId="delivery-last-success" />
      </td>
      <td className="px-2"><ErrorCell lastError={source.last_error} ctx={ctx} /></td>
      <td className="whitespace-nowrap py-1.5 pr-4 text-right">
        <span className="inline-flex items-center gap-1">
          {canEdit && actions.includes('retry') && (
            <button type="button" className={ACTION_BTN} disabled={busy} onClick={() => run('retry')} aria-label={`Retry verification for ${source.name}`}>
              <RotateCw className="h-3 w-3" strokeWidth={1.5} /> Retry
            </button>
          )}
          {canEdit && actions.includes('resume') && (
            <button type="button" className={ACTION_BTN} disabled={busy} onClick={() => run('resume')} aria-label={`Resume ${source.name}`}>
              <Play className="h-3 w-3" strokeWidth={1.5} /> Resume
            </button>
          )}
          <Link className={ACTION_BTN} to={CLOUD_PULL_PATH}>Cloud pull</Link>
        </span>
      </td>
    </tr>
  );
}

function FeedRow({ feed }: { feed: PipeConnectorInput }) {
  const status = feed.enabled ? feed.status : 'disabled';
  return (
    <tr className="border-b border-border/60 align-top text-[12px]" data-testid={`delivery-connector-${feed.id}`}>
      <td className="py-1.5 pl-4 font-mono text-[10.5px] whitespace-nowrap">connector</td>
      <td className="truncate px-2 py-1.5">
        <Link className="hover:underline" to={collectorPath(feed.connector)}>{feed.name}</Link>
        <div className="font-mono text-[10px] text-muted-foreground">{feed.connector} · {feed.source_slug}</div>
      </td>
      <td className="px-2 py-1.5">
        <span className={cn('inline-flex h-4 items-center rounded-sm border px-1.5 font-mono text-[10px]', FEED_TONE[status] ?? 'border-border text-muted-foreground')}>
          {status.replace(/_/g, ' ')}
        </span>
      </td>
      <td className="px-2 py-1.5"><When at={feed.last_success_at} testId="delivery-last-success" /></td>
      <td className="px-2 py-1.5 text-[11px]">
        {feed.last_error ? (
          <span className="text-foreground/90" data-testid="delivery-error-hint">
            {feed.last_error}. Open the collector to check its configuration and provider access.
          </span>
        ) : !feed.enabled ? (
          <span className="text-muted-foreground">Disabled. Enable it on the collector page to resume collection.</span>
        ) : (
          <span className="font-mono text-[10.5px] text-muted-foreground">—</span>
        )}
      </td>
      <td className="whitespace-nowrap py-1.5 pr-4 text-right">
        <Link className={ACTION_BTN} to={collectorPath(feed.connector)}>Collector</Link>
      </td>
    </tr>
  );
}

/** The panel body, separated from the data hooks for tests. */
export function LogSourceDeliveryPanel({
  inputs,
  loading,
  error,
  health,
  hintContext = {},
  canEdit,
}: {
  inputs: PipeLaneInputs | null | undefined;
  loading?: boolean;
  error?: string | null;
  health?: DeliveryHealth | null;
  hintContext?: PullHintContext;
  canEdit: boolean;
}) {
  const pulls = inputs?.pull ?? [];
  const feeds = inputs?.connectors ?? [];
  const attention: DeliveryAttention[] = [
    ...pulls.map(pullAttention),
    ...feeds.map(connectorAttention),
  ].filter((a): a is DeliveryAttention => a !== null);
  const worst = worstAttention(attention);
  const refused = health?.refused_events_24h;
  const refusedCause = refusalCause(health?.last_refusal);

  return (
    <div className="min-w-0 overflow-hidden rounded-md border border-border bg-card" data-testid="log-source-delivery">
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 border-b border-border px-4 py-2">
        <span className={EYEBROW}>Delivery</span>
        <div className="text-[12px] font-semibold text-foreground">Pull sources and connectors</div>
        <div className="flex-1" />
        {hasRefusals(refused) && (
          <span className="font-mono text-[10.5px] text-red-500" data-testid="delivery-refused-attention" title={refusalSentence(refused, health?.last_refusal) ?? undefined}>
            rows refused
          </span>
        )}
        {worst && (
          <span className={cn('font-mono text-[10.5px]', LEVEL_TONE[worst])} data-testid="delivery-attention" title={attentionSummary(attention).join('\n')}>
            {attention.length} {attention.length === 1 ? 'delivery' : 'deliveries'} {worst}
          </span>
        )}
      </div>

      {loading ? (
        <p className="px-4 py-2 text-[11.5px] text-muted-foreground" role="status">Loading deliveries…</p>
      ) : error ? (
        <p className="px-4 py-2 text-[11.5px] text-destructive" role="alert">Deliveries could not be loaded: {error}</p>
      ) : inputs === null ? (
        <p className="px-4 py-2 text-[11.5px] text-muted-foreground">This deployment does not report deliveries yet.</p>
      ) : pulls.length + feeds.length === 0 ? (
        <p className="px-4 py-2 text-[11.5px] text-muted-foreground" data-testid="delivery-empty">
          No cloud pull source or connector delivers into{' '}
          <span className="font-mono">{inputs?.source_slugs.join(', ') || 'this source'}</span>. Pushed events (HTTPS, HEC, OTLP) are listed under writers.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] table-fixed text-left">
            <thead>
              <tr className="h-6 border-b border-border font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="w-[11%] pl-4 font-medium">Kind</th>
                <th className="w-[19%] px-2 font-medium">Delivery</th>
                <th className="w-[10%] px-2 font-medium">State</th>
                <th className="w-[10%] px-2 font-medium">Last success</th>
                <th className="w-[34%] px-2 font-medium">Last error</th>
                <th className="w-[16%] pr-4 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {pulls.map((p) => <PullRow key={`pull-${p.id}`} source={p} ctx={hintContext} canEdit={canEdit} />)}
              {feeds.map((f) => <FeedRow key={`feed-${f.id}`} feed={f} />)}
            </tbody>
          </table>
        </div>
      )}

      <div className="grid grid-cols-[110px_minmax(0,1fr)] items-baseline gap-3 border-t border-border px-4 py-1.5 sm:grid-cols-[140px_minmax(0,1fr)]" data-testid="delivery-rows">
        <div className={EYEBROW}>Rows · lake</div>
        <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 text-[11.5px]">
          <span>
            <span className="text-muted-foreground">accepted 1h </span>
            <span className="font-mono tabular-nums" data-testid="delivery-accepted-1h">{health?.events_last_hour?.toLocaleString() ?? '—'}</span>
          </span>
          <span>
            <span className="text-muted-foreground">accepted 24h </span>
            <span className="font-mono tabular-nums" data-testid="delivery-accepted-24h">{health?.events_last_24h?.toLocaleString() ?? '—'}</span>
          </span>
          <span>
            <span className="text-muted-foreground">last accepted </span>
            <When at={health?.last_event_at} never="none" />
          </span>
          {typeof refused === 'number' ? (
            <span data-testid="delivery-refused-24h" title={refusalSentence(refused, health?.last_refusal) ?? undefined}>
              <span className="text-muted-foreground">refused 24h </span>
              <span className={cn('font-mono tabular-nums', refused > 0 && 'text-red-500')}>{refused.toLocaleString()}</span>
              {refused > 0 && refusedCause && (
                <span className="font-mono text-muted-foreground" data-testid="delivery-refused-cause"> ({refusedCause})</span>
              )}
            </span>
          ) : (
            <span className="text-muted-foreground" data-testid="delivery-refused-unrecorded">
              refused per source: not reported by this lake
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

/** Data-bound panel for the Log Source detail Overview. */
export function LogSourceDelivery({ logSourceId, health }: { logSourceId: string; health?: DeliveryHealth | null }) {
  const { hasPermission } = useAuth();
  const canView = hasPermission('log_sources:view');
  const inputs = usePipeLaneInputs(logSourceId, { enabled: canView });
  const pulls = inputs.data?.pull ?? [];
  // Setup values are fetched only when a hint names them (ExternalId, nano principal, service account).
  const needsAws = pulls.some((p) => p.provider.startsWith('aws') && hintNeedsAwsSetup(p.last_error));
  const needsGcp = pulls.some((p) => p.provider === 'gcp_pubsub' && hintNeedsGcpSetup(p.last_error));
  const aws = usePullSourceAwsSetup({ enabled: needsAws });
  const gcp = usePullSourceGcpSetup({ enabled: needsGcp });
  const hintContext: PullHintContext = {
    externalId: aws.data?.external_id ?? null,
    nanoPrincipalArn: aws.data?.nano_principal_arn ?? null,
    gcpServiceAccount: gcp.data?.service_account ?? null,
  };
  if (!canView) return null;
  return (
    <LogSourceDeliveryPanel
      inputs={inputs.data}
      loading={inputs.isLoading}
      error={inputs.error ? (inputs.error as Error).message : null}
      health={health}
      hintContext={hintContext}
      canEdit={hasPermission('log_sources:edit')}
    />
  );
}
