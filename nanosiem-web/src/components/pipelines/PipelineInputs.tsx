// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3621: the inputs whose events run this pipeline's steps. Push
 * credentials reach the tenant Worker; connector feeds post HEC to the same
 * Worker; cloud pull sources run the lane's steps in the pull container.
 * Each row links to the page that manages it.
 */

import { Link } from 'react-router-dom';
import { collectorPath, pipeInputCount, type PipeLaneInputs } from '@/lib/api/pipelines';
import { PROVIDER_LABEL } from '@/lib/cloud-pull';
import type { PullSourceProvider } from '@/lib/api/pull-sources';
import { formatRelativeCompact, formatUTC } from '@/lib/date-utils';
import { cn } from '@/lib/utils';

export const INGEST_CREDENTIALS_PATH = '/ingestion/log-sources/credentials';
export const CLOUD_PULL_PATH = '/ingestion/log-sources/cloud-pull';

const PUSH_KIND_LABEL: Record<string, string> = { http: 'HTTP', hec: 'HEC', otlp: 'OTLP' };
const TONE: Record<string, string> = {
  active: 'text-emerald-500 border-emerald-500/40',
  success: 'text-emerald-500 border-emerald-500/40',
  pending: 'text-amber-500 border-amber-500/40',
  pending_verification: 'text-amber-500 border-amber-500/40',
  pending_bundle: 'text-amber-500 border-amber-500/40',
  failed: 'text-red-500 border-red-500/40',
  timeout: 'text-red-500 border-red-500/40',
  lease_lost: 'text-amber-500 border-amber-500/40',
};

function StateTag({ state }: { state: string }) {
  return (
    <span className={cn('inline-flex h-4 items-center rounded-sm border px-1.5 font-mono text-[10px]', TONE[state] ?? 'border-border text-muted-foreground')}>
      {state.replace(/_/g, ' ')}
    </span>
  );
}

function When({ at, never = 'never' }: { at: string | null; never?: string }) {
  return at ? (
    <span className="font-mono text-[10.5px]" title={formatUTC(at)}>{formatRelativeCompact(at)}</span>
  ) : (
    <span className="font-mono text-[10.5px] text-muted-foreground">{never}</span>
  );
}

export interface PipelineInputsPanelProps {
  inputs: PipeLaneInputs | null | undefined;
  loading?: boolean;
  error?: string | null;
}

export function PipelineInputsPanel({ inputs, loading, error }: PipelineInputsPanelProps) {
  if (loading) return <p className="px-4 py-2 text-[11.5px] text-muted-foreground" role="status">Loading inputs…</p>;
  if (error) return <p className="px-4 py-2 text-[11.5px] text-destructive" role="alert">Inputs could not be loaded: {error}</p>;
  if (inputs === null) return <p className="px-4 py-2 text-[11.5px] text-muted-foreground">This deployment does not report pipeline inputs yet.</p>;
  if (!inputs) return null;
  if (inputs.source_slugs.length === 0)
    return <p className="px-4 py-2 text-[11.5px] text-muted-foreground">The default source has no lane label, so no input is bound to it.</p>;
  if (pipeInputCount(inputs) === 0)
    return (
      <p className="px-4 py-2 text-[11.5px] text-muted-foreground">
        No input writes <span className="font-mono">{inputs.source_slugs.join(', ')}</span> yet.{' '}
        <Link className="text-primary hover:underline" to={INGEST_CREDENTIALS_PATH}>Issue a credential</Link> or{' '}
        <Link className="text-primary hover:underline" to={CLOUD_PULL_PATH}>add a cloud pull source</Link>.
      </p>
    );
  return (
    <div className="overflow-x-auto" data-testid="pipeline-inputs">
      <table className="w-full min-w-[640px] table-fixed text-left text-[12px]">
        <thead>
          <tr className="h-6 border-b border-border font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            <th className="w-[12%] pl-4 font-medium">Kind</th>
            <th className="w-[30%] px-2 font-medium">Input</th>
            <th className="w-[14%] px-2 font-medium">Lane</th>
            <th className="w-[14%] px-2 font-medium">State</th>
            <th className="w-[12%] px-2 font-medium">Last activity</th>
            <th className="w-[18%] px-2 font-medium">Detail</th>
          </tr>
        </thead>
        <tbody>
          {inputs.push.map((input) => (
            <tr key={`push-${input.credential_id}`} className="h-7 border-b border-border/60" data-testid={`input-push-${input.credential_id}`}>
              <td className="pl-4 font-mono text-[10.5px]">push · {PUSH_KIND_LABEL[input.kind] ?? input.kind}</td>
              <td className="truncate px-2">
                <Link className="hover:underline" to={INGEST_CREDENTIALS_PATH} title={input.credential_id}>{input.label}</Link>
              </td>
              <td className="truncate px-2 font-mono text-[10.5px]">{input.writes.join(', ')}</td>
              <td className="px-2 font-mono text-[10.5px] text-muted-foreground">{input.credential_kind}{input.implicit ? ' · unattributed' : ''}</td>
              <td className="px-2"><When at={input.last_seen_at} /></td>
              <td className="truncate px-2 font-mono text-[10.5px] text-muted-foreground" title={input.credential_id}>{input.credential_id}</td>
            </tr>
          ))}
          {inputs.connectors.map((feed) => (
            <tr key={`feed-${feed.id}`} className="h-7 border-b border-border/60" data-testid={`input-connector-${feed.id}`}>
              <td className="pl-4 font-mono text-[10.5px]">connector</td>
              <td className="truncate px-2">
                <Link className="hover:underline" to={collectorPath(feed.connector)}>{feed.name}</Link>
                <span className="ml-1 font-mono text-[10px] text-muted-foreground">{feed.connector}</span>
              </td>
              <td className="truncate px-2 font-mono text-[10.5px]">{feed.source_slug}</td>
              <td className="px-2"><StateTag state={feed.status} /></td>
              <td className="px-2"><When at={feed.last_run_at} /></td>
              <td className="truncate px-2 text-[11px] text-muted-foreground" title={feed.last_error ?? undefined}>{feed.last_error ?? '—'}</td>
            </tr>
          ))}
          {inputs.pull.map((source) => (
            <tr key={`pull-${source.id}`} className="h-7 border-b border-border/60" data-testid={`input-pull-${source.id}`}>
              <td className="pl-4 font-mono text-[10.5px]">pull · {PROVIDER_LABEL[source.provider as PullSourceProvider] ?? source.provider}</td>
              <td className="truncate px-2">
                <Link className="hover:underline" to={CLOUD_PULL_PATH} title={source.id}>{source.name}</Link>
              </td>
              <td className="truncate px-2 font-mono text-[10.5px]">{source.source_slug}</td>
              <td className="px-2"><StateTag state={source.state} /></td>
              <td className="px-2 font-mono text-[10.5px] text-muted-foreground" title={`Configuration updated ${formatUTC(source.updated_at)}`}>
                updated {formatRelativeCompact(source.updated_at)}
              </td>
              <td className="truncate px-2 text-[11px] text-muted-foreground" title={source.last_error ?? undefined}>{source.last_error ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
