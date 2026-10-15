// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Ingestion → Credentials on dedicated / open-core deployments (NAN-3807):
 * status of OCSF bucket drop sources. A sender that already maps to OCSF
 * (Tenzir) writes files into its source folder in the install's object store;
 * the landing converter records each file it claims. Read-only: sources are
 * created and revoked by the `lean-landing-admin` CLI, which holds the
 * object-store admin rights the API does not have.
 */

import { Fragment, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ChevronDown, ChevronRight } from 'lucide-react';

import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { api } from '@/lib/api';
import {
  LANDING_SOURCES_QUERY_KEY,
  type LandingFile,
  type LandingSourceStatus,
} from '@/lib/api/landing-sources';
import { formatRelativeCompact } from '@/lib/date-utils';
import { cn } from '@/lib/utils';

export const ADD_LANDING_SOURCE_COMMAND = 'docker compose run --rm lean-landing-admin add --name <name>';
const RECENT_FILES = 25;

function shortTime(iso?: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 16).replace('T', ' ');
}

function count(n: number): string {
  return n.toLocaleString('en-US');
}

/** The object key below the source folder (`…/source=<id>/<tail>`), else its last 64 characters. */
export function keyTail(key: string): string {
  const marker = key.indexOf('/source=');
  if (marker >= 0) {
    const slash = key.indexOf('/', marker + 1);
    if (slash >= 0 && slash + 1 < key.length) return key.slice(slash + 1);
  }
  return key.length > 64 ? `…${key.slice(-64)}` : key;
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed';
}

function StateBadge({ state }: { state: string }) {
  const tone =
    state === 'active' || state === 'accepted'
      ? 'text-emerald-500 border-emerald-500/40'
      : state === 'refused'
        ? 'text-red-500 border-red-500/40'
        : state === 'claimed'
          ? 'text-amber-500 border-amber-500/40'
          : 'text-muted-foreground border-border';
  return <span className={cn('inline-flex items-center h-4 px-1.5 rounded-sm border font-mono text-[10px]', tone)}>{state}</span>;
}

function LastSeen({ at }: { at?: string | null }) {
  if (!at) return <span className="font-mono text-[10.5px] text-muted-foreground">never</span>;
  return (
    <span className="whitespace-nowrap">
      <span className="text-[11px] text-foreground">{formatRelativeCompact(at)}</span>{' '}
      <span className="font-mono text-[10.5px] text-muted-foreground">{shortTime(at)}</span>
    </span>
  );
}

function RecentFiles({ sourceId }: { sourceId: string }) {
  const files = useQuery({
    queryKey: [...LANDING_SOURCES_QUERY_KEY, sourceId, 'files'],
    queryFn: () => api.landingSources.files(sourceId, { limit: RECENT_FILES }),
    refetchInterval: 30_000,
  });
  if (files.isLoading) {
    return (
      <div className="flex items-center py-2 px-2">
        <LoadingIcon className="w-3.5 h-3.5 text-muted-foreground" />
      </div>
    );
  }
  if (files.error || !files.data) {
    return (
      <div className="px-2 py-1.5 text-[11px] text-red-500" role="alert">
        {errorText(files.error)}
      </div>
    );
  }
  if (files.data.files.length === 0) {
    return <div className="px-2 py-1.5 text-[11px] text-muted-foreground">No files landed yet.</div>;
  }
  return (
    <table className="w-full text-[11.5px]" data-testid="landing-files-table">
      <thead>
        <tr className="h-6 text-left text-[10px] uppercase tracking-wide text-muted-foreground">
          <th className="px-2 font-medium">Object</th>
          <th className="px-2 font-medium">State</th>
          <th className="px-2 font-medium text-right">Rows ok / refused</th>
          <th className="px-2 font-medium">Reason</th>
          <th className="px-2 font-medium">Seen (UTC)</th>
          <th className="px-2 font-medium">Finished (UTC)</th>
        </tr>
      </thead>
      <tbody>
        {files.data.files.map((file: LandingFile) => (
          <tr key={file.id} className="h-6 border-t border-border" data-testid="landing-file-row">
            <td className="px-2 font-mono text-[10.5px] max-w-[28rem] truncate" title={file.object_key}>
              {keyTail(file.object_key)}
            </td>
            <td className="px-2">
              <StateBadge state={file.state} />
            </td>
            <td className="px-2 font-mono text-[10.5px] text-right tabular-nums">
              {count(file.rows_accepted)} / {count(file.rows_refused)}
            </td>
            <td className="px-2 font-mono text-[10.5px] text-muted-foreground">{file.reason ?? '—'}</td>
            <td className="px-2 font-mono text-[10.5px] text-muted-foreground">{shortTime(file.first_seen_at)}</td>
            <td className="px-2 font-mono text-[10.5px] text-muted-foreground">{shortTime(file.finished_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SourceRow({ source }: { source: LandingSourceStatus }) {
  const [open, setOpen] = useState(false);
  const Chevron = open ? ChevronDown : ChevronRight;
  return (
    <Fragment>
      <tr className="h-7 border-b border-border last:border-b-0" data-testid="landing-source-row">
        <td className="px-1 w-6">
          <button
            type="button"
            className="flex items-center justify-center w-5 h-5 text-muted-foreground hover:text-foreground"
            aria-expanded={open}
            aria-label={open ? `Hide files for ${source.name}` : `Show files for ${source.name}`}
            onClick={() => setOpen((v) => !v)}
          >
            <Chevron className="w-3 h-3" strokeWidth={1.5} />
          </button>
        </td>
        <td className={cn('px-2', source.state === 'active' ? 'text-foreground' : 'text-muted-foreground')}>{source.name}</td>
        <td className="px-2 font-mono text-[10.5px]">{source.route_key}</td>
        <td className="px-2">
          <StateBadge state={source.state} />
        </td>
        <td className="px-2 font-mono text-[10.5px] text-right tabular-nums">
          {count(source.files_accepted)} / <span className={source.files_refused > 0 ? 'text-red-500' : undefined}>{count(source.files_refused)}</span>
          {source.files_in_progress > 0 && <span className="text-amber-500"> +{count(source.files_in_progress)}</span>}
        </td>
        <td className="px-2 font-mono text-[10.5px] text-right tabular-nums">
          {count(source.rows_accepted)} / <span className={source.rows_refused > 0 ? 'text-red-500' : undefined}>{count(source.rows_refused)}</span>
        </td>
        <td className="px-2">
          <LastSeen at={source.last_seen_at} />
        </td>
        <td className="px-2 font-mono text-[10.5px] text-muted-foreground" title={source.last_refusal_at ? shortTime(source.last_refusal_at) : undefined}>
          {source.last_refusal_reason ?? '—'}
        </td>
      </tr>
      {open && (
        <tr className="border-b border-border bg-muted/20">
          <td />
          <td colSpan={7} className="py-1">
            <RecentFiles sourceId={source.source_id} />
          </td>
        </tr>
      )}
    </Fragment>
  );
}

export function LandingSourcesPanel() {
  const list = useQuery({
    queryKey: LANDING_SOURCES_QUERY_KEY,
    queryFn: () => api.landingSources.list(),
    refetchInterval: 30_000,
  });

  return (
    <section className="space-y-2" data-testid="landing-sources-panel">
      <div className="flex items-center gap-3">
        <h2 className="text-[12.5px] font-medium text-foreground">Bucket drop sources (Tenzir)</h2>
        {list.data && (
          <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums">
            {list.data.sources.filter((s) => s.state === 'active').length} active · {list.data.sources.length} total
          </span>
        )}
      </div>

      {list.isLoading ? (
        <div className="flex items-center justify-center py-6">
          <LoadingIcon className="w-4 h-4 text-muted-foreground" />
        </div>
      ) : list.error || !list.data ? (
        <div className="text-[12px] text-red-500" role="alert">
          {errorText(list.error)}
        </div>
      ) : list.data.sources.length === 0 ? (
        <div className="border border-border px-3 py-2.5 text-[11.5px] text-muted-foreground space-y-1.5" data-testid="landing-sources-empty">
          <div>
            No bucket drop sources. A sender that already writes OCSF (for example Tenzir) can drop files straight into
            this install's object store. Add a source from the install host:
          </div>
          <code className="block rounded-sm border border-border bg-muted/40 px-2 py-1 font-mono text-[11px] text-foreground select-all">
            {ADD_LANDING_SOURCE_COMMAND}
          </code>
        </div>
      ) : (
        <table className="w-full border border-border text-[12px]">
          <thead>
            <tr className="h-7 border-b border-border text-left text-[10.5px] uppercase tracking-wide text-muted-foreground">
              <th className="px-1 w-6" />
              <th className="px-2 font-medium">Name</th>
              <th className="px-2 font-medium">Route key</th>
              <th className="px-2 font-medium">State</th>
              <th className="px-2 font-medium text-right">Files ok / refused</th>
              <th className="px-2 font-medium text-right">Rows ok / refused</th>
              <th className="px-2 font-medium">Last seen (UTC)</th>
              <th className="px-2 font-medium">Last refusal</th>
            </tr>
          </thead>
          <tbody>
            {list.data.sources.map((source) => (
              <SourceRow key={source.source_id} source={source} />
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
