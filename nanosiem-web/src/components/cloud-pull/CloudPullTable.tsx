// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Cloud pull → sources (NAN-3596 / NAN-3598 / NAN-3604). A row is `verifying`
 * until nano's broker has assumed the role and read the queue attributes (AWS),
 * read the subscription (GCP), or signed in as the tenant's Entra app and
 * reached the checkpoint container (Azure), then `deploying` until
 * the tenant's pull container runs it. The failure reason sits on the row;
 * a `failed` row offers "Retry verification" (NAN-3618) once the customer has
 * fixed the cause, instead of waiting for the reconciler's periodic re-probe.
 * NAN-3729: AWS and Azure rows offer "Rotate credential" (role / Entra app),
 * edited in place: the row re-verifies and turns active again, no delete.
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { KeyRound, Pause, Play, RotateCw, Trash2 } from 'lucide-react';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { usePullSourceAction, useUpdatePullSourceCredential, type PullSourceAction } from '@/hooks/use-pull-sources';
import type { PullSource, PullSourceState, UpdatePullSourceRequest } from '@/lib/api/pull-sources';
import { PROVIDER_LABEL, pullCredentialEditable, pullRowActions, pullStateLabel, pullTarget, STATE_LABEL, type PullParser } from '@/lib/cloud-pull';
import { formatRelativeCompact, formatUTC } from '@/lib/date-utils';
import { pullErrorHint } from '@/lib/delivery-health';
import { cn } from '@/lib/utils';
import { CloudPullCredentialDialog } from './CloudPullCredentialDialog';

const STATE_TONE: Record<PullSourceState, string> = {
  active: 'text-emerald-500 border-emerald-500/40',
  pending_verification: 'text-amber-500 border-amber-500/40',
  pending_bundle: 'text-amber-500 border-amber-500/40',
  failed: 'text-red-500 border-red-500/40',
  paused: 'text-muted-foreground border-border',
};

const BLOCKED_TONE = 'text-orange-500 border-orange-500/40';

export function PullStateBadge({ state, lastError }: { state: PullSourceState; lastError?: string | null }) {
  const label = pullStateLabel(state, lastError);
  const blocked = label === 'blocked';
  return (
    <span
      data-testid="pull-state"
      title={blocked ? `${STATE_LABEL[state] ?? state}, blocked by the error shown on this row` : undefined}
      className={cn('inline-flex items-center h-4 px-1.5 rounded-sm border font-mono text-[10px]', blocked ? BLOCKED_TONE : (STATE_TONE[state] ?? 'text-muted-foreground border-border'))}
    >
      {label}
    </span>
  );
}

function azureTitle(a: NonNullable<PullSource['azure']>): string {
  return [
    `${a.namespace}.servicebus.windows.net/${a.event_hub}`,
    `consumer group ${a.consumer_group}`,
    `directory ${a.directory_id}`,
    `app ${a.client_id}`,
    a.checkpoint_account ? `checkpoints ${a.checkpoint_account}/${a.checkpoint_container ?? ''}` : null,
  ].filter(Boolean).join('\n');
}

const ACTION_BTN = 'inline-flex items-center gap-1 h-6 px-2 rounded border border-border text-[11px] hover:bg-accent disabled:opacity-50';

/**
 * `pipelineFor` maps a lane label to the pipeline (log source id) that runs
 * it, so the Parser cell links to that pipeline's editor (NAN-3621).
 * `parserFor` (NAN-3657 / NAN-3658) names the parser a source feeds and
 * whether it is deployed: a source whose parser is not deployed pulls into
 * nothing, so the row says so.
 */
export function CloudPullTable({ sources, pipelineFor, parserFor }: {
  sources: PullSource[];
  pipelineFor?: (slug: string) => string | undefined;
  parserFor?: (slug: string) => PullParser;
}) {
  const { hasPermission } = useAuth();
  // Pause / resume / retry all require log_sources:edit on the server
  // (shared_pull_sources.rs fence + identity gate).
  const canEdit = hasPermission('log_sources:edit');
  const canDelete = hasPermission('log_sources:delete');
  const { toast } = useToast();
  const action = usePullSourceAction();
  const [target, setTarget] = useState<PullSource | null>(null);
  // NAN-3729: the row whose credential is being rotated, and a refusal to show in the dialog.
  const [editing, setEditing] = useState<PullSource | null>(null);
  const [editError, setEditError] = useState<string | null>(null);
  const edit = useUpdatePullSourceCredential();
  const openEdit = (source: PullSource | null) => { setEditError(null); setEditing(source); };
  const saveCredential = (source: PullSource, body: UpdatePullSourceRequest) =>
    edit.mutate({ id: source.id, body }, {
      onSuccess: (updated) => {
        openEdit(null);
        toast({
          title: updated.state === 'paused' ? 'Credential updated' : 'Re-verifying with the new credential',
          description: updated.state === 'paused'
            ? `${source.name} stays paused and re-verifies when resumed.`
            : `${source.name}: verifying → deploying → active. It pulls again once active.`,
        });
      },
      onError: (err) => setEditError(err.message),
    });

  const run = (source: PullSource, kind: PullSourceAction) =>
    action.mutate({ id: source.id, action: kind }, {
      onSuccess: () => {
        if (kind === 'delete') toast({ title: 'Pull source deleted', description: `${source.name} stops pulling once the pull container reloads.` });
        if (kind === 'retry') toast({ title: 'Verification queued', description: `${source.name} is back in verification.` });
      },
      onError: (err) => toast({ title: `Could not ${kind === 'retry' ? 'retry verification for' : kind} ${source.name}`, description: err.message, variant: 'destructive' }),
    });
  const busyId = action.isPending ? action.variables?.id : undefined;

  return (
    <div className="rounded-md border border-border overflow-hidden">
      <table className="w-full text-left" data-testid="cloud-pull-table">
        <thead className="bg-card/60 border-b border-border">
          <tr className="h-7 text-[10px] font-mono uppercase tracking-[0.1em] text-muted-foreground">
            <th className="px-2 font-normal">Name</th>
            <th className="px-2 font-normal">Parser</th>
            <th className="px-2 font-normal">Provider</th>
            <th className="px-2 font-normal">Target</th>
            <th className="px-2 font-normal">State</th>
            <th className="px-2 font-normal">Last error</th>
            <th className="px-2 font-normal">Verified</th>
            <th className="px-2 font-normal text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {sources.length === 0 && (
            <tr>
              <td colSpan={8} className="px-3 py-6 text-center text-[11.5px] text-muted-foreground">
                No cloud pull sources yet. Finish the setup above, then add a source.
              </td>
            </tr>
          )}
          {sources.map((s) => {
            const queue = pullTarget(s);
            const queueTitle = s.gcp?.service_account ? `${queue}\nread as ${s.gcp.service_account}`
              : s.azure ? azureTitle(s.azure)
                : queue;
            // NAN-3661: AWS, GCP, Azure and reconciler codes all get an actionable hint.
            const hint = pullErrorHint(s.last_error).hint;
            const busy = busyId === s.id;
            const actions = pullRowActions(s.state);
            const pipeline = pipelineFor?.(s.source_slug);
            const parser = parserFor?.(s.source_slug);
            return (
              <tr key={s.id} data-testid={`pull-row-${s.id}`}
                className={cn('h-7 border-b border-border/60 last:border-b-0 text-[12px] align-middle', s.state === 'paused' && 'text-muted-foreground')}>
                <td className="px-2 text-foreground truncate max-w-[200px]" title={s.name}>{s.name}</td>
                <td className="px-2 py-0.5 max-w-[220px]" data-testid="pull-parser">
                  {parser?.name && <div className="truncate text-[11.5px] text-foreground" title={parser.name} data-testid="pull-parser-name">{parser.name}</div>}
                  <div className="font-mono text-[11px]" data-testid="pull-lane">
                    {pipeline ? (
                      <Link className="hover:underline" to={`/ingestion/pipelines/${encodeURIComponent(pipeline)}`} title="Open this lane's pipeline">{s.source_slug}</Link>
                    ) : s.source_slug}
                  </div>
                  {parser?.deployed === false && (
                    <div className="font-mono text-[10.5px] text-orange-500" data-testid="pull-parser-missing"
                      title={`No ${s.source_slug} parser is deployed on this tenant, so nothing pulled by this source is parsed. Deploy it under Log sources.`}>
                      not deployed
                    </div>
                  )}
                </td>
                <td className="px-2 font-mono text-[11px]" title={s.provider}>{PROVIDER_LABEL[s.provider] ?? s.provider}</td>
                <td className="px-2 font-mono text-[10.5px] truncate max-w-[260px]" title={queueTitle} data-testid="pull-target">
                  {queue || '—'}
                  {s.aws?.bucket && <span className="text-muted-foreground"> · s3://{s.aws.bucket}/{s.aws.prefix ?? ''}</span>}
                  {s.azure && <span className="text-muted-foreground"> · {s.azure.consumer_group || '$Default'}</span>}
                </td>
                <td className="px-2"><PullStateBadge state={s.state} lastError={s.last_error} /></td>
                <td className="px-2 py-1 text-[11px] text-muted-foreground max-w-[320px] break-words" data-testid="pull-last-error">
                  {s.last_error || <span className="font-mono">—</span>}
                  {hint && <div className="mt-0.5 text-foreground/80" data-testid="pull-error-hint">{hint}</div>}
                </td>
                <td className="px-2 font-mono text-[10.5px] whitespace-nowrap">
                  {s.verified_at ? (
                    <span title={formatUTC(s.verified_at)}>{formatRelativeCompact(s.verified_at)}</span>
                  ) : (
                    <span className="text-muted-foreground">never</span>
                  )}
                </td>
                <td className="px-2 text-right whitespace-nowrap">
                  <span className="inline-flex items-center gap-1">
                    {canEdit && actions.includes('retry') && (
                      <button type="button" className={ACTION_BTN} disabled={busy} onClick={() => run(s, 'retry')} aria-label={`Retry verification for ${s.name}`}>
                        <RotateCw className="w-3 h-3" strokeWidth={1.5} /> Retry verification
                      </button>
                    )}
                    {canEdit && actions.includes('resume') && (
                      <button type="button" className={ACTION_BTN} disabled={busy} onClick={() => run(s, 'resume')} aria-label={`Resume ${s.name}`}>
                        <Play className="w-3 h-3" strokeWidth={1.5} /> Resume
                      </button>
                    )}
                    {canEdit && actions.includes('pause') && (
                      <button type="button" className={ACTION_BTN} disabled={busy} onClick={() => run(s, 'pause')} aria-label={`Pause ${s.name}`}>
                        <Pause className="w-3 h-3" strokeWidth={1.5} /> Pause
                      </button>
                    )}
                    {canEdit && pullCredentialEditable(s) && (
                      <button type="button" className={ACTION_BTN} disabled={busy || edit.isPending} onClick={() => openEdit(s)}
                        aria-label={`Rotate credential for ${s.name}`} title={s.aws ? 'Change the AWS role nano assumes' : 'Change the Entra app nano signs in as'}>
                        <KeyRound className="w-3 h-3" strokeWidth={1.5} /> Rotate credential
                      </button>
                    )}
                    {canDelete && actions.includes('delete') && (
                      <button type="button" className={cn(ACTION_BTN, 'text-red-500 hover:bg-red-500/10')} disabled={busy}
                        onClick={() => setTarget(s)} aria-label={`Delete ${s.name}`}>
                        <Trash2 className="w-3 h-3" strokeWidth={1.5} /> Delete
                      </button>
                    )}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <CloudPullCredentialDialog
        source={editing}
        busy={edit.isPending}
        serverError={editError}
        onSubmit={saveCredential}
        onOpenChange={(open) => { if (!open && !edit.isPending) openEdit(null); }}
      />
      <ConfirmDialog
        open={target !== null}
        onOpenChange={(open) => { if (!open) setTarget(null); }}
        title="Delete pull source"
        icon={<Trash2 className="w-4 h-4 text-red-500" strokeWidth={1.5} />}
        description={target ? (
          <>
            nano stops reading <span className="font-mono text-foreground break-all">{pullTarget(target) || target.name}</span>.
            Events already ingested stay searchable.{' '}
            {target.gcp
              ? 'The IAM binding on your subscription is not changed.'
              : target.azure
                ? 'Your app registration, its federated credential and role assignments are not changed.'
                : 'The role in your AWS account is not changed.'}
            {pullCredentialEditable(target) && (
              <> To change the {target.aws ? 'role' : 'app'}, use Rotate credential instead: a new source starts from now, so events queued in between are skipped.</>
            )}
          </>
        ) : null}
        confirmLabel="Delete"
        loadingLabel="Deleting…"
        variant="danger"
        loading={action.isPending && action.variables?.action === 'delete'}
        onConfirm={() => { if (target) run(target, 'delete'); setTarget(null); }}
      />
    </div>
  );
}
