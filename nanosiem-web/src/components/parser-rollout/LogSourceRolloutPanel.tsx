// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * LogSourceDetail on hosted-shared (NAN-2607): the latest parser rollout of
 * this source, a short history, "Retry rollout" on a failed / rolled-back
 * rollout and a one-click revert to the previous published version (itself
 * a rollout).
 */

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Undo2 } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type { LogSourceVersion, TenantParserRollout } from '@/lib/api/types';
import { formatUTCCompact } from '@/lib/date-utils';
import {
  LOG_SOURCE_ROLLOUTS_QUERY_KEY,
  PARSER_ROLLOUTS_QUERY_KEY,
  failureStageLabel,
  previousVersion,
  rolloutStateLabel,
} from '@/lib/parser-rollout';
import { cn } from '@/lib/utils';
import { RolloutStrip } from './RolloutStrip';
import { useLogSourceRollouts } from './use-log-source-rollouts';

const EYEBROW = 'font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] text-muted-foreground';

function isBad(state: string) {
  return state === 'failed' || state === 'rolled_back';
}

function historySummary(r: TenantParserRollout): { label: string; tone: string } {
  if (r.state === 'failed') return { label: 'Last attempt failed', tone: 'text-red-500' };
  if (r.state === 'rolled_back') return { label: 'Last attempt rolled back', tone: 'text-red-500' };
  if (r.state === 'live') return { label: 'Last rollout live', tone: 'text-emerald-500' };
  return { label: rolloutStateLabel(r.state), tone: 'text-amber-500' };
}

export function LogSourceRolloutPanel({
  logSourceId,
  versions,
  onReverted,
}: {
  logSourceId: string;
  versions?: LogSourceVersion[];
  /** Called after a revert (so the page reloads the source / versions). */
  onReverted?: () => void;
}) {
  const { hasPermission } = useAuth();
  const canDeploy = hasPermission('log_sources:deploy');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [confirmRevert, setConfirmRevert] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const rollouts = useLogSourceRollouts(logSourceId);
  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: LOG_SOURCE_ROLLOUTS_QUERY_KEY(logSourceId) });
    void queryClient.invalidateQueries({ queryKey: PARSER_ROLLOUTS_QUERY_KEY });
  };
  const retry = useMutation({
    mutationFn: () => api.requestParserRollout(logSourceId, { reason: 'Retry from the log source page' }),
    onSuccess: () => {
      invalidate();
      toast({ title: 'Rollout requested', description: 'Rolling out to your parser cell.' });
    },
    onError: (err) => toast({ title: 'Retry failed', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' }),
  });
  const target = previousVersion(versions);
  const revert = useMutation({
    mutationFn: () => api.revertLogSourceVersion(logSourceId, target!.id),
    onSuccess: (version) => {
      setConfirmRevert(false);
      invalidate();
      onReverted?.();
      toast({
        title: `Reverted to v${target?.version_number}`,
        description: version.rollout ? 'Rolling out to your parser cell.' : `Saved as v${version.version_number}.`,
      });
    },
    onError: (err) => toast({ title: 'Revert failed', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' }),
  });

  const rows = rollouts.data ?? [];
  const latest = rows[0];
  const history = rows.slice(1);

  const revertButton =
    canDeploy && target ? (
      <button
        type="button"
        onClick={() => setConfirmRevert(true)}
        className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md border border-border text-[11.5px] font-medium text-foreground hover:bg-muted"
      >
        <Undo2 className="h-3.5 w-3.5" strokeWidth={1.5} /> Revert to v{target.version_number}
      </button>
    ) : null;

  const summary = history[0] ? historySummary(history[0]) : null;

  return (
    <section className="rounded-md border border-border bg-card" data-testid="log-source-rollouts">
      {!rollouts.isLoading && latest ? (
        <RolloutStrip
          bare
          eyebrow="Parser cell rollout"
          rollout={latest}
          action={revertButton}
          onRetry={canDeploy && isBad(latest.state) ? () => retry.mutate() : undefined}
          retrying={retry.isPending}
        />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2.5 px-4 py-2 border-b border-border">
            <span className={EYEBROW}>Parser cell rollout</span>
            <span className="flex-1" />
            {revertButton}
          </div>
          <div className="px-4 py-4 text-[11.5px] text-muted-foreground">
            {rollouts.isLoading ? (
              <span className="inline-flex items-center gap-2">
                <LoadingIcon className="h-3.5 w-3.5" strokeWidth={1.5} /> Loading rollouts…
              </span>
            ) : (
              'No rollouts yet. Publishing or deploying a custom parser rolls it out to your parser cell.'
            )}
          </div>
        </>
      )}

      {history.length > 0 && (
        <div className="border-t border-border">
          <button
            type="button"
            onClick={() => setHistoryOpen((v) => !v)}
            aria-expanded={historyOpen}
            className="w-full flex flex-wrap items-center gap-x-2.5 gap-y-1 px-4 py-2.5 text-left hover:bg-muted/40"
          >
            <span className={EYEBROW}>Previous rollouts</span>
            {summary && (
              <span className={cn('inline-flex items-center gap-1.5 text-[11.5px]', summary.tone)}>
                <span className="h-1.5 w-1.5 rounded-full bg-current" />
                <span>{summary.label}</span> · <span className="font-mono text-[10.5px] text-muted-foreground">{formatUTCCompact(history[0].requested_at)}</span>
              </span>
            )}
            <span className="flex-1" />
            <span className="font-mono text-[11px] text-muted-foreground">{historyOpen ? 'hide' : `show ${history.length}`}</span>
          </button>
          {historyOpen && (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px] text-left" data-testid="rollout-history">
                <thead>
                  <tr className="border-t border-border font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">
                    <th className="px-4 py-2 font-semibold w-[110px]">State</th>
                    <th className="px-4 py-2 font-semibold w-[110px]">Kind</th>
                    <th className="px-4 py-2 font-semibold w-[190px]">Requested</th>
                    <th className="px-4 py-2 font-semibold w-[90px]">Bundle</th>
                    <th className="px-4 py-2 font-semibold">Failure</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((r) => (
                    <tr key={r.id} className="border-t border-border align-top font-mono text-[11px]">
                      <td
                        className={cn(
                          'px-4 py-1.5',
                          r.state === 'live' && 'text-emerald-500',
                          isBad(r.state) && 'text-red-500',
                        )}
                      >
                        {rolloutStateLabel(r.state)}
                      </td>
                      <td className="px-4 py-1.5 text-foreground">{r.kind}</td>
                      <td className="px-4 py-1.5 text-muted-foreground" title={r.requested_at}>
                        {formatUTCCompact(r.requested_at)}
                      </td>
                      <td className="px-4 py-1.5 text-muted-foreground">{r.bundle_revision != null ? `r${r.bundle_revision}` : '—'}</td>
                      <td className="px-4 py-1.5">
                        {r.failure_reason ? (
                          <span
                            className="block rounded-[3px] border border-red-500/20 bg-red-500/[0.06] px-2 py-1 leading-[17px] text-red-700 dark:text-red-300 break-words"
                            title={r.failure_reason}
                          >
                            {`${failureStageLabel(r.failure_stage) ?? ''}${r.failure_component ? ` ${r.failure_component}` : ''}: ${r.failure_reason}`.trim()}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      <ConfirmDialog
        open={confirmRevert}
        onOpenChange={setConfirmRevert}
        title={`Revert to v${target?.version_number ?? ''}?`}
        description="The previous parser becomes a new version and rolls out to your parser cell. The current parser keeps serving until the revert is live."
        confirmLabel="Revert"
        loadingLabel="Reverting…"
        loading={revert.isPending}
        variant="warning"
        onConfirm={() => revert.mutate()}
      />
    </section>
  );
}
