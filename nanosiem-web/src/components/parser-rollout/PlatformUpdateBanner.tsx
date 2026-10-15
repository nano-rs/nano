// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * "Platform update available" (decision a, NAN-2603/NAN-2607). A platform
 * release never overwrites a tenant's custom parser: when the tenant's
 * overlay failed on a new platform base (or the base changes a platform
 * parser the tenant customized), the tenant stays on its current bundle and
 * the platform records an offer. The tenant reviews the diff and merges on its
 * own action: a `merge_base` rollout rebuilds, validates and rolls it.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, ChevronDown, ChevronRight, GitMerge, Info } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type { TenantParserBaseOffer, TenantParserRollout } from '@/lib/api/types';
import {
  PARSER_BASE_OFFERS_QUERY_KEY,
  PARSER_ROLLOUT_QUERY_KEY,
  PARSER_ROLLOUTS_QUERY_KEY,
  failureErrorCode,
  failureOrigin,
  failureStageLabel,
  parserRollErrorMessage,
  isTerminal,
  rolloutPollInterval,
  shortSha,
} from '@/lib/parser-rollout';
import { cn } from '@/lib/utils';
import { RolloutStatus } from './RolloutStrip';

const VALIDATION_LABEL: Record<TenantParserBaseOffer['validation_state'], string> = {
  failed: 'your parsers fail on it',
  passed: 'builds with your parsers',
  untested: 'not tested yet',
};

/** Badge for the offer's validation state; a failure is only "your parsers fail" when a validation stage failed. */
function validationBadge(offer: TenantParserBaseOffer): string {
  if (offer.validation_state !== 'failed') return VALIDATION_LABEL[offer.validation_state] ?? offer.validation_state;
  const origin = failureOrigin(offer.failure_stage);
  return origin === 'validation' ? VALIDATION_LABEL.failed : origin === 'platform' ? 'platform roll failed' : 'merge failed';
}

export function PlatformUpdateBanner({ className }: { className?: string }) {
  const { hasPermission } = useAuth();
  const offers = useQuery({
    queryKey: PARSER_BASE_OFFERS_QUERY_KEY,
    queryFn: () => api.listParserBaseOffers(),
    staleTime: 30_000,
  });
  const open = offers.data?.find((o) => o.state === 'available' || o.state === 'merge_pending');
  if (!open) return null;
  return <OfferBanner offer={open} canMerge={hasPermission('log_sources:deploy')} className={className} />;
}

type FailureFields = Pick<TenantParserBaseOffer, 'failure_reason' | 'failure_component' | 'failure_stage'>;

function OfferBanner({ offer, canMerge, className }: { offer: TenantParserBaseOffer; canMerge: boolean; className?: string }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showDiff, setShowDiff] = useState(false);
  const [showDetails, setShowDetails] = useState(false);
  const [mergeRollout, setMergeRollout] = useState<TenantParserRollout | null>(null);
  const merge = useMutation({
    mutationFn: () => api.mergeParserBaseOffer(offer.id),
    onSuccess: (rollout) => {
      setMergeRollout(rollout);
      void queryClient.invalidateQueries({ queryKey: PARSER_BASE_OFFERS_QUERY_KEY });
      void queryClient.invalidateQueries({ queryKey: PARSER_ROLLOUTS_QUERY_KEY });
      toast({ title: 'Merge requested', description: 'The platform update is being rebuilt with your parsers and validated.' });
    },
    onError: (err) => {
      void queryClient.invalidateQueries({ queryKey: PARSER_BASE_OFFERS_QUERY_KEY });
      toast({ title: 'Merge failed', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    },
  });
  const pending = offer.state === 'merge_pending';
  const mergeRolloutId = mergeRollout?.id ?? offer.merge_request_id ?? undefined;
  // Same key as <RolloutStatus>, so React Query shares one fetch/poll.
  const mergeRun = useQuery({
    queryKey: PARSER_ROLLOUT_QUERY_KEY(mergeRolloutId ?? ''),
    queryFn: () => api.getParserRollout(mergeRolloutId as string),
    enabled: !!mergeRolloutId,
    initialData: mergeRollout && mergeRollout.id === mergeRolloutId ? mergeRollout : undefined,
    refetchInterval: (q) => rolloutPollInterval(q.state.data),
  }).data;
  const mergeRunBad = !!mergeRun && (mergeRun.state === 'failed' || mergeRun.state === 'rolled_back');
  const mergeRunMoving = !!mergeRun && !isTerminal(mergeRun);
  const failure: FailureFields | null = mergeRunBad
    ? mergeRun
    : offer.validation_state === 'failed' || offer.failure_reason || offer.failure_component
      ? offer
      : null;

  // NAN-3248: a failed / terminal offer is informational (the parsers stayed on
  // their current base); it collapses to one row so it never buries the source list.
  if (failure && !pending && !merge.isPending && !mergeRunMoving) {
    return (
      <CompactFailedOffer
        offer={offer}
        failure={failure}
        mergeRun={mergeRunBad ? mergeRun : undefined}
        canMerge={canMerge}
        onMerge={() => merge.mutate()}
        showDetails={showDetails}
        onToggleDetails={() => setShowDetails((v) => !v)}
        showDiff={showDiff}
        onToggleDiff={() => setShowDiff((v) => !v)}
        className={className}
      />
    );
  }

  return (
    <div className={cn('rounded-md border border-primary/40 bg-primary/[0.04]', className)} data-testid="platform-update-banner">
      <div className="flex flex-wrap items-center gap-2 px-3 py-1.5">
        <Info className="h-3.5 w-3.5 text-primary" strokeWidth={1.5} />
        <span className="text-[12.5px] font-medium text-foreground">Platform update available</span>
        <OfferRevision offer={offer} />
        <span className="inline-flex items-center h-4 px-1.5 rounded-sm border font-mono text-[9.5px] text-muted-foreground border-border">
          {validationBadge(offer)}
        </span>
        <span className="flex-1" />
        {pending ? (
          <span className="inline-flex items-center gap-1 text-[11.5px] text-amber-500" data-testid="merge-in-progress">
            <LoadingIcon className="h-3 w-3" strokeWidth={1.5} /> Merge in progress
          </span>
        ) : (
          canMerge && (
            <button
              type="button"
              onClick={() => merge.mutate()}
              disabled={merge.isPending}
              className="inline-flex items-center gap-1 h-6 px-2 rounded-sm border border-border bg-background text-[11.5px] hover:bg-muted disabled:opacity-50"
            >
              {merge.isPending ? <LoadingIcon className="h-3 w-3" strokeWidth={1.5} /> : <GitMerge className="h-3 w-3" strokeWidth={1.5} />}
              Merge
            </button>
          )
        )}
      </div>
      <div className="px-3 pb-2 space-y-1.5">
        <p className="text-[11.5px] text-muted-foreground">
          Your parser cell stays on your current parsers until you merge. Merging rebuilds your parsers on the new platform base,
          validates them and rolls them out; nothing changes if validation fails.
        </p>
        <ChangedSources offer={offer} />
        <DiffToggle offer={offer} open={showDiff} onToggle={() => setShowDiff((v) => !v)} />
        {mergeRolloutId && <RolloutStatus rolloutId={mergeRolloutId} initial={mergeRollout} compact />}
      </div>
    </div>
  );
}

function OfferRevision({ offer }: { offer: TenantParserBaseOffer }) {
  return (
    <span className="font-mono text-[10.5px] text-muted-foreground" title={`${offer.base_source_revision}\n${offer.base_content_sha256}`}>
      {/^[0-9a-f]{40}$/.test(offer.base_source_revision) ? offer.base_source_revision.slice(0, 12) : offer.base_source_revision} ·{' '}
      {shortSha(offer.base_content_sha256)}
    </span>
  );
}

function ChangedSources({ offer }: { offer: TenantParserBaseOffer }) {
  if (offer.changed_platform_sources.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-1 text-[11px]">
      <span className="text-muted-foreground">Changed base sources</span>
      {offer.changed_platform_sources.map((s) => (
        <span key={s} className="font-mono text-[10.5px] px-1 rounded-sm border border-border">{s}</span>
      ))}
    </div>
  );
}

/** One-line summary of a failure: the error code once, with its human message. */
function failureSummary(failure: FailureFields): { code: string | null; message: string } {
  const code = failureErrorCode(failure);
  const stage = failureStageLabel(failure.failure_stage);
  const known = parserRollErrorMessage(code);
  if (known) return { code, message: known };
  switch (failureOrigin(failure.failure_stage)) {
    case 'validation':
      return { code, message: `Your parsers fail on this base${stage ? ` (stage ${stage})` : ''}. Nothing changed.` };
    case 'platform':
      return { code, message: `The platform roll failed${stage ? ` at stage ${stage}` : ''}. Your parsers were not the problem and nothing changed.` };
    default:
      return { code, message: 'The merge did not complete. Your parsers stayed on their current base.' };
  }
}

function CompactFailedOffer({
  offer,
  failure,
  mergeRun,
  canMerge,
  onMerge,
  showDetails,
  onToggleDetails,
  showDiff,
  onToggleDiff,
  className,
}: {
  offer: TenantParserBaseOffer;
  failure: FailureFields;
  mergeRun?: TenantParserRollout;
  canMerge: boolean;
  onMerge: () => void;
  showDetails: boolean;
  onToggleDetails: () => void;
  showDiff: boolean;
  onToggleDiff: () => void;
  className?: string;
}) {
  const { code, message } = failureSummary(failure);
  const stage = failureStageLabel(failure.failure_stage);
  const validation = failureOrigin(failure.failure_stage) === 'validation';
  // Only show component / reason when they add something beyond the code.
  const component = failure.failure_component && failure.failure_component !== code ? failure.failure_component : null;
  const reason = failure.failure_reason && failure.failure_reason !== code ? failure.failure_reason : null;
  return (
    <div className={cn('rounded-md border border-border bg-card', className)} data-testid="platform-update-banner" data-compact="true">
      <div className="flex items-center gap-2 px-3 h-7 min-w-0 overflow-hidden" data-testid="offer-compact-row">
        <AlertTriangle className={cn('h-3.5 w-3.5 flex-none', validation ? 'text-red-500' : 'text-amber-500')} strokeWidth={1.5} />
        <span className="text-[12px] font-medium text-foreground whitespace-nowrap">Platform update not applied</span>
        <OfferRevision offer={offer} />
        {code && (
          <span className="font-mono text-[10.5px] text-red-500 whitespace-nowrap" data-testid="offer-error-code">
            {code}
          </span>
        )}
        <span className="min-w-0 flex-1 truncate text-[11.5px] text-muted-foreground" title={message} data-testid="offer-error-message">
          {message}
        </span>
        <button
          type="button"
          onClick={onToggleDetails}
          aria-expanded={showDetails}
          className="inline-flex flex-none items-center gap-1 text-[11.5px] text-primary hover:underline"
        >
          {showDetails ? <ChevronDown className="h-3 w-3" strokeWidth={1.5} /> : <ChevronRight className="h-3 w-3" strokeWidth={1.5} />}
          Details
        </button>
        {canMerge && (
          <button
            type="button"
            onClick={onMerge}
            className="inline-flex flex-none items-center gap-1 h-5 px-1.5 rounded-sm border border-border bg-background text-[11px] hover:bg-muted"
          >
            <GitMerge className="h-3 w-3" strokeWidth={1.5} />
            {mergeRun || offer.merge_request_id ? 'Retry merge' : 'Merge'}
          </button>
        )}
      </div>
      {showDetails && (
        <div className="border-t border-border px-3 py-2 space-y-1.5" data-testid="offer-details">
          <p className="text-[11.5px] text-muted-foreground">
            Informational: your parser cell stays on your current parsers until you merge. Merging rebuilds your parsers on the
            new platform base, validates them and rolls them out; nothing changes if it fails.
          </p>
          <div className="space-y-1" data-testid="offer-failure">
            <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px]">
              <span className={validation ? 'text-red-500' : 'text-amber-500'}>
                {validation ? 'Your parsers fail on this base' : 'Platform-side failure'}
              </span>
              {stage && <span className="font-mono text-[10.5px] text-muted-foreground">stage {stage}</span>}
              {component && <span className="font-mono text-[10.5px]">{component}</span>}
              {mergeRun && (
                <span className="font-mono text-[10.5px] text-muted-foreground" title={mergeRun.id}>
                  platform merge {shortSha(mergeRun.id, 8)} · {mergeRun.state.replace(/_/g, ' ')}
                </span>
              )}
            </div>
            {reason && (
              <pre className="max-h-32 overflow-auto rounded-sm border border-border bg-muted/40 px-2 py-1 font-mono text-[10.5px] whitespace-pre-wrap break-words">
                {reason}
              </pre>
            )}
          </div>
          <ChangedSources offer={offer} />
          <DiffToggle offer={offer} open={showDiff} onToggle={onToggleDiff} />
        </div>
      )}
    </div>
  );
}

function DiffToggle({ offer, open, onToggle }: { offer: TenantParserBaseOffer; open: boolean; onToggle: () => void }) {
  const diff = offer.diff ?? {};
  const fileLists: Array<[string, string[] | undefined]> = [
    ['platform files', diff.platform_files_changed],
    ['your overlay', diff.overlay_files_changed],
  ];
  return (
    <>
      <button
        type="button"
        onClick={onToggle}
        className="inline-flex items-center gap-1 text-[11.5px] text-primary hover:underline"
        aria-expanded={open}
      >
        {open ? <ChevronDown className="h-3 w-3" strokeWidth={1.5} /> : <ChevronRight className="h-3 w-3" strokeWidth={1.5} />}
        View diff
      </button>
      {open && (
        <div className="space-y-1.5" data-testid="offer-diff">
          {typeof diff.unified === 'string' && diff.unified.length > 0 ? (
            <>
              <pre className="max-h-80 overflow-auto rounded-sm border border-border bg-muted/40 px-2 py-1.5 font-mono text-[10.5px] leading-snug whitespace-pre">
                {diff.unified}
              </pre>
              {diff.truncated && <p className="text-[10.5px] text-muted-foreground">Diff truncated.</p>}
            </>
          ) : fileLists.some(([, files]) => files && files.length > 0) ? (
            fileLists.map(([label, files]) =>
              files && files.length > 0 ? (
                <div key={label} className="text-[11px]">
                  <span className="text-muted-foreground">{label}</span>
                  <ul className="mt-0.5 space-y-0.5">
                    {files.map((f) => (
                      <li key={f} className="font-mono text-[10.5px]">{f}</li>
                    ))}
                  </ul>
                </div>
              ) : null,
            )
          ) : (
            <p className="text-[11px] text-muted-foreground">No diff was recorded for this update.</p>
          )}
        </div>
      )}
    </>
  );
}
