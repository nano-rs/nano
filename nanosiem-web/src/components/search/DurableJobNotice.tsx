// SPDX-License-Identifier: AGPL-3.0-or-later

import { Clock, ExternalLink } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import type { SearchJobProgress, SearchJobStatusValue } from '@/lib/api/types';

export interface DurableProductJobState {
  jobId: string;
  status: SearchJobStatusValue;
  queuePosition?: number;
  estimatedWaitSeconds?: number;
  progress?: SearchJobProgress;
}

/**
 * Shared notice for product views that auto-escalate exact work to the durable
 * Search Jobs lane. Queue ownership, cancellation, persistence, and reopening
 * remain in the existing Jobs UI; this component only makes the handoff
 * explicit at the point where it happened.
 */
export function DurableJobNotice({
  job,
  onOpenJobs,
  detail,
}: {
  job: DurableProductJobState;
  onOpenJobs?: () => void;
  /** Why this view ran as a job, replacing the generic "exceeded the
   * interactive lane" line (e.g. a retro hunt, which is always a job on a
   * lean tenant — NAN-3086). */
  detail?: string;
}) {
  const queued = job.status === 'queued';
  const progress = job.progress;
  return (
    <div className="mx-4 mt-4 rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-left">
      <div className="flex items-start gap-3">
        {queued ? (
          <Clock className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" />
        ) : (
          <LoadingIcon className="mt-0.5 h-4 w-4 shrink-0 text-brand" />
        )}
        <div className="min-w-0 flex-1">
          <p className="text-[12px] font-semibold text-fg">
            {queued ? 'Moved to the long-running query queue' : 'Running as a durable query job'}
          </p>
          <p className="mt-1 text-[11px] leading-relaxed text-fg-3">
            {detail ?? 'This exact result exceeded the interactive lane.'} It will keep running if you leave this page.
            {queued && job.queuePosition ? ` Queue position ${job.queuePosition}.` : ''}
            {queued && job.estimatedWaitSeconds
              ? ` Estimated wait ${job.estimatedWaitSeconds}s.`
              : ''}
          </p>
          {progress && job.status === 'running' && (
            <p className="mt-1 text-[10px] font-mono text-fg-3">
              {progress.phase ? `${progress.phase} · ` : ''}
              {progress.percent}% · {(progress.elapsed_ms / 1000).toFixed(1)}s elapsed
            </p>
          )}
          <p className="mt-1 truncate font-mono text-[9px] text-fg-3/70">{job.jobId}</p>
        </div>
        {onOpenJobs && (
          <button
            type="button"
            onClick={onOpenJobs}
            className="inline-flex shrink-0 items-center gap-1 rounded-md border border-border px-2 py-1 text-[10px] font-semibold text-fg-2 transition-colors hover:border-brand/40 hover:text-brand"
          >
            Open Jobs <ExternalLink className="h-3 w-3" />
          </button>
        )}
      </div>
    </div>
  );
}
