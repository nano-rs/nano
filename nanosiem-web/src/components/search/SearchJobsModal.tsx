// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Search Jobs modal (NAN-373 Phase 3)
 *
 * Compact modal to monitor running + recent async search jobs, replacing
 * the Jobs tab from the old Search Hub. Opened from the "…" overflow in
 * the QueryBlock footer. Polls every 3s while there's an active job, 15s
 * otherwise.
 */
import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { X, Loader2, CircleCheck, XCircle, Clock, Play } from 'lucide-react';
import { api } from '@/lib/api';
import type { SearchJobSummary } from '@/lib/api';
import { cn } from '@/lib/utils';

interface SearchJobsModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onLoadJob?: (jobId: string) => void;
  onCancelJob?: (jobId: string) => void;
}

const STATUS_META: Record<
  string,
  { label: string; icon: typeof Clock; color: string }
> = {
  queued: { label: 'Queued', icon: Clock, color: 'text-amber-400' },
  running: { label: 'Running', icon: Loader2, color: 'text-primary' },
  completed: { label: 'Done', icon: CircleCheck, color: 'text-emerald-400' },
  failed: { label: 'Failed', icon: XCircle, color: 'text-destructive' },
  cancelled: { label: 'Cancelled', icon: X, color: 'text-muted-foreground' },
};

function formatElapsed(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const mins = Math.floor(seconds / 60);
  return `${mins}m ${seconds % 60}s`;
}

function JobRow({
  job,
  onLoadJob,
  onCancelJob,
}: {
  job: SearchJobSummary;
  onLoadJob?: (jobId: string) => void;
  onCancelJob?: (jobId: string) => void;
}) {
  const meta = STATUS_META[job.status] ?? STATUS_META.queued;
  const Icon = meta.icon;
  const isActive = job.status === 'queued' || job.status === 'running';

  return (
    <div className="group px-3 py-2 rounded-sm border border-transparent hover:border-border hover:bg-foreground/[0.03] transition-colors">
      <div className="flex items-center gap-2 mb-1">
        <Icon className={cn('w-[12px] h-[12px] shrink-0', meta.color, job.status === 'running' && 'animate-spin')} />
        <span className={cn('font-mono text-[10.5px] uppercase tracking-[0.1em] font-semibold', meta.color)}>
          {meta.label}
        </span>
        {job.queue_position !== undefined && job.status === 'queued' && (
          <span className="font-mono text-[10px] text-muted-foreground">
            position {job.queue_position}
          </span>
        )}
        <span className="ml-auto font-mono text-[10px] text-muted-foreground tabular-nums">
          {formatElapsed(job.elapsed_ms)}
        </span>
      </div>
      <div className="font-mono text-[11px] text-foreground/80 truncate mb-1">{job.query}</div>
      <div className="flex items-center gap-1">
        <span className="font-mono text-[9.5px] text-muted-foreground/70 tabular-nums flex-1 truncate">
          {job.job_id}
        </span>
        <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
          {onLoadJob && job.status === 'completed' && (
            <button
              type="button"
              onClick={() => onLoadJob(job.job_id)}
              className="p-1 rounded hover:bg-foreground/10 text-muted-foreground hover:text-foreground"
              title="Load results"
              aria-label="Load job results"
            >
              <Play className="w-[11px] h-[11px]" />
            </button>
          )}
          {onCancelJob && isActive && (
            <button
              type="button"
              onClick={() => onCancelJob(job.job_id)}
              className="p-1 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive"
              title="Cancel job"
              aria-label="Cancel job"
            >
              <X className="w-[11px] h-[11px]" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export function SearchJobsModal({ open, onOpenChange, onLoadJob, onCancelJob }: SearchJobsModalProps) {
  const { data: jobs = [] } = useQuery({
    queryKey: ['search-jobs'],
    queryFn: () => api.listSearchJobs(),
    refetchInterval: (query) => {
      const data = query.state.data as SearchJobSummary[] | undefined;
      if (!data || !open) return 15_000;
      const hasActive = data.some(j => j.status === 'queued' || j.status === 'running');
      return hasActive ? 3_000 : 15_000;
    },
  });

  // Close on Escape
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onOpenChange(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onOpenChange]);

  if (!open) return null;

  const active = jobs.filter(j => j.status === 'queued' || j.status === 'running');
  const recent = jobs.filter(j => j.status !== 'queued' && j.status !== 'running').slice(0, 10);

  return (
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center pt-[12vh] bg-black/50 backdrop-blur-[2px]"
      onClick={() => onOpenChange(false)}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-[520px] max-w-[92%] max-h-[70vh] bg-card border border-border rounded-xl shadow-[0_40px_100px_rgba(0,0,0,0.6)] overflow-hidden flex flex-col"
      >
        {/* Header */}
        <div className="px-4 py-3 border-b border-border flex items-center gap-2">
          <div className="font-mono text-[10px] tracking-[0.16em] uppercase text-muted-foreground font-semibold">
            Search jobs
          </div>
          {active.length > 0 && (
            <span className="rounded-sm bg-primary/15 text-primary text-[9.5px] px-1 font-semibold tabular-nums">
              {active.length} active
            </span>
          )}
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            className="ml-auto w-6 h-6 flex items-center justify-center rounded-md text-muted-foreground hover:bg-foreground/5 hover:text-foreground transition-colors"
            aria-label="Close"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto scrollbar-thin p-2 space-y-0.5">
          {jobs.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-2 py-12 text-muted-foreground">
              <Clock className="w-5 h-5 opacity-40" />
              <div className="text-[12px] font-medium text-foreground/70">No recent jobs</div>
              <div className="text-[10.5px] text-muted-foreground/70">
                Long-running searches show up here so you can monitor or cancel them.
              </div>
            </div>
          ) : (
            <>
              {active.length > 0 && (
                <>
                  <div className="px-2 pt-2 pb-1 font-mono text-[9.5px] tracking-[0.14em] uppercase text-muted-foreground/60 font-semibold">
                    Active
                  </div>
                  {active.map(job => (
                    <JobRow key={job.job_id} job={job} onLoadJob={onLoadJob} onCancelJob={onCancelJob} />
                  ))}
                </>
              )}
              {recent.length > 0 && (
                <>
                  <div className="px-2 pt-3 pb-1 font-mono text-[9.5px] tracking-[0.14em] uppercase text-muted-foreground/60 font-semibold">
                    Recent
                  </div>
                  {recent.map(job => (
                    <JobRow key={job.job_id} job={job} onLoadJob={onLoadJob} onCancelJob={onCancelJob} />
                  ))}
                </>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="border-t border-border px-3 py-2 flex items-center justify-between font-mono text-[10px] text-muted-foreground">
          <span>Polls every 3s while active · 15s idle</span>
          <span className="inline-flex items-center gap-1">
            <kbd className="px-1 rounded border border-border bg-foreground/5">esc</kbd> close
          </span>
        </div>
      </div>
    </div>
  );
}
