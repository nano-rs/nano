// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronDown, ChevronRight, Clock, Loader2, CircleCheck, XCircle, X, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { api, type SearchJobSummary } from '@/lib/api';

function formatElapsed(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

const STATUS_CONFIG: Record<string, { icon: typeof Clock; label: string; color: string }> = {
  queued: { icon: Clock, label: 'Queued', color: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20' },
  running: { icon: Loader2, label: 'Running', color: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20' },
  completed: { icon: CircleCheck, label: 'Done', color: 'bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/20' },
  failed: { icon: XCircle, label: 'Failed', color: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20' },
  cancelled: { icon: X, label: 'Cancelled', color: 'bg-muted text-muted-foreground border-border' },
};

interface ActiveSearchesPanelProps {
  onLoadJob?: (jobId: string) => void;
  onCancelJob?: (jobId: string) => void;
}

export function ActiveSearchesPanel({ onLoadJob, onCancelJob }: ActiveSearchesPanelProps) {
  const [expanded, setExpanded] = useState(false);
  const queryClient = useQueryClient();

  const { data: jobs } = useQuery({
    queryKey: ['search-jobs'],
    queryFn: () => api.listSearchJobs(),
    refetchInterval: (query) => {
      const data = query.state.data as SearchJobSummary[] | undefined;
      if (!data) return false;
      const hasActive = data.some(j => j.status === 'queued' || j.status === 'running');
      return hasActive ? 3000 : false;
    },
  });

  // Only show if there are active or recent jobs
  if (!jobs || jobs.length === 0) return null;

  const activeCount = jobs.filter(j => j.status === 'queued' || j.status === 'running').length;

  return (
    <div className="border rounded-xl bg-card mb-4">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-3 text-sm hover:bg-accent/50 transition-colors rounded-xl"
      >
        <div className="flex items-center gap-2">
          <Search className="w-4 h-4 text-muted-foreground" />
          <span className="search-console-section-header"><Search />Active Searches</span>
          {activeCount > 0 && (
            <Badge variant="secondary" className="text-[10px] px-1.5 py-0 font-mono">
              {activeCount}
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="search-console-section-meta">{jobs.length} total</span>
          {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </div>
      </button>

      {expanded && (
        <div className="border-t divide-y">
          {jobs.map((job) => {
            const config = STATUS_CONFIG[job.status] || STATUS_CONFIG.cancelled;
            const Icon = config.icon;
            const isActive = job.status === 'queued' || job.status === 'running';
            const isClickable = job.status === 'completed';

            return (
              <div
                key={job.job_id}
                className={cn(
                  'flex items-center gap-3 px-4 py-2.5 text-sm',
                  isClickable && 'cursor-pointer hover:bg-accent/50'
                )}
                onClick={isClickable ? () => onLoadJob?.(job.job_id) : undefined}
              >
                <Icon className={cn(
                  'w-4 h-4 flex-shrink-0',
                  job.status === 'running' && 'animate-spin'
                )} />
                <div className="flex-1 min-w-0">
                  <p className="truncate text-foreground font-mono text-sm">{job.query || 'Search query'}</p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <Badge variant="outline" className={cn('text-[10px] px-1.5 py-0 border', config.color)}>
                      {config.label}
                    </Badge>
                    {job.queue_position != null && job.status === 'queued' && (
                      <span className="text-[10px] font-mono text-muted-foreground">
                        Position {job.queue_position}
                      </span>
                    )}
                    <span className="text-[10px] font-mono text-muted-foreground">
                      {formatElapsed(job.elapsed_ms)}
                    </span>
                  </div>
                </div>
                {isActive && onCancelJob && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 w-7 p-0 flex-shrink-0"
                    onClick={(e) => {
                      e.stopPropagation();
                      onCancelJob(job.job_id);
                      queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
                    }}
                  >
                    <X className="w-3.5 h-3.5" />
                  </Button>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default ActiveSearchesPanel;
