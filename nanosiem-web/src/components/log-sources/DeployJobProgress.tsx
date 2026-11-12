// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5132: the phase and final state of a log source's deploy job.
 *
 * Running: a spinner, "Deploying · Reloading Vector", a 4-step indicator and
 * the elapsed time. Finished: the final state (Deployed / Failed / Rolled back
 * / Interrupted / Deploying: not yet confirmed) and the job's message.
 */
import { useEffect, useState } from 'react';
import { AlertTriangle, Check, RotateCcw } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import type { DeployJob } from '@/lib/api/types';
import {
  elapsedSeconds,
  isTerminal,
  PHASE_STEPS,
  phaseLabel,
  phaseStep,
  stateLabel,
} from '@/lib/deploy-job';
import { cn } from '@/lib/utils';

const VERB: Record<DeployJob['kind'], string> = {
  deploy: 'Deploying',
  undeploy: 'Undeploying',
  publish: 'Publishing',
  deploy_all: 'Deploying all sources',
};

function tone(job: DeployJob): string {
  switch (job.state) {
    case 'succeeded':
      return job.result?.delivery?.state === 'pending' ? 'text-sky-500' : 'text-emerald-500';
    case 'rolled_back':
      return 'text-orange-500';
    case 'failed':
    case 'interrupted':
      return 'text-red-500';
    default:
      return 'text-muted-foreground';
  }
}

export function DeployJobProgress({ job, className }: { job: DeployJob | undefined; className?: string }) {
  const running = !!job && !isTerminal(job);
  const [, tick] = useState(0);
  useEffect(() => {
    if (!running) return undefined;
    const timer = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(timer);
  }, [running]);

  if (!job) return null;
  const step = phaseStep(job.phase);
  const seconds = elapsedSeconds(job);

  return (
    <div
      data-testid="deploy-job-progress"
      data-state={job.state}
      role="status"
      aria-live="polite"
      className={cn(
        'flex items-center gap-2 min-w-0 h-6 px-2 border border-border rounded-[4px] text-[12px]',
        className,
      )}
    >
      {running ? (
        <LoadingIcon className="w-3 h-3 shrink-0" />
      ) : job.state === 'succeeded' ? (
        <Check className={cn('w-3 h-3 shrink-0', tone(job))} strokeWidth={1.5} />
      ) : job.state === 'rolled_back' ? (
        <RotateCcw className={cn('w-3 h-3 shrink-0', tone(job))} strokeWidth={1.5} />
      ) : (
        <AlertTriangle className={cn('w-3 h-3 shrink-0', tone(job))} strokeWidth={1.5} />
      )}
      {running ? (
        <>
          <span className="shrink-0">{VERB[job.kind]}</span>
          <span className="text-muted-foreground shrink-0">·</span>
          <span className="text-muted-foreground truncate" data-testid="deploy-job-phase">
            {phaseLabel(job.phase)}
          </span>
          <span className="flex items-center gap-0.5 shrink-0" aria-hidden>
            {PHASE_STEPS.map((phase, index) => (
              <span
                key={phase}
                className={cn(
                  'w-1.5 h-1.5 rounded-full',
                  index < step ? 'bg-foreground/60' : index === step ? 'bg-sky-500' : 'bg-foreground/15',
                )}
              />
            ))}
          </span>
        </>
      ) : (
        <>
          <span className={cn('shrink-0', tone(job))} data-testid="deploy-job-state">
            {stateLabel(job)}
          </span>
          {job.message && (
            <span className="text-muted-foreground truncate" title={job.message}>
              {job.message}
            </span>
          )}
        </>
      )}
      <span className="ml-auto pl-1 font-mono text-[10.5px] text-muted-foreground shrink-0">{seconds}s</span>
    </div>
  );
}
