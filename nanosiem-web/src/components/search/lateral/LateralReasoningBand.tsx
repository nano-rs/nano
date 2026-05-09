// SPDX-License-Identifier: AGPL-3.0-or-later

import { Fragment } from 'react';
import type { LateralSummary } from './types';

interface LateralReasoningBandProps {
  summary: LateralSummary;
  criticalPath: string[];
  onPivotNode: (id: string) => void;
}

export function LateralReasoningBand({
  summary,
  criticalPath,
  onPivotNode,
}: LateralReasoningBandProps) {
  const seedLabel = summary.seed.id;
  const reachCritical = summary.reachCritical;
  const reachCrown = summary.reachCrown;
  const deadEnds = summary.deadEnds;
  const hops = summary.hops;
  const windowDuration = summary.windowLabel.split('·')[1]?.trim() ?? summary.windowLabel;

  return (
    <div className="px-3 py-2 border-b border-border shrink-0 bg-background/40">
      <div className="flex items-start gap-3">
        <div className="flex flex-col items-center gap-0.5 shrink-0 pt-0.5">
          <span className="font-mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground/70">
            reach
          </span>
          <span className="font-mono text-[22px] text-foreground leading-none tabular-nums">
            {summary.nodes}
          </span>
          <span className="font-mono text-[9px] text-muted-foreground/80">assets</span>
        </div>

        <div className="flex-1 min-w-0">
          <div className="font-mono text-[10.5px] text-muted-foreground/80 leading-relaxed">
            <span className="text-foreground">{seedLabel}</span> reached{' '}
            {reachCritical > 0 ? (
              <>
                <span className="text-[oklch(72%_0.18_28)]">
                  {reachCritical} critical asset{reachCritical === 1 ? '' : 's'}
                </span>{' '}
              </>
            ) : (
              'no critical assets '
            )}
            in {hops} hop{hops === 1 ? '' : 's'}
            {windowDuration ? <> across {windowDuration}</> : null}.{' '}
            {reachCrown > 0 && (
              <>
                Chain touches {reachCrown}{' '}
                <span className="text-[oklch(72%_0.18_28)]">
                  crown-jewel{reachCrown > 1 ? 's' : ''}
                </span>
                {deadEnds > 0 && (
                  <>
                    {' '}
                    and {deadEnds} dead-end{deadEnds > 1 ? 's' : ''}
                  </>
                )}
                .
              </>
            )}
            {reachCrown === 0 && deadEnds > 0 && (
              <>
                Chain hit {deadEnds} dead-end{deadEnds > 1 ? 's' : ''}.
              </>
            )}
          </div>

          {criticalPath.length > 1 && (
            <div className="mt-1.5 flex items-center gap-1 font-mono text-[10px] text-muted-foreground/70 flex-wrap">
              <span className="text-muted-foreground/80">critical path:</span>
              {criticalPath.map((id, i) => (
                <Fragment key={`${id}-${i}`}>
                  <button
                    onClick={() => onPivotNode(id)}
                    className="font-mono text-[10.5px] text-foreground px-1 rounded-sm bg-[oklch(68%_0.18_28/0.1)] border border-[oklch(68%_0.18_28/0.3)] hover:bg-[oklch(68%_0.18_28/0.2)] transition-colors"
                  >
                    {id}
                  </button>
                  {i < criticalPath.length - 1 && (
                    <span className="text-muted-foreground/70">→</span>
                  )}
                </Fragment>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
