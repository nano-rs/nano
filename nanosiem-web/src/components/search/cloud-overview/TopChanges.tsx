// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';
import type { CloudOverviewChange } from '@/lib/api/types';
import { CloudCard, cloudSevTone } from './shared';

interface TopChangesProps {
  changes: CloudOverviewChange[];
  /** Click the actor cell to pivot into that principal */
  onPivotActor?: (actor: string) => void;
  /** Click the target cell to scope by resource_name */
  onPivotTarget?: (target: string) => void;
  /** Click the account cell to scope by cloud_account_id */
  onPivotAccount?: (account: string) => void;
}

export function TopChanges({ changes, onPivotActor, onPivotTarget, onPivotAccount }: TopChangesProps) {
  return (
    <CloudCard
      title="Top changes"
      subtitle={`${changes.length} recent · IAM · SG · S3 · KMS`}
      accent="oklch(70% 0.16 55)"
    >
      <div className="divide-y divide-border">
        {changes.map((c, i) => {
          const tone = cloudSevTone(c.severity);
          return (
            <div
              key={`${c.at}-${i}`}
              className="grid grid-cols-[48px_auto_1fr_auto] gap-2 px-3 py-1.5 items-center hover:bg-foreground/[0.03] text-[11.5px] font-mono"
            >
              <span className="text-muted-foreground/80 tabular-nums">{c.at}</span>
              <span
                className={cn(
                  'text-[9.5px] uppercase tracking-[0.1em] px-1 py-0.5 rounded text-center whitespace-nowrap shrink-0',
                  tone.bg,
                  tone.text
                )}
              >
                {c.kind}
              </span>
              <div className="min-w-0 flex items-baseline gap-2 flex-wrap">
                <button
                  onClick={() => onPivotActor?.(c.actor)}
                  disabled={!onPivotActor}
                  className="text-muted-foreground/80 truncate enabled:hover:text-primary enabled:hover:underline"
                  title={onPivotActor ? `Filter by user=${c.actor}` : undefined}
                >
                  {c.actor}
                </button>
                <span className="text-foreground">{c.action}</span>
                <span className="text-muted-foreground/70">→</span>
                <button
                  onClick={() => onPivotTarget?.(c.target)}
                  disabled={!onPivotTarget}
                  className="text-foreground truncate enabled:hover:text-primary enabled:hover:underline"
                  title={onPivotTarget ? `Filter by resource_name=${c.target}` : undefined}
                >
                  {c.target}
                </button>
                {c.detail && (
                  <span className="text-muted-foreground/70 text-[10.5px] truncate">
                    {c.detail}
                  </span>
                )}
              </div>
              <button
                onClick={() => onPivotAccount?.(c.account)}
                disabled={!onPivotAccount}
                className="text-muted-foreground/70 text-[10px] shrink-0 enabled:hover:text-primary enabled:hover:underline"
                title={onPivotAccount ? `Filter by cloud_account_id=${c.account}` : undefined}
              >
                {c.account}
              </button>
            </div>
          );
        })}
        {changes.length === 0 && (
          <div className="px-3 py-6 text-center text-[11px] font-mono text-muted-foreground/60">
            No sensitive changes in this window
          </div>
        )}
      </div>
    </CloudCard>
  );
}
