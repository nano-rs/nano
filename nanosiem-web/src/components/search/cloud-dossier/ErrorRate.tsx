// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';
import type { CloudDossierErrorRate } from '@/lib/api/types';
import { CloudCard, cloudSevTone, fmtCount } from '../cloud-overview/shared';

interface ErrorRateProps {
  data: CloudDossierErrorRate;
  /** Click an error code row to scope by status= */
  onPivotErrorCode?: (code: string) => void;
}

export function ErrorRate({ data, onPivotErrorCode }: ErrorRateProps) {
  const total = Math.max(1, data.events_total);
  const pctFailed = data.events_failed / total;
  const pctDenied = data.events_denied / total;

  return (
    <CloudCard
      title="Allow / deny · error rate"
      subtitle={`${(pctFailed * 100).toFixed(2)}% failed · ${(pctDenied * 100).toFixed(2)}% denied`}
      accent="oklch(68% 0.14 30)"
    >
      <div className="p-3">
        <div className="flex items-end gap-4">
          <div>
            <div className="text-[10px] font-mono uppercase tracking-[0.1em] text-muted-foreground/70">
              Allowed
            </div>
            <div className="text-[22px] font-semibold tabular-nums text-foreground">
              {fmtCount(data.events_allowed)}
            </div>
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase tracking-[0.1em] text-muted-foreground/70">
              Failed
            </div>
            <div className="text-[22px] font-semibold tabular-nums text-[oklch(72%_0.17_28)]">
              {fmtCount(data.events_failed)}
            </div>
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase tracking-[0.1em] text-muted-foreground/70">
              Denied
            </div>
            <div className="text-[22px] font-semibold tabular-nums text-[oklch(78%_0.14_60)]">
              {fmtCount(data.events_denied)}
            </div>
          </div>
        </div>
        <div className="mt-3">
          <div className="h-2 rounded-full bg-foreground/[0.06] overflow-hidden flex">
            <div
              className="h-full bg-[oklch(72%_0.16_160)]"
              style={{ width: `${(1 - pctFailed) * 100}%` }}
            />
            <div
              className="h-full bg-[oklch(78%_0.14_60)]"
              style={{ width: `${Math.max(0, pctFailed - pctDenied) * 100}%` }}
            />
            <div
              className="h-full bg-[oklch(72%_0.17_28)]"
              style={{ width: `${pctDenied * 100}%` }}
            />
          </div>
          <div className="flex items-center gap-3 mt-1.5 text-[10.5px] font-mono text-muted-foreground/70">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-sm bg-[oklch(72%_0.16_160)]" />
              allow
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-sm bg-[oklch(78%_0.14_60)]" />
              error
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-sm bg-[oklch(72%_0.17_28)]" />
              denied
            </span>
          </div>
        </div>

        {data.top_errors.length > 0 && (
          <div className="mt-3 pt-3 border-t border-border">
            <div className="text-[9.5px] font-mono uppercase tracking-[0.1em] text-muted-foreground/70 mb-1.5">
              Top error codes
            </div>
            <div className="space-y-1">
              {data.top_errors.map((e) => {
                const tone = cloudSevTone(e.severity);
                return (
                  <button
                    key={e.code}
                    onClick={() => onPivotErrorCode?.(e.code)}
                    disabled={!onPivotErrorCode}
                    className="w-full grid grid-cols-[1fr_auto_auto] items-center gap-2 text-[11.5px] font-mono text-left enabled:hover:bg-foreground/[0.03] rounded-sm px-1 py-0.5 enabled:cursor-pointer"
                    title={onPivotErrorCode ? `Filter by status=${e.code}` : undefined}
                  >
                    <span className="flex items-center gap-1.5">
                      <span className={cn('w-1.5 h-1.5 rounded-full', tone.dot)} />
                      <span className={tone.text}>{e.code}</span>
                    </span>
                    <span className="w-24 h-[3px] bg-foreground/[0.06] rounded-full overflow-hidden">
                      <div
                        className="h-full"
                        style={{
                          width: `${Math.min(100, e.pct * 100 * 4)}%`,
                          background: 'oklch(72% 0.17 28)',
                        }}
                      />
                    </span>
                    <span className="tabular-nums text-muted-foreground/80 text-right w-14">
                      {e.count.toLocaleString()}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </CloudCard>
  );
}
