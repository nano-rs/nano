// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';
import type { CloudOverviewAccount } from '@/lib/api/types';
import { InfoTip } from '@/components/ui/info-tip';
import { CloudCard, cloudSevTone, fmtCount } from './shared';

interface AccountsGridProps {
  accounts: CloudOverviewAccount[];
  onPickAccount?: (account: CloudOverviewAccount) => void;
}

export function AccountsGrid({ accounts, onPickAccount }: AccountsGridProps) {
  const maxEvents = Math.max(1, ...accounts.map((a) => a.events));
  return (
    <CloudCard
      title="Accounts"
      subtitle={
        <span className="inline-flex items-center gap-1">
          {accounts.length} tracked · click to scope
          <InfoTip label="About the accounts grid">
            Color shows risk from detection rules that fired on the account. The bar
            shows its event count next to the busiest account.
          </InfoTip>
        </span>
      }
      accent="oklch(68% 0.14 240)"
    >
      <div className="grid grid-cols-4 gap-2 p-3">
        {accounts.map((a) => {
          const tone = cloudSevTone(a.band);
          const widthPct = Math.max(6, (a.events / maxEvents) * 100);
          return (
            <button
              key={a.id}
              onClick={() => onPickAccount?.(a)}
              className="text-left bg-background/40 border border-border hover:border-muted-foreground/60 rounded-md p-2.5 group transition-colors"
            >
              <div className="flex items-center gap-1.5 mb-1">
                <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', tone.dot)} />
                <span className="font-mono text-[10.5px] text-muted-foreground/80 truncate">
                  {a.provider === 'gcp' ? 'gcp · ' : ''}
                  {a.name}
                </span>
                {a.alerts > 0 && (
                  <span className="ml-auto text-[9.5px] font-mono px-1 rounded bg-[oklch(62%_0.18_28/0.15)] text-[oklch(72%_0.17_28)]">
                    {a.alerts}
                  </span>
                )}
              </div>
              <div className="flex items-baseline gap-1.5 mb-1.5">
                <span className={cn('text-[18px] font-semibold tabular-nums', tone.text)}>
                  {a.risk}
                </span>
                <span className="text-[9.5px] text-muted-foreground/70">/100</span>
                <span
                  className={cn(
                    'text-[10px] font-mono ml-auto',
                    a.delta > 0
                      ? 'text-[oklch(72%_0.17_28)]'
                      : a.delta < 0
                      ? 'text-[oklch(72%_0.16_160)]'
                      : 'text-muted-foreground/70'
                  )}
                >
                  {a.delta > 0 ? '▲' : a.delta < 0 ? '▼' : '·'}
                  {Math.abs(a.delta)}
                </span>
              </div>
              <div className="h-1 bg-foreground/[0.06] rounded-sm overflow-hidden">
                <div
                  className={cn('h-full', tone.dot)}
                  style={{ width: `${widthPct}%` }}
                />
              </div>
              <div className="flex items-center justify-between mt-1.5 text-[10px] font-mono text-muted-foreground/80">
                <span className="tabular-nums">{fmtCount(a.events)}</span>
                <span>
                  {a.principals} p · {a.regions} r
                </span>
              </div>
              {a.top_principal && (
                <div className="mt-1 text-[10px] font-mono text-muted-foreground/70 truncate">
                  top: <span className="text-muted-foreground/80">{a.top_principal}</span>
                </div>
              )}
            </button>
          );
        })}
      </div>
    </CloudCard>
  );
}
