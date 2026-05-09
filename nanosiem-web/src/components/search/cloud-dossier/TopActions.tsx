// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';
import type { CloudDossierActionRow } from '@/lib/api/types';
import { CloudCard } from '../cloud-overview/shared';

interface TopActionsProps {
  actions: CloudDossierActionRow[];
  /** Click an action name to scope the base search by action= */
  onPivotAction?: (name: string) => void;
}

const serviceAccent = (service: string) => {
  switch (service) {
    case 'iam':
      return 'oklch(65% 0.19 30)';
    case 'sts':
      return 'oklch(68% 0.14 30)';
    case 'secretsmanager':
    case 'secrets':
      return 'oklch(62% 0.18 0)';
    case 's3':
      return 'oklch(66% 0.16 170)';
    case 'kms':
      return 'oklch(68% 0.13 290)';
    case 'ec2':
      return 'oklch(66% 0.13 240)';
    case 'lambda':
      return 'oklch(66% 0.15 30)';
    case 'cloudformation':
    case 'cfn':
      return 'oklch(62% 0.12 280)';
    default:
      return 'oklch(65% 0.05 250)';
  }
};

export function TopActions({ actions, onPivotAction }: TopActionsProps) {
  const max = Math.max(1, ...actions.map((a) => a.count));
  return (
    <CloudCard
      title="Top API actions"
      subtitle={`${actions.length} distinct · highlighted are sensitive`}
      accent="oklch(68% 0.14 50)"
    >
      <div className="p-2">
        <div className="grid grid-cols-[1fr_72px_72px] gap-2 px-2 pb-1 text-[9.5px] font-mono uppercase tracking-[0.08em] text-muted-foreground/70">
          <span>Action</span>
          <span className="text-right">Count</span>
          <span className="text-right">Errors</span>
        </div>
        {actions.length === 0 && (
          <div className="px-2 py-6 text-center text-[11px] font-mono text-muted-foreground/60">
            No API activity in this window
          </div>
        )}
        {actions.map((a) => {
          const pct = a.count / max;
          return (
            <button
              key={`${a.service}:${a.name}`}
              onClick={() => onPivotAction?.(a.name)}
              disabled={!onPivotAction}
              className={cn(
                'w-full grid grid-cols-[1fr_72px_72px] gap-2 px-2 py-1 rounded-sm hover:bg-foreground/[0.03] items-center font-mono text-[11.5px] relative text-left',
                onPivotAction && 'enabled:hover:text-primary cursor-pointer',
                a.anomaly && 'bg-[oklch(68%_0.18_28/0.06)]'
              )}
              title={onPivotAction ? `Filter by action=${a.name}` : undefined}
            >
              <span className="flex items-center gap-1.5 min-w-0">
                <span
                  className="w-1 h-3 rounded-sm shrink-0"
                  style={{ background: serviceAccent(a.service) }}
                />
                <span
                  className={cn(
                    'truncate',
                    a.anomaly
                      ? 'text-[oklch(72%_0.17_28)]'
                      : 'text-muted-foreground group-hover:text-foreground'
                  )}
                >
                  {a.service}:{a.name}
                </span>
                {a.sensitive && (
                  <span className="text-[9px] font-mono px-1 rounded bg-foreground/[0.08] text-muted-foreground/80 shrink-0">
                    sensitive
                  </span>
                )}
              </span>
              <span className="text-right tabular-nums relative">
                <span className="text-muted-foreground/80">{a.count.toLocaleString()}</span>
                <div
                  className="absolute right-0 bottom-[-2px] h-[2px] rounded-full"
                  style={{
                    width: `${pct * 60}px`,
                    background: serviceAccent(a.service),
                    opacity: 0.6,
                  }}
                />
              </span>
              <span
                className={cn(
                  'text-right tabular-nums',
                  a.errors > 100
                    ? 'text-[oklch(72%_0.17_28)]'
                    : 'text-muted-foreground/70'
                )}
              >
                {a.errors > 0 ? a.errors.toLocaleString() : '—'}
              </span>
            </button>
          );
        })}
      </div>
    </CloudCard>
  );
}
