// SPDX-License-Identifier: AGPL-3.0-or-later

import { Layers } from 'lucide-react';
import type { AssetDossierProcesses } from '@/lib/api/types';
import { SectionCard, EmptyCell } from './_shared';

interface ProcessesCardProps {
  processes: AssetDossierProcesses;
}

export function ProcessesCard({ processes }: ProcessesCardProps) {
  const { unique, rare, from_office, top, rare_list } = processes;
  const maxCount = Math.max(1, ...top.map((t) => t.count));

  const rareBadge =
    rare > 0 ? (
      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold text-primary bg-primary/10 border border-primary/25 tabular-nums">
        {rare} rare
      </span>
    ) : null;

  return (
    <SectionCard
      title="Processes"
      badge={rareBadge}
      action={<span>Open tree ↗</span>}
      icon={<Layers className="w-[13px] h-[13px] text-muted-foreground/70" />}
    >
      {unique === 0 ? (
        <EmptyCell>No process events for this entity in range</EmptyCell>
      ) : (
        <div className="space-y-3">
          <div className="text-[11px] text-muted-foreground/70">
            <span className="font-mono text-foreground tabular-nums">{unique}</span> unique
            {from_office > 0 && (
              <>
                {' · '}
                <span className="font-mono text-foreground tabular-nums">{from_office}</span>{' '}
                from Office
              </>
            )}
          </div>

          {rare_list.length > 0 && (
            <div>
              <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70 mb-1.5">
                Rare / suspicious
              </div>
              <ul className="space-y-2">
                {rare_list.map((r) => (
                  <li key={r.name} className="text-[12px] space-y-0.5">
                    <div className="flex items-baseline gap-1.5 flex-wrap">
                      <span className="font-mono text-foreground">{r.name}</span>
                      <span className="text-[10px] font-mono text-primary">
                        {r.prev.toFixed(1)}%
                      </span>
                      {r.flags.map((f) => (
                        <span
                          key={f}
                          className="text-[9.5px] font-mono uppercase tracking-[0.08em] px-1 py-0.5 rounded bg-[oklch(72%_0.14_80/0.12)] text-[oklch(72%_0.14_80)]"
                        >
                          {f}
                        </span>
                      ))}
                      {r.hash && (
                        <span className="text-[10px] font-mono text-muted-foreground/70 ml-auto">
                          {r.hash.slice(0, 8)}…
                        </span>
                      )}
                    </div>
                    {r.cmd && (
                      <div className="text-[10.5px] font-mono text-muted-foreground/70 truncate">
                        {r.cmd}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {top.length > 0 && (
            <div>
              <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70 mb-1.5">
                Most frequent
              </div>
              <ul className="space-y-1.5">
                {top.slice(0, 5).map((t) => (
                  <li key={t.name} className="flex items-center gap-2 text-[12px]">
                    <span className="font-mono text-foreground w-[120px] truncate shrink-0">
                      {t.name}
                    </span>
                    <div className="flex-1 h-1.5 rounded-full bg-foreground/6 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-primary/60"
                        style={{ width: `${(t.count / maxCount) * 100}%` }}
                      />
                    </div>
                    <span className="text-[11px] font-mono tabular-nums text-muted-foreground/70 w-10 text-right">
                      {t.count}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </SectionCard>
  );
}
