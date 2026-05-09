// SPDX-License-Identifier: AGPL-3.0-or-later

import { ShieldCheck } from 'lucide-react';
import type { AssetDossierAuth } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { SectionCard, EmptyCell, StatCell } from './_shared';
import { formatCompact } from '../helpers';

interface AuthCardProps {
  auth: AssetDossierAuth;
}

export function AuthCard({ auth }: AuthCardProps) {
  const { success, failure, interactive, network, lateral, recent } = auth;
  const total = success + failure;

  if (total === 0 && recent.length === 0) {
    return (
      <SectionCard
        title="Authentication"
        action={<span>All auth events ↗</span>}
        icon={<ShieldCheck className="w-[13px] h-[13px] text-muted-foreground/70" />}
      >
        <EmptyCell>No auth events for this entity in range</EmptyCell>
      </SectionCard>
    );
  }

  return (
    <SectionCard
      title="Authentication"
      action={<span>All auth events ↗</span>}
      icon={<ShieldCheck className="w-[13px] h-[13px] text-muted-foreground/70" />}
    >
      <div className="space-y-3">
        <div className="text-[11px] text-muted-foreground/70 font-mono">
          <span className="tabular-nums text-foreground">{formatCompact(success)}</span> success ·{' '}
          <span
            className={cn(
              'tabular-nums',
              failure > 0 ? 'text-[oklch(62%_0.18_28)]' : 'text-foreground'
            )}
          >
            {formatCompact(failure)}
          </span>{' '}
          fail
        </div>

        <div className="grid grid-cols-4 gap-2">
          <StatCell value={success} label="SUCCESS" />
          <StatCell value={failure} label="FAILURE" tone={failure > 0 ? 'warn' : 'default'} />
          <StatCell value={interactive} label="INTERACT." />
          <StatCell value={network + lateral} label="NETWORK" />
        </div>

        {recent.length > 0 && (
          <div>
            <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70 mb-1.5">
              Recent logons
            </div>
            <ul className="space-y-1.5">
              {recent.slice(0, 6).map((r, i) => (
                <li
                  key={`${r.ts}-${i}`}
                  className="flex items-center gap-2 text-[11.5px] font-mono"
                >
                  <span className="tabular-nums text-muted-foreground/70 w-[62px] shrink-0">
                    {r.ts}
                  </span>
                  <span
                    className="w-1.5 h-1.5 rounded-full shrink-0"
                    style={{
                      background:
                        r.result === 'failure'
                          ? 'oklch(62% 0.18 28)'
                          : 'oklch(72% 0.16 160)',
                    }}
                  />
                  <span className="text-muted-foreground/70 w-[80px] truncate shrink-0">
                    {r.auth_type}
                  </span>
                  {r.user && (
                    <span className="text-foreground truncate max-w-[140px]">{r.user}</span>
                  )}
                  {r.src && (
                    <span className="text-muted-foreground/70 truncate">
                      via <span className="text-foreground">{r.src}</span>
                    </span>
                  )}
                  {r.result === 'failure' && r.reason && (
                    <span className="ml-auto text-[oklch(62%_0.18_28)] truncate max-w-[120px]">
                      {r.reason}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </SectionCard>
  );
}

