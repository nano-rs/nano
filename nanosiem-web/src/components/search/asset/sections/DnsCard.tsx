// SPDX-License-Identifier: AGPL-3.0-or-later

import { Globe } from 'lucide-react';
import type { AssetDossierDns } from '@/lib/api/types';
import { SectionCard, EmptyCell, StatCell } from './_shared';
import { formatCompact } from '../helpers';

interface DnsCardProps {
  dns: AssetDossierDns;
}

export function DnsCard({ dns }: DnsCardProps) {
  const { queries, unique, nx, rare_tlds, top } = dns;

  if (queries === 0 && top.length === 0) {
    return (
      <SectionCard
        title="DNS"
        action={<span>Top domains ↗</span>}
        icon={<Globe className="w-[13px] h-[13px] text-muted-foreground/70" />}
      >
        <EmptyCell>No DNS events for this entity in range</EmptyCell>
      </SectionCard>
    );
  }

  return (
    <SectionCard
      title="DNS"
      action={<span>Top domains ↗</span>}
      icon={<Globe className="w-[13px] h-[13px] text-muted-foreground/70" />}
    >
      <div className="space-y-3">
        <div className="text-[11px] text-muted-foreground/70 font-mono">
          <span className="tabular-nums text-foreground">{formatCompact(queries)}</span> queries ·{' '}
          <span className="tabular-nums text-foreground">{formatCompact(nx)}</span> NXDOMAIN
        </div>

        <div className="grid grid-cols-3 gap-2">
          <StatCell value={unique} label="UNIQUE" />
          <StatCell value={nx} label="NXDOMAIN" tone={nx > 0 ? 'warn' : 'default'} />
          <StatCell
            value={rare_tlds}
            label="RARE TLD"
            tone={rare_tlds > 0 ? 'critical' : 'default'}
          />
        </div>

        {top.length > 0 && (
          <div>
            <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70 mb-1.5">
              Top domains
            </div>
            <ul className="space-y-1">
              {top.slice(0, 6).map((d) => (
                <li key={d.domain} className="flex items-baseline gap-2 text-[11.5px]">
                  <span className="font-mono text-foreground truncate flex-1" title={d.domain}>
                    {d.domain}
                  </span>
                  <span className="text-[10.5px] font-mono tabular-nums text-muted-foreground/70 shrink-0">
                    {formatCompact(d.count)}
                  </span>
                  {d.nx > 0 && (
                    <span className="text-[9.5px] font-mono uppercase tracking-[0.08em] px-1 py-0.5 rounded bg-[oklch(72%_0.14_80/0.12)] text-[oklch(72%_0.14_80)] shrink-0">
                      nx {d.nx}
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

