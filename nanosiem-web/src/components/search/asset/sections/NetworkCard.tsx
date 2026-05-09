// SPDX-License-Identifier: AGPL-3.0-or-later

import { Globe } from 'lucide-react';
import type { AssetDossierNetwork } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { SectionCard, EmptyCell, StatCell } from './_shared';
import { formatBytes, formatCompact } from '../helpers';

interface NetworkCardProps {
  network: AssetDossierNetwork;
}

export function NetworkCard({ network }: NetworkCardProps) {
  const { total_conns, bytes_in, bytes_out, unique_dsts, new_domains, top_dsts, rare_countries } =
    network;

  if (total_conns === 0 && top_dsts.length === 0) {
    return (
      <SectionCard
        title="Network"
        action={<span>Top destinations ↗</span>}
        icon={<Globe className="w-[13px] h-[13px] text-muted-foreground/70" />}
      >
        <EmptyCell>No network events for this entity in range</EmptyCell>
      </SectionCard>
    );
  }

  const maxBytes = Math.max(1, ...top_dsts.map((d) => d.bytes));
  const rareCountry = rare_countries[0];

  return (
    <SectionCard
      title="Network"
      action={<span>Top destinations ↗</span>}
      icon={<Globe className="w-[13px] h-[13px] text-muted-foreground/70" />}
    >
      <div className="space-y-3">
        <div className="text-[11px] text-muted-foreground/70 font-mono">
          <span className="tabular-nums text-foreground">{formatCompact(total_conns)}</span> conns ·{' '}
          <span className="tabular-nums text-foreground">
            {formatBytes(bytes_in + bytes_out)}
          </span>
        </div>

        <div className="grid grid-cols-4 gap-2">
          <StatCell value={unique_dsts} label="UNIQ DSTS" />
          <StatCell
            value={new_domains}
            label="NEW DOMAINS"
            tone={new_domains > 0 ? 'warn' : 'default'}
          />
          {rareCountry ? (
            <StatCell
              value={rareCountry.country}
              label="RARE COUNTRY"
              tone="critical"
            />
          ) : (
            <StatCell value={0} label="RARE CTRY" />
          )}
          <StatCell value={0} label="LATERAL" />
        </div>

        {top_dsts.length > 0 && (
          <div>
            <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70 mb-1.5">
              Top destinations by bytes
            </div>
            <ul className="space-y-1.5">
              {top_dsts.slice(0, 6).map((d) => (
                <li key={d.host} className="flex items-center gap-2 text-[12px]">
                  <span
                    className={cn(
                      'text-[10px] font-mono w-6 shrink-0',
                      d.rep === 'new-domain' || d.rep === 'suspicious'
                        ? 'text-[oklch(62%_0.18_28)]'
                        : 'text-muted-foreground/70'
                    )}
                  >
                    {d.country ?? '—'}
                  </span>
                  <span
                    className={cn(
                      'font-mono truncate max-w-[180px]',
                      d.rep === 'new-domain' || d.rep === 'suspicious'
                        ? 'text-[oklch(62%_0.18_28)]'
                        : 'text-foreground'
                    )}
                  >
                    {d.host}
                  </span>
                  {d.rep === 'new-domain' && (
                    <span className="text-[9.5px] font-mono uppercase tracking-[0.08em] px-1 py-0.5 rounded bg-[oklch(72%_0.14_80/0.12)] text-[oklch(72%_0.14_80)]">
                      rare-tld + new
                    </span>
                  )}
                  <div className="flex-1 h-1.5 rounded-full bg-foreground/6 overflow-hidden min-w-[40px]">
                    <div
                      className="h-full rounded-full bg-primary/50"
                      style={{ width: `${(d.bytes / maxBytes) * 100}%` }}
                    />
                  </div>
                  <span className="text-[11px] font-mono tabular-nums text-muted-foreground/70 w-14 text-right shrink-0">
                    {formatBytes(d.bytes)}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </SectionCard>
  );
}

