// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ReactNode } from 'react';
import { Cloud, Box, Globe, Users, Layers, Edit } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { CloudDossierFacets, CloudDossierFacetItem } from '@/lib/api/types';
import { fmtCount } from '../cloud-overview/shared';

interface FacetsBandProps {
  facets: CloudDossierFacets;
  eventsTotal: number;
  onFacetClick?: (dim: string, value: string) => void;
  /** Currently-active filters — used to visually mark matching rows as selected */
  activeFilters?: {
    services: string[];
    regions: string[];
    accounts: string[];
    resource_types: string[];
    change_types: string[];
  };
}

interface FacetColumn {
  key: string;
  label: string;
  icon: ReactNode;
  items: CloudDossierFacetItem[];
  bar: string;
}

export function FacetsBand({ facets, eventsTotal, onFacetClick, activeFilters }: FacetsBandProps) {
  const isActive = (colKey: string, name: string): boolean => {
    if (!activeFilters) return false;
    switch (colKey) {
      case 'service':
        return activeFilters.services.includes(name);
      case 'region':
        return activeFilters.regions.includes(name);
      case 'account':
        return activeFilters.accounts.includes(name);
      case 'resource_type':
        return activeFilters.resource_types.includes(name);
      case 'change_type':
        return activeFilters.change_types.includes(name);
      default:
        return false;
    }
  };
  const cols: FacetColumn[] = [
    {
      key: 'provider',
      label: 'Provider',
      icon: <Cloud className="w-[11px] h-[11px]" strokeWidth={1.5} />,
      items: facets.provider,
      bar: 'oklch(68% 0.14 240)',
    },
    {
      key: 'service',
      label: 'Service',
      icon: <Box className="w-[11px] h-[11px]" strokeWidth={1.5} />,
      items: facets.service.slice(0, 9),
      bar: 'oklch(68% 0.14 50)',
    },
    {
      key: 'region',
      label: 'Region',
      icon: <Globe className="w-[11px] h-[11px]" strokeWidth={1.5} />,
      items: facets.region.slice(0, 9),
      bar: 'oklch(68% 0.14 170)',
    },
    {
      key: 'account',
      label: 'Account',
      icon: <Users className="w-[11px] h-[11px]" strokeWidth={1.5} />,
      items: facets.account,
      bar: 'oklch(68% 0.14 280)',
    },
    {
      key: 'resource_type',
      label: 'Resource Type',
      icon: <Layers className="w-[11px] h-[11px]" strokeWidth={1.5} />,
      items: facets.resource_type.slice(0, 9),
      bar: 'oklch(68% 0.14 320)',
    },
    {
      key: 'change_type',
      label: 'Change Type',
      icon: <Edit className="w-[11px] h-[11px]" strokeWidth={1.5} />,
      items: facets.change_type,
      bar: 'oklch(68% 0.14 30)',
    },
  ];
  const max = (items: CloudDossierFacetItem[]) =>
    Math.max(1, ...items.map((i) => i.count));

  return (
    <div className="bg-card border border-border rounded-lg px-3.5 py-3">
      <div className="flex items-center gap-2 mb-3 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold">
        <Cloud className="w-[12px] h-[12px] text-primary" strokeWidth={1.5} />
        Cloud investigation ·{' '}
        <span className="normal-case tracking-normal text-foreground">
          {eventsTotal.toLocaleString()} events · group by: service
        </span>
      </div>
      <div className="grid grid-cols-6 gap-x-4 gap-y-0.5 text-[12px]">
        {cols.map((col) => (
          <div key={col.key} className="min-w-0">
            <div className="flex items-center gap-1.5 pb-1.5 border-b border-border text-[10.5px] font-mono text-muted-foreground/80 uppercase tracking-[0.08em]">
              <span className="text-muted-foreground/70">{col.icon}</span>
              {col.label}
            </div>
            <div className="pt-1 space-y-[2px]">
              {col.items.map((it) => {
                const pct = it.count / max(col.items);
                const active = isActive(col.key, it.name);
                return (
                  <button
                    key={it.name}
                    onClick={() => onFacetClick?.(col.key, it.name)}
                    className={cn(
                      'group w-full text-left grid grid-cols-[1fr_auto] items-center gap-2 px-1.5 py-[3px] rounded-sm relative hover:bg-foreground/[0.04]',
                      active && 'bg-primary/10 ring-1 ring-primary/30',
                      !active && it.anomaly && 'bg-[oklch(68%_0.18_28/0.06)]'
                    )}
                  >
                    <div className="min-w-0 flex items-center gap-1.5">
                      <span
                        className={cn(
                          'font-mono truncate text-[11.5px]',
                          active
                            ? 'text-primary'
                            : it.anomaly
                            ? 'text-[oklch(72%_0.17_28)]'
                            : 'text-muted-foreground group-hover:text-foreground'
                        )}
                      >
                        {it.name}
                      </span>
                      {col.key === 'account' && it.label && (
                        <span className="text-muted-foreground/70 text-[10px] shrink-0">
                          · {it.label}
                        </span>
                      )}
                    </div>
                    <span className="tabular-nums text-[10.5px] text-muted-foreground/80 shrink-0">
                      {fmtCount(it.count)}
                    </span>
                    <div className="col-span-2 h-[2px] rounded-full bg-foreground/[0.06] overflow-hidden">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${pct * 100}%`,
                          background: it.anomaly ? 'oklch(68% 0.18 28)' : col.bar,
                          opacity: 0.8,
                        }}
                      />
                    </div>
                  </button>
                );
              })}
              {col.items.length === 0 && (
                <div className="text-[10.5px] text-muted-foreground/60 italic px-1.5 py-1">
                  no data
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
