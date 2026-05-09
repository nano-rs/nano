// SPDX-License-Identifier: AGPL-3.0-or-later

import { Globe, AlertTriangle } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { CloudDossierIdentity, CloudDossierRegion } from '@/lib/api/types';
import { CloudCard, fmtCount } from '../cloud-overview/shared';

interface RegionsStripProps {
  regions: CloudDossierRegion[];
  identity: CloudDossierIdentity;
  /** Click a region tile to scope the base search to that region */
  onPivotRegion?: (regionId: string) => void;
  /** Click an IP in the impossible-travel callout to scope the base search */
  onPivotIp?: (ip: string) => void;
}

export function RegionsStrip({
  regions,
  identity,
  onPivotRegion,
  onPivotIp,
}: RegionsStripProps) {
  const anomalous = regions.filter((r) => r.anomaly !== null && r.anomaly !== undefined);
  const travelIps = identity.ips.slice(0, 2);

  return (
    <CloudCard
      title="Regions touched"
      subtitle={`${regions.length} region${regions.length === 1 ? '' : 's'}${
        anomalous.length ? ` · ${anomalous.length} anomaly flag${anomalous.length === 1 ? '' : 's'}` : ''
      }`}
      accent="oklch(68% 0.14 170)"
    >
      <div className="p-3 space-y-3">
        {anomalous.length > 0 && travelIps.length >= 2 && (
          <div className="rounded-md border border-[oklch(62%_0.18_28/0.4)] bg-[oklch(62%_0.18_28/0.08)] px-3 py-2 flex items-start gap-2.5">
            <AlertTriangle
              className="w-4 h-4 text-[oklch(72%_0.17_28)] shrink-0 mt-0.5"
              strokeWidth={2}
            />
            <div className="min-w-0 flex-1">
              <div className="text-[12.5px] text-foreground font-medium">
                Impossible travel on {identity.id}
              </div>
              <div className="text-[11px] text-muted-foreground/80 mt-0.5 font-mono">
                Same principal was observed from{' '}
                <button
                  onClick={() => onPivotIp?.(travelIps[0].ip)}
                  disabled={!onPivotIp}
                  className="text-[oklch(72%_0.17_28)] enabled:hover:underline"
                  title={onPivotIp ? `Filter by src_ip=${travelIps[0].ip}` : undefined}
                >
                  {travelIps[0].ip}
                  {travelIps[0].geo ? ` (${travelIps[0].geo})` : ''}
                </button>{' '}
                and{' '}
                <button
                  onClick={() => onPivotIp?.(travelIps[1].ip)}
                  disabled={!onPivotIp}
                  className="text-[oklch(72%_0.17_28)] enabled:hover:underline"
                  title={onPivotIp ? `Filter by src_ip=${travelIps[1].ip}` : undefined}
                >
                  {travelIps[1].ip}
                  {travelIps[1].geo ? ` (${travelIps[1].geo})` : ''}
                </button>{' '}
                within the same window.
              </div>
            </div>
          </div>
        )}
        {regions.length === 0 ? (
          <div className="py-6 text-center text-[11px] text-muted-foreground/60 font-mono">
            No regions touched in this window
          </div>
        ) : (
          <div className="grid grid-cols-3 gap-2">
            {regions.map((r) => (
              <button
                key={r.id}
                onClick={() => onPivotRegion?.(r.id)}
                disabled={!onPivotRegion}
                className={cn(
                  'rounded-md border px-2.5 py-1.5 flex items-center gap-2 text-left',
                  onPivotRegion && 'enabled:hover:border-primary/50 transition-colors cursor-pointer',
                  r.anomaly
                    ? 'border-[oklch(62%_0.18_28/0.4)] bg-[oklch(62%_0.18_28/0.06)]'
                    : 'border-border bg-foreground/[0.03]'
                )}
                title={onPivotRegion ? `Filter by cloud_region=${r.id}` : undefined}
              >
                <div className="w-6 h-6 rounded-sm bg-background/60 border border-border flex items-center justify-center shrink-0">
                  <Globe
                    className={cn(
                      'w-[12px] h-[12px]',
                      r.anomaly ? 'text-[oklch(72%_0.17_28)]' : 'text-muted-foreground/70'
                    )}
                    strokeWidth={1.5}
                  />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-[11.5px] text-foreground truncate">
                      {r.id}
                    </span>
                    {r.new_for_principal && (
                      <span className="text-[9px] font-mono px-1 rounded bg-[oklch(72%_0.17_28/0.2)] text-[oklch(72%_0.17_28)]">
                        NEW
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-muted-foreground/70 font-mono truncate">
                    {r.label ?? '—'} · {fmtCount(r.count)}
                  </div>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>
    </CloudCard>
  );
}
