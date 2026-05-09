// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';
import type { CloudDossierResource } from '@/lib/api/types';
import { CloudCard, cloudSevTone } from '../cloud-overview/shared';

interface TopResourcesProps {
  resources: CloudDossierResource[];
  /** Click a resource row to scope by resource_name / resource_id */
  onPivotResource?: (arn: string) => void;
}

export function TopResources({ resources, onPivotResource }: TopResourcesProps) {
  return (
    <CloudCard
      title="Resources touched"
      subtitle={`${resources.length} principal-targeted resource${resources.length === 1 ? '' : 's'}`}
      accent="oklch(68% 0.14 320)"
    >
      <div className="p-2">
        {resources.length === 0 && (
          <div className="px-2 py-6 text-center text-[11px] font-mono text-muted-foreground/60">
            No resources touched in this window
          </div>
        )}
        <div className="space-y-[1px]">
          {resources.map((r) => {
            const tone = cloudSevTone(r.severity);
            const resourceShort = r.arn.split(':').slice(-1)[0] ?? r.arn;
            return (
              <button
                key={r.arn}
                onClick={() => onPivotResource?.(r.arn)}
                disabled={!onPivotResource}
                className="w-full grid grid-cols-[1fr_auto_auto] gap-3 items-center px-2 py-1.5 rounded-sm hover:bg-foreground/[0.03] font-mono text-[11.5px] text-left enabled:hover:text-primary enabled:cursor-pointer"
                title={onPivotResource ? `Filter by this resource` : undefined}
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className={cn('w-1 h-3 rounded-sm shrink-0', tone.dot)} />
                    <span className="text-foreground truncate">{resourceShort}</span>
                  </div>
                  <div className="text-[10px] text-muted-foreground/70 pl-[10px] truncate">
                    {r.type || '—'}
                    {r.account && ` · ${r.account}`}
                  </div>
                  {r.touched.length > 0 && (
                    <div className="text-[10px] text-muted-foreground/60 pl-[10px] truncate">
                      {r.touched.join(' · ')}
                    </div>
                  )}
                </div>
                <div className="text-right shrink-0">
                  <div className="tabular-nums text-muted-foreground/90">
                    {r.changes.toLocaleString()}
                  </div>
                  <div className="text-[9.5px] text-muted-foreground/70 tabular-nums">
                    {r.last_at}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </CloudCard>
  );
}
