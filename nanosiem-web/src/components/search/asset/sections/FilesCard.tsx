// SPDX-License-Identifier: AGPL-3.0-or-later

import { FileText } from 'lucide-react';
import type { AssetDossierFiles } from '@/lib/api/types';
import { SectionCard, EmptyCell } from './_shared';
import { formatBytes, formatCompact } from '../helpers';

interface FilesCardProps {
  files: AssetDossierFiles;
  onOpenAll?: () => void;
}

export function FilesCard({ files, onOpenAll }: FilesCardProps) {
  const { writes, sensitive, exec, recent } = files;

  if (writes === 0 && recent.length === 0) {
    return (
      <SectionCard
        title="File activity"
        action={<span>All file events ↗</span>}
        onActionClick={onOpenAll}
        icon={<FileText className="w-[13px] h-[13px] text-muted-foreground/70" />}
      >
        <EmptyCell>No file events for this entity in range</EmptyCell>
      </SectionCard>
    );
  }

  return (
    <SectionCard
      title="File activity"
      action={<span>All file events ↗</span>}
      onActionClick={onOpenAll}
      icon={<FileText className="w-[13px] h-[13px] text-muted-foreground/70" />}
    >
      <div className="space-y-3">
        <div className="text-[11px] text-muted-foreground/70 font-mono">
          <span className="tabular-nums text-foreground">{formatCompact(writes)}</span> writes
          {sensitive > 0 && (
            <>
              {' · '}
              <span className="tabular-nums text-[oklch(72%_0.14_80)]">{sensitive}</span> sensitive
            </>
          )}
          {exec > 0 && (
            <>
              {' · '}
              <span className="tabular-nums text-foreground">{exec}</span> exec
            </>
          )}
        </div>

        {recent.length > 0 && (
          <ul className="space-y-2">
            {recent.slice(0, 5).map((r, i) => (
              <li key={`${r.ts}-${i}`} className="text-[11.5px]">
                <div className="flex items-baseline gap-2">
                  <span className="font-mono text-muted-foreground/70 tabular-nums shrink-0">
                    {r.ts}
                  </span>
                  <span className="text-[9.5px] font-mono uppercase tracking-[0.08em] px-1 py-0.5 rounded bg-foreground/5 text-muted-foreground/70 shrink-0">
                    {r.action.toUpperCase()}
                  </span>
                  {r.size_bytes > 0 && (
                    <span className="text-[10.5px] font-mono text-muted-foreground/70 shrink-0">
                      {formatBytes(r.size_bytes)}
                    </span>
                  )}
                </div>
                <div className="text-[12px] font-mono text-foreground mt-0.5 truncate" title={r.path}>
                  {r.path}
                </div>
                {r.proc && (
                  <div className="text-[10.5px] font-mono text-muted-foreground/70 mt-0.5">
                    by <span className="text-foreground/80">{r.proc}</span>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </SectionCard>
  );
}
