// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-482 — collapsible band header row (spans the full table).

import { ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { BandMeta } from './helpers';

interface BandHeaderProps {
  band: BandMeta;
  count: number;
  open: boolean;
  onToggle: () => void;
}

export function BandHeader({ band, count, open, onToggle }: BandHeaderProps) {
  return (
    <tr
      className="border-b border-border cursor-pointer select-none"
      onClick={onToggle}
      style={{ background: 'color-mix(in srgb, var(--panel) 60%, transparent)' }}
    >
      <td colSpan={11} className="px-3 py-2">
        <div className="flex items-center gap-2.5">
          <ChevronRight
            className={cn('w-3 h-3 text-muted-foreground transition-transform', open && 'rotate-90')}
            strokeWidth={2}
          />
          <span
            className="w-[5px] h-[5px] rounded-full"
            style={{
              background: band.accent,
              boxShadow: band.id === 'firing' ? `0 0 6px ${band.accent}` : 'none',
            }}
          />
          <span className="text-[11.5px] font-semibold text-foreground tracking-[0.01em]">
            {band.label}
          </span>
          <span className="text-[10.5px] text-muted-foreground tabular-nums font-mono">{count}</span>
          <span className="text-muted-foreground/60 mx-1">·</span>
          <span className="text-[10.5px] text-muted-foreground">{band.hint}</span>
        </div>
      </td>
    </tr>
  );
}
