// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Main's NAN-3661 Log Sources list flag, ported by NAN-4941: a source whose
 * pull config or connector feed is failed, blocked or paused. The reason is on
 * hover; the source's Delivery panel has the detail and the fix.
 */

import { AlertTriangle } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { attentionSummary, worstAttention, type DeliveryAttention } from '@/lib/delivery-attention';
import { cn } from '@/lib/utils';

const TONE: Record<string, string> = {
  failed: 'bg-red-500/12 text-red-500',
  blocked: 'bg-orange-500/12 text-orange-500',
  paused: 'bg-foreground/[0.06] text-muted-foreground',
};

export function DeliveryAttentionBadge({ items }: { items: DeliveryAttention[] }) {
  const worst = worstAttention(items);
  if (!worst) return null;
  const kinds = new Set(items.map((i) => i.kind));
  const what = kinds.size === 1 ? [...kinds][0] : 'delivery';
  const lines = attentionSummary(items);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={(e) => e.stopPropagation()}
          data-testid="delivery-attention-badge"
          aria-label={`${what} ${worst}: ${lines.join('; ')}`}
          className={cn('shrink-0 inline-flex items-center gap-1 h-[15px] px-1 rounded-[3px] font-mono text-[9px] uppercase tracking-wider', TONE[worst])}
        >
          <AlertTriangle className="w-[9px] h-[9px]" strokeWidth={1.5} />
          {what} {worst}
        </button>
      </TooltipTrigger>
      <TooltipContent side="top" sideOffset={6} collisionPadding={8} className="text-[11px] max-w-[360px]">
        <div className="flex flex-col gap-0.5">
          {lines.map((line) => (
            <span key={line} className="font-mono text-[10.5px]">{line}</span>
          ))}
          <span className="text-muted-foreground">Open the source for the fix (Delivery panel).</span>
        </div>
      </TooltipContent>
    </Tooltip>
  );
}
