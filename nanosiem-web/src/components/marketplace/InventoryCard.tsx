// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ReactNode } from 'react';
import { inventoryAction, inventoryReason, type InventoryItem } from '@/lib/api/marketplace-inventory';
import { AirgapBadge } from './IntegrationCard';
import { MonoSwatch } from './MonoSwatch';
import { executionStageLabel, inventoryHealthLabel } from '@/lib/marketplace-labels';

export interface CatalogCardProps {
  /** Stable id, exposed as `data-mp-slug`. */
  id: string;
  name: string;
  /** Mono meta line under the name, e.g. `baseline · healthy`. */
  meta: ReactNode;
  /** Two-line body text. */
  body: ReactNode;
  /** Mono footer label on the left (execution stage / delivery path). */
  footerLabel: ReactNode;
  /** Mono footer action/state on the right. */
  footerAction: ReactNode;
  footerActionDisabled?: boolean;
  /** Top-right slot (e.g. the air-gap badge). */
  trailing?: ReactNode;
  disabled?: boolean;
  onOpen: () => void;
}

/** The one Marketplace integration card. Every catalog entry renders through it. */
export function CatalogCard({ id, name, meta, body, footerLabel, footerAction, footerActionDisabled, trailing, disabled, onOpen }: CatalogCardProps) {
  return <button type="button" onClick={onOpen} data-mp-card data-mp-slug={id} disabled={disabled}
    className="bg-card border border-border/60 rounded-lg p-3.5 text-left hover:border-border hover:bg-muted/20 transition-colors group relative shadow-none disabled:cursor-not-allowed disabled:hover:border-border/60 disabled:hover:bg-card">
    <div className="flex items-start gap-3">
      <MonoSwatch ch={(name.trim()[0] || '?').toUpperCase()} tone="var(--primary)" size={38} />
      <div className="flex-1 min-w-0">
        <div className="text-[13.5px] font-semibold text-foreground leading-tight truncate">{name}</div>
        <p className="mt-1 font-mono text-[10.5px] text-muted-foreground">{meta}</p>
      </div>
      {trailing}
    </div>
    <p className="text-[11.5px] text-muted-foreground mt-3 line-clamp-2 leading-[1.5]">{body}</p>
    <div className="mt-3.5 pt-3 border-t border-border/60 flex items-center justify-between min-h-[24px]">
      <span className="font-mono text-[10.5px]">{footerLabel}</span>
      <span className="font-mono text-[11px]" aria-disabled={footerActionDisabled ? true : undefined}>{footerAction}</span>
    </div>
  </button>;
}

/** Small mono chip for the card meta line (`pull`). 1px border, no fill. */
export function MetaBadge({ children }: { children: ReactNode }) {
  return <span className="inline-flex items-center h-[15px] px-1 border border-border rounded-sm font-mono text-[10.5px] leading-none text-muted-foreground align-[1px]">{children}</span>;
}

export function InventoryCard({ item, onOpen, airGap = false }: { item: InventoryItem; onOpen: () => void; airGap?: boolean }) {
  // Platform feeds and connectors need live connectivity. Custom providers only
  // claim offline availability for the explicitly local transform/lookup types.
  const requiresNetwork = item.kind !== 'custom' || item.id.startsWith('connector:') || !['transform', 'lookup'].includes(item.connector);
  return <CatalogCard id={item.id} name={item.name} onOpen={onOpen}
    meta={<>{item.kind} · {inventoryHealthLabel(item.effective_health)}</>}
    body={inventoryReason(item)}
    footerLabel={executionStageLabel(item.execution_stage)}
    footerAction={inventoryAction(item)}
    footerActionDisabled={airGap && item.kind === 'premium' && !item.entitled}
    trailing={airGap && <AirgapBadge requiresNetwork={requiresNetwork} />} />;
}
