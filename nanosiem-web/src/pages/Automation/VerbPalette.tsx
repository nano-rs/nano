// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — verb palette (mock soar3-case.jsx EntityAct + VerbPalette).
 * Click or right-click an entity pill to list what can be done to it with
 * the tenant's packs: effect mark, verb, ↺ when an inverse exists, the
 * connection (or why it is unavailable) and the vendor badge. Picking one
 * opens Run action prefilled; nothing is sent from the palette itself.
 */
import { useRef, useState, type KeyboardEvent } from 'react';
import type { SoarCatalog, SoarConnection } from '@/lib/api/soar';
import { Popover, PopoverAnchor, PopoverContent } from '@/components/ui/popover';
import { cn } from '@/lib/utils';
import { verbOf, type EntityKind } from './soar-model';
import { EFF_TXT, EffMark, Entity, Inv, Vendor } from './soar-kit';
import { paletteItems, shortValue, type PaletteItem } from './case-model';

export function VerbPalette({
  kind,
  value,
  catalog,
  connections,
  canRun,
  demo = false,
  caseLabel,
  size = 'sm',
  onPick,
}: {
  kind: EntityKind;
  value: string;
  catalog: SoarCatalog | undefined;
  connections: SoarConnection[];
  canRun: boolean;
  demo?: boolean;
  /** Mono case reference in the palette header, e.g. CASE-1042. */
  caseLabel?: string;
  size?: 'sm' | 'md';
  onPick: (item: PaletteItem) => void;
}) {
  const [open, setOpen] = useState(false);
  const list = useRef<HTMLDivElement>(null);
  const items = open ? paletteItems(kind, catalog, connections, { canRun, demo }) : [];

  const onListKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    e.preventDefault();
    const buttons = Array.from(list.current?.querySelectorAll<HTMLButtonElement>('button:not([disabled])') ?? []);
    if (!buttons.length) return;
    const at = buttons.indexOf(document.activeElement as HTMLButtonElement);
    const next = e.key === 'ArrowDown' ? (at + 1) % buttons.length : (at - 1 + buttons.length) % buttons.length;
    buttons[next]?.focus();
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverAnchor asChild>
        <button
          type="button"
          aria-label={`Actions for ${value}`}
          aria-haspopup="menu"
          aria-expanded={open}
          title="Click or right-click for actions"
          onClick={() => setOpen((o) => !o)}
          onContextMenu={(e) => {
            e.preventDefault();
            setOpen(true);
          }}
          className={cn(
            'inline-flex max-w-full cursor-context-menu rounded-[4px] align-middle hover:ring-1 hover:ring-primary/60 focus:outline-none focus-visible:ring-1 focus-visible:ring-ring',
            open && 'ring-1 ring-primary/60',
          )}
        >
          <Entity t={kind} v={shortValue(value)} title={value} size={size} className="max-w-[260px]" />
        </button>
      </PopoverAnchor>
      <PopoverContent
        align="start"
        sideOffset={4}
        className="w-[320px] overflow-hidden rounded-[10px] border-border-2 p-0"
        data-testid="verb-palette"
        onOpenAutoFocus={(e) => {
          e.preventDefault();
          list.current?.querySelector<HTMLButtonElement>('button:not([disabled])')?.focus();
        }}
      >
        <div className="flex items-center gap-2 border-b border-border px-3 py-2.5">
          <Entity t={kind} v={shortValue(value)} title={value} size="sm" className="max-w-[220px]" />
          <span className="flex-1" />
          {caseLabel && <span className="font-mono text-[10px] text-fg-4">{caseLabel}</span>}
        </div>
        <div ref={list} role="menu" aria-label={`Actions for ${value}`} className="flex max-h-[320px] flex-col overflow-y-auto p-1" onKeyDown={onListKey}>
          {items.map((it) => (
            <button
              key={`${it.pack.name}.${it.action.name}`}
              type="button"
              role="menuitem"
              disabled={!!it.why}
              title={it.why ?? `${it.action.display_name} · ${it.pack.display_name}`}
              onClick={() => {
                setOpen(false);
                onPick(it);
              }}
              className={cn(
                'flex h-9 shrink-0 items-center gap-2.5 rounded-md px-2.5 text-left focus:outline-none',
                it.why ? 'cursor-not-allowed opacity-45' : 'hover:bg-primary/[0.08] focus-visible:bg-primary/[0.08]',
              )}
            >
              <EffMark e={it.effect} size={9} />
              <span className={cn('text-[12px] font-medium', it.effect ? EFF_TXT[it.effect] : 'text-foreground')}>
                {verbOf(it.action.name, it.action.display_name)}
              </span>
              {it.action.rollback && <Inv className="text-[10px]" />}
              <span className="flex-1" />
              <span className="max-w-[130px] truncate text-[10.5px] text-muted-foreground">{it.why ?? it.connection?.label}</span>
              <Vendor p={it.pack.name} label={it.pack.vendor} size={16} />
            </button>
          ))}
          {items.length === 0 && <div className="px-3 py-3 text-[11.5px] text-muted-foreground">No actions for this entity type.</div>}
        </div>
        <div className="border-t border-border px-3 py-1.5 font-mono text-[10px] text-fg-4">Opens Run action prefilled · approval follows server policy</div>
      </PopoverContent>
    </Popover>
  );
}
