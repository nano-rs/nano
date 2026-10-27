// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4661 — the canvas "add to …" / "add step" block picker: a popover
 * anchored to the button with the palette's entries (Blocks, then pack
 * actions), a search box and keyboard navigation. A pick inserts exactly at
 * the button's lane; nothing is inserted until the user picks.
 */
import { Fragment, useMemo, useState, type KeyboardEvent, type ReactElement } from 'react';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { cn } from '@/lib/utils';
import type { BlockEntry } from './FlowPalette';

/** DOM id for an entry (keys hold spaces and dots). */
const optId = (key: string) => `fbp-${key.replace(/[^A-Za-z0-9_-]/g, '_')}`;

export function FlowBlockPicker({ entries, onPick, children, label }: {
  /** Entries for this slot; `off` already carries why a block cannot go here. */
  entries: () => BlockEntry[];
  onPick: (e: BlockEntry) => void;
  /** The button the popover anchors to. */
  children: ReactElement;
  label: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>{children}</PopoverTrigger>
      {open && (
        <PopoverContent align="center" className="w-[280px] p-0" aria-label={label} data-testid="block-picker">
          <PickerBody entries={entries()} onPick={(e) => { setOpen(false); onPick(e); }} onClose={() => setOpen(false)} />
        </PopoverContent>
      )}
    </Popover>
  );
}

function PickerBody({ entries, onPick, onClose }: { entries: BlockEntry[]; onPick: (e: BlockEntry) => void; onClose: () => void }) {
  const [q, setQ] = useState('');
  const shown = useMemo(() => entries.filter((x) => x.label.toLowerCase().includes(q.toLowerCase())), [entries, q]);
  const enabled = shown.filter((x) => !x.off);
  const [active, setActive] = useState<string | null>(null);
  const cur = enabled.find((x) => x.key === active) ?? enabled[0] ?? null;
  const step = (d: 1 | -1) => {
    if (!enabled.length) return;
    const i = cur ? enabled.indexOf(cur) : -1;
    setActive(enabled[(i + d + enabled.length) % enabled.length].key);
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); step(1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); step(-1); }
    else if (e.key === 'Enter') { e.preventDefault(); if (cur) onPick(cur); }
    // The editor's window Escape (deselect / close palette) must not fire too.
    else if (e.key === 'Escape') { e.preventDefault(); onClose(); }
  };
  let group: string | null = null;
  return (
    <div className="flex flex-col" onKeyDown={onKey}>
      <div className="border-b border-border p-2">
        <input
          autoFocus
          value={q}
          onChange={(e) => { setQ(e.target.value); setActive(null); }}
          placeholder="Search blocks"
          aria-label="Search blocks to add"
          role="combobox"
          aria-expanded
          aria-controls="flow-block-picker-list"
          aria-activedescendant={cur ? optId(cur.key) : undefined}
          className="h-7 w-full rounded border border-border bg-background px-2 text-[12px] text-foreground outline-none placeholder:text-muted-foreground focus:border-fg-4"
        />
      </div>
      <div id="flow-block-picker-list" role="listbox" className="flex max-h-[280px] flex-col overflow-auto p-1.5">
        {shown.map((x) => {
          const head = x.group !== group ? (group = x.group) : null;
          const on = cur?.key === x.key;
          return (
            <Fragment key={x.key}>
              {head && <div className="px-1.5 pb-1 pt-1.5 font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">{head === 'Logic' ? 'Blocks' : head}</div>}
              <button
                type="button"
                id={optId(x.key)}
                role="option"
                aria-selected={on}
                disabled={!!x.off}
                title={x.off || undefined}
                tabIndex={-1}
                onMouseEnter={() => !x.off && setActive(x.key)}
                onClick={() => onPick(x)}
                data-testid="picker-row"
                className={cn('flex h-7 w-full shrink-0 items-center gap-2 rounded px-1.5 text-left disabled:opacity-50', on && 'bg-background')}
              >
                <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-foreground">{x.label}</span>
                {x.off ? <span className="max-w-[55%] shrink-0 truncate text-[10.5px] text-muted-foreground">{x.off}</span> : x.tag}
              </button>
            </Fragment>
          );
        })}
        {!shown.length && <div className="px-1.5 py-2 text-[11.5px] text-muted-foreground">No blocks match.</div>}
      </div>
    </div>
  );
}
