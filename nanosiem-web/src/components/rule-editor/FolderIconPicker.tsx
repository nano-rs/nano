// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-730 — compact 5×4 icon picker for custom rule folders.
//
// Two surfaces share this picker:
//   • Inline (FolderIconPicker) — embedded in the "+ folder" / "New folder…"
//     create flows alongside the name input. The user picks an icon at
//     create time; the chosen slug is sent to the parent's onSubmit/onChange.
//   • Popover (FolderIconPickerPopover) — wraps a custom folder header in
//     RuleRail's context-menu "Change icon…" entry so analysts can update
//     an existing folder without re-creating it.
//
// Both surfaces render the same 5×4 grid from `FOLDER_ICONS` and call back
// with a slug. Persistence + audit happen in the parent.

import { useState, type ReactNode } from 'react';
import { Popover, PopoverAnchor, PopoverContent } from '@/components/ui/popover';
import { cn } from '@/lib/utils';
import { FOLDER_ICONS } from './folder-icons';

interface FolderIconPickerProps {
  value: string;
  onChange: (slug: string) => void;
  /** Compact (h-7 w-7) by default. Override to embed in tighter rows. */
  buttonClassName?: string;
}

/**
 * Stateless inline grid. Use inside a parent that already controls the
 * input value (e.g. the "+ folder" inline form). The grid does NOT close
 * itself on click — selection stays visible so the user can review before
 * submitting the form.
 */
export function FolderIconPicker({ value, onChange, buttonClassName }: FolderIconPickerProps) {
  return (
    <div className="grid grid-cols-5 gap-1" role="radiogroup" aria-label="Folder icon">
      {FOLDER_ICONS.map(({ slug, Component, label }) => {
        const active = slug === value;
        return (
          <button
            key={slug}
            type="button"
            role="radio"
            aria-checked={active}
            aria-label={label}
            title={label}
            onClick={() => onChange(slug)}
            className={cn(
              'inline-flex items-center justify-center h-7 w-7 rounded-md border transition-colors',
              active
                ? 'border-[var(--primary)]/55 bg-[color-mix(in_srgb,var(--primary)_12%,transparent)] text-[var(--primary)]'
                : 'border-border bg-foreground/[0.02] text-muted-foreground hover:text-foreground hover:bg-[color-mix(in_srgb,var(--foreground)_4%,transparent)]',
              buttonClassName,
            )}
          >
            <Component className="w-3.5 h-3.5" strokeWidth={1.75} />
          </button>
        );
      })}
    </div>
  );
}

interface FolderIconPickerPopoverProps {
  /** Currently-selected icon slug — typically from `folderSettings[name]`. */
  value: string;
  /** Open/close is parent-controlled so callers can wire it from a context-menu. */
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Called with the picked slug. Popover closes after a pick. */
  onPick: (slug: string) => void;
  /** Trigger (anchor) element. The popover anchors to this. */
  children: ReactNode;
  /** Optional title shown at the top of the popover. */
  title?: string;
}

/**
 * Popover wrapper for editing an existing folder's icon. Used by RuleRail's
 * context-menu "Change icon…" path. Picks dispatch immediately and close
 * the popover; cancellation is implicit (click outside / Esc).
 */
export function FolderIconPickerPopover({
  value,
  open,
  onOpenChange,
  onPick,
  children,
  title,
}: FolderIconPickerPopoverProps) {
  const [draft, setDraft] = useState(value);

  // PopoverAnchor (rather than PopoverTrigger) so the wrapped element keeps
  // its own click semantics — RuleRail also wires the same node into a
  // ContextMenuTrigger and to a folder-toggle button click. Anchor only
  // handles positioning, not interaction.
  return (
    <Popover open={open} onOpenChange={(o) => { onOpenChange(o); if (o) setDraft(value); }}>
      <PopoverAnchor asChild>{children}</PopoverAnchor>
      <PopoverContent className="w-[208px] p-2" align="start" sideOffset={4}>
        {title && (
          <div className="px-1 pb-1.5 font-mono text-[9.5px] tracking-[0.12em] uppercase text-muted-foreground/70">
            {title}
          </div>
        )}
        <FolderIconPicker
          value={draft}
          onChange={(slug) => {
            setDraft(slug);
            onPick(slug);
            onOpenChange(false);
          }}
        />
      </PopoverContent>
    </Popover>
  );
}
