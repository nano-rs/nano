// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-482 — floating pill shown when rows are selected.

import { CheckCircle2, MinusCircle, Tag, Download, Trash2, X } from 'lucide-react';

interface BulkActionBarProps {
  count: number;
  onEnable: () => void;
  onDisable: () => void;
  onTag?: () => void;
  onExport?: () => void;
  onDelete: () => void;
  onClear: () => void;
  disabled?: boolean;
}

export function BulkActionBar({
  count,
  onEnable,
  onDisable,
  onTag,
  onExport,
  onDelete,
  onClear,
  disabled,
}: BulkActionBarProps) {
  return (
    <div
      role="toolbar"
      aria-label="Bulk rule actions"
      className="absolute bottom-4 left-1/2 -translate-x-1/2 z-50 flex items-center gap-1 rounded-lg border border-border bg-card shadow-[0_8px_24px_rgba(0,0,0,0.4)] px-2 py-1.5"
      style={{ animation: 'slideIn 0.18s ease' }}
    >
      <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums px-2">
        {count} selected
      </span>
      <div className="w-px h-5 bg-border mx-1" />
      <button
        type="button"
        disabled={disabled}
        onClick={onEnable}
        className="h-7 px-2 rounded-md text-[11.5px] text-foreground hover:bg-foreground/5 flex items-center gap-1.5 disabled:opacity-50"
      >
        <CheckCircle2 className="w-3.5 h-3.5" strokeWidth={2} />
        Enable
      </button>
      <button
        type="button"
        disabled={disabled}
        onClick={onDisable}
        className="h-7 px-2 rounded-md text-[11.5px] text-foreground hover:bg-foreground/5 flex items-center gap-1.5 disabled:opacity-50"
      >
        <MinusCircle className="w-3.5 h-3.5" strokeWidth={2} />
        Disable
      </button>
      {onTag && (
        <button
          type="button"
          disabled={disabled}
          onClick={onTag}
          className="h-7 px-2 rounded-md text-[11.5px] text-foreground hover:bg-foreground/5 flex items-center gap-1.5 disabled:opacity-50"
        >
          <Tag className="w-3.5 h-3.5" strokeWidth={2} />
          Tag
        </button>
      )}
      {onExport && (
        <button
          type="button"
          disabled={disabled}
          onClick={onExport}
          className="h-7 px-2 rounded-md text-[11.5px] text-foreground hover:bg-foreground/5 flex items-center gap-1.5 disabled:opacity-50"
        >
          <Download className="w-3.5 h-3.5" strokeWidth={2} />
          Export
        </button>
      )}
      <div className="w-px h-5 bg-border mx-1" />
      <button
        type="button"
        disabled={disabled}
        onClick={onDelete}
        className="h-7 px-2 rounded-md text-[11.5px] text-destructive hover:bg-destructive/10 flex items-center gap-1.5 disabled:opacity-50"
      >
        <Trash2 className="w-3.5 h-3.5" strokeWidth={2} />
        Delete
      </button>
      <button
        type="button"
        onClick={onClear}
        aria-label="Clear selection"
        className="h-7 w-7 rounded-md text-muted-foreground hover:text-foreground hover:bg-foreground/5 flex items-center justify-center ml-1"
      >
        <X className="w-3.5 h-3.5" strokeWidth={2} />
      </button>
    </div>
  );
}
