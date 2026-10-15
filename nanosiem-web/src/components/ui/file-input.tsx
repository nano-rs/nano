// SPDX-License-Identifier: AGPL-3.0-or-later
import * as React from 'react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

export interface FileInputProps {
  /** Id of the underlying `<input type="file">`; point a `<Label htmlFor>` at it. */
  id: string;
  accept?: string;
  /** Name of the currently chosen file, or null when none is chosen. Controlled. */
  fileName: string | null;
  onFile: (file: File) => void;
  /** Clears the selection. When omitted no clear action is shown. */
  onClear?: () => void;
  buttonLabel?: React.ReactNode;
  emptyLabel?: React.ReactNode;
  disabled?: boolean;
  className?: string;
  'aria-describedby'?: string;
}

function ClearIcon() {
  return <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" className="h-3 w-3">
    <path d="M6 6l12 12M18 6L6 18" />
  </svg>;
}

/**
 * Compact file picker: a visually hidden native input driven by a small
 * secondary button, with the chosen filename in mono beside it. The button is
 * the single tab stop; a `<Label htmlFor={id}>` still targets the native input.
 * The input value is reset after every pick so choosing the same file again
 * fires `onFile`.
 */
export function FileInput({ id, accept, fileName, onFile, onClear, buttonLabel = 'Choose file…', emptyLabel = 'no file', disabled, className, ...aria }: FileInputProps) {
  const input = React.useRef<HTMLInputElement>(null);
  const statusId = `${id}-status`;
  return <div className={cn('flex h-7 min-w-0 items-center gap-2', className)}>
    <input ref={input} id={id} type="file" accept={accept} disabled={disabled} tabIndex={-1} className="sr-only"
      aria-describedby={[statusId, aria['aria-describedby']].filter(Boolean).join(' ')}
      onChange={event => {
        const file = event.target.files?.[0];
        event.target.value = '';
        if (file) onFile(file);
      }} />
    <Button type="button" variant="secondary" size="sm" className="h-7 shrink-0 px-2.5 text-[11.5px]" disabled={disabled}
      aria-describedby={statusId} onClick={() => input.current?.click()}>
      {buttonLabel}
    </Button>
    <span id={statusId} className={cn('min-w-0 truncate font-mono text-[10.5px]', fileName ? 'text-foreground' : 'text-muted-foreground')} title={fileName ?? undefined}>
      {fileName ?? emptyLabel}
    </span>
    {fileName && onClear && <button type="button" disabled={disabled} onClick={onClear} aria-label={`Clear ${fileName}`}
      className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-muted/40 hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:opacity-50">
      <ClearIcon />
    </button>}
  </div>;
}
