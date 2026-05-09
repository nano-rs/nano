// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-484 — CODE lens. Thin chrome around the existing CodeMirror editor.
// Toolbar surfaces detection_mode + validation state; CodeMirror handles
// syntax, autocomplete, and linting as before.

import { forwardRef } from 'react';
import {
  Check,
  Circle,
  Terminal,
  AlertCircle,
  Copy,
  ClipboardPaste,
  Scissors,
  TextSelect,
  Undo2,
  Redo2,
  WandSparkles,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { CodeMirrorEditor, type CodeMirrorEditorRef } from '@/components/editor';
import type { ValidationState } from '@/components/editor/detection-linter';
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuShortcut,
  ContextMenuTrigger,
} from '@/components/ui/context-menu';

interface CodeLensProps {
  value: string;
  onChange: (v: string) => void;
  onValidationChange?: (v: ValidationState | null) => void;
  readOnly?: boolean;
  /** Extracted from the YAML frontmatter; purely for the tone of the toolbar badge. */
  detectionMode?: 'realtime' | 'scheduled' | null;
  validation?: ValidationState | null;
  /** Click handler on the Valid/Invalid toolbar badge — opens the details dialog. */
  onOpenValidationDetails?: () => void;
  /** Triggered by the context menu Format Query entry. */
  onFormat?: () => void;
}

export const CodeLens = forwardRef<CodeMirrorEditorRef, CodeLensProps>(function CodeLens(
  { value, onChange, onValidationChange, readOnly, detectionMode, validation, onOpenValidationDetails, onFormat },
  ref,
) {
  // Context menu actions. We defer Cut/Copy/Paste/Select All/Undo/Redo to the
  // browser's document.execCommand, which CodeMirror respects when the editor
  // has focus. Falls back gracefully in headless/test environments.
  const exec = (cmd: string) => {
    try {
      document.execCommand(cmd);
    } catch {
      // execCommand is deprecated on some browsers but still widely available;
      // there's no better cross-CM-version entry point for clipboard actions
      // without reaching into the EditorView instance from this shell.
    }
  };
  const modeLabel =
    detectionMode === 'scheduled' ? 'scheduled' : detectionMode === 'realtime' ? 'real-time' : '—';
  const modeHint =
    detectionMode === 'scheduled'
      ? 'runs on cron schedule'
      : detectionMode === 'realtime'
        ? 'streams via materialized view'
        : 'detection mode not set';

  const valStatus: 'valid' | 'invalid' | 'unchecked' = validation
    ? validation.valid
      ? 'valid'
      : 'invalid'
    : 'unchecked';
  const valTone =
    valStatus === 'valid'
      ? 'text-[var(--success)]'
      : valStatus === 'invalid'
        ? 'text-[var(--destructive)]'
        : 'text-muted-foreground';

  return (
    <div className="flex-1 min-w-0 h-full flex flex-col min-h-0">
      <div className="h-8 flex items-center px-3 gap-3 border-b border-border bg-background/60 text-[10.5px] font-mono shrink-0">
        <span className="inline-flex items-center gap-1.5 text-muted-foreground">
          <Terminal className="w-3 h-3" strokeWidth={1.75} />
          CODE
        </span>
        <span className="text-muted-foreground/60">·</span>
        <span className="inline-flex items-center gap-1 text-muted-foreground">
          <Circle
            className={cn(
              'w-2 h-2 fill-current',
              detectionMode === 'scheduled'
                ? 'text-[var(--success)]'
                : detectionMode === 'realtime'
                  ? 'text-[var(--primary)]'
                  : 'text-muted-foreground',
            )}
            strokeWidth={0}
          />
          <span>{modeLabel}</span>
          <span className="text-muted-foreground/60">{modeHint}</span>
        </span>

        <div className="flex-1" />

        <button
          type="button"
          onClick={onOpenValidationDetails}
          disabled={!onOpenValidationDetails}
          title={valStatus === 'invalid' ? 'Click to see why' : 'Validation details'}
          className={cn(
            'inline-flex items-center gap-1 rounded px-1 -mx-1 transition-colors',
            valTone,
            onOpenValidationDetails && 'hover:bg-foreground/5 cursor-pointer',
            !onOpenValidationDetails && 'cursor-default',
          )}
        >
          {valStatus === 'valid' ? (
            <Check className="w-3 h-3" strokeWidth={1.75} />
          ) : valStatus === 'invalid' ? (
            <AlertCircle className="w-3 h-3" strokeWidth={1.75} />
          ) : (
            <Circle className="w-3 h-3" strokeWidth={1.5} />
          )}
          <span className="font-semibold">
            {valStatus === 'valid' ? 'Valid' : valStatus === 'invalid' ? 'Invalid' : 'Unchecked'}
          </span>
        </button>
      </div>

      <ContextMenu>
        <ContextMenuTrigger asChild>
          <div className="flex-1 min-h-0 bg-background">
            <CodeMirrorEditor
              ref={ref}
              value={value}
              onChange={onChange}
              onValidationChange={onValidationChange}
              readOnly={readOnly}
              className="h-full"
            />
          </div>
        </ContextMenuTrigger>
        <ContextMenuContent className="w-48">
          <ContextMenuItem onClick={() => exec('cut')} disabled={readOnly}>
            <Scissors className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
            Cut
            <ContextMenuShortcut>⌘X</ContextMenuShortcut>
          </ContextMenuItem>
          <ContextMenuItem onClick={() => exec('copy')}>
            <Copy className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
            Copy
            <ContextMenuShortcut>⌘C</ContextMenuShortcut>
          </ContextMenuItem>
          <ContextMenuItem onClick={() => exec('paste')} disabled={readOnly}>
            <ClipboardPaste className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
            Paste
            <ContextMenuShortcut>⌘V</ContextMenuShortcut>
          </ContextMenuItem>
          <ContextMenuSeparator />
          <ContextMenuItem onClick={() => exec('selectAll')}>
            <TextSelect className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
            Select all
            <ContextMenuShortcut>⌘A</ContextMenuShortcut>
          </ContextMenuItem>
          <ContextMenuSeparator />
          <ContextMenuItem onClick={() => exec('undo')} disabled={readOnly}>
            <Undo2 className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
            Undo
            <ContextMenuShortcut>⌘Z</ContextMenuShortcut>
          </ContextMenuItem>
          <ContextMenuItem onClick={() => exec('redo')} disabled={readOnly}>
            <Redo2 className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
            Redo
            <ContextMenuShortcut>⇧⌘Z</ContextMenuShortcut>
          </ContextMenuItem>
          {onFormat && (
            <>
              <ContextMenuSeparator />
              <ContextMenuItem onClick={onFormat} disabled={readOnly}>
                <WandSparkles className="w-3.5 h-3.5 mr-2" strokeWidth={1.75} />
                Format query
              </ContextMenuItem>
            </>
          )}
        </ContextMenuContent>
      </ContextMenu>
    </div>
  );
});
